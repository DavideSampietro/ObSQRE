#include "subtol_srv.h"
#include "base64.h"

#include <iostream>
#include <cstdio>
#include <chrono>
#include <ctime>
#include <random>
#include <utility>
#include <limits>
#include <vector>
#include <cstring>
#include <exception>
#include <stdexcept>

#include "boost/algorithm/string.hpp"
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"

// helpers for std::chrono which is INSANE!!!
using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

void subtol_srv::process_headers(std::istream &request, http_request_t &proc)
{
	// use C++ initializer lists
	static std::vector<const char*> supported_methods {"GET", "POST", "DELETE"};
	static std::vector<const char*> supported_headers {"Content-Length:", "Cookie:", "Host:"};

	// some other checks -- avoid repeated headers...
	bool already_found_content_length = false;
	bool already_found_host = false;

	// get the HTTP request line
	std::string request_line;
	std::getline(request, request_line);

	// tokenize it around whitespaces
	std::vector<std::string> reql_tokens;
	boost::split(reql_tokens, request_line, boost::is_any_of(" "), boost::token_compress_off);

	if(reql_tokens.size() != 3 || reql_tokens[2] != "HTTP/1.1\r")
	{
		proc.set_http_response(400);
		return;
	}

	int method = -1;
	
	for(unsigned int i = 0; i < supported_methods.size(); i++)
		if(reql_tokens[0] == supported_methods[i])
		{
			method = i;
			break;
		}

	if(method == -1)
	{
		proc.set_http_response(501);
		return;
	}

	// enums require explicit cast
	proc.method = (http_method_t)method;

	// if everything is correct, just dump the resource...
	proc.resource = std::move(reql_tokens[1]);

	std::string header_title;
	while(request.peek() != '\r') // the empty line at the end of HTTP headers
	{
		/*
			This code will work properly for cURL, Python Requests and Firefox but doesn't save from intentional tampering.
			Accepted format: (SP is single space)
			<header-name><:> SP <header-content>
		*/
		int header_num = -1;

		// get stuff up to the first whitespace (<SP>)
		request >> header_title;

		for(unsigned int i = 0; i < supported_headers.size(); i++)
			if(header_title == supported_headers[i])
			{
				header_num = i;
				break;
			}

		switch(header_num)
		{
			case 0: // Content-Length
				// dump content-length
				request >> proc.content_length;
				if(request) // the stream may get invalid due to invalid characters, in which case YOU STOP!
				{
					request.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				}
				if(!request || already_found_content_length)
				{
					proc.set_http_response(400);
					return; // rough but hey...
				}
				already_found_content_length = true;
				break;
			case 1: // Cookie
				{
					std::string cookies;
					std::getline(request, cookies);
					// pray for return value optimization!!! This should happen as the rhs is of type &&
					std::list<std::string> valid_cookie = parse_cookie_header(cookies);

					/*
						Lazy way, I can do that since I'm going to process only one cookie!
					*/
					if(valid_cookie.size())
					{
						proc.session_id = valid_cookie.front().substr(1 + valid_cookie.front().find_first_of('='));
						valid_cookie.pop_front();
					}
				}
				break;
			case 2: // Host
				// don't need this, just compliance with HTTP/1.1 protocol...
				request.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				if(already_found_host)
				{
					proc.set_http_response(400);
					return;
				}
				else
					already_found_host = true;
				break;
			default:
				// ignore line...
				request.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		}
	}

	// discard the last \n after peeking a leading \r
	request.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

	if(!already_found_host)
	{
		proc.set_http_response(400);
	}
}

// just discards invalid cookies
std::list<std::string> subtol_srv::parse_cookie_header(std::string &cookies)
{
	// for comfort, please append = to cookie name!!
	static std::vector<const char*> accepted_cookies {"session-id="};

	// i want constant time deletion
	std::list<std::string> ck_tokens;
	boost::split(ck_tokens, cookies, boost::is_any_of("; \r\n"), boost::token_compress_on);


	for(auto it = ck_tokens.begin(); it != ck_tokens.end(); )
	{
		unsigned int i;

		for(i = 0; i < accepted_cookies.size(); i++)
			if(boost::starts_with(*it, accepted_cookies[i]))
				break;

		if(i == accepted_cookies.size()) // this means it is an invalid cookie
			it = ck_tokens.erase(it);
		else
			++it;
	}

	return ck_tokens;
}

/*
	When I get the raw pointer, I don't want any other thread to work on that
	pointer as well.
	In order to do that, I substitute the currently loaded pointer in the unsorted_map
	with a nullptr using its move constructor.
*/
std::unique_ptr<subtol_session_t> subtol_srv::get_context_handle(const std::string &session_id, bool &found)
{
	std::unique_ptr<subtol_session_t> fetch;
	
	found = true;

	try {
		std::lock_guard<std::mutex> lck_context(session_guard);
		// transfer ownership and store nullptr into contexts
		fetch = std::move(session_store.at(session_id));
	} catch(const std::out_of_range &oore) {
		found = false;
		fetch = nullptr;
	}
	
	return fetch;
}

void subtol_srv::restore_context_handle(const std::string &session_id, std::unique_ptr<subtol_session_t> &pl)
{
	std::lock_guard<std::mutex> lck_context(session_guard);
	session_store[session_id] = std::move(pl);
}

void subtol_srv::process_api_calls(http_request_t &proc, std::istream &request)
{
	static std::vector<const char*> api_calls {"/start_session", "/attestation", "/poll", "/configure", "/close", "/load", "/substring", "/suffix"};

	unsigned int which_api_call = 0;

	while(which_api_call < api_calls.size() && !boost::starts_with(proc.resource, api_calls[which_api_call]))
		++which_api_call;

	if(which_api_call < api_calls.size())
	{
		// chop request...
		proc.resource = proc.resource.substr(std::strlen(api_calls[which_api_call]));
	}

	switch(which_api_call)
	{
		case 0: // start_session
			start_session(proc);
			break;

		case 1: // attestation
			attestation(proc, request);
			break;
		
		case 2: // poll
			poll(proc);
			break;
			
		case 3: // configure
			configure(proc, request);
			break;
		
		case 4: // close
			close(proc);
			break;
		
		case 5: // load
			load(proc, request);
			break;
		
		case 6: // substring
			substring(proc, request);
			break;
		
		case 7: // suffix
			suffix(proc);
			break;
			
		default:
			proc.set_http_response(404);
	}
}

void subtol_srv::suffix(http_request_t &proc)
{
	// wrong resource
	if(proc.resource != "")
	{
		proc.set_http_response(414);
		return;
	}
	
	// wrong method
	if(proc.method != GET)
	{
		proc.set_http_response(405);
		return;
	}
	
	bool found;
	std::unique_ptr<subtol_session_t> sess = get_context_handle(proc.session_id, found);
	
	// wrong session-id
	if(!found)
	{
		proc.set_http_response(404);
		return;
	}
	
	// session already active
	if(sess.get() == nullptr)
	{
		proc.set_http_response(409);
		return;
	}
	
	if(sess->phase == 2)
	{
		std::uint8_t mac[16];
		std::uint8_t iv[12];
		std::int32_t *payload;
		std::size_t payload_size;

		encl.call_fetch_sa(sess->attestation_context, &payload, &payload_size, iv, mac);
		
		if(payload_size != 0 && payload != nullptr)
		{
			bin_msg_out(proc.response_body, iv, mac, (std::uint8_t*) payload, payload_size * sizeof(std::int32_t));
			std::free(payload);
		}
		else
			proc.set_http_response(404);
	}
	else
		proc.set_http_response(401);
	
	restore_context_handle(proc.session_id, sess);
}

void subtol_srv::substring(http_request_t &proc, std::istream &request)
{
	// wrong resource
	if(proc.resource != "")
	{
		proc.set_http_response(414);
		return;
	}
	
	// wrong method
	if(proc.method != GET)
	{
		proc.set_http_response(405);
		return;
	}
	
	// empty body
	if(proc.content_length == -1)
		proc.set_http_response(411);
	
	bool found;
	std::unique_ptr<subtol_session_t> sess = get_context_handle(proc.session_id, found);
	
	// wrong session-id
	if(!found)
	{
		proc.set_http_response(404);
		return;
	}
	
	// session already active
	if(sess.get() == nullptr)
	{
		proc.set_http_response(409);
		return;
	}
	
	if(sess->phase == 2)
	{
		std::unique_ptr<char[]> buff_array(new char[proc.content_length+1]);
		request.read(&buff_array[0], proc.content_length);
		buff_array[proc.content_length] = '\0';

		std::uint8_t mac[16];
		std::uint8_t iv[12];
		std::uint8_t *payload;
		std::size_t payload_size;

		bin_msg_in(&buff_array[0], iv, mac, &payload, &payload_size);
	
		// Fix memory leakage
		if(payload != nullptr)
		{
			// res[0] and res[1] keep start and end
			// res[2] and res[3] make 64-bit for time
			std::int32_t res[4];
			std::int64_t *res64 = (std::int64_t*) res;
		
			tt start = hres::now();
			encl.call_query(sess->attestation_context, payload, payload_size, iv, mac, res);
			tt end = hres::now();
		
			nano diff = end - start;
			res64[1] = diff.count();
		
			bin_msg_out(proc.response_body, iv, mac, (std::uint8_t*) res, 4 * sizeof(std::int32_t));
			delete[] payload;
		}
		else
			proc.set_http_response(400);
	}
	else
		proc.set_http_response(401);
	
	restore_context_handle(proc.session_id, sess);
}

void subtol_srv::load(http_request_t &proc, std::istream &request)
{
	// wrong resource
	if(proc.resource != "")
	{
		proc.set_http_response(414);
		return;
	}
	
	// wrong method
	if(proc.method != POST)
	{
		proc.set_http_response(405);
		return;
	}
	
	// empty body
	if(proc.content_length == -1)
		proc.set_http_response(411);
	
	bool found;
	std::unique_ptr<subtol_session_t> sess = get_context_handle(proc.session_id, found);
	
	// wrong session-id
	if(!found)
	{
		proc.set_http_response(404);
		return;
	}
	
	// session already active
	if(sess.get() == nullptr)
	{
		proc.set_http_response(409);
		return;
	}
	
	if(sess->phase == 2)
	{
		std::unique_ptr<char[]> buff_array(new char[proc.content_length+1]);
		
		request.read(&buff_array[0], proc.content_length);
		buff_array[proc.content_length] = '\0';

		std::unique_ptr<std::uint8_t[]> mac(new std::uint8_t[16]);
		std::unique_ptr<std::uint8_t[]> iv(new std::uint8_t[12]);
		std::uint8_t *payload;
		std::size_t payload_size;

		bin_msg_in(&buff_array[0], &iv[0], &mac[0], &payload, &payload_size);
	
		if((int)payload_size <= 64)
		{
			proc.set_http_response(400);
			if(payload != nullptr)
				delete[] payload;
		}
		
		else {
			proc.set_http_response(202);
			// release ownership (to avoid deallocation) and returns handled pointer
			subtol_session_t *temp = sess.release();
			std::thread background_loading(&subtol_srv::async_loader, this, proc.session_id, temp,
				std::unique_ptr<std::uint8_t[]>(payload), payload_size, std::unique_ptr<std::uint8_t[]>(std::move(iv)), std::unique_ptr<std::uint8_t[]>(std::move(mac)));
			// it becomes non-joinable and the function can safely return to answer the client
			// since the context will be a nullptr, it won't be usable until async_loader returns
			background_loading.detach();
		}
	}
	else {
		proc.set_http_response(401);
		restore_context_handle(proc.session_id, sess);
	}
}

void subtol_srv::async_loader(std::string sess_id, subtol_session_t *sess, std::unique_ptr<std::uint8_t[]> payload, std::size_t payload_size, std::unique_ptr<std::uint8_t[]> iv, std::unique_ptr<std::uint8_t[]> mac)
{
	FILE *fp;
	char *filename = new char[payload_size - 64 + 1];
	
	// make filename a \0 terminated string
	std::memcpy(filename, &payload[64], payload_size - 64);
	filename[payload_size - 64] = '\0';
	
	fp = fopen(filename, "rb");
	
	if(fp != NULL)
	{
		encl.call_loader(sess->attestation_context, fp, &payload[0], &iv[0], &mac[0]);
		fclose(fp);
	}
	
	std::unique_ptr<subtol_session_t> temp_ptr(sess);
	restore_context_handle(sess_id, temp_ptr);
	
	delete[] filename;
}

void subtol_srv::configure(http_request_t &proc, std::istream &request)
{
	// wrong resource
	if(proc.resource != "")
	{
		proc.set_http_response(414);
		return;
	}
	
	// wrong method
	if(proc.method != POST)
	{
		proc.set_http_response(405);
		return;
	}
	
	// empty body
	if(proc.content_length == -1)
		proc.set_http_response(411);
	
	bool found;
	std::unique_ptr<subtol_session_t> sess = get_context_handle(proc.session_id, found);
	
	// wrong session-id
	if(!found)
	{
		proc.set_http_response(404);
		return;
	}
	
	// session already active
	if(sess.get() == nullptr)
	{
		proc.set_http_response(409);
		return;
	}
	
	if(sess->phase == 2)
	{
		std::unique_ptr<char[]> buff_array(new char[proc.content_length+1]);
		request.read(&buff_array[0], proc.content_length);
		buff_array[proc.content_length] = '\0';

		std::uint8_t mac[16];
		std::uint8_t iv[12];
		std::uint8_t *payload;
		std::size_t payload_size;

		bin_msg_in(&buff_array[0], iv, mac, &payload, &payload_size);
	
		if(payload_size != 7 * sizeof(std::uint32_t))
		{
			proc.set_http_response(400);
		}
		else {
			sgx_status_t res = encl.call_configure(sess->attestation_context, payload, mac);
		
			if(res != SGX_SUCCESS)
				proc.set_http_response(400);
			else
				proc.set_http_response(200);
		}
		
		// Fix memory leakage
		if(payload != nullptr)
			delete[] payload;
	}
	else
		proc.set_http_response(401);
	
	restore_context_handle(proc.session_id, sess);
}

void subtol_srv::close(http_request_t &proc)
{
	bool restore = false;

	if(proc.resource != "")
	{
		proc.set_http_response(414);
		return;
	}
	
	if(proc.method != DELETE)
	{
		proc.set_http_response(405);
		return;
	}
	
	// lock the required session
	bool found;
	std::unique_ptr<subtol_session_t> sess = get_context_handle(proc.session_id, found);
	
	if(!found)
		proc.set_http_response(404);
	
	else if(sess.get() == nullptr)
		proc.set_http_response(409);
	
	else {
		sgx_status_t ret;
		
		if(sess->phase == 2)
			ret = encl.call_close_session(sess->attestation_context);
		else
			ret = encl.close_attestation_context(sess->attestation_context);
			
		if(ret != SGX_SUCCESS) // if attestation context was not cleaned-up...
		{
			// if you fail to delete entry from enclave, don't erase the session from the http server as well
			restore = true;
			int status_code;
			
			if(ret == SGX_ERROR_INVALID_STATE)
				status_code = 409;
			else if(ret == SGX_ERROR_INVALID_PARAMETER)
				status_code = 404;
			else
				status_code = 500;
			
			proc.set_http_response(status_code);
		}
	
		if(!restore)
		{
			std::lock_guard<std::mutex> s_guard(session_guard);
			session_store.erase(proc.session_id);
		}
		else
			restore_context_handle(proc.session_id, sess);
	}
}

void subtol_srv::poll(http_request_t &proc)
{
	if(proc.resource != "")
	{
		proc.set_http_response(414);
		return;
	}
	
	if(proc.method != GET)
	{
		proc.set_http_response(405);
		return;
	}
	
	// lock the required session
	bool found;
	std::unique_ptr<subtol_session_t> sess = get_context_handle(proc.session_id, found);
	
	if(!found)
		proc.set_http_response(404);
	
	else if(sess.get() == nullptr)
		proc.set_http_response(409);
	
	else {
		proc.set_http_response(200);
		restore_context_handle(proc.session_id, sess);
	}
}

void subtol_srv::start_session(http_request_t &proc)
{
	static const char * const _rnd_string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static const int _rnd_len = std::strlen(_rnd_string);
	
	if(proc.resource != "")
	{
		proc.set_http_response(404);
		return;
	}
	
	if(proc.method != GET)
	{
		proc.set_http_response(405);
		return;
	}

	sgx_status_t status_code;
	sgx_ra_context_t ctx;
	
	// for phase 1 of attestation process
	std::uint32_t egid;
	sgx_ra_msg1_t msg1;

	ctx = encl.create_attestation_context(&status_code);
	
	if(status_code != SGX_SUCCESS)
	{
		proc.set_http_response(500);
		return;
	}
	
	status_code = encl.attestation_phase_1(ctx, &egid, &msg1);
	
	if(status_code != SGX_SUCCESS)
	{
		proc.set_http_response(500);
		
		do {
			status_code = encl.close_attestation_context(ctx);
		} while(status_code != SGX_SUCCESS);
		
		return;
	}
	
	// if I got here, everything went fine with enclaves!
	char cookie[33];
	bool inserted = true;
	std::mt19937 gen(time(NULL));
	subtol_session_t *next_session = new subtol_session_t;

	// create session record
	next_session->attestation_context = ctx;
	next_session->phase = 1;
	
	do {
		for(int i = 0; i < 32; i++)
			cookie[i] = _rnd_string[gen() % _rnd_len];
		
		cookie[32] = '\0';
		
		{
			std::lock_guard<std::mutex> lck_session(session_guard);
			auto res = session_store.emplace(cookie, next_session);
			// in the unlikely case we generate right the same token!!!
			inserted = std::get<1>(res);
		}
		
	} while(!inserted);

	proc.session_id = cookie;
	msg01_marshalling(proc.response_body, egid, &msg1);
}

void subtol_srv::attestation(http_request_t &proc, std::istream &request)
{
	bool reset_handle = true;
	
	// invalid cookie
	if(proc.session_id.length() != 32)
	{
		proc.set_http_response(403);
		return;
	}

	// method not allowed
	if((proc.resource == "" && proc.method != DELETE) ||
		(proc.resource == "/1" && proc.method != POST) ||
		(proc.resource == "/2" && proc.method != POST))
	{
		proc.set_http_response(405);
		return;
	}
	
	// lock the required session
	bool found;
	std::unique_ptr<subtol_session_t> sess = get_context_handle(proc.session_id, found);
		
	if(!found) // session not existing
	{
		proc.set_http_response(404);
		return;
	}
	
	else if(sess.get() == nullptr) // session already in use
	{
		proc.set_http_response(409);
		return;
	}
	
	// actually process request if all the preconditions are met (session correctly fetched from session_store)
	if(sess->phase != 1)
		// use close instead!!!
		proc.set_http_response(403);
	
	else if(proc.resource == "")
	{
		sgx_status_t status;
		
		status = encl.close_attestation_context(sess->attestation_context);
		
		if(status == SGX_SUCCESS)
		{
			{
				std::lock_guard<std::mutex> lck_session(session_guard);
				session_store.erase(proc.session_id);
			}
			
			reset_handle = false;
			proc.set_http_response(200);
		}
		
		else
			proc.set_http_response(500);
	}
	
	else if(proc.resource == "/1")
	{
		sgx_status_t status;
		
		// here I actually NEED to read from the socket...
		if(proc.content_length == -1)
			proc.set_http_response(411);
			
		else {
			std::unique_ptr<char[]> buff_array(new char[proc.content_length+1]);
			request.read(&buff_array[0], proc.content_length);
			buff_array[proc.content_length] = '\0';

			std::uint32_t msg2_size;
			sgx_ra_msg2_t *msg2 = nullptr;
			std::uint32_t msg3_size;
			sgx_ra_msg3_t *msg3 = nullptr;

			msg2_marshalling(&buff_array[0], &msg2, &msg2_size);

			if(msg2_size == (std::uint32_t)-1) // wrong json body...
			{
				proc.set_http_response(400);
			}
			else {
				status = encl.attestation_phase_2(sess->attestation_context, msg2, msg2_size, &msg3, &msg3_size);

				if(status != SGX_SUCCESS)
					proc.set_http_response(422);
				else
					msg3_marshalling(proc.response_body, msg3_size, msg3);
			}

			if(msg2 != nullptr)
				delete[] msg2;

			if(msg3 != nullptr)
				// TODO => check whether to use delete[] or std::free
				std::free(msg3);
		}
	}
	
	else if(proc.resource == "/2")
	{	
		if(proc.content_length == -1)
			proc.set_http_response(411);
			
		else {
			std::unique_ptr<char[]> buff_array(new char[proc.content_length+1]);
			request.read(&buff_array[0], proc.content_length);
			buff_array[proc.content_length] = '\0';

			std::uint8_t mac[16];
			std::uint8_t iv[12];
			std::uint8_t *payload;
			std::size_t payload_size;

			bin_msg_in(&buff_array[0], iv, mac, &payload, &payload_size);

			if(payload_size == (std::size_t)-1) // wrong json body...
			{
				proc.set_http_response(400);
			}
			
			else {
				sgx_status_t res = encl.exchange_msg4(sess->attestation_context, payload, payload_size, mac);
				
				if(res == SGX_SUCCESS)
				{
					res = encl.call_create_session(sess->attestation_context);
					sess->phase = 2;
					proc.set_http_response(200);
				}

				else {
					res = encl.close_attestation_context(sess->attestation_context);
		
					if(res == SGX_SUCCESS)
					{
						{
							std::lock_guard<std::mutex> lck_session(session_guard);
							session_store.erase(proc.session_id);
						}
			
						reset_handle = false;
						proc.set_http_response(410);
					}
					
					else
						proc.set_http_response(500);
				}
			}
			
			// Fix memory leakage
			if(payload != nullptr)
				delete[] payload;
		}
	}
	
	else
		proc.set_http_response(404);
	
	if(reset_handle)
		restore_context_handle(proc.session_id, sess);
}

void subtol_srv::bin_msg_in(char *json_msg, std::uint8_t *iv, std::uint8_t *mac, std::uint8_t **payload, std::size_t *size)
{
	rapidjson::Document doc;
	
	std::string base64_string;
	std::vector<unsigned char> buffer;
	
	*payload = nullptr;
	*size = -1;
	
	rapidjson::ParseResult is_valid_json = doc.Parse(json_msg);
	
	if(!is_valid_json)
		return;
	
	auto it = doc.FindMember("iv");
	if(it != doc.MemberEnd() && it->value.IsString())
	{
		base64_string.assign(it->value.GetString());
		if(base64_dec(buffer, base64_string) == 12)
			std::memcpy(iv, buffer.data(), 12);
		else return;
	}
	else return;
	
	it = doc.FindMember("mac");
	if(it != doc.MemberEnd() && it->value.IsString())
	{
		base64_string.assign(it->value.GetString());
		if(base64_dec(buffer, base64_string) == 16)
			std::memcpy(mac, buffer.data(), 16);
		else return;
	}
	else return;
	
	it = doc.FindMember("payload");
	if(it != doc.MemberEnd() && it->value.IsString())
	{
		base64_string.assign(it->value.GetString());
		int paylen = base64_dec(buffer, base64_string);
		
		if(paylen > 0)
		{
			*payload = new std::uint8_t[paylen];
			std::memcpy(*payload, buffer.data(), paylen);
			*size = paylen;
		}
		else return;
	}
	else return;
}

void subtol_srv::bin_msg_out(asio::streambuf &response, std::uint8_t *iv, std::uint8_t *mac, std::uint8_t *payload, std::size_t size)
{
	rapidjson::Document doc;
	std::string buffer;

	doc.SetObject();
	rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
	
	base64_enc(buffer, iv, 12);
	doc.AddMember("iv", buffer, allocator);
	
	buffer.assign("");
	base64_enc(buffer, mac, 16);
	doc.AddMember("mac", buffer, allocator);
	
	buffer.assign("");
	base64_enc(buffer, payload, size);
	doc.AddMember("payload", buffer, allocator);
	
	rapidjson::StringBuffer json_string;
	rapidjson::Writer<rapidjson::StringBuffer> writer(json_string);
	doc.Accept(writer);
	
	std::ostream out(&response);
	out << json_string.GetString();
}

void subtol_srv::msg01_marshalling(asio::streambuf &response, std::uint32_t msg0, sgx_ra_msg1_t *msg1)
{
	rapidjson::Document doc;
	std::string buffer;

	doc.SetObject();
	rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();

	rapidjson::Value msg0_json(rapidjson::kObjectType);
		base64_enc(buffer, (unsigned char*)&msg0, sizeof(msg0));
		msg0_json.AddMember("extended_epid_group_id", buffer, allocator);
		buffer.assign("");

	rapidjson::Value msg1_json(rapidjson::kObjectType);
		rapidjson::Value srv_pubk(rapidjson::kObjectType);
			base64_enc(buffer, (unsigned char*)&msg1->g_a.gx, SGX_ECP256_KEY_SIZE);
			srv_pubk.AddMember("x_coord", buffer, allocator);
			buffer.assign("");
			base64_enc(buffer, (unsigned char*)&msg1->g_a.gy, SGX_ECP256_KEY_SIZE);
			srv_pubk.AddMember("y_coord", buffer, allocator);
			buffer.assign("");
		msg1_json.AddMember("sgx_server_ec_pubkey", srv_pubk, allocator);
		base64_enc(buffer, (unsigned char*)&msg1->gid, sizeof(sgx_epid_group_id_t));
		msg1_json.AddMember("sgx_epid_group_id", buffer, allocator);

	doc.AddMember("msg0", msg0_json, allocator);
	doc.AddMember("msg1", msg1_json, allocator);

	// now serialize the built json!
	rapidjson::StringBuffer json_string;
	rapidjson::Writer<rapidjson::StringBuffer> writer(json_string);
	doc.Accept(writer);

	std::ostream out(&response);
	out << json_string.GetString();
}

void subtol_srv::msg2_marshalling(char *jmsg2, sgx_ra_msg2_t **msg2, std::uint32_t *msg2_size)
{
	rapidjson::Document doc;
	std::vector<unsigned char> buffer;
	std::string base64_string;
	int sigrl_size;

	// init ** for notifying the caller what's going on...
	*msg2 = nullptr;
	*msg2_size = -1;

	rapidjson::ParseResult is_valid_json = doc.Parse(jmsg2);
	if(!is_valid_json)
		return;

	// now staaaart parsin' the whoooole json...
	auto it = doc.FindMember("sigrl_size");
	if(it != doc.MemberEnd() && it->value.IsUint())
		sigrl_size = it->value.GetUint();
	else return;

	// allocate a proper msg2 struct with a good sigrl field!!!
	*msg2 = (sgx_ra_msg2_t*) new std::uint8_t[sizeof(sgx_ra_msg2_t) + sigrl_size];
	(*msg2)->sig_rl_size = sigrl_size;

	// dump kdf
	it = doc.FindMember("kdf");
	if(it != doc.MemberEnd() && it->value.IsUint())
	{
		(*msg2)->kdf_id = it->value.GetUint();
	}
	else return;

	// dump quote type
	it = doc.FindMember("quote_type");
	if(it != doc.MemberEnd() && it->value.IsUint())
		(*msg2)->quote_type = it->value.GetUint();
	else return;

	// dump the public key of the client Gb
	it = doc.FindMember("sgx_client_ec_pubkey");
	if(it != doc.MemberEnd())
	{
		auto it_x = it->value.FindMember("x_coord");
		auto it_y = it->value.FindMember("y_coord");

		if(it_x != doc.MemberEnd() && it_y != doc.MemberEnd() &&
			it_x->value.IsString() && it_y->value.IsString())
		{
			base64_string.assign(it_x->value.GetString());
			if(base64_dec(buffer, base64_string) == SGX_ECP256_KEY_SIZE)
				std::memcpy(&(*msg2)->g_b.gx, (void*)buffer.data(), SGX_ECP256_KEY_SIZE);
			else return;

			base64_string.assign(it_y->value.GetString());
			if(base64_dec(buffer, base64_string) == SGX_ECP256_KEY_SIZE)
				std::memcpy(&(*msg2)->g_b.gy, (void*)buffer.data(), SGX_ECP256_KEY_SIZE);
			else return; // wrong public key coordinate size
		}
		else return; // x_coord or y_coord not found
	}
	else return; // sgx_client_ec_pubkey not found

	// dump the signature
	it = doc.FindMember("sig_sp");
	if(it != doc.MemberEnd())
	{
		auto it_x = it->value.FindMember("x_coord");
		auto it_y = it->value.FindMember("y_coord");

		if(it_x != doc.MemberEnd() && it_y != doc.MemberEnd() &&
			it_x->value.IsString() && it_y->value.IsString())
		{
			base64_string.assign(it_x->value.GetString());
			if(base64_dec(buffer, base64_string) == SGX_ECP256_KEY_SIZE)
				std::memcpy(&(*msg2)->sign_gb_ga.x, (void*)buffer.data(), SGX_ECP256_KEY_SIZE);
			else return;

			base64_string.assign(it_y->value.GetString());
			if(base64_dec(buffer, base64_string) == SGX_ECP256_KEY_SIZE)
				std::memcpy(&(*msg2)->sign_gb_ga.y, (void*)buffer.data(), SGX_ECP256_KEY_SIZE);
			else return; // wrong signature coordinate size
		}
		else return; // x_coord or y_coord not found
	}
	else return; // signature not found

	// dump the cmac_a
	it = doc.FindMember("cmac_a");
	if(it != doc.MemberEnd() && it->value.IsString())
	{
		base64_string.assign(it->value.GetString());
		if(base64_dec(buffer, base64_string) == 16) // 16 is mac field size
			std::memcpy(&(*msg2)->mac, (void*)buffer.data(), 16);
		else return;
	}
	else return;

	// dump the spid
	it = doc.FindMember("spid");
	if(it != doc.MemberEnd() && it->value.IsString())
	{
		base64_string.assign(it->value.GetString());
		if(base64_dec(buffer, base64_string) == 16) // 16 is the SPID field size...
			std::memcpy(&(*msg2)->spid, (void*)buffer.data(), 16);
		else return;
	}
	else return;

	// finally dump the sigrl!!!
	it = doc.FindMember("sigrl");
	if(sigrl_size)
	{
		if(it != doc.MemberEnd() && it->value.IsString()) // sigrl not empty...
		{
			base64_string.assign(it->value.GetString());
			if(base64_dec(buffer, base64_string) == sigrl_size)
				std::memcpy(&(*msg2)->sig_rl, (void*)buffer.data(), sigrl_size);
			else return;
		}
		else return;
	}
	else if(it == doc.MemberEnd() || !it->value.IsNull())
		return;

	*msg2_size = sizeof(sgx_ra_msg2_t) + sigrl_size;
}

void subtol_srv::msg3_marshalling(asio::streambuf &response, std::uint32_t msg3_size, sgx_ra_msg3_t *msg3)
{
	rapidjson::Document doc;
	std::string buffer;

	doc.SetObject();
	rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();

	base64_enc(buffer, (unsigned char*)&(msg3->mac), 16);
	doc.AddMember("cmac_m", buffer, allocator);
	buffer.assign("");

	rapidjson::Value Ga(rapidjson::kObjectType);
		base64_enc(buffer, (unsigned char*)&(msg3->g_a.gx), SGX_ECP256_KEY_SIZE);
		Ga.AddMember("x_coord", buffer, allocator);
		buffer.assign("");
		base64_enc(buffer, (unsigned char*)&(msg3->g_a.gy), SGX_ECP256_KEY_SIZE);
		Ga.AddMember("y_coord", buffer, allocator);
		buffer.assign("");
	doc.AddMember("sgx_server_ec_pubkey", Ga, allocator);

	base64_enc(buffer, (unsigned char*)&(msg3->ps_sec_prop), sizeof(sgx_ps_sec_prop_desc_t));
	doc.AddMember("security_prop", buffer, allocator);
	buffer.assign("");

	base64_enc(buffer, (unsigned char*)&(msg3->quote), msg3_size - offsetof(sgx_ra_msg3_t, quote));
	doc.AddMember("quote", buffer, allocator);

	// now serialize the built json!
	rapidjson::StringBuffer json_string;
	rapidjson::Writer<rapidjson::StringBuffer> writer(json_string);
	doc.Accept(writer);

	std::ostream out(&response);
	out << json_string.GetString();
}

void subtol_srv::process_request(asio::ip::tcp::socket &client)
{
	// read-end of the socket
	asio::streambuf socket_in;
	std::istream request(&socket_in);
	// write-end of the socket
	asio::streambuf socket_out;
	std::ostream response(&socket_out);
	// request struct
	http_request_t handle;

	try {
		asio::error_code read_error;
		std::size_t amount = 1;

		// read all the http headers
		asio::read_until(client, socket_in, "\r\n\r\n", read_error);

		while(read_error)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			if(client.available() == 0)
				break;
			asio::read_until(client, socket_in, "\r\n\r\n", read_error);
		}

		if(read_error)
			throw asio::system_error(read_error);

		process_headers(request, handle);

		if(handle.status_code == 200) // this means the previous phase was successful!!!
		{
			// read the rest of the body...
			int remaining = handle.content_length - socket_in.in_avail();

			if(handle.content_length > 0)
			{
				amount = asio::read(client, socket_in, asio::transfer_exactly(remaining), read_error);
				remaining -= amount;
				amount = 1;

				// >= was causing unwanted delays here!
				while(remaining > 0 && amount)
				{
					std::this_thread::sleep_for(std::chrono::milliseconds(500));
					amount = asio::read(client, socket_in, asio::transfer_exactly(remaining), read_error);
					remaining -= amount;
				}

				if(remaining > 0)
					throw asio::system_error(read_error);
			}

			process_api_calls(handle, request); // throws asio::system_error, which can be caught by the exception handler!
		}

		// later on...
		response << "HTTP/1.1 " << handle.status_code << " \r\n"; // protocol requires space anyways
		response << "Content-Type: application/json\r\n";
		response << "Content-Length: " << handle.response_body.size() << "\r\n";
		
		if(handle.session_id.length())
			response << "Set-Cookie: session-id=" << handle.session_id << "; HttpOnly\r\n";
		
		response << "Connection: close\r\n";
		response << "Server: subtol ToyServer\r\n\r\n";

		size_t purge_bytes1 = client.send(socket_out.data());
		size_t purge_bytes2 = client.send(handle.response_body.data());

		socket_out.consume(purge_bytes1);
		handle.response_body.consume(purge_bytes2);
	} catch(const asio::system_error &ase) {
		std::cerr << ase.what() << std::endl;
	}
}
