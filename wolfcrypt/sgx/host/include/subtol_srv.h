#ifndef SUBTOL_SRV_H
#define SUBTOL_SRV_H

#include "toy_server.h"

#include <unordered_map>
#include <string>
#include <memory>

#include "subtol_enclave.h"
#include "toy_server_request.h"

#include "sgx_key_exchange.h"

struct subtol_session_t {
	sgx_ra_context_t attestation_context;
	// book-keeping of the interactions between client and server
	int phase;
};

class subtol_srv: public toy_server {
private:
	// embedded enclave
	subtol_enclave encl;
	
	// session store
	std::mutex session_guard;
	std::unordered_map<std::string, std::unique_ptr<subtol_session_t>> session_store;
	
	// access methods for session store
	std::unique_ptr<subtol_session_t> get_context_handle(const std::string &session_id, bool &found);
	void restore_context_handle(const std::string &session_id, std::unique_ptr<subtol_session_t> &pl);
	
	// http parsing
	void process_headers(std::istream &request, http_request_t &proc);
	std::list<std::string> parse_cookie_header(std::string &cookies);
	
	// API calls
	void process_api_calls(http_request_t &proc, std::istream &request);
	
	void start_session(http_request_t &proc);
	void attestation(http_request_t &proc, std::istream &request);
	void poll(http_request_t &proc);
	void configure(http_request_t &proc, std::istream &request);
	void close(http_request_t &proc);
	void load(http_request_t &proc, std::istream &request);
	void substring(http_request_t &proc, std::istream &request);
	void suffix(http_request_t &proc);
	
	void async_loader(std::string sess_id, subtol_session_t *sess,
		std::unique_ptr<std::uint8_t[]> payload, std::size_t payload_size,
		std::unique_ptr<std::uint8_t[]> iv, std::unique_ptr<std::uint8_t[]> mac);
	
	// message exchange
	
	// special format for attestation messages
	void msg01_marshalling(asio::streambuf &response, std::uint32_t msg0, sgx_ra_msg1_t *msg1);
	void msg2_marshalling(char *jmsg2, sgx_ra_msg2_t **msg2, std::uint32_t *msg2_size);
	void msg3_marshalling(asio::streambuf &response, std::uint32_t msg3_size, sgx_ra_msg3_t *msg3);
	
	// common format for other exchanged data
	void bin_msg_in(char *json_msg, std::uint8_t *iv, std::uint8_t *mac, std::uint8_t **payload, std::size_t *size);
	void bin_msg_out(asio::streambuf &response, std::uint8_t *iv, std::uint8_t *mac, std::uint8_t *payload, std::size_t size);

protected:
	void process_request(asio::ip::tcp::socket &client);

public:
	explicit subtol_srv(std::uint16_t port_number): toy_server(port_number) {
		encl.init_enclave();
	}

	~subtol_srv() { }
};

#endif // SUBTOL_SRV_H
