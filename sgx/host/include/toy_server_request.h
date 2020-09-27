#ifndef TOY_SERVER_REQUEST_H
#define TOY_SERVER_REQUEST_H

#include <string>
#include "asio/streambuf.hpp"

typedef enum{GET, POST, DELETE} http_method_t;

struct http_request_t {
private:
	static bool already_init;
	// http status codes from 100~599 (potentially) => 0~599 for convenience
	static const char *response_bodies[600];

public:
	// these fields are public for ease-of-use
	// (instead of a thousand getter-setter methods!!!)
	int status_code;
	int content_length;
	http_method_t method;
	std::string resource;
	std::string session_id;
	asio::streambuf response_body;

	//void set_http_response(http_request_t &req, int status_code);
	http_request_t() {
		status_code = 200;
		content_length = -1;
	}
	void set_http_response(int status_code);

	static void init_strings();
};

#endif
