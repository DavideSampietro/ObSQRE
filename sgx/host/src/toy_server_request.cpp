#include "toy_server_request.h"

// static variables
bool http_request_t::already_init = false;
const char* http_request_t::response_bodies[600];

void http_request_t::init_strings()
{
	for(int i = 0; i < 599; i++)
		response_bodies[i] = nullptr;

	// put here error strings
	response_bodies[200] = "{\"status\":\"OK\"}";
	response_bodies[202] = "{\"status\":\"Accepted\"}";
	response_bodies[400] = "{\"error\":\"Bad Request\"}";
	response_bodies[401] = "{\"error\":\"Unauthorized\"}";
	response_bodies[403] = "{\"error\":\"Forbidden\"}";
	response_bodies[404] = "{\"error\":\"Not Found\"}";
	response_bodies[405] = "{\"error\":\"Method Not Allowed\"}";
	response_bodies[409] = "{\"error\":\"Conflict\"}";
	response_bodies[410] = "{\"error\":\"Gone\"}";
	response_bodies[414] = "{\"error\":\"URI Too Long\"}";
	response_bodies[411] = "{\"error\":\"Length Required\"}";
	response_bodies[418] = "{\"error\":\"I'm A Teapot\"}";
	response_bodies[422] = "{\"error\":\"Unprocessable Entity\"}";
	response_bodies[500] = "{\"error\":\"Internal Server Error\"}";
	response_bodies[501] = "{\"error\":\"Not Implemented\"}";

	already_init = true;
}

void http_request_t::set_http_response(int status_code)
{
	this->status_code = status_code;

	if(already_init && response_bodies[status_code] != nullptr)
		this->response_body.sputn(response_bodies[status_code], std::strlen(response_bodies[status_code]));
}
