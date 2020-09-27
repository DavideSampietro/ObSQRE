#ifndef TOY_SERVER_H
#define TOY_SERVER_H

#include <list>

#include <cstdint>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include "asio.hpp"


class toy_server {
private:
	// killswitch
	std::atomic<bool> run_server;

	// Socket listener
	std::uint16_t server_port;
	asio::io_context cont;
	asio::ip::tcp::acceptor server_socket;

	// Pending HTTP requests
	std::mutex requests_mutex;
	std::condition_variable no_requests;
	std::list<asio::ip::tcp::socket> pending_requests;
	
	// private methods
	void accept_request();

protected:
	virtual void process_request(asio::ip::tcp::socket &client) = 0;
	//virtual void cleanup() = 0;

public:
	explicit toy_server(std::uint16_t port_number);
	virtual ~toy_server() {
		/* there are at least four ways to handle the server:
			1. spawn a listener thread, call kill_switch from main and then joining
			the listener thread (like I did with sigwait)
			2. create a custom signal handler that invokes kill_switch on a global
			toy_server object. Main thread will return from listening and this will
			be a graceful death as well.
			3. never call kill_switch, the server will be always running until it
			fails
			4. define a derived class with protected access specifier that instantiated
			a thread for listening and then killswitches and joins it in the destructor

			If I put kill_switch here, I wouldn't have any way to join all the spawn
			threads, because the thread destroying the object, most probably the "main"
			would exit immediately and all the threads it spanwd would be killed as
			well!!!
		*/
	}

	void kill_switch();

	void launch_server(int concurrency);
};

#endif
