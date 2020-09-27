#include "toy_server.h"

#include <iostream>
#include <cstddef>
#include <cstdlib>

toy_server::toy_server(std::uint16_t port_number): cont(), server_socket(cont)
{
	server_port = port_number;
}

void toy_server::launch_server(int concurrency)
{
	asio::error_code error;
	std::thread *thread_pool;

	if(concurrency <= 0)
	{
		std::cerr << "Number of worker threads <= 0" << std::endl;
		return;
	}

	// initialize the listener
	server_socket.open(asio::ip::tcp::v4(), error);
	if(error)
	{
		std::cerr << "An error occurred while opening the listener => " << error.message() << std::endl;
		return;
	}

	server_socket.bind(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), server_port), error);
	if(error)
	{
		std::cerr << "An error occurred while binding the listener => " << error.message() << std::endl;
		server_socket.close(error);
		return;
	}
	
	server_socket.listen(asio::socket_base::max_listen_connections, error);
	run_server.store(true);

	// instantiate an array of worker threads, default constructed (not representing any real thread of execution)
	thread_pool = new std::thread[concurrency];

	for(int i = 0; i < concurrency; i++)
		// move assignment
		thread_pool[i] = std::thread(&toy_server::accept_request, this);

	while(true)
	{
		try {
			// create socket without opening it
			asio::ip::tcp::socket connection(cont);
			// connection here passed by reference... [blocking]
			server_socket.accept(connection);

			if(!run_server.load())
				break;

			{
				std::lock_guard<std::mutex> lck_list(requests_mutex);
				// invokes the version of push_back with move constructor, so that now new connection is empty
				pending_requests.push_back(std::move(connection));
				no_requests.notify_one();
			}
			// connection is killed here since we are exiting the scope, so no leaks!
		} catch(const asio::system_error &ase) {
			std::cerr << "While running server => " << ase.what() << std::endl;
		}
	}

	// now it's time to kill all the working threads...
	// if I got here, run_server.load() evaluates to false, so no need to set it to false again!
	{
		// push_back dummy socket to make sure no thread will stumble in pending_requests.empty()!
		std::lock_guard<std::mutex> lck_list(requests_mutex);
		pending_requests.push_back(asio::ip::tcp::socket(cont));
		no_requests.notify_all();
	}

	for(int i = 0; i < concurrency; i++)
		thread_pool[i].join();
	delete[] thread_pool;

	// destroys all pending connections...
	pending_requests.clear();
	server_socket.close(error);
}

void toy_server::kill_switch()
{
	// activate kill switch
	run_server.store(false);

	// wake-up listening server socket
	if(server_socket.is_open())
	{
		asio::ip::tcp::socket shutdown(cont);
		asio::ip::tcp::endpoint edp(asio::ip::make_address("127.0.0.1"), server_port);
		shutdown.connect(edp);
		shutdown.close();
	}
}

void toy_server::accept_request()
{
	while(true)
	{
		// create empty socket
		asio::ip::tcp::socket request(cont);

		{
			std::unique_lock<std::mutex> lck_list(requests_mutex);

			if(pending_requests.empty())
				no_requests.wait(lck_list);

			if(!run_server.load())
				break;

			// move assignment
			request = std::move(pending_requests.front());
			pending_requests.pop_front();
		}

		// set O_NONBLOCK mode in order to allow non-blocking operations
		request.non_blocking(true);
		process_request(request);
	}
}
