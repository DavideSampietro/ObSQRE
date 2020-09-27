#include <iostream>
#include <cstdlib>
#include <signal.h>
#include <thread>

#include "toy_server_request.h"
#include "subtol_srv.h"

void disable_sigterm();

int main(int argc, char **argv)
{
	int port = 49000;

	if(argc > 1)
		port = std::atoi(argv[1]);

	// https://docs.oracle.com/cd/E19455-01/806-5257/6je9h033a/index.html
	// when you are going to use sigwait on a specific signal, it is better
	// blocked everywhere!
	disable_sigterm();

	// initialize http bodies
	http_request_t::init_strings();
	// create server
	subtol_srv srv(port);

	std::cout << "Launching server on port: " << port << std::endl;
	std::cout << "Server PID: " << getpid() << std::endl;
	// spawn listener
	std::thread listener(&toy_server::launch_server, &srv, 4);

	// main will sigwait for SIGTERM, after which it softly kills the server
	sigset_t w;
	int signo;

	sigemptyset(&w);
	sigaddset(&w, SIGTERM);
	sigwait(&w, &signo);

	srv.kill_switch();
	listener.join();

	std::cout << "subtol server shut down correctly" << std::endl;

	return 0;
}

void disable_sigterm()
{
	sigset_t blk_list;
	sigemptyset(&blk_list);
	sigaddset(&blk_list, SIGTERM);
	sigprocmask(SIG_BLOCK, &blk_list, NULL);
}
