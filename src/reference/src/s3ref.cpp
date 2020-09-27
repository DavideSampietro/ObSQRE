#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <chrono>

#include "init.h"
#include "ref_context.h"

using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

const int no_runs = 32;

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		std::cerr << "usage: ./s3 <input_txt>" << std::endl;
		return 1;
	}

	std::ifstream cmd_file;
	cmd_file.open(argv[1], std::ios::in);

	if(!cmd_file.is_open())
	{
		std::cerr << "file not found" << std::endl;
		return 1;
	}

	std::string cmd_str;

	while(std::getline(cmd_file, cmd_str))
	{
		if(cmd_str == "")
			continue;

		int len = cmd_str.length();
		char *command = new char[len + 1];
		std::memcpy(command, cmd_str.c_str(), len);
		command[len] = '\0';

		char *fname = std::strtok(command, " ");
		char *pwd = std::strtok(NULL, " ");
		char *query = std::strtok(NULL, " ");

		// try to open the file
		std::filebuf text;
		text.open(fname, std::ios::binary | std::ios::in);
		std::ifstream map(std::string(fname) + ".map", std::ios::in);
		if(!text.is_open())
		{
			std::cerr << "file " << fname << "not found, moving on" << std::endl;
			continue;
		}
		if(!map.is_open())
		{
			std::cerr << "map file for " << fname << "not found, moving on" << std::endl;
			continue;	
		}

		// map the query
		int qlen = std::strlen(query);
		unsigned char *map_query = new unsigned char[qlen + 1];
		map_query[qlen] = '\0';

		std::string mapper;
		std::getline(map, mapper, (char)255);
		
		for(int i = 0; i < qlen; i++)
			map_query[i] = mapper.find(query[i], 0);

		// create session
		ref_context_t *sess = init_ref_context(text, pwd);

		for(int i = 0; i < no_runs; i++)
		{
			std::int32_t s, e;

			tt s_time = hres::now();
			sess->query(map_query, qlen, s, e);
			tt e_time = hres::now();

			nano diff = e_time - s_time;
			std::cout << fname << "," << qlen << "," << s << "," << e << "," << diff.count() << std::endl;
		}

		delete sess;
		delete[] command;
		delete[] map_query;
	}

	return 0;
}
