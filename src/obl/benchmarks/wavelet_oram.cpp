#include <iostream>
#include <chrono>
#include <cassert>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <cstdint>

#include <vector>
#include <utility>

#include "obl/primitives.h"

#include "obl/rec.h"
#include "obl/circuit.h"

const int test_iters = 1024;

// if you store in sepate ORAMs, you don't need *3
//const int gbit_size = (1 << 27) * 3;
const int gbit_size = 1 << 27;

const int size_start = 4;
const int size_end = 9;

// helpers for std::chrono which is INSANE!!!
using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

int main()
{
	obl::coram_factory circ(3, 8); // default parametrization for circuit oram

	srand(time(NULL));

	// data blocks
	std::uint8_t *data = new std::uint8_t[gbit_size];
	obl::gen_rand(data, gbit_size);
	
	// times
	std::vector<nano> benchmarks;
	benchmarks.reserve(test_iters);

	// 2^i bits in each ORAM block
	for(int i = 10; i <= 19; i++)
	{	
		std::size_t B = 1 << (i-3);
		std::size_t N = gbit_size / B;

		std::uint8_t buffer[B];

		for(int csize = 4; csize <= 8; csize++)
		{
			obl::recursive_oram recoram(N, B, csize, &circ);

			// Now using full initialization
			for(unsigned int i = 0; i < N; i++)
				recoram.access(i, &data[i*B], buffer);
	
			for(int i = 0; i < test_iters; i++)
			{
				obl::block_id rnd_bid = rand() % N;
		
				// get times
				tt start = hres::now();
				recoram.access(rnd_bid, nullptr, buffer);
				tt end = hres::now();

				benchmarks[i] = end - start;

				assert(memcmp(buffer, &data[rnd_bid*B], B) == 0);
			}
	
			for(int i = 0; i < test_iters; i++)
				std::cout << N << "," << B << "," << (1 << csize) << "," << benchmarks[i].count() << std::endl;
		}
	}
	
	return 0;
}
