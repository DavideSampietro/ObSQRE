#include <cstdint>
#include <iostream>
#include <fstream>
#include <chrono>
#include <cassert>

#include <vector>
#include <utility>

#include "obl/primitives.h"

#include "obl/rec.h"
#include "obl/circuit.h"
#include "obl/ring.h"
#include "obl/path.h"

const int test_iters = 1024;
const int size_start = 9;
const int size_end = 28;

// helpers for std::chrono which is INSANE!!!
using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

int main()
{
	obl::coram_factory circ(3, 8); // default parametrization for circuit oram
	obl::path_factory path(4, 64);
	obl::roram_factory ring_small(4, 6, 3, 32);
	obl::roram_factory ring_big(8, 13, 8, 41); // stash sizes taken from paper for LAMBDA=80
	
	// initialize vector of pairs
	std::vector<std::pair<obl::oram_factory*, std::string>> test_cases;
	
	test_cases.push_back(std::make_pair(&circ, "circuit"));
	// INFO => removing path
	//test_cases.push_back(std::make_pair(&path, "path"));
	test_cases.push_back(std::make_pair(&ring_small, "ring4_3"));
	test_cases.push_back(std::make_pair(&ring_big, "ring8_8"));
	
	// times
	std::vector<nano> benchmarks;
	benchmarks.reserve(test_iters);
	
	std::cout << "oram_type,N,recmap_size,time" << std::endl;
	
	std::size_t N = 1 << size_end;
	std::vector<std::int64_t> reference_values;
	reference_values.reserve(N);

	for(unsigned int i = 0; i < N; i++)
	{
		std::int64_t load_val;
		obl::gen_rand((std::uint8_t*) &load_val, sizeof(std::int64_t));
		reference_values[i] = load_val;
	}

	for(int size = size_start; size <= size_end; size++) // number of elements in the last level oram
	{
		N = 1 << size;
		std::int64_t bid_mask = N - 1;
		
		for(unsigned int rr = 0; rr < test_cases.size(); rr++) // for every ORAM
		{
			for(int csize = 4; csize <= 10; csize++) // for every recursive ORAM csize (16, 32, 64, 128, 256, 512, 1024)
			{
				// initialize recursive ORAM
				std::int64_t dummy;
				obl::recursive_oram recoram(N, sizeof(std::int64_t), csize, std::get<0>(test_cases[rr]));

				// Now using full initialization
				for(unsigned int i = 0; i < N; i++)
					recoram.access(i, (std::uint8_t*) &reference_values[i], (std::uint8_t*) &dummy);
		
				for(int i = 0; i < test_iters; i++)
				{
					obl::block_id rnd_bid;
			
					obl::gen_rand((std::uint8_t*) &rnd_bid, sizeof(obl::block_id));
					rnd_bid = rnd_bid & bid_mask;

					assert((unsigned int)rnd_bid < N);
			
					// get times
					tt start = hres::now();
					recoram.access(rnd_bid, (std::uint8_t*) &reference_values[rnd_bid], (std::uint8_t*) &dummy);
					tt end = hres::now();
					benchmarks[i] = end - start;
				}
		
				for(int i = 0; i < test_iters; i++)
					std::cout << std::get<1>(test_cases[rr]) << "," << N << "," << (1 << csize) << "," << benchmarks[i].count() << std::endl;
			}
		}
	}
	
	return 0;
}
