#include <iostream>
#include <chrono>
#include <vector>
#include <cstdint>
#include <cassert>

#include "obl/oram.h"
#include "obl/ring.h"
//#include "obl/ring_wolf.h"
#include "obl/primitives.h"

// helpers for std::chrono which is INSANE!!!
using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

const int pow_lower = 16;
const int pow_upper = 26;
const int bench_size = 1024;

void test_oram(std::string, obl::tree_oram*, std::vector<std::int64_t>&, std::vector<obl::leaf_id>&);

int main()
{
	std::vector<std::int64_t> mirror_data;
	std::vector<obl::leaf_id> position_map;
	
	// reserve for the maximum size
	mirror_data.reserve(1 << pow_upper);
	position_map.reserve(1 << pow_upper);
	
	for(int i = 0; i < (1 << pow_upper); i++)
	{
		std::int64_t val;
		obl::gen_rand((std::uint8_t*) &val, sizeof(std::int64_t));
		mirror_data[i] = val;
	}
	
	for(int p = pow_lower; p < pow_upper; p++)
	{
		std::size_t N = 1 << p;
		obl::tree_oram *rram;
		
		rram = new obl::ring_oram(N, sizeof(std::int64_t), 4, 6, 3, 32);
		test_oram("ring4_3", rram, mirror_data, position_map);
		delete rram;
		
		rram = new obl::ring_oram(N, sizeof(std::int64_t), 8, 13, 8, 41);
		test_oram("ring8_8", rram, mirror_data, position_map);
		delete rram;
		
		/*rram = new obl::ring_wolf(N, sizeof(std::int64_t), 4, 6, 3, 32);
		test_oram("wolf4_3", rram, mirror_data, position_map);
		delete rram;
		
		rram = new obl::ring_wolf(N, sizeof(std::int64_t), 8, 13, 8, 41);
		test_oram("wolf8_8", rram, mirror_data, position_map);
		delete rram;*/
	}
}

void test_oram(std::string oname, obl::tree_oram *rram, std::vector<std::int64_t> &data, std::vector<obl::leaf_id> &map)
{
	static std::vector<nano> times;
	std::size_t N = rram->get_N();
	
	// only affects the vector the first time
	times.reserve(bench_size);
	
	for(unsigned int i = 0; i < N; i++)
	{
		obl::leaf_id next_leef;
		obl::gen_rand((std::uint8_t*) &next_leef, sizeof(obl::leaf_id));

		rram->write(i, (std::uint8_t*) &data[i], next_leef);
		map[i] = next_leef;
	}
	
	for(int i = 0; i < bench_size; i++)
	{
		std::int64_t value_out;
		obl::leaf_id next_leef;
		obl::block_id rnd_bid;
		
		obl::gen_rand((std::uint8_t*) &next_leef, sizeof(obl::leaf_id));
		obl::gen_rand((std::uint8_t*) &rnd_bid, sizeof(obl::block_id));
		
		rnd_bid = (rnd_bid & ((1ULL << 63)-1)) % N;

		tt start = hres::now();
		rram->access(rnd_bid, map[rnd_bid], nullptr, (std::uint8_t*) &value_out, next_leef);
		tt end = hres::now();
		
		times[i] = end-start;
		
		map[rnd_bid] = next_leef;

		assert(value_out == data[rnd_bid]);
	}
	
	for(int i = 0; i < bench_size; i++)
		std::cout << oname << "," << N << "," << times[i].count() << std::endl;
}
