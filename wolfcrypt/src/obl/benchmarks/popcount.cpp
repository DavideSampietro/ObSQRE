#include <iostream>
#include <vector>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>

#include "obl/primitives.h"

const int runs = 32;

const int power = 27;
const int bufsize = 1 << power;

using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

int rank(std::uint64_t*, std::size_t, int, int);
int simple_popcount(std::uint64_t*, std::size_t);

int main()
{
	std::vector<nano> benchmarks;
	benchmarks.reserve(runs);

	// 1 Gib <=> 128MB
	std::uint8_t *v = new std::uint8_t[bufsize];
	std::memset(v, 0xAA, bufsize);

	srand(time(NULL));

	std::cout << "function,size,time\n";

	for(int s = 7; s <= power; s++)
	{
		std::size_t S = 1 << s;

		int bitsize = S << 3;
		int max_len = bitsize / 2;

		int start = rand() % (bitsize - max_len);
		int end = start + (rand() % max_len);
		
		// make them both even
		start &= (~1);
		end &= (~1);

		for(int i = 0; i < runs; i++)
		{
			tt st = hres::now();
			int res = rank((std::uint64_t*) v, S >> 3, start, end);
			tt nd = hres::now();

			benchmarks[i] = nd - st;

			assert(res == (end-start) / 2);
		}

		for(int i = 0; i < runs; i++)
			std::cout << "rank," << S << "," << benchmarks[i].count() << std::endl;
		

		for(int i = 0; i < runs; i++)
		{
			tt st = hres::now();
			volatile int res = simple_popcount((std::uint64_t*) v, S >> 3);
			tt nd = hres::now();

			benchmarks[i] = nd - st;
		}

		for(int i = 0; i < runs; i++)
			std::cout << "popcountll," << S << "," << benchmarks[i].count() << std::endl;
	}

	delete[] v;
	return 0;
}

// avoid inlining to take into account function call latency
int __attribute__((noinline)) simple_popcount(std::uint64_t *v, std::size_t S)
{
	int acc = 0;

	for(unsigned int i = 0; i < S; i++)
		acc += __builtin_popcountll(v[i]);

	return acc;
}

int rank(std::uint64_t *v, std::size_t S, int st, int end)
{
	int acc = 0;

	for(unsigned int i = 0; i < S; i++)
	{
		std::uint64_t mask_st = obl::ternary_op(st > 0, -1ULL << st, -1ULL);
		mask_st = obl::ternary_op(st >= 64, 0ULL, mask_st);

		std::uint64_t mask_end = obl::ternary_op(end >= 64, -1ULL, -1ULL >> (64 - end));
		mask_end = obl::ternary_op(end <= 0, 0ULL, mask_end);

		std::uint64_t mask = mask_st & mask_end;

		acc += __builtin_popcountll(v[i] & mask);

		st -= 64;
		end -= 64;
	}

	return acc;
}