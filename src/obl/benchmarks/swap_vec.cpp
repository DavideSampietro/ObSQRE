#include "obl/primitives.h"
#include "obl/utils.h"
#include <cstdint>
#include <cstddef>

//#include <emmintrin.h>
#include <immintrin.h>

#include <iostream>
#include <vector>
#include <cstring>
#include <cassert>
#include <chrono>

const int maxsize = 1 << 26;
const int runs = 256;

// helpers for std::chrono which is INSANE!!!
using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

void swap_vect(bool, std::uint8_t*, std::uint8_t*, std::size_t);

int main()
{
	//std::uint8_t *d_buff1, *d_buff2;
	//std::uint8_t *buffer1 = (std::uint8_t*) man_aligned_alloc((void**) &d_buff1, maxsize, 32);
	//std::uint8_t *buffer2 = (std::uint8_t*) man_aligned_alloc((void**) &d_buff2, maxsize, 32);
	std::uint8_t *buffer1 = new std::uint8_t[maxsize];
	std::uint8_t *buffer2 = new std::uint8_t[maxsize];

	obl::gen_rand(buffer1, maxsize);
	obl::gen_rand(buffer2, maxsize);

	std::vector<nano> benchmarks;
	benchmarks.reserve(runs);

	std::cout << "method,size,time\n";

	for(int i = 15; i <= 26; i++)
	{
		std::size_t S = 1ULL << i;

		for(int j = 0; j < runs; j++)
		{
			tt start = hres::now();
			swap_vect(j % 2 == 0, buffer1, buffer2, S);
			tt end = hres::now();

			benchmarks[j] = end - start;
		}

		for(int j = 0; j < runs; j++)
			std::cout << "vector," << S << "," << benchmarks[j].count() << std::endl;

		for(int j = 0; j < runs; j++)
		{
			tt start = hres::now();
			obl::swap(j % 2 == 0, buffer1, buffer2, S);
			tt end = hres::now();

			benchmarks[j] = end - start;
		}

		for(int j = 0; j < runs; j++)
			std::cout << "scalar," << S << "," << benchmarks[j].count() << std::endl;

	}

	//delete[] d_buff1;
	//delete[] d_buff2;

	delete[] buffer1;
	delete[] buffer2;

	return 0;
}

void swap_vect(bool swap, std::uint8_t *a, std::uint8_t *b, std::size_t size)
{
	std::uint64_t mask64 = obl::ternary_op(swap, -1ULL, 0);
	std::uint8_t mask8 = (std::uint8_t) mask64;

	// broadcast mask64 to 256-bit register
	__m256i mask256 = _mm256_set1_epi64x(mask64);
	__m256i a256, b256, tmp256;

	std::size_t rem = size & 31;

	while(rem)
	{
		std::uint8_t tmp = (*a ^ *b) & mask8;
		*a = *a ^ tmp;
		*b = *b ^ tmp;

		--rem;

		++a;
		++b;
	}

	std::size_t full = size >> 5;

	while(full)
	{
		a256 = _mm256_loadu_si256((__m256i*) a);
		b256 = _mm256_loadu_si256((__m256i*) b);

		--full;

		a += 32;
		tmp256 = _mm256_xor_si256(a256, b256);
		b += 32;
		tmp256 = _mm256_and_si256(tmp256, mask256);

		a256 = _mm256_xor_si256(a256, tmp256);
		b256 = _mm256_xor_si256(b256, tmp256);

		_mm256_storeu_si256((__m256i*)(a-32), a256);
		_mm256_storeu_si256((__m256i*)(b-32), b256);
	}
}