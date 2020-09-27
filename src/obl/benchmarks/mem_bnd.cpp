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

const int maxsize = 1 << 30;

// helpers for std::chrono which is INSANE!!!
using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

void swap_vect(bool, std::uint8_t*, std::uint8_t*, std::size_t);
void m_bandwidth(std::uint64_t*, std::size_t);
void b_bandwidth(std::uint64_t*, std::size_t);
void s_bandwidth(std::uint64_t*, std::uint64_t, std::size_t);

int main()
{
	std::uint8_t *buffer1 = new std::uint8_t[maxsize];
	std::uint8_t *buffer2 = new std::uint8_t[maxsize];

	tt st, end;

	obl::gen_rand(buffer1, maxsize);
	obl::gen_rand(buffer2, maxsize);

	std::cerr << "gen_rand completed!\n\n";

	// s_bandwidth
	st = hres::now();
	s_bandwidth((std::uint64_t*) buffer1, 0xbeaddeafdeafbeefULL, maxsize >> 3);
	end = hres::now();

	std::cerr << "s_bandwidth runtime: " << (end-st).count() / 1000.0 << " us\n";
	std::cerr << "estimated bandwidth usage (1x): " << 1.0 * 1000000000.0 / (end-st).count() << " GB/s\n\n";

	// check s_bandwidth
	int S = maxsize >> 3;
	std::uint64_t *w = (std::uint64_t*) buffer1;

	for(int i = 0; i < S; i++)
	{
		assert(w[i] == 0xbeaddeafdeafbeefULL);
	}

	// m_bandwidth
	st = hres::now();
	m_bandwidth((std::uint64_t*) buffer1, maxsize >> 3);
	end = hres::now();

	std::cerr << "m_bandwidth runtime: " << (end-st).count() / 1000.0 << " us\n";
	std::cerr << "estimated bandwidth (2x): " << 2.0 * 1000000000.0 / (end-st).count() << " GB/s\n\n";

	// b_bandwidth
	st = hres::now();
	b_bandwidth((std::uint64_t*) buffer2, maxsize >> 3);
	end = hres::now();

	std::cerr << "b_bandwidth runtime: " << (end-st).count() / 1000.0 << " us\n";
	std::cerr << "estimated bandwidth usage (1x): " << 1.0 * 1000000000.0 / (end-st).count() << " GB/s\n\n";

	// swap_vect
	st = hres::now();
	swap_vect(true, buffer1, buffer2, maxsize);
	end = hres::now();

	std::cerr << "swap_vect runtime: " << (end-st).count() / 1000.0 << " us\n";
	std::cerr << "estimated bandwidth usage (4x): " << 4.0 * 1000000000.0 / (end-st).count() << " GB/s\n\n";

	// obl::swap
	st = hres::now();
	obl::swap(false, buffer1, buffer2, maxsize);
	end = hres::now();

	std::cerr << "obl::swap runtime: " << (end-st).count() / 1000.0 << " us\n";
	std::cerr << "estimated bandwidth usage (4x): " << 4.0 * 1000000000.0 / (end-st).count() << " GB/s\n\n";

	// memcpy
	st = hres::now();
	memcpy(buffer1, buffer2, maxsize);
	end = hres::now();

	std::cerr << "memcpy runtime: " << (end-st).count() / 1000.0 << " us\n";
	std::cerr << "estimated bandwidth usage (2x): " << 2.0 * 1000000000.0 / (end-st).count() << " GB/s\n\n";

	delete[] buffer1;
	delete[] buffer2;

	return 0;
}

// cld -- clear direction flag => move forward
// stosq -- set *rdi to value of %rax
void s_bandwidth(std::uint64_t *v, std::uint64_t value, std::size_t s)
{
	asm volatile(
		"cld;\n\t"
		"mov %2, %%rdi;\n\t"
		"mov %0, %%rcx;\n\t"
		"mov %1, %%rax;\n\t"
		"rep stosq;\n\t"
		:
		: "g"(s), "g"(value), "g"(v)
	);
}

void m_bandwidth(std::uint64_t *v, std::size_t s)
{
	for(unsigned int i = 0; i < s; i++)
	{
		v[i] = v[i] + 1;
	}
}

void b_bandwidth(std::uint64_t *v, std::size_t s)
{
	volatile std::uint64_t *w = v;

	for(unsigned int i = 0; i < s; i++)
		// no side effects but compiler cannot optimize it out due to volatile
		w[i] << 1;
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