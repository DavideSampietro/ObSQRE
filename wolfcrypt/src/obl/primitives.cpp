#include "obl/primitives.h"
#include "obl/oassert.h"

#include <immintrin.h>

namespace obl {

#ifdef __AVX2__
#pragma message("Using AVX2-accelerated version of oblivious swap")
	void swap(bool swap, std::uint8_t *a, std::uint8_t *b, std::size_t size)
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
#else
	void swap(bool swap, std::uint8_t *a, std::uint8_t *b, std::size_t size)
	{
		// do it 64-bit-word-wise
		std::uint64_t mask64 = obl::ternary_op(swap, -1ULL, 0);
		int size64 = size >> 3;
		std::uint64_t *a64 = (std::uint64_t*)a;
		std::uint64_t *b64 = (std::uint64_t*)b;

		for(int i = 0; i < size64; i++)
		{
			std::uint64_t buf = (a64[i] ^ b64[i]) & mask64;
			a64[i] ^= buf;
			b64[i] ^= buf;
		}
		
		// manage the remainder, the last 8 bytes
		a = (std::uint8_t*)(a64 + size64);
		b = (std::uint8_t*)(b64 + size64);
		std::uint8_t mask8 = mask64;
		size &= 7;
		
		for(unsigned int i = 0; i < size; i++)
		{
			std::uint8_t buf = (a[i] ^ b[i]) & mask8;
			a[i] ^= buf;
			b[i] ^= buf;	
		}
	}
#endif
	
	void replace(bool we, std::uint8_t *dst, std::uint8_t *src, size_t size)
	{
		// do it 64-bit-word-wise
		std::uint64_t mask64 = ternary_op(we, -1ULL, 0);
		int size64 = size >> 3;
		std::uint64_t *dst64 = (std::uint64_t*)dst;
		std::uint64_t *src64 = (std::uint64_t*)src;

		for(int i = 0; i < size64; i++)
		{
			std::uint64_t buf = (dst64[i] ^ src64[i]) & mask64;
			dst64[i] ^= buf;
		}

		// manage the remainder, the last 8 bytes
		dst = (std::uint8_t*)(dst64 + size64);
		src = (std::uint8_t*)(src64 + size64);
		std::uint8_t mask8 = mask64;
		size &= 7;
		
		for(unsigned int i = 0; i < size; i++)
		{
			std::uint8_t buf = (src[i] ^ dst[i]) & mask8;
			dst[i] ^= buf;
		}
	}

	void gen_rand(std::uint8_t *dst, std::size_t len)
	{
		// this is basically a VERY UGLY std::uint64_t
		unsigned long long int buffer;

		for(unsigned int i = 0; i < len; i++)
		{
			if((i & 7) != 0)
				buffer >>= 8;
			else
				__builtin_ia32_rdrand64_step(&buffer);

			dst[i] = buffer;
		}
	}

	std::int8_t get_rand_byte()
	{
		static uint64_t buffer = 0;
		static int avail = 0;

		if(avail == 0)
		{
			gen_rand((std::uint8_t*) &buffer, sizeof(std::uint64_t));
			avail = 8;
		}

		std::int8_t ret = buffer;
		ret &= 127; // make sure it is >= 0
		buffer >>= 8;
		--avail;

		return ret;
	}

	void gen_rand_seed(std::uint8_t *dst, std::size_t len)
	{
		// this is basically a VERY UGLY std::uint64_t
		unsigned long long int buffer;

		for(unsigned int i = 0; i < len; i++)
		{
			if((i & 7) != 0)
				buffer >>= 8;
			else {
				// as implemented inside intrinsics header files
				__builtin_ia32_rdseed_di_step(&buffer);
				// depleted entropy
				assert(buffer != 0ULL);
			}

			dst[i] = buffer;
		}
	}

}
