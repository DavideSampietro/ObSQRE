#ifndef OBL_PRIMITIVES_H
#define OBL_PRIMITIVES_H

#include <cstdint>
#include <cstddef>

namespace obl {

	// oblivious swap
	void swap(bool swap, std::uint8_t *a, std::uint8_t *b, size_t size);
	void replace(bool we, std::uint8_t *dst, std::uint8_t *src, size_t size);

	// generate random data. Wrapper for the RDRND instruction
	void gen_rand(std::uint8_t *dst, std::size_t len);
	std::int8_t get_rand_byte();

	// generate random seed. Wrapper for the RDSEED instruction
	void gen_rand_seed(std::uint8_t *dst, std::size_t len);

	//std::uint64_t ternary_op(bool sel, std::uint64_t a, std::uint64_t b);
	/*
		I was first implementing this as a template, providing specializations for
		each signed/unsigned of each width (8, 16, 32, 64).
		However, this does the trick since:
		- the input parameters are passed by value, and so, even when feeding a
		std::[u]int[8|16|32|64]_t, this is padded properly to std::uint64_t
		- the operations are executed in 64-bit registers, and the result is "truncated"
		when assigning it from std::uint64_t to std::[u]int[8|16|32|64]_t

		I implemented it in the header in order to allow inlining by compiler.
	*/
	inline std::uint64_t ternary_op(bool sel, std::uint64_t a, std::uint64_t b)
	{
		std::uint64_t out;

		asm volatile(
			"cmpb $0, %1;\n\t"
			"movq %2, %0;\n\t"
			"cmovz %3, %0;\n\t"
			: "=r"(out)
			: "m"(sel), "g"(a), "m"(b)
		);

		return out;
	}

}

#endif // OBL_PRIMITIVES_H
