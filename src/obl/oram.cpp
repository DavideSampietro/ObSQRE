#include "obl/oram.h"

// Bit Twiddling Hacks
// By Sean Eron Anderson
// seander@cs.stanford.edu
std::uint64_t next_two_power(std::uint64_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;
	v++;

	return v;
}

namespace obl {

	tree_oram::tree_oram(std::size_t N, std::size_t B, unsigned int Z)
	{
		this->N = N;

		// pad the number of elements to the closest NEXT power of 2
		std::uint64_t n_pow = next_two_power(this->N);
		if(n_pow <= 1)
			n_pow = 2;

		// set the total capacity (which equals the number of buckets)
		capacity = n_pow - 1;

		// set the depth of the ORAM tree
		L = __builtin_ctzll(n_pow) - 1;

		this->B = B; // B is the REAL block size in bytes
		this->Z = Z;

		access_counter = 0;
	}

}
