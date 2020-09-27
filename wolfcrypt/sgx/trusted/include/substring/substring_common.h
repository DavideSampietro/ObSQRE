#ifndef SUBSTRING_COMMON_H
#define SUBSTRING_COMMON_H

#include "obl/primitives.h"

template<typename Int>
inline
Int linear_scan(Int *v, Int idx, Int limit)
{
	Int ret = -1;

	for(Int i = 0; i <= limit; i++)
		ret = obl::ternary_op(i == idx, v[i], ret);

	return ret;
}

inline std::size_t fill_with_ones(std::size_t v)
{
	// on x86-64, sizeof(std::size_t) = 8
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;

	return v;
}

inline std::size_t get_subroot(std::size_t N)
{
	std::size_t NN = fill_with_ones(N+1);
	std::size_t rem = N - (NN >> 1);
	std::size_t max_left_subtree = (NN ^ (NN >> 1)) >> 1;
	std::size_t offset = obl::ternary_op(rem > max_left_subtree, max_left_subtree, rem);

	return (NN >> 2) + offset;
}

#endif // SUBSTRING_COMMON_H
