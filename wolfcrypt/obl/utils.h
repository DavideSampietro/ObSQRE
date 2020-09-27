#ifndef OBL_UTILS_H
#define OBL_UTILS_H

#include <cstdint>
#include <cstddef>
#include <cstdlib>

#include "obl/oram.h"

// inlines for navigating a binary heap
inline std::int64_t get_parent(std::int64_t x)
{
	return (x-1) >> 1;
}

inline std::int64_t get_left(std::int64_t x)
{
	return (x << 1) + 1;
}

inline std::int64_t get_right(std::int64_t x)
{
	return (x << 1) + 2;
}

// get the max depth where a block can be evicted given its leaf and current eviction path
inline int get_max_depth(obl::leaf_id leaf, obl::leaf_id path, int L)
{
	return __builtin_ctzll((leaf ^ path) | (1ULL << L));
}

inline std::size_t pad_bytes(std::size_t s, unsigned int align)
{
	return s + (align - (s % align)) % align;
}

// inspired by StackOverflow
// al must be a power of 2!
inline void* man_aligned_alloc(void **buff, std::size_t sz, std::size_t al)
{
	*buff = malloc(sz + al);
	return (void*) (((std::uint64_t)*buff + al) & ~(al - 1));
}

#endif // OBL_UTILS_H
