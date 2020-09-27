#ifndef NBWT_HPP
#define NBWT_HPP

#include "cbbst.h"
#include "substring/substring_common.h"
#include "obl/primitives.h"

// Interface

template<typename Int, typename Char>
inline
void nbwt_query(
	obl::ods::cbbst *index, Int *C, Int alpha,
	Char *q, Int qlen,
	Int *s, Int *e
);

// since we have no buckets here
// this is not inefficient since the scan of C will be linear in the final oblivious version
template<typename Int>
static Int get_offset(Int *C, Int idx, Int alpha)
{
	Int ret = 1;

	for(Int i = 0; i < alpha; i++)
	{
		Int tmp = C[i];
		ret += obl::ternary_op(i < idx, tmp, 0);
	}

	return ret;
}

// Implementation

template<typename Int, typename Char>
void nbwt_query(obl::ods::cbbst *index, Int *C, Int alpha, Char *q, Int qlen, Int *s, Int *e)
{
	Int start, end;
	const Int subtree_size = index->get_N();
	const Int L = index->get_L();

	--qlen;

	start = get_offset<Int>(C, (Int) q[qlen], alpha);
	end = get_offset<Int>(C, (Int) q[qlen] + 1, alpha) - 1;
	--qlen;

	while(qlen != -1)
	{
		Int char_index = (Int) q[qlen];
		Int offset = get_offset<Int>(C, char_index, alpha);

		Int rank_f = 0;
		Int rank_l = 0;

		Int subtree = char_index * subtree_size;
		Int limit = linear_scan<Int>(C, char_index, alpha - 1);

		index->select_subtree(char_index);

		Int h = 0;
		Int p_s = 0;
		Int p_e = limit;

		for(int l = 0; l < L; l++)
		{
			// perform access to the dummy block!
			Int heap_biased;
			heap_biased = obl::ternary_op(h >= limit, -1, h + subtree);

			Int real_idx = p_s + get_subroot(p_e - p_s);
			Int curr_idx;
			index->read(heap_biased, (std::uint8_t*) &curr_idx, l);

			bool go_left = curr_idx >= start;
			bool to_update = (curr_idx < start) & (real_idx >= rank_f) & (heap_biased != -1);

			rank_f = obl::ternary_op(to_update, real_idx + 1, rank_f);
			index->update(heap_biased, (std::uint8_t*) &curr_idx, go_left, l);

			h = (h << 1) + 1 + obl::ternary_op(go_left, 0, 1);
			p_s = obl::ternary_op(go_left, p_s, real_idx + 1);
			p_e = obl::ternary_op(go_left, real_idx, p_e);
		}

		index->select_subtree(char_index);

		h = 0;
		p_s = 0;
		p_e = limit;

		for(int l = 0; l < L; l++)
		{
			// perform access to the dummy block!
			Int heap_biased;
			heap_biased = obl::ternary_op(h >= limit, -1, h + subtree);

			Int real_idx = p_s + get_subroot(p_e - p_s);
			Int curr_idx;
			index->read(heap_biased, (std::uint8_t*) &curr_idx, l);

			bool go_left = curr_idx > end;
			bool to_update = (curr_idx <= end) & (real_idx >= rank_l) & (heap_biased != -1);

			rank_l = obl::ternary_op(to_update, real_idx + 1, rank_l);
			index->update(heap_biased, (std::uint8_t*) &curr_idx, go_left, l);

			h = (h << 1) + 1 + obl::ternary_op(go_left, 0, 1);
			p_s = obl::ternary_op(go_left, p_s, real_idx + 1);
			p_e = obl::ternary_op(go_left, real_idx, p_e);
		}

		// support for dummy characters
		bool dummy_char = (char_index < 0) | (char_index >= alpha);
		start = obl::ternary_op(dummy_char, start, offset + rank_f);
		end = obl::ternary_op(dummy_char, end, offset + rank_l - 1);

		--qlen;
	}

	*s = start;
	*e = end;
}

#endif // NBWT_HPP
