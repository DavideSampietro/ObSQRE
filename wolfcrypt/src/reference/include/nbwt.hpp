#ifndef NBWT_H
#define NBWT_H

#include "substring_common.hpp"

// Interface

template<typename Int, typename Char>
inline
void nbwt_query(Int **bbwt, Int *C,
	Char *q, Int qlen,
	Int *s, Int *e
);

// Static functions

// since we have no buckets here
// this approach is suboptimal for non-oblivious version, but I don't expect
// it to impact too much on performance
template<typename Int>
static Int get_offset(Int *C, Int idx)
{
	Int ret = 1;

	for(Int i = 0; i < idx; i++)
		ret += C[i];

	return ret;
}

// Implementation

template<typename Int, typename Char>
void nbwt_query(Int **bbwt, Int *C, Char *q, Int qlen, Int *s, Int *e)
{
	Int start, end;

	*s = -1;
	*e = -1;

	--qlen;
	if(q[qlen] == 255)
		return;

	start = get_offset(C, (Int) q[qlen]);
	end = get_offset(C, (Int) (q[qlen] + 1)) - 1;
	--qlen;

	while(qlen != -1)
	{
		if(q[qlen] == 255)
		{
			--qlen;
			continue;
		}

		Int offset = get_offset(C, (Int) q[qlen]);

		Int rank_f = 0;
		Int rank_l = 0;

		Int *subtree = bbwt[(Int) q[qlen]];
		Int limit = C[(Int) q[qlen]];

		Int h = 0;
		Int p_s = 0;
		Int p_e = limit;

		while(h < limit)
		{
			Int real_idx = p_s + get_subroot(p_e - p_s);

			bool go_left = subtree[h] >= start;
			bool to_update = subtree[h] < start && real_idx >= rank_f;

			rank_f = to_update ? real_idx + 1 : rank_f;

			p_s = go_left ? p_s : real_idx + 1;
			p_e = go_left ? real_idx : p_e;

			h = (h << 1) + 1 + (go_left ? 0 : 1);
		}

		h = 0;
		p_s = 0;
		p_e = limit;

		while(h < limit)
		{
			Int real_idx = p_s + get_subroot(p_e - p_s);

			bool go_left = subtree[h] > end;
			bool to_update = subtree[h] <= end && real_idx >= rank_l;

			rank_l = to_update ? real_idx + 1 : rank_l;

			p_s = go_left ? p_s : real_idx + 1;
			p_e = go_left ? real_idx : p_e;

			h = (h << 1) + 1 + (go_left ? 0 : 1);
		}

		start = offset + rank_f;
		end = offset + rank_l - 1;

		--qlen;
	}

	*s = start;
	*e = end;
}

#endif // NBWT_H
