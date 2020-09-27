#ifndef S3_PSI_H
#define S3_PSI_H

#include <cstddef>
#include "substring_common.hpp"

// Interface

template<typename Int, typename Char>
inline
void sapsi_query(
	Int *psi, Int len, Int *C,
	Char *q, Int qlen,
	Int *s, Int *e
);

// Implementation

template<typename Int, typename Char>
void sapsi_query(Int *psi, Int len, Int *C, Char *q, Int qlen, Int *s, Int *e)
{
	Int start, end;

	*s = -1;
	*e = -1;

	// index the last character of the query
	--qlen;
	if(q[qlen] == 255)
		return;

	// process the last character of the query
	start = C[(Int)q[qlen]];
	end = C[(Int)q[qlen] + 1] - 1;
	--qlen;

	while(qlen != -1)
	{
		if(q[qlen] == 255)
		{
			--qlen;
			continue;
		}
		
		// those are the ranges of the subtree where we are required to perform our search
		Int low_bound = C[(Int)q[qlen]];
		Int upp_bound = C[(Int)q[qlen] + 1] - 1;

		// this is the current section of PSI array that is considered
		Int psi_s = 0;
		Int psi_e = len + 1;

		Int h = 0; // position in the heap
		Int next_start = -1;

		while(h <= len)
		{
			Int curr_psi = psi[h];
			Int real_idx;

			real_idx = psi_s + get_subroot(psi_e - psi_s);

			bool right_range = real_idx >= low_bound && real_idx <= upp_bound;
			bool in_psi_range = curr_psi >= start && curr_psi <= end;
			bool go_left = real_idx >= low_bound && (real_idx > upp_bound || curr_psi >= start);

			next_start = right_range && in_psi_range ? real_idx : next_start;

			h = (h << 1) + 1 + (go_left ? 0 : 1);
			psi_s = go_left ? psi_s : real_idx + 1;
			psi_e = go_left ? real_idx : psi_e;
		}

		// reset values
		psi_s = 0;
		psi_e = len + 1;

		h = 0;
		Int next_end = -1;

		while(h <= len)
		{
			Int curr_psi = psi[h];
			Int real_idx;

			real_idx = psi_s + get_subroot(psi_e - psi_s);

			bool right_range = real_idx >= low_bound && real_idx <= upp_bound;
			bool in_psi_range = curr_psi >= start && curr_psi <= end;
			bool go_right = real_idx <= upp_bound && (curr_psi <= end || real_idx < low_bound);

			next_end = right_range && in_psi_range ? real_idx : next_end;

			h = (h << 1) + 1 + (go_right ? 1 : 0);
			psi_s = go_right ? real_idx + 1 : psi_s;
			psi_e = go_right ? psi_e : real_idx;
		}

		start = next_start;
		end = next_end;

		--qlen;
	}

	*s = start;
	*e = end;
}

#endif // S3_PSI_H
