#ifndef S3_PSI_HPP
#define S3_PSI_HPP

#include <cstddef>
#include "cbbst.h"
#include "obl/primitives.h"
#include "substring/substring_common.h"

// Interface

template<typename Int, typename Char>
inline
void sapsi_query(
	obl::ods::cbbst *psi, Int *C, Int alpha,
	Char *q, Int qlen,
	Int *s, Int *e
);

// Implementation

template<typename Int, typename Char>
void sapsi_query(obl::ods::cbbst *psi, Int *C, Int alpha, Char *q, Int qlen, Int *s, Int *e)
{
	Int start, end;
	Int len = psi->get_N();
	int L = psi->get_L();

	// index the last character of the query
	--qlen;

	// process the last character of the query
	start = linear_scan<Int>(C, (Int)q[qlen], alpha);
	end = linear_scan<Int>(C, (Int)q[qlen] + 1, alpha) - 1;
	--qlen;

	while(qlen != -1)
	{
		// those are the ranges of the subtree where we are required to perform our search
		Int char_index = (Int) q[qlen];
		Int low_bound = linear_scan<Int>(C, char_index, alpha);
		Int upp_bound = linear_scan<Int>(C, char_index + 1, alpha) - 1;

		// this is the current section of PSI array that is considered
		Int psi_s = 0;
		Int psi_e = len;

		Int h = 0; // position in the heap
		Int next_start = -1;

		for(int l = 0; l < L; l++)
		{
			// perform access to the dummy block!
			h = obl::ternary_op(h >= len, -1, h);

			Int real_idx = psi_s + get_subroot(psi_e - psi_s);
			Int curr_psi;
			psi->read(h, (std::uint8_t*) &curr_psi, l);

			bool right_range = (real_idx >= low_bound) & (real_idx <= upp_bound);
			bool in_psi_range = (curr_psi >= start) & (curr_psi <= end);
			bool go_right = (real_idx < low_bound) | (right_range & (curr_psi < start));

			next_start = obl::ternary_op(right_range & in_psi_range & (h != -1), real_idx, next_start);

			psi->update(h, (std::uint8_t*) &curr_psi, !go_right, l);

			h = (h << 1) + 1 + obl::ternary_op(go_right, 1, 0);
			psi_s = obl::ternary_op(go_right, real_idx + 1, psi_s);
			psi_e = obl::ternary_op(go_right, psi_e, real_idx);
		}

		// reset values
		psi_s = 0;
		psi_e = len;

		h = 0;
		Int next_end = -1;

		for(int l = 0; l < L; l++)
		{
			h = obl::ternary_op(h >= len, -1, h);

			Int real_idx = psi_s + get_subroot(psi_e - psi_s);
			Int curr_psi;
			psi->read(h, (std::uint8_t*) &curr_psi, l);

			bool right_range = (real_idx >= low_bound) & (real_idx <= upp_bound);
			bool in_psi_range = (curr_psi >= start) & (curr_psi <= end);
			bool go_right = (real_idx < low_bound) | (right_range & (curr_psi <= end));

			next_end = obl::ternary_op(right_range & in_psi_range & (h != -1), real_idx, next_end);

			psi->update(h, (std::uint8_t*) &curr_psi, !go_right, l);

			h = (h << 1) + 1 + obl::ternary_op(go_right, 1, 0);
			psi_s = obl::ternary_op(go_right, real_idx + 1, psi_s);
			psi_e = obl::ternary_op(go_right, psi_e, real_idx);
		}

		// support for dummy characters
		bool dummy_char = (char_index < 0) | (char_index >= alpha);
		start = obl::ternary_op(dummy_char, start, next_start);
		end = obl::ternary_op(dummy_char, end, next_end);

		--qlen;
	}

	*s = start;
	*e = end;
}

#endif // S3_PSI_HPP
