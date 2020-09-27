#ifndef VBWT_HPP
#define VBWT_HPP

#include "obl/rec.h"
#include "obl/primitives.h"
#include "substring/substring_common.h"

// Interface

template<typename Int, typename Char>
inline
void vbwt_query(obl::recursive_oram *index, Int *C,
	Int s_rate, std::size_t s_size, std::uint64_t enc_bit, Int alpha,
	Char *q, Int qlen,
	Int *s, Int *e
);

// Static functions

static int partial_rank(std::uint16_t *ch, int limit, int sample_rate, std::int16_t target, int enc_bit)
{
	int p_rank = 0;

	int hword = 0;
	int shift_right = 0;
	std::uint16_t mask = (1 << enc_bit) - 1;

	for(int i = 0; i < sample_rate; i++)
	{
		std::uint16_t current = (ch[hword] >> shift_right) & mask;

		shift_right += enc_bit;
		if(shift_right > 16) // this is a known, public parameter, so you don't need to hide this if
		{
			++hword;
			shift_right -= 16;
			current = current | (ch[hword] << (enc_bit - shift_right));
			current = current & mask;
		}

		p_rank += obl::ternary_op((current == target) & (i < limit), 1, 0);
	}

	return p_rank;
}

// Implementation

template<typename Int, typename Char>
void vbwt_query(obl::recursive_oram *index, Int *C,
	Int s_rate, std::size_t s_size, std::uint64_t enc_bit, Int alpha,
	Char *q, Int qlen,
	Int *s, Int *e)
{
	Int start, end;
	std::uint8_t buffer[s_size];

	--qlen;

	start = linear_scan<Int>(C, (Int) q[qlen], alpha);
	end = linear_scan<Int>(C, (Int) q[qlen] + 1, alpha) - 1;
	--qlen;

	while(qlen != -1)
	{
		// base offset
		Int char_index = (Int) q[qlen];
		Int base_offset = linear_scan<Int>(C, char_index, alpha);

		// process start
		Int inner_offset = start % s_rate;
		Int outer_offset = start / s_rate;

		index->access(outer_offset, nullptr, buffer);

		Int *acc = (Int*)buffer;
		Int sample_offset = linear_scan<Int>(acc, char_index, alpha-1);

		std::uint16_t *ch = (std::uint16_t*)(acc + alpha);
		Int next_start = base_offset + sample_offset + partial_rank(ch, inner_offset, s_rate, char_index, enc_bit);

		// process end
		inner_offset = (end % s_rate) + 1;
		outer_offset = end / s_rate;

		index->access(outer_offset, nullptr, buffer);

		acc = (Int*)buffer;
		sample_offset = linear_scan<Int>(acc, char_index, alpha-1);

		ch = (std::uint16_t*)(acc + alpha);
		Int next_end = base_offset + sample_offset + partial_rank(ch, inner_offset, s_rate, char_index, enc_bit) - 1;
		
		// support for dummy characters
		bool dummy_char = (char_index < 0) | (char_index >= alpha);
		start = obl::ternary_op(dummy_char, start, next_start);
		end = obl::ternary_op(dummy_char, end, next_end);

		--qlen;
	}

	*s = start;
	*e = end;
}

#endif // VBWT_HPP
