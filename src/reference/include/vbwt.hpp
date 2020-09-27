#ifndef VBWT_H
#define VBWT_H

#include <cstdint>

// Interface

template<typename Int, typename Char>
inline
void vbwt_query(void *index, Int *C,
	Int s_rate, std::size_t s_size, std::uint64_t enc_bit, Int alpha,
	Char *q, Int qlen,
	Int *s, Int *e
);

// Static functions

static int partial_rank(std::uint16_t *ch, int limit, std::int16_t target, int enc_bit)
{
	int p_rank = 0;

	int hword = 0;
	int shift_right = 0;
	std::uint16_t mask = (1 << enc_bit) - 1;

	for(int i = 0; i < limit; i++)
	{
		std::uint16_t current = (ch[hword] >> shift_right) & mask;

		shift_right += enc_bit;
		if(shift_right > 16)
		{
			++hword;
			shift_right -= 16;
			current |= ((ch[hword] << (enc_bit - shift_right)) & mask);
		}

		if(current == target)
			++p_rank;
	}

	return p_rank;
}

// Implementation

template<typename Int, typename Char>

void vbwt_query(void *index, Int *C,
	Int s_rate, std::size_t s_size, std::uint64_t enc_bit, Int alpha,
	Char *q, Int qlen,
	Int *s, Int *e
)
{
	Int start, end;

	*s = -1;
	*e = -1;

	--qlen;
	if(q[qlen] == 255)
		return;

	start = C[(Int) q[qlen]];
	end = C[(Int) q[qlen] + 1] - 1;
	--qlen;

	// avoid compiler complaints
	std::uint8_t *u_index = (std::uint8_t*) index;

	while(qlen != -1)
	{
		if(q[qlen] == 255)
		{
			--qlen;
			continue;
		}

		// process start
		Int inner_offset = start % s_rate;
		Int outer_offset = start / s_rate;

		std::int32_t *acc = (Int*)(u_index + (outer_offset * s_size));
		std::uint16_t *ch = (std::uint16_t*)(acc + alpha);
		start = C[(Int) q[qlen]] + acc[(Int) q[qlen]] + partial_rank(ch, inner_offset, (Int) q[qlen], enc_bit);

		// process end
		inner_offset = (end % s_rate) + 1;
		outer_offset = end / s_rate;

		acc = (Int*)(u_index + (outer_offset * s_size));
		ch = (std::uint16_t*)(acc + alpha);
		end = C[(Int) q[qlen]] + acc[(Int) q[qlen]] + partial_rank(ch, inner_offset, (Int) q[qlen], enc_bit) - 1;

		--qlen;
	}

	*s = start;
	*e = end;
}

#endif // VBWT_H
