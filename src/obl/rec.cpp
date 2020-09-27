#include "obl/rec.h"
#include "obl/primitives.h"

#define DUMMY_LEAF -1

namespace obl {

	constexpr leaf_id sign_bit = (1ULL << (sizeof(leaf_id) * 8 - 1)) - 1;

	// this is to avoid generating randomly a -1!
	inline leaf_id leaf_abs(leaf_id x)
	{
		return x & sign_bit;
	}

	recursive_oram::recursive_oram(std::size_t N, std::size_t B, unsigned int csize, oram_factory *allocator)
	{
		this->N = N;
		this->C = next_two_power(this->N);
		std::size_t capacity = C;

		rmap_csize = 1 << csize;
		rmap_bits = csize;
		
		// evaluate rmap_opt
		rmap_opt = __builtin_ctzll(C) % csize;
		if(rmap_opt == 0) // non-critical branch
			rmap_opt = csize;

		rmap_levs = 0;
		while(capacity > 1)
		{
			capacity >>= csize;
			++rmap_levs;
		}
		// peel away the very first level of recursion which is absorbed into pos_map
		--rmap_levs;
		
		// if there is only one level, it is already optimized
		/*if(rmap_levs == 1)
			rmap_bits = rmap_opt;*/

		if(rmap_levs > 0)
		{
			rmap = new tree_oram*[rmap_levs];
			std::size_t rec_N = 1;

			for(int i = 0; i < rmap_levs; i++)
			{
				int tmp_rmap;
				
				if(i == rmap_levs - 2)
					tmp_rmap = rmap_opt;
				else
					tmp_rmap = rmap_bits;
				
				if(i == rmap_levs - 1)
					rec_N <<= rmap_opt;
				else
					rec_N <<= rmap_bits;
				
				rmap[i] = allocator->spawn_oram(rec_N, sizeof(leaf_id) * (1 << tmp_rmap));				
			}
		}
		else
			rmap = nullptr;

		pos_map = new leaf_id[rmap_csize];
		for(int i = 0; i < rmap_csize; i++)
			pos_map[i] = DUMMY_LEAF;

		oram = allocator->spawn_oram(this->N, B);
	}

	recursive_oram::~recursive_oram()
	{
		delete[] pos_map;
		delete oram;

		if(rmap != nullptr)
		{
			for(int i = 0; i < rmap_levs; i++)
				delete rmap[i];

			delete[] rmap;
		}
	}

	leaf_id recursive_oram::scan_map(leaf_id *map, int idx, leaf_id replacement, bool to_init)
	{
		leaf_id leef = DUMMY_LEAF;

		for(int i = 0; i < rmap_csize; i++)
		{
			leaf_id tmp = map[i];

			leef = ternary_op(i == idx, tmp, leef);
			tmp = ternary_op(to_init, DUMMY_LEAF, tmp);
			map[i] = ternary_op(i == idx, replacement, tmp);
		}

		return leef;
	}

	void recursive_oram::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		bool to_initialize = false;

		leaf_id tmp_pos_map[rmap_csize];
		leaf_id leef, ev_leef, dummy_leef;

		// length of the current chunk of position map you are considering
		int ch_len;
		// given the current partition in rmap_csize chunks of ch_len, select the correct
		// index in the partial position map
		int n_bid;
		// offset in the current chunk to be used while descending the recursive pos_map
		block_id rem_bid;
		// recursive block for the intermediate ORAMs used to store the position map
		block_id rec_bid = 0;
		
		// to inject optimization
		int local_bits = rmap_levs == 1 ? rmap_opt : rmap_bits;

		/* Access the constant size position map */
		gen_rand((std::uint8_t*) &ev_leef, sizeof(leaf_id));
		gen_rand((std::uint8_t*) &dummy_leef, sizeof(leaf_id));
		ev_leef = leaf_abs(ev_leef);
		dummy_leef = leaf_abs(dummy_leef);

		ch_len = C >> local_bits;
		// fix to compile with O3
		if(ch_len == 0)
			ch_len = 1;
		
		rem_bid = bid;
		n_bid = rem_bid >> __builtin_ctzll(ch_len);

		leef = scan_map(pos_map, n_bid, ev_leef, to_initialize);

		to_initialize |= leef == DUMMY_LEAF;
		leef = ternary_op(!to_initialize, leef, dummy_leef);

		/* Access recursive ORAMs */
		for(int i = 0; i < rmap_levs; i++)
		{
			leaf_id ev_leef_p, leef_p;
			gen_rand((std::uint8_t*) &ev_leef_p, sizeof(leaf_id));
			gen_rand((std::uint8_t*) &dummy_leef, sizeof(leaf_id));
			ev_leef_p = leaf_abs(ev_leef_p);
			dummy_leef = leaf_abs(dummy_leef);

			// this holds the sequence of "branches" travelled so far in the position map
			rec_bid = (rec_bid << local_bits) | n_bid;
			rem_bid = rem_bid - n_bid * ch_len;
			
			// is the current iteration to optimize?
			if(i == rmap_levs - 2)
				local_bits = rmap_opt;
			else
				local_bits = rmap_bits;
			
			ch_len = ch_len >> local_bits;
			if(ch_len == 0)
				ch_len = 1;
			
			n_bid = rem_bid >> __builtin_ctzll(ch_len);

			// read the position map
			rmap[i]->access_r(rec_bid, leef, (std::uint8_t*) tmp_pos_map);

			// scan the chunk of the recursive position map
			leef_p = scan_map(tmp_pos_map, n_bid, ev_leef_p, to_initialize);

			to_initialize |= leef_p == DUMMY_LEAF;
			leef_p = ternary_op(!to_initialize, leef_p, dummy_leef);

			// evict
			rmap[i]->access_w(rec_bid, leef, (std::uint8_t*) tmp_pos_map, ev_leef);

			ev_leef = ev_leef_p;
			leef = leef_p;
		}

		oram->access(bid, leef, data_in, data_out, ev_leef);
	}
}
