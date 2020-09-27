#include "obl/ring.h"
#include "obl/primitives.h"
#include "obl/utils.h"

#include "obl/oassert.h"

#include <cstdlib>

static void increment_ctr(std::uint8_t *ctr, std::uint64_t inc)
{
	for(int i = 15; i >= 0; i--)
	{
		inc += ctr[i];
		ctr[i] = inc;
		inc >>= 8;
	}
}


namespace obl {

	struct ring_block_t {
		leaf_id lid;
		std::uint8_t payload[];
	};

	struct ring_bucket_t {
		// valid_mask and access_count are STORED IN CLEAR according to the paper
		std::uint64_t valid;
		std::uint64_t access_count;
		// the IV used for the ctr mode
		obl_aes_ctr_128bit_iv_t bu_iv;
		// encrypted metadata + data (in a single bundle)
		uint8_t payload[];
	};

	ring_oram::ring_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int A, unsigned int stash_size): tree_oram(N, B, Z)
	{
		this->S = S;

		this->stash_size = stash_size;
		this->A = A;

		// a block is multiple of the size of an AES block
		block_size = pad_bytes(sizeof(block_t) + this->B, 16);
		metadata_size = pad_bytes(sizeof(block_id) * (this->S + this->Z), 16);
		bucket_size = pad_bytes(sizeof(bucket_t) + metadata_size + (this->Z + this->S) * block_size, 8);

		tree.set_entry_size(bucket_size);
		tree.reserve(capacity);

		// for the stash
		stash.set_entry_size(block_size);
		stash.reserve(stash_size);
		s_bid = new block_id[stash_size];

		// for eviction
		eviction_path.set_entry_size(block_size);
		eviction_path.reserve((L+1) * this->Z);
		eviction_meta = new block_id[(L+1) * this->Z];
		to_reshuffle = new bool[L+1];

		for(unsigned int i = 0; i < stash_size; i++)
			s_bid[i] = -1;

		det_eviction = 0;
		access_counter = 0;

		init();
	}

	ring_oram::~ring_oram()
	{
		std::memset(master_key, 0x00, sizeof(sgx_aes_ctr_128bit_key_t));

		std::memset(s_bid, 0x00, sizeof(block_id) * stash_size);
		std::memset(eviction_meta, 0x00, sizeof(block_id) * (L+1) * Z);

		std::memset(&stash[0], 0x00, block_size * stash_size);
		std::memset(&eviction_path[0], 0x00, block_size * (L+1) * Z);

		delete[] s_bid;
		delete[] eviction_meta;
		delete[] to_reshuffle;
	}

	void ring_oram::init()
	{
		gen_rand((std::uint8_t*) master_key, sizeof(sgx_aes_ctr_128bit_key_t));

		for(unsigned int i = 0; i < capacity; i++)
		{
			tree[i].access_count = 0;
			tree[i].valid = 0;
		}
	}

	void ring_oram::knuth_alg_s(std::uint64_t &selected, std::uint64_t still_valid, std::uint64_t candidates, int n, int len)
	{
		int m = 0; // number of elements chosen so far
		int t = 0; // number of elements scanned out of the candidates
		int N = __builtin_popcountll(candidates); // extract the total number of candidates -- O(1) on x86_64

		// clear the selected bitmask
		selected = 0;

		for(int i = 0; i < len; i++)
			if((still_valid >> i) & 1)
			{
				bool not_is_candidate = ((candidates >> i) & 1) == 0;
				// extract a random byte
				std::int8_t u = get_rand_byte();
				bool skip = (N - t) * u >= ((n - m) << 7);

				std::uint64_t sel = ternary_op(skip | not_is_candidate, 0ULL, 1ULL) << i;
				selected |= sel;

				// number of selected entries
				m += ternary_op(skip | not_is_candidate, 0, 1);
				// a candidate was scanned
				t += ternary_op(not_is_candidate, 0, 1);
			}
	}

	int ring_oram::pseudo_xor_trick(block_id bid, leaf_id path, std::uint8_t *out)
	{
		// start from root
		int l_index = 0;

		// data of the selected block
		std::uint8_t xored_block[block_size];
		int real_offset = get_rand_byte() % (Z+S);
		obl_aes_ctr_128bit_iv_t iv_final;

		// buffer for the IV, which gets auto-incremented by SGX methods
		obl_aes_ctr_128bit_iv_t temp_iv;

		// metadata
		block_id meta[Z+S];

		for(int i = 0; i <= L; i++)
		{
			std::memcpy(temp_iv, tree[l_index].bu_iv, sizeof(obl_aes_ctr_128bit_iv_t));

			sgx_aes_ctr_decrypt(
				&master_key,
				tree[l_index].payload,
				sizeof(block_id)*(Z+S),
				temp_iv, // gets incremented by the size in AES blocks of the metadata
				128,
				(std::uint8_t*) meta
			);

			bool found = false;
			int offset = get_rand_byte() % (Z+S);
			std::int8_t current_max = -1;
			std::uint64_t t_valid = tree[l_index].valid;

			// try to find the correct block or select a dummy block
			for(unsigned int j = 0; j < Z+S; j++)
				if((t_valid >> j) & 1)
				{
					// draw random byte -- assured to be >= 0
					std::int8_t next = get_rand_byte();

					// do I update with dummy index?
					bool tmp_dummy = (meta[j] == -1) & (next > current_max) & !found;
					// has it been found?
					bool tmp = (meta[j] == bid);

					offset = ternary_op(tmp_dummy, j, offset);
					offset = ternary_op(tmp, j, offset);

					current_max = ternary_op(tmp_dummy, next, current_max);
					found |= tmp;
				}

			// increment access counter
			++tree[l_index].access_count;
			// invalidate that block
			tree[l_index].valid &= (~(1ULL << offset));

			replace(found, xored_block, tree[l_index].payload + metadata_size + offset*block_size, block_size);
			replace(found, iv_final, temp_iv, sizeof(obl_aes_ctr_128bit_iv_t));
			real_offset = ternary_op(found, offset, real_offset);

			// navigate to the next node in the heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
		}

		increment_ctr(iv_final, (real_offset * block_size) >> 4);

		sgx_aes_ctr_decrypt(
			&master_key,
			xored_block,
			block_size,
			iv_final,
			128,
			out
		);

		return get_parent(l_index);
	}

	void ring_oram::evict_path(leaf_id path)
	{
		std::int64_t l_index = 0;

		// decrypted bucket stuff
		block_id meta[Z+S];
		std::uint8_t bucket_buffer[(Z+S) * block_size];

		obl_aes_ctr_128bit_iv_t iv;

		// set all eviction metadata to dummy, which is -1
		// XXX - bugfix: (Z+S) -> Z, because it's only Z blocks per bucket during the eviction
		// This should solve the double free as well
		std::memset(eviction_meta, 0xFF, sizeof(block_id) * (L+1) * Z);

		for(int i = 0; i <= L; i++) // for every bucket in the path
		{
			to_reshuffle[i] = true;

			std::memcpy(iv, tree[l_index].bu_iv, sizeof(obl_aes_ctr_128bit_iv_t));

			sgx_aes_ctr_decrypt(
				&master_key,
				tree[l_index].payload,
				sizeof(block_id)*(Z+S),
				iv,
				128,
				(std::uint8_t*) meta
			);

			/*
				This is a deviation from the standard protocol, which mandates to only
				decrypt the blocks to select.
				In our case, where block size is negligible, I think it's more performant
				to fully decrypt a bucket rather than manually incrementing an IV and
				perform single AES block decryptions for Z times.
			*/
			sgx_aes_ctr_decrypt(
				&master_key,
				tree[l_index].payload + metadata_size,
				block_size * (Z+S),
				iv,
				128,
				bucket_buffer
			);

			std::uint64_t valid = tree[l_index].valid;

			// filter out the remaining entries to shrink to Z entries to evict
			if(tree[l_index].access_count < S) // access_count is a public parameter so no need to hide
			{
				std::uint64_t candidate;
				std::uint64_t dummies = 0;
				std::uint64_t shutdown;

				// create a bitmask of dummy blocks
				for(unsigned int j = 0; j < Z+S; j++)
					dummies |= ternary_op(meta[j] == -1, 1ULL, 0ULL) << j;

				// candidates are valid dummy blocks
				candidate = valid & dummies;

				// invalidate enough block to get #valids to Z
				knuth_alg_s(shutdown, valid, candidate, S - tree[l_index].access_count, Z+S);

				valid &= ~shutdown;
			}

			int k = 0;
			for(unsigned int j = 0; j < Z+S; j++)
				if((valid >> j) & 1)
				{
					std::memcpy(&eviction_path[i*Z + k], bucket_buffer + j*block_size, block_size);
					eviction_meta[i*Z + k] = meta[j];

					++k;
				}

			assert(k == 0 || (unsigned int)k == Z);

			// select next bucket in the path
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
		}

		for(int i = L-1; i >= 0; i--) // for every fetched bucket
		{
			for(unsigned int c = 0; c < Z; c++) // for every block in that bucket
			{
				int j = i*Z + c;

				block_id current_bid = eviction_meta[j];
				int maxd = get_max_depth(eviction_path[j].lid, path, L);
				// if dummy, no need to evict!!
				bool already_evicted = current_bid == -1;

				for(int bu = L; bu > i; bu--) // for every bucket in the underlying path...
				{
					// generate random offset
					int offset = get_rand_byte() % Z;
					bool valid_bucket = (bu <= maxd) & !already_evicted;

					for(unsigned int b = 0; b < Z; b++) // for every block
						offset = ternary_op((eviction_meta[bu*Z + b] == -1) & valid_bucket, b, offset);

					offset = offset + bu*Z;

					bool evict_real = valid_bucket & (eviction_meta[offset] == -1);

					replace(evict_real, (std::uint8_t*) &eviction_path[offset], (std::uint8_t*) &eviction_path[j], block_size);

					block_id bid_bak = eviction_meta[offset];
					eviction_meta[offset] = ternary_op(evict_real, current_bid, bid_bak);

					already_evicted |= evict_real;
				}

				eviction_meta[j] = ternary_op(already_evicted, -1, current_bid);
			}
		}

		for(unsigned int i = 0; i < stash_size; i++)
		{
			block_id current_bid = s_bid[i];
			// if dummy, no need to evict!!
			int maxd = get_max_depth(stash[i].lid, path, L);
			bool already_evicted = (current_bid == -1);

			for(int bu = L; bu >= 0; bu--) // for every bucket in the underlying path...
			{
				// generate random offset
				int offset = get_rand_byte() % Z;
				bool valid_bucket = (bu <= maxd) & !already_evicted;

				for(unsigned int b = 0; b < Z; b++) // for every block
					offset = ternary_op((eviction_meta[bu*Z + b] == -1) & valid_bucket, b, offset);

				offset = offset + bu*Z;

				bool evict_real = valid_bucket & (eviction_meta[offset] == -1);

				replace(evict_real, (std::uint8_t*) &eviction_path[offset], (std::uint8_t*) &stash[i], block_size);

				block_id offset_bid = eviction_meta[offset];

				eviction_meta[offset] = ternary_op(evict_real, current_bid, offset_bid);

				already_evicted |= evict_real;
			}

			s_bid[i] = ternary_op(already_evicted, -1, current_bid);
		}
	}

	void ring_oram::wb_path(leaf_id path)
	{
		int l_index = 0;
		std::uint8_t bucket_body[(Z+S) * block_size];
		block_id bucket_meta[Z+S];
		obl_aes_ctr_128bit_iv_t iv;

		for(int i = 0; i <= L; i++)
		{
			if(to_reshuffle[i])
			{
				intersperse((block_t*) bucket_body, &eviction_path[Z*i], bucket_meta, &eviction_meta[Z*i]);

				// generate random iv
				gen_rand(iv, sizeof(obl_aes_ctr_128bit_iv_t));

				// fill bucket ctx data
				std::memcpy(tree[l_index].bu_iv, iv, sizeof(obl_aes_ctr_128bit_iv_t));
				tree[l_index].access_count = 0;
				tree[l_index].valid = 0x7FFFFFFFFFFFFFFFULL;

				// fill bucket encrypted data
				sgx_aes_ctr_encrypt(
					&master_key,
					(std::uint8_t*) bucket_meta,
					sizeof(block_id)*(Z+S),
					iv,
					128,
					tree[l_index].payload
				);

				sgx_aes_ctr_encrypt(
					&master_key,
					bucket_body,
					block_size * (Z+S),
					iv,
					128,
					tree[l_index].payload + metadata_size
				);
			}

			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
		}
	}

	void ring_oram::intersperse(block_t *dst, block_t *src, block_id *dst_meta, block_id *src_meta)
	{
		std::uint64_t not_selected = (std::uint64_t) -1;
		std::memset(dst_meta, 0xFF, sizeof(block_id)*(Z+S));

		for(unsigned int i = 0; i < Z; i++)
		{
			int dest_offset = get_rand_byte() % (Z+S-i);
			int src_id = src_meta[i];

			for(unsigned int j = 0; j < Z+S; j++)
			{
				int dst_id = dst_meta[j];
				bool valid = (dst_id == -1) & ((not_selected >> j) & 1ULL);

				dest_offset -= ternary_op(valid, 1, 0);
				valid &= dest_offset == -1;
				not_selected = not_selected & ~(ternary_op(valid, 1ULL << j, 0));

				replace(valid, (std::uint8_t*)dst + j*block_size, (std::uint8_t*)src + i*block_size, block_size);
				dst_meta[j] = ternary_op(valid, src_id, dst_id);
			}
		}
	}

	void ring_oram::early_reshuffle(leaf_id path)
	{
		std::int64_t l_index = 0;

		// decrypted bucket stuff
		block_id meta[Z+S];
		std::uint8_t bucket_buffer[(Z+S) * block_size];

		obl_aes_ctr_128bit_iv_t iv;

		std::memset(eviction_meta, 0xff, sizeof(block_id) * (L+1) * Z);

		for(int i = 0; i <= L; i++) // for every bucket in the path
		{
			if(tree[l_index].access_count >= S)
			{
				to_reshuffle[i] = true;

				std::memcpy(iv, tree[l_index].bu_iv, sizeof(obl_aes_ctr_128bit_iv_t));

				sgx_aes_ctr_decrypt(
					&master_key,
					tree[l_index].payload,
					sizeof(block_id)*(Z+S),
					iv,
					128,
					(std::uint8_t*) meta
				);

				sgx_aes_ctr_decrypt(
					&master_key,
					tree[l_index].payload + metadata_size,
					block_size * (Z+S),
					iv,
					128,
					bucket_buffer
				);

				int k = 0;
				std::uint64_t cur_valid = tree[l_index].valid;
				for(unsigned int j = 0; j < Z+S; j++)
					if((cur_valid >> j) & 1)
					{
						std::memcpy(&eviction_path[i*Z + k], bucket_buffer + j * block_size, block_size);
						eviction_meta[i*Z + k] = meta[j];

						++k;
					}
			}
			else
				to_reshuffle[i] = false;

			// select next bucket in the path
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
		}

		/*
			NB : Stash analysis in the paper states that reshuffles don't affect stash
			occupancy, so I decide to totally kill eviction in presence of reshuffles
			because those were not taken into account in overflow analysis.
			Here I just reshuffle and restore a random permutation, with S dummy blocks.
			This partially conflicts with the pseudocode in the paper, however, even if
			stash occupancy is slightly affected, avoiding the eviction during the reshuffle
			certainly produces a faster implementation.
		*/
	}

	void ring_oram::access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif)
	{
		std::uint8_t fetched_block[block_size];
		block_t *ffb = (block_t*) fetched_block;

		++access_counter;

		// try to retrieve the block from the path
		pseudo_xor_trick(bid, lif, fetched_block);

		// search for the requested element by traversing the buckets in the stash
		for(unsigned int i = 0; i < stash_size; i++)
		{
			block_id sbid = s_bid[i];
			replace(bid == sbid, fetched_block, (std::uint8_t*) &stash[i], block_size);
			s_bid[i] = ternary_op(bid == sbid, -1, sbid);
		}

		std::memcpy(data_out, ffb->payload, B);

		// build the block to write!
		ffb->lid = next_lif;
		// if write operation, write the fed data
		if(data_in != nullptr)
			std::memcpy(ffb->payload, data_in, B);

		// evict the block to the stash
		bool already_evicted = false;
		for(unsigned int i = 0; i < stash_size; i++)
		{
			block_id sbid = s_bid[i];
			bool we = !already_evicted & (sbid == -1);
			replace(we, (std::uint8_t*) &stash[i], fetched_block, block_size);
			s_bid[i] = ternary_op(we, bid, sbid);
			already_evicted |= we;
		}

		assert(already_evicted);

		if(access_counter % A == 0)
		{
			evict_path(det_eviction);
			wb_path(det_eviction);
			++det_eviction;
		}

		// just reshuffle without local eviction
		early_reshuffle(lif);
		wb_path(lif);
	}

	void ring_oram::access_r(block_id bid, leaf_id lif, std::uint8_t *data_out)
	{
		std::uint8_t fetched_block[block_size];
		block_t *ffb = (block_t*) fetched_block;

		++access_counter;

		// try to retrieve the block from the path
		pseudo_xor_trick(bid, lif, fetched_block);

		// search for the requested element by traversing the buckets in the stash
		for(unsigned int i = 0; i < stash_size; i++)
		{
			block_id sbid = s_bid[i];
			replace(bid == sbid, fetched_block, (std::uint8_t*) &stash[i], block_size);
			s_bid[i] = ternary_op(bid == sbid, -1, sbid);
		}

		std::memcpy(data_out, ffb->payload, B);
	}

	void ring_oram::access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif)
	{
		std::uint8_t fetched_block[block_size];
		block_t *ffb = (block_t*) fetched_block;

		// build the block to write!
		ffb->lid = next_lif;
		std::memcpy(ffb->payload, data_in, B);

		// evict the block to the stash
		bool already_evicted = false;
		for(unsigned int i = 0; i < stash_size; i++)
		{
			block_id sbid = s_bid[i];
			bool we = !already_evicted & (sbid == -1);
			replace(we, (std::uint8_t*) &stash[i], fetched_block, block_size);
			s_bid[i] = ternary_op(we, bid, sbid);
			already_evicted |= we;
		}

		assert(already_evicted);

		if(access_counter % A == 0)
		{
			evict_path(det_eviction);
			wb_path(det_eviction);
			++det_eviction;
		}

		// just reshuffle without local eviction
		early_reshuffle(lif);
		wb_path(lif);
	}

	void ring_oram::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
	{
		std::uint8_t fetched_block[block_size];
		block_t *ffb = (block_t*) fetched_block;

		++access_counter;

		// build the block to write!
		ffb->lid = next_lif;
		std::memcpy(ffb->payload, data_in, B);

		// evict the block to the stash
		bool already_evicted = false;
		for(unsigned int i = 0; i < stash_size; i++)
		{
			block_id sbid = s_bid[i];
			bool we = !already_evicted & (sbid == -1);
			replace(we, (std::uint8_t*) &stash[i], fetched_block, block_size);
			s_bid[i] = ternary_op(we, bid, sbid);
			already_evicted |= we;
		}

		assert(already_evicted);

		if(access_counter % A == 0)
		{
			evict_path(det_eviction);
			wb_path(det_eviction);
			++det_eviction;
		}
	}

}
