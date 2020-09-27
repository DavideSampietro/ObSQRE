#include "obl/circuit.h"
#include "obl/utils.h"
#include "obl/primitives.h"

#include "obl/oassert.h"

#include <cstdlib>
#include <cstring>

#define DUMMY -1
#define BOTTOM -2


namespace obl {

	struct circuit_block_t {
		block_id bid;
		leaf_id lid;
		std::uint8_t payload[];
	};

	struct circuit_bucket_t {
		obl_aes_gcm_128bit_iv_t iv;
		bool reach_l, reach_r;
		obl_aes_gcm_128bit_tag_t mac __attribute__ ((aligned(8)));
		// since payload is going to be a multiple of 16 bytes, the struct will be memory aligned!
		uint8_t payload[];
	};

	circuit_oram::circuit_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S): tree_oram(N, B, Z)
	{
		// align structs to 8-bytes
		/*
			Since AES-GCM is basically an AES-CTR mode, and AES-CTR mode is a "stream-cipher",
			you actually don't need to pad everything to 16 bytes which is AES block size
		*/
		block_size = pad_bytes(sizeof(block_t) + this->B, 8);
		bucket_size = pad_bytes(sizeof(bucket_t) + this->Z * block_size, 8);

		// stash allocation
		this->S = S;
		stash.set_entry_size(block_size);
		stash.reserve(this->S);

		for(unsigned int i = 0; i < this->S; i++)
			stash[i].bid = DUMMY;

		// ORAM tree allocation
		tree.set_entry_size(bucket_size);
		tree.reserve(capacity);

		// fetched_path allocation
		fetched_path.set_entry_size(block_size);
		fetched_path.reserve((L+1) * this->Z);

		// allocate arrays for eviction
		longest_jump_down = new std::int64_t[L+2]; // counting root = 0 and stash = -1 and L additional levels
		closest_src_bucket = new std::int64_t[L+2];
		next_dst_bucket = new std::int64_t[L+2];

		// allocate data struct for integrity checking
		adata = new auth_data_t[L+1];

		init();
	}

	circuit_oram::~circuit_oram()
	{
		std::memset(_crypt_buffer, 0x00, sizeof(Aes) + 16);

		std::memset(&stash[0], 0x00, block_size * S);
		std::memset(&fetched_path[0], 0x00, block_size * (L+1) * Z);

		free(_crypt_buffer);
		delete[] adata;
		delete[] longest_jump_down;
		delete[] closest_src_bucket;
		delete[] next_dst_bucket;
	}

	void circuit_oram::init()
	{
		obl_aes_gcm_128bit_key_t master_key;
		obl_aes_gcm_128bit_iv_t iv;
		auth_data_t empty_auth;
		std::uint8_t empty_bucket[Z*block_size];

		// generate random master key
		gen_rand(master_key, OBL_AESGCM_KEY_SIZE);

		// initialize aes handle
		crypt_handle = (Aes*) man_aligned_alloc(&_crypt_buffer, sizeof(Aes), 16);
		wc_AesGcmSetKey(crypt_handle, master_key, OBL_AESGCM_KEY_SIZE);

		// clear the authenticated data and the bucket
		std::memset(&empty_auth, 0x00, sizeof(auth_data_t));
		std::memset(empty_bucket, 0xff, Z*block_size);

		// generate random IV
		gen_rand(iv, OBL_AESGCM_IV_SIZE);

		wc_AesGcmEncrypt(crypt_handle,
			tree[0].payload,
			empty_bucket,
			Z*block_size,
			iv,
			OBL_AESGCM_IV_SIZE,
			merkle_root,
			OBL_AESGCM_MAC_SIZE,
			(std::uint8_t*) &empty_auth,
			sizeof(auth_data_t)
		);

		// now dump to the protected storage
		std::memcpy(tree[0].mac, merkle_root, sizeof(obl_aes_gcm_128bit_tag_t));
		std::memcpy(tree[0].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
		tree[0].reach_l = false;
		tree[0].reach_r = false;
	}

	std::int64_t circuit_oram::fetch_path(leaf_id path)
	{
		// always start from root
		std::int64_t l_index = 0;
		int i;

		// start verifying the mac stored in the root, from the SAFE part of the memory
		obl_aes_gcm_128bit_tag_t reference_mac;
		std::memcpy(reference_mac, merkle_root, sizeof(obl_aes_gcm_128bit_tag_t)); // drop the & since not needed

		/*
			the additional method init (to be refined in the SGX deployment) actually inits
			the root node in a proper way, storing the correct "accessed" flags inside
			the root bucket. So the mac there contained in the root will always be valid
		*/
		bool reachable = true;

		std::memset(adata, 0x00, sizeof(auth_data_t) * (L+1));

		for(i = 0; i <= L && reachable; i++)
		{
			std::int64_t leftch = get_left(l_index);
			std::int64_t rightch = get_right(l_index);

			// this data will be authenticated data in the GCM mode
			// dump from encrypted bucket header
			adata[i].valid_l = tree[l_index].reach_l;
			adata[i].valid_r = tree[l_index].reach_r;

			// dump left and right child mac if valid, otherwise pad with 0s
			if(adata[i].valid_l)
				std::memcpy(adata[i].left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			if(adata[i].valid_r)
				std::memcpy(adata[i].right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			// if they are not valid, authentication data for the corresponding mac would be 0x00..0
			// however this was already covered by the memset before the loop

			// decrypt using the IV
			int dec = wc_AesGcmDecrypt(crypt_handle,
				(std::uint8_t*) &fetched_path[Z*i],
				tree[l_index].payload,
				Z*block_size,
				tree[l_index].iv,
				OBL_AESGCM_IV_SIZE,
				reference_mac,
				OBL_AESGCM_MAC_SIZE,
				(std::uint8_t*) &adata[i],
				sizeof(auth_data_t)
			);

			// MAC mismatch is a critical error
			//assert(dec != AES_GCM_AUTH_E);
			assert(dec == 0);

			/*
				NB: this doesn't need to be oblivious since an attacker might always see
				the sequences of accesses to the buckets and understand whether or not a
				bucket has already been accessed
				NB 2: fetch this from data which was dumped and authenticated, and taken
				from PROTECTED MEMORY. This should avoid some kind of attacks
			*/
			reachable = (path >> i) & 1 ? adata[i].valid_r : adata[i].valid_l;
			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);

			if(reachable)
			{
				/*
					NB: this isn't oblivious as well since you are just publicly traversing
					the ORAM tree
				*/
				std::uint8_t *src = ((path >> i) & 1) ? adata[i].right_mac : adata[i].left_mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
		}

		// fill the other buckets with "empty" blocks
		while(i <= L)
		{
			int base = Z*i;

			for(unsigned int j = 0; j < Z; j++)
				fetched_path[base + j].bid = DUMMY;

			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}

		return get_parent(l_index);
	}

	void circuit_oram::wb_path(leaf_id path, std::int64_t leaf)
	{
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;
		bool reachable = true;

		// update the reachability flags
		for(int i = 0; i < L; i++)
		{
			if(((path >> i) & 1) == 0) // if you take the left path
			{
				adata[i].valid_r = reachable && adata[i].valid_r; // this serves as initialization for initial dummy values
				reachable = reachable && adata[i].valid_l; // this propagates reachability
				adata[i].valid_l = true; // this marks the path as already fetched, and thus valid
			}
			else { // else
				adata[i].valid_l = reachable && adata[i].valid_l;
				reachable = reachable && adata[i].valid_r;
				adata[i].valid_r = true;
			}
		}

		// leaves have always unreachable children
		adata[L].valid_l = false;
		adata[L].valid_r = false;

		for(int i = L; i >= 0; i--)
		{
			// generate a new random IV
			gen_rand(iv, OBL_AESGCM_IV_SIZE);

			// save encrypted payload
			wc_AesGcmEncrypt(crypt_handle,
				tree[leaf].payload,
				(std::uint8_t*) &fetched_path[Z*i],
				Z*block_size,
				iv,
				OBL_AESGCM_IV_SIZE,
				mac,
				OBL_AESGCM_MAC_SIZE,
				(std::uint8_t*) &adata[i],
				sizeof(auth_data_t)
			);

			// save "mac" + iv + reachability flags
			std::memcpy(tree[leaf].mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
			std::memcpy(tree[leaf].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
			tree[leaf].reach_l = adata[i].valid_l;
			tree[leaf].reach_r = adata[i].valid_r;

			// update the mac for the parent for the evaluation of its mac
			if(i > 0)
			{
				/*
					NB: this isn't oblivious as the attacker knows which path you are performing
					the eviction!
				*/
				std::uint8_t *target_mac = ((path >> (i-1)) & 1) ? adata[i-1].right_mac : adata[i-1].left_mac;
				std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
			}

			// move to the bucket in the upper level
			leaf = get_parent(leaf);
		}

		// now dump the last mac to the merkle_root!
		std::memcpy(merkle_root, mac, sizeof(obl_aes_gcm_128bit_tag_t));
	}

	bool circuit_oram::has_free_block(block_t *bl, int len)
	{
		bool free_block = false;

		for(int i = 0; i < len; i++)
		{
			free_block |= bl->bid == DUMMY;
			bl = (block_t*)((std::uint8_t*) bl + block_size);
		}

		return free_block;
	}

	std::int64_t circuit_oram::get_max_depth_bucket(block_t *bl, int len, leaf_id path)
	{
		std::int64_t max_d = -1;

		for(int i = 0; i < len; i++)
		{
			int candidate = get_max_depth(bl->lid, path, L);
			block_id bid = bl->bid;
			max_d = ternary_op((candidate > max_d) & (bid != DUMMY), candidate, max_d);
			bl = (block_t*)((std::uint8_t*) bl + block_size);
		}

		return max_d;
	}

	void circuit_oram::deepest(leaf_id path)
	{
		// allow -1 indexing for stash
		std::int64_t *ljd = longest_jump_down + 1;
		std::int64_t *csb = closest_src_bucket + 1;

		std::int64_t closest_src_bucket = -1;
		std::int64_t goal = -1;

		goal = get_max_depth_bucket(&stash[0], S, path);
		ljd[-1] = goal;
		csb[-1] = BOTTOM;

		for(int i = 0; i <= L; i++)
		{
			csb[i] = ternary_op(goal >= i, closest_src_bucket, BOTTOM);

			std::int64_t jump = get_max_depth_bucket(&fetched_path[Z*i], Z, path);
			ljd[i] = jump;

			closest_src_bucket = ternary_op(jump >= goal, i, closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);
		}
	}

	void circuit_oram::target()
	{
		std::int64_t *ndb = next_dst_bucket + 1;
		std::int64_t *csb = closest_src_bucket + 1;

		std::int64_t src = BOTTOM;
		std::int64_t dst = BOTTOM;

		for(int i = L; i >= 0; i--)
		{
			bool has_dummy = has_free_block(&fetched_path[Z*i], Z);
			bool reached_bucket = src == i;

			// you reached the correct bucket up in the path if src == i
			ndb[i] = ternary_op(reached_bucket, dst, BOTTOM);
			dst = ternary_op(reached_bucket, BOTTOM, dst);
			src = ternary_op(reached_bucket, BOTTOM, src);

			/*
				dst == -2 => no deeper bucket is going to be filled
				csb[i] != -2 => someone in the upper path can fill this bucket
				has_dummy => is there a free block?
				ndb[i] != -2 => or will be a block evicted?
			*/
			std::int64_t closest_src = csb[i];
			bool new_dst = (closest_src != BOTTOM) & (((dst == BOTTOM) & has_dummy) | (ndb[i] != BOTTOM));

			dst = ternary_op(new_dst, i, dst);
			src = ternary_op(new_dst, closest_src, src);
		}

		// now the stash
		bool stash_reached_bucket = src == DUMMY;
		ndb[-1] = ternary_op(stash_reached_bucket, dst, BOTTOM);
	}

	void circuit_oram::eviction(leaf_id path)
	{
		std::int64_t dst;

		std::int64_t *ljd = longest_jump_down + 1;
		std::int64_t *ndb = next_dst_bucket + 1;

		std::uint8_t _hold[block_size];
		block_t *hold = (block_t*) _hold;
		hold->bid = DUMMY;

		bool fill_hold = ndb[-1] != BOTTOM;

		for(unsigned int i = 0; i < S; i++)
		{
			bool deepest_block = (get_max_depth(stash[i].lid, path, L) == ljd[-1]) & fill_hold & (stash[i].bid != DUMMY);
			swap(deepest_block, _hold, (std::uint8_t*) &stash[i], block_size);
		}

		dst = ndb[-1];

		for(int i = 0; i <= L; i++)
		{
			std::int64_t next_dst = ndb[i];

			// necessary to evict hold if it is not dummy and it reached its maximum depth
			bool necessary_eviction = (i == dst) & (hold->bid != DUMMY);
			dst = ternary_op(necessary_eviction, BOTTOM, dst);

			bool swap_hold_with_valid = next_dst != BOTTOM;
			dst = ternary_op(swap_hold_with_valid, next_dst, dst);

			//bool already_swapped = false;
			for(unsigned int j = 0; j < Z; j++)
			{
				bool deepest_block = (get_max_depth(fetched_path[Z*i + j].lid, path, L) == ljd[i]) & (fetched_path[Z*i + j].bid != DUMMY);

				swap(
					(!swap_hold_with_valid & necessary_eviction & (fetched_path[Z*i + j].bid == DUMMY)) | (swap_hold_with_valid & deepest_block),
					_hold, (std::uint8_t*) &fetched_path[Z*i + j], block_size);
			}
		}
	}

	void circuit_oram::evict(leaf_id path)
	{
		std::int64_t leaf = fetch_path(path);

		deepest(path);
		target();
		eviction(path);

		wb_path(path, leaf);
	}

	void circuit_oram::access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		std::int64_t leaf_idx = fetch_path(lif);

		fetched->bid = DUMMY;

		// search for the requested block by traversing the bucket sequence from root to leaf
		for(int i = 0; i <= L; i++)
			for(unsigned int j = 0; j < Z; j++)
			{
				block_id fpbid = fetched_path[Z*i + j].bid;
				swap(fpbid == bid, _fetched, (std::uint8_t*) &fetched_path[Z*i + j], block_size);
			}

		// search for the requested element by traversing the buckets in the stash
		// -- all of them, in order to avoid leakage in the number of entries in the stash
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(bid == sbid, _fetched, (std::uint8_t*) &stash[i], block_size);
		}

		assert(fetched->bid == bid || data_in != nullptr);

		// build the block to write!
		fetched->bid = bid;
		fetched->lid = next_lif;

		std::memcpy(data_out, fetched->payload, B);

		// if write operation, write the fed data
		if(data_in != nullptr)
			std::memcpy(fetched->payload, data_in, B);

		// evict the created block to the stash
		bool already_evicted = false;
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t*) &stash[i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}

		// if this fails, it means that the stash overflowed and you cannot insert any new element!
		assert(already_evicted);

		wb_path(lif, leaf_idx);

		/*
			CIRCUIT ORAM DETERMINISTIC EVICTION
		*/
		evict(2*access_counter);
		evict(2*access_counter + 1);

		// increment the access counter
		++access_counter;
	}

	void circuit_oram::access_r(block_id bid, leaf_id lif, std::uint8_t *data_out)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		leaf_idx_split = fetch_path(lif);

		fetched->bid = DUMMY;

		// search for the requested block by traversing the bucket sequence from root to leaf
		for(int i = 0; i <= L; i++)
			for(unsigned int j = 0; j < Z; j++)
			{
				block_id fpbid = fetched_path[Z*i + j].bid;
				swap(fpbid == bid, _fetched, (std::uint8_t*) &fetched_path[Z*i + j], block_size);
			}

		// search for the requested element by traversing the buckets in the stash
		// -- all of them, in order to avoid leakage in the number of entries in the stash
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(bid == sbid, _fetched, (std::uint8_t*) &stash[i], block_size);
		}

		std::memcpy(data_out, fetched->payload, B);
	}

	void circuit_oram::access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		// build the block to write!
		fetched->bid = bid;
		fetched->lid = next_lif;
		std::memcpy(fetched->payload, data_in, B);

		// evict the created block to the stash
		bool already_evicted = false;
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t*) &stash[i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}

		// if this fails, it means that the stash overflowed and you cannot insert any new element!
		assert(already_evicted);

		wb_path(lif, leaf_idx_split);

		/*
			CIRCUIT ORAM DETERMINISTIC EVICTION
		*/
		evict(2*access_counter);
		evict(2*access_counter + 1);

		// increment the access counter
		++access_counter;
	}

	void circuit_oram::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		// build the block to write!
		fetched->bid = bid;
		fetched->lid = next_lif;
		std::memcpy(fetched->payload, data_in, B);

		// evict the created block to the stash
		bool already_evicted = false;
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t*) &stash[i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}

		assert(already_evicted);

		evict(2*access_counter);
		evict(2*access_counter + 1);

		++access_counter;
	}

}
