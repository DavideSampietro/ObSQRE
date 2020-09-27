#include "obl/so_path.h"
#include "obl/utils.h"
#include "obl/primitives.h"

#include "obl/oassert.h"

#include <cstdlib>
#include <cstring>

#define DUMMY -1

namespace obl {

	struct so_path_block_t {
		block_id bid;
		leaf_id lid;
		std::uint8_t payload[];
	};

	struct so_path_bucket_t {
		obl_aes_gcm_128bit_iv_t iv;
		bool reach_l, reach_r;
		obl_aes_gcm_128bit_tag_t mac __attribute__ ((aligned(8)));
		// since payload is going to be a multiple of 16 bytes, the struct will be memory aligned!
		uint8_t payload[];
	};

	so_path_oram::so_path_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S): tree_oram(N, B, Z)
	{
		// align structs to 8-bytes
		block_size = pad_bytes(sizeof(block_t) + this->B, 8);
		bucket_size = pad_bytes(sizeof(bucket_t) + this->Z * block_size, 8);

		// stash allocation
		this->S = S;

		// ORAM tree allocation
		tree.set_entry_size(bucket_size);
		tree.reserve(capacity);

		// fetched_path allocation
		fetched_path.set_entry_size(block_size);
		fetched_path.reserve((L+1) * this->Z);

		// allocate data struct for integrity checking
		adata = new auth_data_t[L+1];

		init();
	}

	so_path_oram::~so_path_oram()
	{
		std::memset(_crypt_buffer, 0x00, sizeof(Aes) + 16);

		std::memset(&fetched_path[0], 0x00, block_size * (L+1) * Z);

		free(_crypt_buffer);
		delete[] adata;
	}

	void so_path_oram::init()
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

	std::int64_t so_path_oram::fetch_path(leaf_id path)
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

	void so_path_oram::wb_path(leaf_id path, std::int64_t leaf)
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

	void so_path_oram::access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		std::int64_t leaf_idx = fetch_path(lif);

		fetched->bid = DUMMY;

		bool found_in_path = false;
		// search for the block in the fetched path
		// if found, replace with dummy block
		for(int i = 0; i <= L && !found_in_path; i++)
		{
			int offset = Z * i;
			
			for(unsigned int j = 0; j < Z; j++)
				if(fetched_path[offset + j].bid == bid)
				{
					std::memcpy(_fetched, (std::uint8_t*) &fetched_path[Z*i + j], block_size);
					fetched_path[offset + j].bid = DUMMY;
					found_in_path = true;
					
					// equivalent to break but more elegant
					j = Z;
				}
		}

		// backup data read from the fetched path (may be overwritten later on by data-in)
		if(found_in_path)
			std::memcpy(data_out, fetched->payload, B);

		// eviction
		if(found_in_path)
		{
			std::unique_ptr<block_t> to_append((block_t*) new std::uint8_t[block_size]);
			
			if(data_in == nullptr)
				std::memcpy(to_append->payload, fetched->payload, B);
			else
				std::memcpy(to_append->payload, data_in, B);
			
			to_append->bid = bid;
			to_append->lid = next_lif;
			
			stash.push_back(std::move(to_append));
		}
		else
		{
			bool found_in_stash = false;
			
			for(auto it = stash.begin(); it != stash.end() && !found_in_stash; ++it)
				if((*it)->bid == bid)
				{
					found_in_stash = true;
					std::memcpy(data_out, (*it)->payload, B);
					(*it)->lid = next_lif;
				
					if(data_in != nullptr)
						std::memcpy((*it)->payload, fetched->payload, B);
				}
			
			if(!found_in_stash)
			{
				std::unique_ptr<block_t> to_append((block_t*) new std::uint8_t[block_size]);
			
				if(data_in == nullptr)
					std::memcpy(to_append->payload, fetched->payload, B);
				else
					std::memcpy(to_append->payload, data_in, B);
			
				to_append->bid = bid;
				to_append->lid = next_lif;
			
				stash.push_back(std::move(to_append));
			}
		}

		// perform in-place eviction of the current path
		for(int i = L-1; i >= 0; i--) // for every bucket in the fetched path, from leaf to root
		{
			for(unsigned int z1 = 0; z1 < Z; z1++) // for every block in the source bucket
			{
				int under_ev = i*Z + z1;
				
				if(fetched_path[under_ev].bid != DUMMY) // skip this block if dummy
				{
				
					std::int64_t maxd = get_max_depth(fetched_path[under_ev].lid, lif, L);

					for(int j = maxd; j > i; j--) // for every bucket from the deepest to the one right under [i]
					{
						int offset = j*Z;

						for(unsigned int z2 = 0; z2 < Z; z2++) // for every block in the target bucket
							if(fetched_path[offset + z2].bid == DUMMY)
							{
								std::memcpy((std::uint8_t*) &fetched_path[offset + z2], (std::uint8_t*) &fetched_path[under_ev], block_size);
								fetched_path[under_ev].bid = DUMMY;
								z2 = Z;
								j = i;
							}
					}
				}
			}
		}

		// perform eviction of the stash
		for(auto it = stash.begin(); it != stash.end(); ++it) // for every block in the stash
		{
			std::int64_t maxd = get_max_depth((*it)->lid, lif, L);
			bool evicted = false;

			for(int i = maxd; i >= 0 && !evicted; i--) // for every bucket in the path (in reverse order)
			{
				int offset = i*Z;

				for(unsigned int j = 0; j < Z; j++) // for every block in a bucket
					if(fetched_path[offset + j].bid == DUMMY)
					{
						std::memcpy((std::uint8_t*) &fetched_path[offset + j], (std::uint8_t*) it->get(), block_size);
						evicted = true;
						j = Z;
						
						auto it2 = stash.erase(it);
						it2--;
						it = it2;
					}
			}
		}
		
		assert(stash.size() <= S);

		wb_path(lif, leaf_idx);
		++access_counter;
	}

	void so_path_oram::access_r(block_id bid, leaf_id lif, std::uint8_t *data_out)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		leaf_idx_split = fetch_path(lif);

		fetched->bid = DUMMY;

		bool found_in_path = false;
		for(int i = 0; i <= L && !found_in_path; i++)
		{
			int offset = Z * i;
			
			for(unsigned int j = 0; j < Z; j++)
				if(fetched_path[offset + j].bid == bid)
				{
					std::memcpy(_fetched, (std::uint8_t*) &fetched_path[Z*i + j], block_size);
					fetched_path[offset + j].bid = DUMMY;
					found_in_path = true;
					
					// equivalent to break but more elegant
					j = Z;
				}
		}

		if(!found_in_path)
			for(auto it = stash.begin(); it != stash.end(); ++it)
				if((*it)->bid == bid)
				{
					std::memcpy(fetched->payload, (*it)->payload, B);
					stash.erase(it);
					break;
				}

		std::memcpy(data_out, fetched->payload, B);
	}

	void so_path_oram::access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif)
	{
		// append block to the stash
		std::unique_ptr<block_t> to_append((block_t*) new std::uint8_t[block_size]);
		std::memcpy(to_append->payload, data_in, B);
		to_append->bid = bid;
		to_append->lid = next_lif;
		stash.push_back(std::move(to_append));

		// perform in-place eviction of the current path
		for(int i = L-1; i >= 0; i--) // for every bucket in the fetched path, from leaf to root
		{

			for(unsigned int z1 = 0; z1 < Z; z1++) // for every block in the source bucket
			{
				int under_ev = i*Z + z1;
				if(fetched_path[under_ev].bid != DUMMY) // skip this block if dummy
				{
					std::int64_t maxd = get_max_depth(fetched_path[under_ev].lid, lif, L);

					for(int j = maxd; j > i; j--) // for every bucket from the deepest to the one right under [i]
					{
						int offset = j*Z;

						for(unsigned int z2 = 0; z2 < Z; z2++) // for every block in the target bucket
							if(fetched_path[offset + z2].bid == DUMMY)
							{
								std::memcpy((std::uint8_t*) &fetched_path[offset + z2], (std::uint8_t*) &fetched_path[under_ev], block_size);
								fetched_path[under_ev].bid = DUMMY;
								z2 = Z;
								j = i;
							}
					}
				}
			}
		}

		// perform eviction of the stash
		for(auto it = stash.begin(); it != stash.end(); ++it) // for every block in the stash
		{
			std::int64_t maxd = get_max_depth((*it)->lid, lif, L);
			bool evicted = false;

			for(int i = maxd; i >= 0 && !evicted; i--) // for every bucket in the path (in reverse order)
			{
				int offset = i*Z;

				for(unsigned int j = 0; j < Z; j++) // for every block in a bucket
					if(fetched_path[offset + j].bid == DUMMY)
					{
						std::memcpy((std::uint8_t*) &fetched_path[offset + j], (std::uint8_t*) it->get(), block_size);
						evicted = true;
						j = Z;
						
						auto it2 = stash.erase(it);
						--it2;
						it = it2;
					}
			}
		}

		// if this fails, it means that the stash overflowed and you cannot insert any new element!
		assert(stash.size() <= S);

		wb_path(lif, leaf_idx_split);

		// increment the access counter
		++access_counter;
	}

	void so_path_oram::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
	{
		// append block to the stash
		std::unique_ptr<block_t> to_append((block_t*) new std::uint8_t[block_size]);
		std::memcpy(to_append->payload, data_in, B);
		to_append->bid = bid;
		to_append->lid = next_lif;
		stash.push_back(std::move(to_append));

		leaf_id lif;
		gen_rand((std::uint8_t*) &lif, sizeof(leaf_id));
		std::int64_t leaf_idx = fetch_path(lif);

		// perform in-place eviction of the current path
		for(int i = L-1; i >= 0; i--) // for every bucket in the fetched path, from leaf to root
		{
			for(unsigned int z1 = 0; z1 < Z; z1++) // for every block in the source bucket
			{
				int under_ev = i*Z + z1;
				if(fetched_path[under_ev].bid != DUMMY) // skip this block if dummy
				{
					std::int64_t maxd = get_max_depth(fetched_path[under_ev].lid, lif, L);

					for(int j = maxd; j > i; j--) // for every bucket from the deepest to the one right under [i]
					{
						int offset = j*Z;

						for(unsigned int z2 = 0; z2 < Z; z2++) // for every block in the target bucket
							if(fetched_path[offset + z2].bid == DUMMY)
							{
								std::memcpy((std::uint8_t*) &fetched_path[offset + z2], (std::uint8_t*) &fetched_path[under_ev], block_size);
								fetched_path[under_ev].bid = DUMMY;
								z2 = Z;
								j = i;
							}
					}
				}
			}
		}

		// perform eviction of the stash
		for(auto it = stash.begin(); it != stash.end(); ++it) // for every block in the stash
		{
			std::int64_t maxd = get_max_depth((*it)->lid, lif, L);
			bool evicted = false;

			for(int i = maxd; i >= 0 && !evicted; i--) // for every bucket in the path (in reverse order)
			{
				int offset = i*Z;

				for(unsigned int j = 0; j < Z; j++) // for every block in a bucket
					if(fetched_path[offset + j].bid == DUMMY)
					{
						std::memcpy((std::uint8_t*) &fetched_path[offset + j], (std::uint8_t*) it->get(), block_size);
						evicted = true;
						j = Z;
						
						auto it2 = stash.erase(it);
						--it2;
						it = it2;
					}
			}
		}
		
		assert(stash.size() <= S);

		wb_path(lif, leaf_idx);
	}
}
