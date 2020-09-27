#ifndef CIRCUIT_ORAM_H
#define CIRCUIT_ORAM_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/flexible_array.hpp"

#include <cstdint>
#include <cstddef>

#include <wolfcrypt/aes.h>

#ifdef SGX_ENCLAVE_ENABLED
	#include "obl/sgx_host_allocator.hpp"
#endif

namespace obl
{
	// forward declarations
	struct circuit_block_t;
	struct circuit_bucket_t;

	class circuit_oram: public tree_oram
	{
	private:
		typedef circuit_block_t block_t;
		typedef circuit_bucket_t bucket_t;
	
		std::size_t block_size; // aligned block size
		std::size_t bucket_size; // aligned/padded encrypted bucket size

		// stash
		flexible_array<block_t> stash;
		unsigned int S; // stash size

		// content of the ORAM
		#ifdef SGX_ENCLAVE_ENABLED
			flexible_array<bucket_t, sgx_host_allocator> tree;
		#else
			flexible_array<bucket_t> tree;
		#endif

		// fetched_path
		flexible_array<block_t> fetched_path;

		// crypto stuff
		void *_crypt_buffer;
		Aes *crypt_handle;
		obl_aes_gcm_128bit_tag_t merkle_root;
		// this is used to authenticate and rebuild the merkle tree
		auth_data_t *adata;

		// arrays needed for eviction
		std::int64_t *longest_jump_down, *closest_src_bucket, *next_dst_bucket;

		// private methods
		void init();

		std::int64_t fetch_path(leaf_id path);
		void wb_path(obl::leaf_id path, std::int64_t leaf);

		// circuit ORAM eviction preprocessing
		void evict(leaf_id path); // wrapper
		void deepest(leaf_id path);
		void target(); // leaf idx in the binary heap
		void eviction(leaf_id path);

		// helper methods
		bool has_free_block(block_t *bl, int len);
		std::int64_t get_max_depth_bucket(block_t *bl, int len, leaf_id path);

		// split operation variables
		std::int64_t leaf_idx_split;

	public:
		circuit_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S);
		~circuit_oram();

		void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif);

		// split fetch and eviction phases of the access method
		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out);
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif);

		// only write block into the stash and perfom evictions
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class coram_factory: public oram_factory {
	private:
		unsigned int Z, S;
	public:
		coram_factory(unsigned int Z, unsigned int S) {
			this->Z = Z;
			this->S = S;
		}

		tree_oram* spawn_oram(std::size_t N, std::size_t B) {
			return new circuit_oram(N, B, Z, S);
		}
	};

}

#endif // CIRCUIT_ORAM_H
