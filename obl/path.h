#ifndef PATH_ORAM_H
#define PATH_ORAM_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/flexible_array.hpp"

#include <cstdint>
#include <cstddef>

#include <wolfcrypt/aes.h>

#ifdef SGX_ENCLAVE_ENABLED
	#include "obl/sgx_host_allocator.hpp"
#endif

namespace obl {
	struct path_block_t;
	struct path_bucket_t;

	class path_oram: public tree_oram
	{
	private:
		typedef path_block_t block_t;
		typedef path_bucket_t bucket_t;
	
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

		// private methods
		void init();

		std::int64_t fetch_path(leaf_id path);
		void wb_path(obl::leaf_id path, std::int64_t leaf);

		// split operation variables
		std::int64_t leaf_idx_split;

	public:
		path_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S);
		~path_oram();

		void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif);

		// cannot apply stash optimization to these two functions
		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out);
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif);

		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class path_factory: public oram_factory {
	private:
		unsigned int Z, S;
	public:
		path_factory(unsigned int Z, unsigned int S) {
			this->Z = Z;
			this->S = S;
		}

		tree_oram* spawn_oram(std::size_t N, std::size_t B) {
			// since path oram has the largest stash size, improve it
			unsigned int real_S = N < S ? N : S;
			return new path_oram(N, B, Z, real_S);
		}
	};
}

#endif // PATH_ORAM_H
