#ifndef SO_RING_ORAM_H
#define SO_RING_ORAM_H

#include "obl/oram.h"
#include "obl/flexible_array.hpp"
#include "obl/types.h"

#include <cstring>
#include <cstdint>
#include <cstddef>

#include <list>
#include <memory>
#include <utility>

#include "sgx_tcrypto.h"

#ifdef SGX_ENCLAVE_ENABLED
	#include "sgx_host_allocator.hpp"
#endif

namespace obl
{
	struct so_ring_block_t;
	struct so_ring_bucket_t;

	class so_ring_oram: public tree_oram
	{
	private:
		typedef so_ring_block_t block_t;
		typedef so_ring_bucket_t bucket_t;
	
		std::uint64_t det_eviction; // used to implement Gentry's deterministic eviction procedure
		unsigned int A; // eviction rate

		// sizing of the blocks/buckets
		unsigned int S;
		std::size_t block_size; // aligned block size
		std::size_t metadata_size;
		std::size_t bucket_size; // aligned/padded encrypted bucket size

		// content of the ORAM
		#ifdef SGX_ENCLAVE_ENABLED
			flexible_array<bucket_t, sgx_host_allocator> tree;
		#else
			flexible_array<bucket_t> tree;
		#endif

		// eviction buffers
		flexible_array<block_t> eviction_path;
		block_id *eviction_meta;
		bool *to_reshuffle;

		// stash
		unsigned int stash_size;
		std::list<std::pair<block_id, std::unique_ptr<block_t>>> stash;

		// crypto stuff
		sgx_aes_ctr_128bit_key_t master_key;

		// private methods
		void init();
		int pseudo_xor_trick(block_id bid, leaf_id path, std::uint8_t *out, bool &found_in_tree);

		void early_reshuffle(leaf_id path);

		void evict_path(leaf_id path);
		void eviction_procedure(leaf_id path);
		void wb_path(leaf_id path);

		// assume dst to be Z+S and src to be Z
		void intersperse(block_t *dst, block_t *src, block_id *dst_meta, block_id *src_meta);

		/* The Art of Computer Programming vol. 2
			Knuth sampling (aka Algorithm S) */
		void knuth_alg_s(std::uint64_t &selected, std::uint64_t candidates, int n, int N);

	public:
		so_ring_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int A, unsigned int stash_size);
		~so_ring_oram();

		void access(block_id bid, leaf_id lid, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif);

		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out);
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif);

		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class so_roram_factory: public oram_factory {
	private:
		unsigned int Z, S, stash_size, A;
	public:
		so_roram_factory(unsigned int Z, unsigned int S, unsigned int A, unsigned int stash_size) {
			this->Z = Z;
			this->S = S;
			this->A = A;
			this->stash_size = stash_size;
		}

		tree_oram* spawn_oram(std::size_t N, std::size_t B) {
			return new so_ring_oram(N, B, Z, S, A, stash_size);
		}
	};

}

#endif // SO_RING_ORAM_H
