#ifndef LINEAR_ORAM_H
#define LINEAR_ORAM_H

#include <cstddef>
#include <cstdint>

#include "obl/oram.h"
#include "obl/flexible_array.hpp"

namespace obl {
	
	struct linear_block_t;
	
	class linear_oram: public tree_oram {
	private:
		typedef linear_block_t block_t;
		
		// stash
		flexible_array<block_t> stash;
		unsigned int S; // stash size
		std::size_t block_size;
		
	public:
		linear_oram(std::size_t N, std::size_t B);
		~linear_oram() { }
		
		void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif);
		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out);
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif);
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	// no factory for linear
	// this ORAM is meant to be a fallback when instantiating ORAMs whose
	// stash size >= N!

}

#endif
