#ifndef ORAM_H
#define ORAM_H

#include <cstdint>
#include <cstddef>

std::uint64_t next_two_power(std::uint64_t v);

namespace obl {

	typedef std::int32_t leaf_id;
	typedef std::int32_t block_id;

	class tree_oram {
	protected:
		// sizing of the ORAM
		std::size_t N;
		std::size_t capacity;
		int L;

		std::uint64_t access_counter;

		// sizing of the blocks/buckets
		unsigned int Z; // number of blocks/records inside each bucket
		std::size_t B; // number of bytes for each block in the ORAM

	public:
		tree_oram(std::size_t N, std::size_t B, unsigned int Z);
		virtual ~tree_oram() {};
		
		std::size_t get_N() const {
			return N;
		}

		// pure abstract methods to implement in derived classes

		// access function
		virtual void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif) = 0;

		// split fetch and eviction phases of the access method
		virtual void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out) = 0;
		virtual void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif) = 0;

		// only write block into the stash and perfom evictions
		virtual void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif) = 0;
	};

	// used to implement the abstract factory design pattern
	class oram_factory {
	public:
		virtual tree_oram* spawn_oram(std::size_t N, std::size_t B) = 0;
		virtual ~oram_factory() { };
	};

}

#endif // ORAM_H
