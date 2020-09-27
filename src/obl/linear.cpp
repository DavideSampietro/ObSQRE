#include "obl/linear.h"
#include "obl/primitives.h"

#define DUMMY -1

#include "obl/oassert.h"

namespace obl {
	
	struct linear_block_t {
		block_id bid;
		std::uint8_t payload[];
	};
	
	linear_oram::linear_oram(std::size_t N, std::size_t B): tree_oram(N, B, 0)
	{
		block_size = sizeof(block_t) + this->B;
		S = N;
		
		stash.set_entry_size(block_size);
		stash.reserve(S);

		for(unsigned int i = 0; i < S; i++)
			stash[i].bid = DUMMY;
	}
	
	void linear_oram::access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		fetched->bid = DUMMY;

		// single scan over the stash
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(sbid == bid, (std::uint8_t*) &stash[i], _fetched, block_size);
		}
		
		std::memcpy(data_out, fetched->payload, B);

		// assemble block to write into the stash
		if(data_in != nullptr)
			std::memcpy(fetched->payload, data_in, B);

		fetched->bid = bid;

		// evict the created block to the stash
		bool already_evicted = false;
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(sbid == DUMMY, _fetched, (std::uint8_t*) &stash[i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}

		assert(already_evicted);
	}

	void linear_oram::access_r(block_id bid, leaf_id lif, std::uint8_t *data_out)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		fetched->bid = DUMMY;

		// single scan over the stash
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(sbid == bid, (std::uint8_t*) &stash[i], _fetched, block_size);
		}

		std::memcpy(data_out, fetched->payload, B);
	}

	void linear_oram::access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		// build the block to write!
		fetched->bid = bid;
		std::memcpy(fetched->payload, data_in, B);

		// evict the created block to the stash
		bool already_evicted = false;
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(sbid == DUMMY, _fetched, (std::uint8_t*) &stash[i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}

		// if this fails, it means that the stash overflowed and you cannot insert any new element!
		assert(fetched->bid == DUMMY);
	}

	void linear_oram::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t*) _fetched;

		// build the block to write!
		fetched->bid = bid;
		std::memcpy(fetched->payload, data_in, B);

		// evict the created block to the stash
		for(unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(sbid == DUMMY, _fetched, (std::uint8_t*) &stash[i], block_size);
		}

		assert(fetched->bid == DUMMY);
	}
	
}
