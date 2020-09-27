#include "contexts/subtol_context.h"
#include "sgx_wrapper_t.h"

static const int buffer_size = 512;

void subtol_context_t::load_sa(unsigned int csize, unsigned int sa_block)
{
	std::int32_t idx;
	std::size_t rec_oram_block_size = sa_block * sizeof(std::int32_t);
	std::size_t rec_oram_blocks = (N + 1) / sa_block + ((N + 1) % sa_block ? 1 : 0);

	std::int32_t *enc_buff = new std::int32_t[sa_block * buffer_size];
	std::int32_t *dec_buff = new std::int32_t[sa_block];

	suffix_array = new obl::recursive_oram(rec_oram_blocks, rec_oram_block_size, csize, allocator);
	sa_bundle_size = sa_block;
	sa_total_blocks = rec_oram_blocks;
	current_start_index = 0;

	// all but last and possibly incomplete block
	--rec_oram_blocks;
	idx = 0;

	while(rec_oram_blocks != 0)
	{
		std::size_t curr_blocks = rec_oram_blocks > buffer_size ? buffer_size : rec_oram_blocks;

		ocall_get_blob(fb, (std::uint8_t*) enc_buff, curr_blocks * rec_oram_block_size, -1);

		for(unsigned int i = 0; i < curr_blocks; i++)
		{
			ippsAES_GCMDecrypt((std::uint8_t*) &enc_buff[i * sa_block], (std::uint8_t*) dec_buff, rec_oram_block_size, cc);
			suffix_array->access(idx, (std::uint8_t*) dec_buff, (std::uint8_t*) enc_buff); // enc_buff is a placeholder!
			++idx;
		}

		rec_oram_blocks -= curr_blocks;
	}

	// manage remainder
	std::size_t rem = (N + 1) % sa_block;
	// if rem == 0, I discarded a full block
	if(rem == 0)
		rem = sa_block;

	ocall_get_blob(fb, (std::uint8_t*) enc_buff, rem * sizeof(std::int32_t), -1);
	ippsAES_GCMDecrypt((std::uint8_t*) enc_buff, (std::uint8_t*) dec_buff, rem * sizeof(std::int32_t), cc);
	suffix_array->access(idx, (std::uint8_t*) dec_buff, (std::uint8_t*) enc_buff); // enc_buff is a placeholder!

	delete[] enc_buff;
	delete[] dec_buff;
}

void subtol_context_t::fetch_sa(std::int32_t *sa_chunk)
{
	if(suffix_array != nullptr)
	{
		obl::block_id sa_bid = (current_start_index / sa_bundle_size) % sa_total_blocks;
		current_start_index += sa_bundle_size;
		suffix_array->access(sa_bid, nullptr, (std::uint8_t*) sa_chunk);
	}
}
