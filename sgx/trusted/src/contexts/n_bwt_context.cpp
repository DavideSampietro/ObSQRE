#include "contexts/n_bwt_context.h"

#include "obl/oram.h"
#include "obl/primitives.h"

#include <cstdint>
#include <cstring>
#include "sgx_wrapper_t.h"

#include "substring/nbwt.hpp"

void n_bwt_context_t::init()
{
	load_c();
	load_index(65536);
}

void n_bwt_context_t::load_c()
{
	C = new std::uint32_t[alpha];
	std::uint32_t *C_enc = new std::uint32_t[alpha];

	ocall_get_blob(fb, (std::uint8_t*) C_enc, sizeof(std::int32_t) * alpha, -1);
	ippsAES_GCMDecrypt((std::uint8_t*) C_enc, (std::uint8_t*) C, sizeof(std::int32_t) * alpha, cc);

	delete[] C_enc;
}

void n_bwt_context_t::load_index(std::size_t buffer_size)
{
	// adjust real N
	// find maximum frequency of a character
	N = 0;
	max_occ = 0;
	
	for(unsigned int i = 0; i < alpha; i++)
	{
		std::size_t tmp = C[i];
		N += tmp;
		max_occ = obl::ternary_op(tmp >= max_occ, tmp, max_occ);
	}

	// establish number of levels -- dumped from alternate constructor of cbbst
	std::uint64_t max_occ_pad = next_two_power(max_occ);
	if(max_occ_pad <= 1)
		max_occ_pad = 2;

	L = __builtin_popcountll(max_occ_pad - 1);

	// spread over levels
	std::size_t *lvl_size = new std::size_t[L];

	fill_level_size(lvl_size);
	index = new obl::ods::cbbst(max_occ, sizeof(std::int32_t), allocator, lvl_size, L, alpha);

	delete[] lvl_size;

	// load data
	index->init_loading();
	fill_levels(buffer_size);
	index->finalize_loading();
}

void n_bwt_context_t::fill_levels(std::size_t buffer_size)
{
	std::uint32_t *enc_buff, *dec_buff;

	// init encryption
	enc_buff = new std::uint32_t[buffer_size];
	dec_buff = new std::uint32_t[buffer_size];

	for(unsigned int a = 0; a < alpha; a++)
	{
		index->select_subtree(a);
		std::size_t rem = max_occ;
		std::size_t lvl_size = 1;

		for(int l = 0; l < L; l++)
		{
			std::size_t lvl_amount = lvl_size < rem ? lvl_size : rem;
			rem -= lvl_amount;
			lvl_size <<= 1;

			index->init_level(l);

			while(lvl_amount != 0)
			{
				std::size_t current_load = lvl_amount > buffer_size ? buffer_size : lvl_amount;
				lvl_amount -= current_load;

				ocall_get_blob(fb, (std::uint8_t*) enc_buff, current_load * sizeof(std::int32_t), -1);
				ippsAES_GCMDecrypt((std::uint8_t*) enc_buff, (std::uint8_t*) dec_buff, current_load * sizeof(std::int32_t), cc);

				index->load_values((std::uint8_t*) dec_buff, current_load);
			}
		}
	}

	delete[] enc_buff;
	delete[] dec_buff;
}

void n_bwt_context_t::fill_level_size(std::size_t *lvl)
{
	std::size_t total = max_occ * alpha;

	std::size_t oram_size = alpha;
	for(int i = 0; i < L; i++)
	{
		std::size_t f_size = total > oram_size ? oram_size : total;

		lvl[i] = f_size;

		total -= f_size;
		oram_size <<= 1;
	}
}

void n_bwt_context_t::query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end)
{
	nbwt_query<std::uint32_t, unsigned char>(index, C, alpha, q, len, &start, &end);
}
