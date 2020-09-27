#include "contexts/n_bwt_context_b.h"

#include "sgx_wrapper_t.h"
#include <cstdint>

void n_bwt_context_b_t::fill_level_size(std::size_t *lvl)
{
	std::int32_t *Crem = new std::int32_t[alpha];
	std::size_t lvl_size = 1;

	std::memcpy(Crem, C, sizeof(std::int32_t) * alpha);

	for(int l = 0; l < L; l++)
	{
		std::size_t acc = 0;

		for(unsigned int a = 0; a < alpha; a++)
		{
			std::size_t tmp = (std::size_t)Crem[a] > lvl_size ? lvl_size : Crem[a];
			Crem[a] -= tmp;
			acc += tmp;
		}

		lvl[l] = acc;
		lvl_size <<= 1;
	}

	delete[] Crem;
}

void n_bwt_context_b_t::fill_levels(std::size_t buffer_size)
{
	std::uint32_t *enc_buff, *dec_buff;

	// init encryption
	enc_buff = new std::uint32_t[buffer_size];
	dec_buff = new std::uint32_t[buffer_size];

	for(unsigned int a = 0; a < alpha; a++)
	{
		index->select_subtree(a);
		std::size_t rem = max_occ;
		std::size_t Crem = C[a];
		std::size_t lvl_size = 1;

		for(int l = 0; l < L; l++)
		{
			std::size_t lvl_amount = lvl_size < rem ? lvl_size : rem;
			std::size_t valid_amount = lvl_size < Crem ? lvl_size : Crem;
			rem -= lvl_amount;
			Crem -= valid_amount;
			lvl_size <<= 1;

			index->init_level(l);

			while(lvl_amount != 0)
			{
				std::size_t current_load = lvl_amount > buffer_size ? buffer_size : lvl_amount;
				std::size_t current_valid = valid_amount > buffer_size ? buffer_size : valid_amount;
				lvl_amount -= current_load;
				valid_amount -= current_valid;

				ocall_get_blob(fb, (std::uint8_t*) enc_buff, current_load * sizeof(std::int32_t), -1);
				ippsAES_GCMDecrypt((std::uint8_t*) enc_buff, (std::uint8_t*) dec_buff, current_load * sizeof(std::int32_t), cc);

				index->load_values_with_dummies((std::uint8_t*) dec_buff, current_load, current_valid);
			}
		}
	}

	delete[] enc_buff;
	delete[] dec_buff;
}
