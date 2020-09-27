#include "n_bwt_context.h"

#include <cstdint>
#include <cstring>

#include "nbwt.hpp"
#include "nucleotide.hpp"

void n_bwt_context_t::init()
{
	load_c();
	load_index(32);
}

void n_bwt_context_t::load_c()
{
	C = new std::int32_t[alpha];
	std::uint32_t *C_enc = new std::uint32_t[alpha];

	fb.sgetn((char*) C_enc, sizeof(std::int32_t) * alpha);
	ippsAES_GCMDecrypt((std::uint8_t*) C_enc, (std::uint8_t*) C, sizeof(std::int32_t) * alpha, cc);

	delete[] C_enc;
}

void n_bwt_context_t::load_index(std::size_t buffer_size)
{
	std::uint32_t *enc_buff, *dec_buff;

	// init encryption buffer
	enc_buff = new std::uint32_t[buffer_size];
	dec_buff = new std::uint32_t[buffer_size];

	// find maximum frequency of a character
	max_occ = -1;
	for(unsigned int i = 0; i < alpha; i++)
	{
		int tmp = C[i];
		max_occ = tmp >= max_occ ? tmp : max_occ;
	}

	// allocate index
	index = new std::int32_t*[alpha];

	for(unsigned int i = 0; i < alpha; i++)
		index[i] = new std::int32_t[C[i]];

	for(unsigned int a = 0; a < alpha; a++)
	{
		std::size_t rem = max_occ;
		std::size_t rem_real = C[a];
		std::uint8_t *idx_buff = (std::uint8_t*) index[a];

		while(rem != 0)
		{
			std::size_t current_load = rem > buffer_size ? buffer_size : rem;
			std::size_t real_load = rem_real > current_load ? current_load : rem_real;

			fb.sgetn((char*) enc_buff, current_load * sizeof(std::int32_t));
			ippsAES_GCMDecrypt((std::uint8_t*) enc_buff, (std::uint8_t*) dec_buff, current_load * sizeof(std::int32_t), cc);

			if(rem_real != 0)
			{
				std::memcpy(idx_buff, dec_buff, real_load * sizeof(std::int32_t));
				idx_buff += real_load * sizeof(std::int32_t);
			}

			rem_real -= real_load;
			rem -= current_load;
		}
	}

	delete[] enc_buff;
	delete[] dec_buff;
}

void n_bwt_context_t::query(unsigned char *q, int qlen, std::int32_t &start, std::int32_t &end)
{
	nbwt_query<std::int32_t, unsigned char>(index, C, q, qlen, &start, &end);
}
