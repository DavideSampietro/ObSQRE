#include "contexts/sa_psi_context.h"

#include <cstdint>
#include <cstring>
#include "sgx_wrapper_t.h"

#include "substring/s3psi.hpp"

void sa_psi_context_t::init()
{
	load_c();
	load_index(65536);
}

void sa_psi_context_t::load_c()
{
	C = new std::uint32_t[alpha+1];
	std::uint32_t *C_enc = new std::uint32_t[alpha+1];

	ocall_get_blob(fb, (std::uint8_t*) C_enc, sizeof(std::int32_t) * (alpha + 1), -1);
	ippsAES_GCMDecrypt((std::uint8_t*) C_enc, (std::uint8_t*) C, sizeof(std::int32_t) * (alpha + 1), cc);

	delete[] C_enc;
}

void sa_psi_context_t::load_index(size_t buffer_size)
{
	std::uint32_t *enc_buff, *dec_buff;
	int L;
	std::size_t lvl_size = 1;
	std::size_t rem = N + 1;

	// init encryption
	enc_buff = new std::uint32_t[buffer_size];
	dec_buff = new std::uint32_t[buffer_size];

	// init ccbst
	index = new obl::ods::cbbst(N + 1, sizeof(std::uint32_t), allocator);
	index->init_loading();
	L = index->get_L();

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

	index->finalize_loading();

	delete[] enc_buff;
	delete[] dec_buff;
}

void sa_psi_context_t::query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end)
{
	sapsi_query<std::uint32_t, unsigned char>(index, C, alpha, q, len, &start, &end);
}
