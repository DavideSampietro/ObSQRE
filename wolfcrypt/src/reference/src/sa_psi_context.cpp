#include "sa_psi_context.h"

#include <cstdint>
#include <cstring>

#include "sapsi.hpp"
#include "nucleotide.hpp"

void sa_psi_context_t::init()
{
	load_c();
	load_index(32);
}

void sa_psi_context_t::load_c()
{
	C = new std::int32_t[alpha+1];
	std::uint32_t *C_enc = new std::uint32_t[alpha+1];

	fb.sgetn((char*) C_enc, sizeof(std::int32_t) * (alpha + 1));
	ippsAES_GCMDecrypt((std::uint8_t*) C_enc, (std::uint8_t*) C, sizeof(std::int32_t) * (alpha + 1), cc);

	delete[] C_enc;
}

void sa_psi_context_t::load_index(size_t buffer_size)
{
	std::uint32_t *enc_buff;
	std::size_t rem = N + 1;

	// init encryption
	enc_buff = new std::uint32_t[buffer_size];

	index = new std::int32_t[N + 1];
	std::uint8_t *load_buff = (std::uint8_t*) index;

	while(rem != 0)
	{
		std::size_t current_load = rem > buffer_size ? buffer_size : rem;

		fb.sgetn((char*) enc_buff, current_load * sizeof(std::int32_t));
		ippsAES_GCMDecrypt((std::uint8_t*) enc_buff, load_buff, current_load * sizeof(std::int32_t), cc);

		load_buff += current_load * sizeof(std::int32_t);
		rem -= current_load;
	}

	delete[] enc_buff;
}

void sa_psi_context_t::query(unsigned char *q, int qlen, std::int32_t &start, std::int32_t &end)
{
	sapsi_query<std::int32_t, unsigned char>(index, N, C, q, qlen, &start, &end);
}
