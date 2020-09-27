#include "bwt_context.h"

#include <cstdint>
#include <cstring>

#include "nucleotide.hpp"
#include "vbwt.hpp"

void bwt_context_t::init()
{
	load_meta();
	load_c();
	load_index(5);
}

void bwt_context_t::load_meta()
{
	std::uint64_t meta[3];
	fb.sgetn((char*) meta, 3 * sizeof(std::uint64_t));
	ippsAES_GCMProcessAAD((std::uint8_t*) meta, 3 * sizeof(std::uint64_t), cc);

	sample_rate = meta[0];
	no_bits = meta[1];
	sample_size = meta[2];
}

void bwt_context_t::load_c()
{
	C = new std::int32_t[alpha+1];
	std::uint32_t *C_enc = new std::uint32_t[alpha+1];

	fb.sgetn((char*) C_enc, sizeof(std::int32_t) * (alpha + 1));
	ippsAES_GCMDecrypt((std::uint8_t*) C_enc, (std::uint8_t*) C, sizeof(std::int32_t) * (alpha + 1), cc);

	delete[] C_enc;
}

void bwt_context_t::load_index(std::size_t buffer_size)
{
	std::uint8_t *enc_buff = new std::uint8_t[buffer_size * sample_size];

	std::size_t no_samples = (N + 1) / sample_rate + ((N + 1) % sample_rate == 0 ? 0 : 1);

	index = (void*) std::malloc(sample_size * no_samples);
	std::uint8_t *idx_load = (std::uint8_t*) index;

	while(no_samples != 0)
	{
		std::size_t fetch_size = no_samples > buffer_size ? buffer_size : no_samples;
		std::size_t fetch_size_bytes = fetch_size * sample_size;

		fb.sgetn((char*) enc_buff, fetch_size_bytes);
		ippsAES_GCMDecrypt(enc_buff, idx_load, fetch_size_bytes, cc);

		no_samples -= fetch_size;
		idx_load += fetch_size_bytes;
	}

	delete[] enc_buff;
}

void bwt_context_t::query(unsigned char *q, int qlen, std::int32_t &start, std::int32_t &end)
{
	vbwt_query<std::int32_t, unsigned char>(index, C, sample_rate, sample_size, no_bits, alpha, q, qlen, &start, &end);
}
