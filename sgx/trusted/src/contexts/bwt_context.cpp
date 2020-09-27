#include "contexts/bwt_context.h"

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "sgx_wrapper_t.h"

#include "substring/vbwt.hpp"

void bwt_context_t::init()
{
	load_meta();
	load_c();
	load_index(8);
}

void bwt_context_t::load_meta()
{
	std::uint64_t meta[3];
	ocall_get_blob(fb, (std::uint8_t*) meta, 3 * sizeof(std::uint64_t), -1);
	ippsAES_GCMProcessAAD((std::uint8_t*) meta, 3 * sizeof(std::uint64_t), cc);

	sample_rate = meta[0];
	no_bits = meta[1];
	sample_size = meta[2];
}

void bwt_context_t::load_c()
{
	C = new std::uint32_t[alpha+1];
	std::uint32_t *C_enc = new std::uint32_t[alpha+1];

	ocall_get_blob(fb, (std::uint8_t*) C_enc, sizeof(std::int32_t) * (alpha + 1), -1);
	ippsAES_GCMDecrypt((std::uint8_t*) C_enc, (std::uint8_t*) C, sizeof(std::int32_t) * (alpha + 1), cc);

	delete[] C_enc;
}

void bwt_context_t::load_index(std::size_t buffer_size)
{
	std::uint8_t *enc_buff = new std::uint8_t[buffer_size * sample_size];
	std::uint8_t *dec_buff = new std::uint8_t[buffer_size * sample_size];

	std::size_t no_samples = (N + 1) / sample_rate + ((N + 1) % sample_rate == 0 ? 0 : 1);

	obl::block_id idx = 0;
	index = new obl::recursive_oram(no_samples, sample_size, csize, allocator);

	while(no_samples != 0)
	{
		std::size_t fetch_size = no_samples > buffer_size ? buffer_size : no_samples;
		std::size_t fetch_size_bytes = fetch_size * sample_size;

		ocall_get_blob(fb, enc_buff, fetch_size_bytes, -1);
		ippsAES_GCMDecrypt(enc_buff, dec_buff, fetch_size_bytes, cc);

		std::uint8_t *current_sample = dec_buff;

		for(unsigned int i = 0; i < fetch_size; i++)
		{
			// enc_buf is a real placeholder
			index->access(idx, current_sample, enc_buff);
			current_sample += sample_size;
			++idx;
		}

		no_samples -= fetch_size;
	}

	delete[] enc_buff;
	delete[] dec_buff;
}

void bwt_context_t::query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end)
{
	vbwt_query<std::uint32_t, unsigned char>(index, C, sample_rate, sample_size, no_bits, alpha, q, len, &start, &end);
}
