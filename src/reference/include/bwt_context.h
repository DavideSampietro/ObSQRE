#ifndef BWT_CONTEXT_H
#define BWT_CONTEXT_H

#include <fstream>
#include <cstdint>
#include "ref_context.h"

struct bwt_context_t: public ref_context_t {
	void *index;

	std::uint64_t sample_rate;
	std::uint64_t no_bits;
	std::uint64_t sample_size;

	bwt_context_t(std::filebuf &fb, size_t N, unsigned int alpha, IppsAES_GCMState *cc):
		ref_context_t(fb, N, alpha, cc)
	{
		index = nullptr;
	}

	void init();
	void load_meta();
	void load_c();
	void load_index(std::size_t buffer_size);

	void query(unsigned char *q, int qlen, std::int32_t &start, std::int32_t &end);

	~bwt_context_t() {
		if(index != nullptr)
			std::free(index);
	}
};

#endif // BWT_CONTEXT_H
