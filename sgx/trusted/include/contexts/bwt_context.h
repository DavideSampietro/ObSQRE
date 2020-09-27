#ifndef BWT_CONTEXT_H
#define BWT_CONTEXT_H

#include <cstdint>
#include "contexts/subtol_context.h"
#include "obl/rec.h"

struct bwt_context_t: public subtol_context_t {
	unsigned int csize;
	obl::recursive_oram *index;

	std::uint64_t sample_rate;
	std::uint64_t no_bits;
	std::uint64_t sample_size;

	bwt_context_t(void *fb, size_t N, unsigned int alpha, obl::oram_factory *allocator, IppsAES_GCMState *cc, unsigned int csize):
		subtol_context_t(fb, N, alpha, allocator, cc)
	{
		this->csize = csize;
		index = nullptr;
	}

	void init();
	void load_meta();
	void load_c();
	void load_index(std::size_t buffer_size);

	void query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end);

	~bwt_context_t() {
		if(index != nullptr)
			delete index;
	}
};

#endif // BWT_CONTEXT_H
