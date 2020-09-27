#ifndef N_BWT_CONTEXT_H
#define N_BWT_CONTEXT_H

#include "contexts/subtol_context.h"
#include "cbbst.h"

struct n_bwt_context_t: public subtol_context_t {
	obl::ods::cbbst *index;

	std::size_t max_occ;
	int L;

	n_bwt_context_t(void *fb, size_t N, unsigned int alpha, obl::oram_factory *allocator, IppsAES_GCMState *cc):
		subtol_context_t(fb, N, alpha, allocator, cc)
	{
		index = nullptr;
	}

	void init();
	void load_c();
	void load_index(std::size_t buffer_size);

	virtual void fill_level_size(std::size_t *lvl);
	virtual void fill_levels(std::size_t buffer_size);

	void query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end);

	virtual ~n_bwt_context_t() {
		if(index != nullptr)
			delete index;
	}
};

#endif // N_BWT_CONTEXT_H
