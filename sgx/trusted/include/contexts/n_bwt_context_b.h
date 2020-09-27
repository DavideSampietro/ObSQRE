#ifndef N_BWT_CONTEXT_ALT_H
#define N_BWT_CONTEXT_ALT_H

#include "contexts/n_bwt_context.h"

struct n_bwt_context_b_t: public n_bwt_context_t {

	n_bwt_context_b_t(void *fb, size_t N, unsigned int alpha, obl::oram_factory *allocator, IppsAES_GCMState *cc):
		n_bwt_context_t(fb, N, alpha, allocator, cc) { }

	~n_bwt_context_b_t() { }

	// alternate loaders
	virtual void fill_level_size(std::size_t *lvl);
	virtual void fill_levels(std::size_t buffer_size);
};

#endif
