#ifndef SA_PSI_CONTEXT_H
#define SA_PSI_CONTEXT_H

#include "contexts/subtol_context.h"
#include "cbbst.h"

struct sa_psi_context_t: public subtol_context_t {
	obl::ods::cbbst *index;

	sa_psi_context_t(void *fb, size_t N, unsigned int alpha, obl::oram_factory *allocator, IppsAES_GCMState *cc):
		subtol_context_t(fb, N, alpha, allocator, cc)
	{
		index = nullptr;
	}

	void init();
	void load_c();
	void load_index(std::size_t buffer_size);

	void query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end);

	~sa_psi_context_t() {
		if(index != nullptr)
			delete index;
	}
};

#endif // SA_PSI_CONTEXT_H
