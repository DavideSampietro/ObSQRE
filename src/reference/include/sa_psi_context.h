#ifndef SA_PSI_CONTEXT_H
#define SA_PSI_CONTEXT_H

#include <cstdint>
#include <fstream>
#include "ref_context.h"

struct sa_psi_context_t: public ref_context_t {
	std::int32_t *index;

	sa_psi_context_t(std::filebuf &fb, size_t N, unsigned int alpha, IppsAES_GCMState *cc):
		ref_context_t(fb, N, alpha, cc)
	{
		index = nullptr;
	}

	void init();
	void load_c();
	void load_index(std::size_t buffer_size);

	void query(unsigned char *q, int qlen, std::int32_t &start, std::int32_t &end);

	~sa_psi_context_t() {
		if(index != nullptr)
			delete[] index;
	}
};

#endif // SA_PSI_CONTEXT_H
