#ifndef N_BWT_CONTEXT_H
#define N_BWT_CONTEXT_H

#include <cstdint>
#include <fstream>
#include "ref_context.h"

struct n_bwt_context_t: public ref_context_t {
	std::int32_t **index;

	int max_occ;

	n_bwt_context_t(std::filebuf &fb, size_t N, unsigned int alpha, IppsAES_GCMState *cc):
		ref_context_t(fb, N, alpha, cc)
	{
		index = nullptr;
	}

	void init();
	void load_c();
	void load_index(std::size_t buffer_size);

	void query(unsigned char *q, int qlen, std::int32_t &start, std::int32_t &end);

	~n_bwt_context_t() {
		if(index != nullptr)
		{
			for(unsigned int i = 0; i < alpha; i++)
				delete[] index[i];

			delete[] index;
		}
	}
};

#endif // N_BWT_CONTEXT_H
