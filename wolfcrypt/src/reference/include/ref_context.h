#ifndef SUBTOL_CONTEXT_H
#define SUBTOL_CONTEXT_H

#include <ipp/ippcp.h>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <fstream>

struct ref_context_t {
	std::filebuf &fb;
	size_t N;
	unsigned int alpha;
	int32_t *C;
	IppsAES_GCMState *cc;

	ref_context_t(std::filebuf &fb, size_t N, unsigned int alpha, IppsAES_GCMState *cc): fb(fb) {
		this->N = N;
		this->alpha = alpha;
		this->cc = cc;

		C = nullptr;
	}

	virtual ~ref_context_t() {
		if(cc != nullptr)
			std::free(cc);

		if(C != nullptr)
			delete[] C;
	}

	void verify_mac(std::uint8_t *mac) {
		uint8_t final_mac[16];
		ippsAES_GCMGetTag(final_mac, 16, cc);
		assert(std::memcmp(final_mac, mac, 16) == 0);

		std::free(cc);
		cc = nullptr;

		fb.close();
	}

	// virtual methods
	virtual void init() = 0;
	virtual void load_index(std::size_t buffer_size) = 0;

	// put the sauce here!!!
	virtual void query(unsigned char *q, int qlen, std::int32_t &start, std::int32_t &end) = 0;
};

#endif // SUBTOL_CONTEXT_H
