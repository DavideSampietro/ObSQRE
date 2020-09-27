#ifndef SUBTOL_CONTEXT_H
#define SUBTOL_CONTEXT_H

#include "obl/oram.h"
#include "obl/rec.h"

#include <ipp/ippcp.h>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <cstring>

/*
	structs and classes are equivalent in C++, with the difference that members
	without access specifier are by default public in the former, whereas private
	in the latter.
	Since this struct is going to be used inside the enclave, in order to ease its
	use, I prefer leaving everything public.
	Wise use of public members is delegated to the programmer.
*/
struct subtol_context_t {
	void *fb;
	std::size_t N;
	unsigned int alpha;
	std::uint32_t *C;
	obl::oram_factory *allocator;
	IppsAES_GCMState *cc;

	obl::recursive_oram *suffix_array;
	unsigned int sa_bundle_size;
	unsigned int sa_total_blocks;
	std::uint32_t current_start_index;

	subtol_context_t(void *fb, size_t N, unsigned int alpha, obl::oram_factory *allocator, IppsAES_GCMState *cc) {
		this->fb = fb;
		this->N = N;
		this->alpha = alpha;
		this->allocator = allocator;
		this->cc = cc;

		suffix_array = nullptr;
		C = nullptr;
		
		current_start_index = 0;
	}

	virtual ~subtol_context_t() {
		delete allocator;

		if(cc != nullptr)
		{
			int gcm_state_size;
			ippsAES_GCMGetSize(&gcm_state_size);
			std::memset(cc, 0x00, gcm_state_size);
			std::free(cc);
		}

		if(C != nullptr)
			delete[] C;

		if(suffix_array != nullptr)
			delete suffix_array;
	}

	void load_sa(unsigned int csize, unsigned int sa_block);
	void fetch_sa(std::int32_t *sa_chunk);

	bool verify_mac(std::uint8_t *mac) {
		uint8_t final_mac[16];
		ippsAES_GCMGetTag(final_mac, 16, cc);
		fb = nullptr;

		int gcm_state_size;
		ippsAES_GCMGetSize(&gcm_state_size);
		std::memset(cc, 0x00, gcm_state_size);
		std::free(cc);
		cc = nullptr;
		
		return consttime_memequal(final_mac, mac, 16);
	}

	// virtual methods
	virtual void init() = 0;
	virtual void load_index(std::size_t buffer_size) = 0;

	// put the sauce here!!!
	virtual void query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end) = 0;
};

#endif // SUBTOL_CONTEXT_H
