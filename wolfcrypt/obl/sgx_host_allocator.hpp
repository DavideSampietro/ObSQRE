#ifndef SGX_HOST_ALLOCATOR_HPP
#define SGX_HOST_ALLOCATOR_HPP

#include <cstddef>

#include <sgx_error.h>

// extern declarations for host malloc and free
extern "C" sgx_status_t host_alloc(void **out, std::size_t s);
extern "C" sgx_status_t host_free(void *in);

class sgx_host_allocator {
public:
	void* allocate(std::size_t s) {
		void *ptr;
		host_alloc(&ptr, s);
		return ptr;
	}

	void deallocate(void *ptr) {
		host_free(ptr);
	}
};

#endif //SGX_HOST_ALLOCATOR_HPP
