#include "sgx_wrapper_t.h"

#include <sgx_trts.h>
#include <assert.h>

void host_alloc(void **out, size_t s)
{
	void *buffer;

	// although not necessary, this check is not costly
	assert(sgx_is_within_enclave(out, sizeof(void*)));

	// ocall_host_alloc basically wraps a call to malloc from the host (untrusted)
	// portion of the code
	ocall_host_alloc(&buffer, s);

	// now you want to check that the untrusted code actually allocated stuff
	// in the untrusted memory
	assert(sgx_is_outside_enclave(buffer, s) == 1);

	*out = buffer;
}
