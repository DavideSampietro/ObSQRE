#ifndef OBL_OASSERT_H
#define OBL_OASSERT_H

#ifndef SGX_ENCLAVE_ENABLED
	#include <cassert>
#else
	// as defined in SGX headers
	// assert is defined as a macro so you cannot export it
	// gcc fortunately implements this via a reserved illegal instruction UD2
	#define assert(e) ((e) ? ((void)0) : __builtin_trap());
#endif

#endif // OBL_OASSERT_H
