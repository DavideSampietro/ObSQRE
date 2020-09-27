#ifndef SGX_WRAPPER_T_H
#define SGX_WRAPPER_T_H

// place your include here...
#include "subtol_t.h"

// other includes...
#include "sgx_tcrypto.h"

// msg 4 custom greeting string
extern const char * const enclave_ack_string;
extern const char * const enclave_nack_string;

// place the ISV public key here...
// stub taken from the python client code
extern const sgx_ec256_public_t isv_public_key;

#endif
