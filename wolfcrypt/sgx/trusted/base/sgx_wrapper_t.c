#include "sgx_wrapper_t.h"

// msg 4 custom greeting string
const char * const enclave_ack_string = "trusted subtol enclave";
const char * const enclave_nack_string = "untrusted enclave";

// place the ISV public key here...
// stub taken from the python client code
const sgx_ec256_public_t isv_public_key = {
	{
		0xcd, 0x24, 0xb0, 0x44, 0x4f, 0xf5, 0x8d, 0x70,
		0x73, 0x0d, 0xaf, 0xdb, 0xda, 0xbd, 0xe1, 0x2c,
		0x25, 0x34, 0xcc, 0x05, 0x25, 0x86, 0x3c, 0xba,
		0x39, 0xaa, 0xd4, 0x5c, 0x34, 0xfa, 0x81, 0xe8
	},
	{
		0xa6, 0x61, 0x2e, 0x9e, 0xd4, 0xdd, 0x57, 0xc2,
		0x44, 0x61, 0x5b, 0xca, 0xca, 0xea, 0x0b, 0x63,
		0xfe, 0x30, 0x73, 0x7c, 0x4e, 0x10, 0x30, 0x12,
		0x91, 0xcf, 0x62, 0x29, 0x5e, 0x65, 0x06, 0xe5
	}
};