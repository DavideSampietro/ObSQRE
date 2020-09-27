#include "sgx_wrapper_t.h"

#include "sgx_key_exchange.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"

#include "string.h"
#include "stdint.h"

void ecall_get_dhke_parameter(sgx_status_t *init_status, sgx_ra_context_t *dhke_context)
{
	// for the moment, don't require PSE session
	int b_pse = 0;

	*init_status = sgx_ra_init(&isv_public_key, b_pse, dhke_context);
}

void ecall_close_dhke_context(sgx_status_t *cl_status, sgx_ra_context_t dhke_context)
{
	*cl_status = sgx_ra_close(dhke_context);
}

void ecall_msg4(sgx_status_t *handshake_status, sgx_ra_context_t dhke_context, uint8_t *mac, uint8_t *str, size_t len)
{
	// first off, try to retrieve the session key SK if it was correctly set
	sgx_ra_key_128_t session_key;
	sgx_status_t ret = sgx_ra_get_keys(dhke_context, SGX_RA_KEY_SK, &session_key);
	
	if(ret != SGX_SUCCESS)
	{
		*handshake_status = ret;
		return;
	}
	
	// now authenticate the message
	sgx_cmac_128bit_tag_t out_cmac;
	
	sgx_rijndael128_cmac_msg(&session_key, str, len, &out_cmac);
	
	memset(session_key, 0x00, 16);
	
	if(memcmp(out_cmac, mac, 16) != 0)
	{
		*handshake_status = SGX_ERROR_MAC_MISMATCH;
		return;
	}
	
	// now that the string is authenticated, compare with the known strings
	if(len == strlen(enclave_ack_string) && memcmp(str, enclave_ack_string, len) == 0)
		*handshake_status = SGX_SUCCESS;

	// even though that error message was meant for another purpose, it well suits here...
	else if(len == strlen(enclave_nack_string) && memcmp(str, enclave_ack_string, len) == 0)
		*handshake_status = SGX_ERROR_INVALID_ENCLAVE;

	else
		*handshake_status = SGX_ERROR_INVALID_PARAMETER;
}
