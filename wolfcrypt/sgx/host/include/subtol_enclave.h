#ifndef SUBTOL_ENCLAVE_H
#define SUBTOL_ENCLAVE_H

#include "base/attested_enclave.h"

#include <sgx_error.h>
#include <sgx_key_exchange.h>

#include <cstdio>
#include <cstdint>
#include <cstddef>

class subtol_enclave:public attested_enclave {

public:
	subtol_enclave(): attested_enclave("subtol.signed.so") {};
	~subtol_enclave() {};
	
	sgx_status_t call_create_session(sgx_ra_context_t ctx)
	{
		sgx_status_t ret;
		create_session(eid, &ret, ctx);
		
		return ret;
	}
	
	sgx_status_t call_configure(sgx_ra_context_t ctx, std::uint8_t *cfg, std::uint8_t *mac)
	{
		sgx_status_t ret;
		configure(eid, &ret, ctx, cfg, mac);
		
		return ret;
	}
	
	sgx_status_t call_loader(sgx_ra_context_t ctx, void *fp, std::uint8_t *passphrase, std::uint8_t *iv, std::uint8_t *mac)
	{
		sgx_status_t ret;
		loader(eid, &ret, ctx, fp, passphrase, iv, mac);
		
		return ret;
	}
	
	sgx_status_t call_close_session(sgx_ra_context_t ctx)
	{
		sgx_status_t ret;
		close_session(eid, &ret, ctx);
		
		return ret;
	}
	
	sgx_status_t call_query(sgx_ra_context_t ctx, std::uint8_t *q, std::size_t len, std::uint8_t *iv, std::uint8_t *mac, std::int32_t *res)
	{
		sgx_status_t ret;
		query(eid, &ret, ctx, q, len, iv, mac, res);
		
		return ret;
	}
	
	sgx_status_t call_fetch_sa(sgx_ra_context_t ctx, std::int32_t **sa, std::size_t *len, std::uint8_t *iv, std::uint8_t *mac)
	{
		sgx_status_t ret;
		fetch_sa(eid, &ret, ctx, sa, len, iv, mac);
		
		return ret;
	}
	
};

#endif
