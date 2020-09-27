#include "base/attested_enclave.h"

#include "sgx_uae_service.h"
#include "sgx_ukey_exchange.h"


sgx_ra_context_t attested_enclave::create_attestation_context(sgx_status_t *err)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_ra_context_t ctx;

	ecall_get_dhke_parameter(eid, &ret, &ctx);

	if(ret == SGX_SUCCESS)
	{
		std::lock_guard<std::mutex> lsync(list_sync);
		open_contexts.push_front(ctx);
	}

	if(err != nullptr)
		*err = ret;

	return ctx;
}

sgx_status_t attested_enclave::attestation_phase_1(sgx_ra_context_t session, std::uint32_t *egid, sgx_ra_msg1_t *msg1)
{
	sgx_status_t ret;

	ret = sgx_get_extended_epid_group_id(egid);

	if(ret == SGX_SUCCESS)
		ret = sgx_ra_get_msg1(session, eid, sgx_ra_get_ga, msg1);

	return ret;
}

sgx_status_t attested_enclave::attestation_phase_2(sgx_ra_context_t session,
	sgx_ra_msg2_t *msg2, std::uint32_t msg2_size,
	sgx_ra_msg3_t **msg3, std::uint32_t *msg3_size)
{
	sgx_status_t ret;

	ret = sgx_ra_proc_msg2(session, eid,
		sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, // automatically generated functions
		msg2, msg2_size,
		msg3, msg3_size);

	return ret;
}

sgx_status_t attested_enclave::exchange_msg4(sgx_ra_context_t session, std::uint8_t *payload, std::size_t len, std::uint8_t *mac)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ecall_msg4(eid, &ret, session, mac, payload, len);
	
	return ret;
}

sgx_status_t attested_enclave::close_attestation_context(sgx_ra_context_t session)
{
	{
		std::lock_guard<std::mutex> lsync(list_sync);
		open_contexts.remove(session);
	}

	// now deallocate from the enclave
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ecall_close_dhke_context(eid, &ret, session);

	return ret;
}

attested_enclave::~attested_enclave()
{
	sgx_status_t dummy;
	
	{
		std::lock_guard<std::mutex> lsync(list_sync);

		for(auto it = open_contexts.begin(); it != open_contexts.end(); ++it)
			ecall_close_dhke_context(eid, &dummy, *it);
	}
}
