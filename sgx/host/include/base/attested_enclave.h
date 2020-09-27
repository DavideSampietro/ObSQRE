#ifndef ATTESTED_ENCLAVE_H
#define ATTESTED_ENCLAVE_H

#include "enclave_base.h"
#include "sgx_key_exchange.h"

#include <cstdint>
#include <list>
#include <mutex>

class attested_enclave: public enclave_base {
private:
	std::mutex list_sync;
	std::list<sgx_ra_context_t> open_contexts;

public:
	explicit attested_enclave(const std::string &shared_object_filepath): enclave_base(shared_object_filepath) {}
	virtual ~attested_enclave();

	// attestation flow
	sgx_ra_context_t create_attestation_context(sgx_status_t *err);

	sgx_status_t attestation_phase_1(sgx_ra_context_t session, std::uint32_t *egid, sgx_ra_msg1_t *msg1);

	sgx_status_t attestation_phase_2(sgx_ra_context_t session,
		sgx_ra_msg2_t *msg2, std::uint32_t msg2_size,
		sgx_ra_msg3_t **msg3, std::uint32_t *msg3_size);
	
	sgx_status_t exchange_msg4(sgx_ra_context_t session, std::uint8_t *payload, std::size_t len, std::uint8_t *mac);

	sgx_status_t close_attestation_context(sgx_ra_context_t session);
};

#endif
