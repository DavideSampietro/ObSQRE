#ifndef ENCLAVE_BASE_H
#define ENCLAVE_BASE_H

#include <string>

#include "sgx_eid.h"
#include "sgx_attributes.h"
#include "sgx_error.h"

#include "sgx_wrapper_u.h"

class enclave_base {
protected:
	sgx_enclave_id_t eid;

private:
	std::string enclave_name;
	sgx_misc_attribute_t attr;
	bool enclave_initialized;

public:
	explicit enclave_base(const std::string &shared_object_filepath);
	virtual ~enclave_base();

	sgx_status_t init_enclave();
};

#endif
