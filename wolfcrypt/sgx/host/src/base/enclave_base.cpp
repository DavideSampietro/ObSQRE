#include "base/enclave_base.h"

#include "sgx_urts.h"

enclave_base::enclave_base(const std::string &shared_object_filepath)
{
	enclave_name = shared_object_filepath;
	enclave_initialized = false;

	// clear sgx_misc_attribute_t -- not used now
	attr.misc_select = 0; // reserved for future use
	attr.secs_attr.flags = 0;
	attr.secs_attr.xfrm = 0;
}

sgx_status_t enclave_base::init_enclave()
{
	sgx_status_t ret;
	bool retry = true;

	while(retry)
	{
		// first two NULLs are because of deprecated params, last one is unused!
		// SGX_DEBUG_FLAG is automatically set to the proper value when dealing with a debug or release enclave
		ret = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);

		if(ret == SGX_ERROR_DEVICE_BUSY || ret == SGX_ERROR_MEMORY_MAP_CONFLICT)
			retry = true; // temporary errors
		else
			retry = false;
	}

	if(ret == SGX_SUCCESS)
		enclave_initialized = true;

	return ret;
}

enclave_base::~enclave_base()
{
	if(enclave_initialized)
		sgx_destroy_enclave(eid);
}
