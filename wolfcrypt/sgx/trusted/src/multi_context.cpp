#include "sgx_wrapper_t.h"

#include "standalone_interface.h"

#include <sgx_error.h>
#include <sgx_tcrypto.h>

// sgx_ra_context_t is an uint32_t
#include <sgx_key_exchange.h>
#include <sgx_spinlock.h>

#include "user_session.h"
#include <unordered_map>

#include "obl/primitives.h"

#include <cstring>

// instead of mutexes, which require OCALLs in order to work, I emply spinlocks, that don't require enclave exit.
// I drew the idea from Intel's code in the SDK performing remote attestation, that seems to use them instead of
// mutexes in order to manage concurrent access to a vector
sgx_spinlock_t session_lock = SGX_SPINLOCK_INITIALIZER;

std::unordered_map<sgx_ra_context_t, user_session_t> session;

void create_session(sgx_status_t *ret, sgx_ra_context_t ctx)
{
	sgx_status_t retval = SGX_SUCCESS;
	
	// create a fresh context
	user_session_t clean_session;
	
	// acquire the lock
	sgx_spin_lock(&session_lock);
	
		// check whether the session already exists
		auto it = session.find(ctx);
		if(it == session.end())
		{
			session[ctx] = std::move(clean_session);
			sgx_spin_unlock(&session_lock);
		}
		else {
			sgx_spin_unlock(&session_lock);
			retval = SGX_ERROR_INVALID_PARAMETER;
		}
	
	// write status code
	*ret = retval;
}

void close_session(sgx_status_t *ret, sgx_ra_context_t ctx)
{
	sgx_status_t retval = SGX_SUCCESS;
	
	sgx_spin_lock(&session_lock);
	
		auto it = session.find(ctx);
		
		if(it == session.end())
			retval = SGX_ERROR_INVALID_PARAMETER;
		else if(it->second.busy)
			retval = SGX_ERROR_INVALID_STATE;
		else
			session.erase(it);
	
	sgx_spin_unlock(&session_lock);
	
	if(retval == SGX_SUCCESS)
		retval = sgx_ra_close(ctx);
	
	*ret = retval;
}

void configure(sgx_status_t *ret, sgx_ra_context_t ctx, std::uint8_t *cfg, std::uint8_t *mac)
{
	sgx_status_t retval = SGX_SUCCESS;
	
	// check whether or not the mac matches
	sgx_ra_key_128_t session_key;
	sgx_cmac_128bit_tag_t out_cmac;
	retval = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &session_key);
	
	if(retval == SGX_SUCCESS) // if not, ctx is invalid argument
	{
		sgx_rijndael128_cmac_msg(&session_key, cfg, 7 * sizeof(unsigned int), &out_cmac);
		std::memset(session_key, 0x00, 16);
		
		if(memcmp(out_cmac, mac, 16) != 0)
			retval = SGX_ERROR_MAC_MISMATCH;
		
		else {
			std::uint32_t *cfg32 = (std::uint32_t*) cfg;
			
			// it was not worth to set the busy flag for just 8 assignments
			// I expect session.find to take a lot more than the if-else stuff
			sgx_spin_lock(&session_lock);
				
				auto it = session.find(ctx);
				
				if(it == session.end())
					retval = SGX_ERROR_INVALID_PARAMETER;
				else if(it != session.end() && it->second.status == 1)
				{
					it->second.cfg.base_oram = (obl_oram_t) cfg32[0];
					it->second.cfg.Z = cfg32[1];
					it->second.cfg.stash_size = cfg32[2];
					it->second.cfg.S = cfg32[3];
					it->second.cfg.A = cfg32[4];
					it->second.cfg.csize = cfg32[5];
					it->second.cfg.sa_block = cfg32[6];
					it->second.status = 2;
				}
				else
					retval = SGX_ERROR_INVALID_STATE;
			
			sgx_spin_unlock(&session_lock);
		}
	}
	
	*ret = retval;
}

void loader(sgx_status_t *ret, sgx_ra_context_t ctx, void *fp, std::uint8_t *passphrase, std::uint8_t *iv, std::uint8_t *mac)
{
	sgx_status_t retval = SGX_SUCCESS;
	
	// passphrase is a AES-GCM string held in a buffer of at most 64-bytes
	std::uint8_t dec_passphrase[64];
	sgx_ra_key_128_t session_key;
	
	retval = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &session_key);
	
	if(retval == SGX_SUCCESS) // session key correctly retrieved
	{
		sgx_aes_gcm_128bit_tag_t gcm_mac;
		std::memcpy(gcm_mac, mac, 16);
		
		retval = sgx_rijndael128GCM_decrypt(&session_key, passphrase, 64, dec_passphrase, iv, 12, NULL, 0, &gcm_mac);
		std::memset(session_key, 0x00, 16);
		
		if(retval == SGX_SUCCESS)
		{
			sgx_spin_lock(&session_lock);
			
				auto it = session.find(ctx);
				
				if(it == session.end() || it->second.status != 2 || it->second.busy)
				{
					sgx_spin_unlock(&session_lock);
					retval = SGX_ERROR_INVALID_STATE;
				}
				else {
					// dump required stuff
					it->second.busy = true;
					subtol_config_t cfg = it->second.cfg;
					sgx_spin_unlock(&session_lock);
					
					subtol_context_t *context = init_subtol_context(fp, (char*) dec_passphrase, cfg);
					
					sgx_spin_lock(&session_lock);
					
					// iterators may change due to modifications to the container
					it = session.find(ctx);
					
					it->second.ctx = std::unique_ptr<subtol_context_t>(context);
					it->second.busy = false;
	
					if(context != nullptr)
						it->second.status = 3;
					
					sgx_spin_unlock(&session_lock);
					
					context = nullptr;
				}
		}
	}
	
	*ret = retval;
}

void query(sgx_status_t *ret, sgx_ra_context_t ctx, uint8_t *q, size_t len, uint8_t *iv, uint8_t *mac, int32_t *res)
{
	sgx_status_t retval = SGX_SUCCESS;
	
	// passphrase is a AES-GCM string held in a buffer of at most 64-bytes
	sgx_ra_key_128_t session_key;
	
	retval = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &session_key);
	
	if(retval == SGX_SUCCESS) // session key correctly retrieved
	{
		unsigned char *qq = new unsigned char[len];
		
		sgx_aes_gcm_128bit_tag_t gcm_mac;
		std::memcpy(gcm_mac, mac, 16);
		
		retval = sgx_rijndael128GCM_decrypt(&session_key, q, len, (std::uint8_t*) qq, iv, 12, NULL, 0, &gcm_mac);
		
		if(retval == SGX_SUCCESS)
		{
			sgx_spin_lock(&session_lock);
			
				auto it = session.find(ctx);
				
				if(it == session.end() || it->second.status != 3 || it->second.busy)
				{
					sgx_spin_unlock(&session_lock);
					retval = SGX_ERROR_INVALID_STATE;
				}
				else {
					// dump required stuff
					it->second.busy = true;
					std::unique_ptr<subtol_context_t> context = std::move(it->second.ctx);
					sgx_spin_unlock(&session_lock);
					
					std::uint32_t tmp_res[2];
					context->query(qq, len, tmp_res[0], tmp_res[1]);
					// this is to later fetch suffix-array entries
					context->current_start_index = obl::ternary_op((tmp_res[0] != -1) & (tmp_res[0] <= tmp_res[1]), tmp_res[0], 0);
					
					sgx_spin_lock(&session_lock);
					// iterators may change due to modifications to the container
					it = session.find(ctx);
					it->second.busy = false;
					it->second.ctx = std::move(context);
					sgx_spin_unlock(&session_lock);
					
					// encrypt results
					obl::gen_rand(iv, 12);
					retval = sgx_rijndael128GCM_encrypt(&session_key, (std::uint8_t*) tmp_res, 2 * sizeof(std::int32_t), (std::uint8_t*) res, iv, 12, NULL, 0, &gcm_mac);
					std::memcpy(mac, gcm_mac, 16);
				}
		}
		
		std::memset(qq, 0x00, len);
		delete[] qq;
	}

	std::memset(session_key, 0x00, 16);
	*ret = retval;
}

void fetch_sa(sgx_status_t *ret, sgx_ra_context_t ctx, int32_t **sa, size_t *len, uint8_t *iv, uint8_t *mac)
{
	sgx_status_t retval = SGX_SUCCESS;
	
	std::int32_t *outbuf;

	sgx_ra_key_128_t session_key;
	sgx_aes_gcm_128bit_tag_t gcm_mac;
	
	retval = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &session_key);
	
	if(retval == SGX_SUCCESS) // session key correctly retrieved
	{
		sgx_spin_lock(&session_lock);
		
			auto it = session.find(ctx);
			
			if(it == session.end() || it->second.status != 3 || it->second.busy)
			{
				sgx_spin_unlock(&session_lock);
				retval = SGX_ERROR_INVALID_STATE;
			}
			else {
				it->second.busy = true;
				std::unique_ptr<subtol_context_t> context = std::move(it->second.ctx);
				sgx_spin_unlock(&session_lock);
				
				if(context->suffix_array != nullptr)
				{
					std::int32_t buff[context->sa_bundle_size];
					context->fetch_sa(buff);
					
					host_alloc((void**) &outbuf, sizeof(std::int32_t) * context->sa_bundle_size);

					obl::gen_rand(iv, 12);
					retval = sgx_rijndael128GCM_encrypt(&session_key, (std::uint8_t*) buff, context->sa_bundle_size *sizeof(std::int32_t),
						(std::uint8_t*) outbuf, iv, 12, NULL, 0, &gcm_mac);
					std::memcpy(mac, gcm_mac, 16);
					
					*sa = outbuf;
					*len = context->sa_bundle_size;
				}
				else {
					retval = SGX_ERROR_INVALID_PARAMETER;
					*sa = nullptr;
					*len = 0;
				}
				
				sgx_spin_lock(&session_lock);
				// iterators may change due to modifications to the container
				it = session.find(ctx);
				it->second.busy = false;
				it->second.ctx = std::move(context);
				sgx_spin_unlock(&session_lock);
			}
	}
	
	std::memset(session_key, 0x00, 16);
	*ret = retval;
}
