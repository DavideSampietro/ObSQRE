#include "standalone_interface.h"

#include "sgx_wrapper_t.h"

#include <cstdint>
#include <cstring>
#include <cassert>
#include <sgx_trts.h>

#include "cbbst.h"
#include "opt_allocator.hpp"
#include "obl/circuit.h"
#include "obl/ring.h"
#include "obl/path.h"
#include "obl/rec.h"
#include "obl/primitives.h"

#include "contexts/sa_psi_context.h"
#include "contexts/bwt_context.h"
#include "contexts/n_bwt_context.h"
#include "contexts/n_bwt_context_b.h"

#include <ipp/ippcp.h>
#include <wolfcrypt/pbkdf.h>

const int linear_break_even = 256;

static int obl_strlen(char *pwd)
{
	/* 
		64 is the max size of a subtol passphrase.
		This is pretty dummy actually:
		- scan 64 bytes
		- for each 0x00 increase zeroes
		- return 64-zeroes
		
		Assume that the passphrase is a C-string padded with 0s at the end
	*/
	int zeroes = 0;
	
	for(int i = 0; i < 64; i++)
		zeroes += (pwd[i] == 0x00);
	
	return 64 - zeroes;
}

subtol_context_t* init_subtol_context(void *fb, char *pwd, subtol_config_t &cfg)
{
	size_t filesize;
	uint8_t aes_key[16];
	// AES-GCM material
	uint8_t iv[12];
	uint8_t mac[16];
	uint8_t *salt;
	IppsAES_GCMState *cc;
	int gcm_state_size;
	// header
	bool has_sa;
	uint64_t algorithm_selection, algo;
	uint64_t header[4];

	// fb is a void* pointer, that is meant to point to a FILE*
	// since enclaves don't allow direct use of syscalls, some I/O structs are left unimplemented in the sgx_tlibc
	// we don't need to check where that pointer belongs since it will just be handled to untrusted code to perform
	// file operations

	// get MAC
	ocall_get_file_size(fb, &filesize);
	ocall_get_blob(fb, mac, 16, filesize - 16);

	// get headers
	ocall_get_blob(fb, (uint8_t*) &algorithm_selection, sizeof(uint64_t), 0);
	has_sa = algorithm_selection >= 4;
	algo = algorithm_selection % 4;

	ocall_get_blob(fb, (uint8_t*) header, 4 * sizeof(uint64_t), -1);
	// for now only 4-bytes integers are supported
	assert(header[2] == sizeof(int32_t));

	// get aes-gcm IV which is suggested to be 12-bytes in size
	ocall_get_blob(fb, iv, 12, -1);
	// dump the salt
	salt = new uint8_t[header[3]];
	ocall_get_blob(fb, salt, header[3], -1);
	wc_PBKDF2(aes_key, (unsigned char*)pwd, obl_strlen(pwd), salt, header[3], 16384, 16, WC_HASH_TYPE_SHA256);
	std::memset(pwd, 0x00, 64);

	// initialize crypto stuff and authenticate unencrypted data
	// taken from sgx_tcrypto sdk code
	ippsAES_GCMGetSize(&gcm_state_size);
	cc = (IppsAES_GCMState*) malloc(gcm_state_size);
	ippsAES_GCMInit(aes_key, 16, cc, gcm_state_size);
	std::memset(aes_key, 0x00, 16);

	ippsAES_GCMReset(cc);
	ippsAES_GCMProcessIV(iv, 12, cc);

	// authenticate unencrypted data
	ippsAES_GCMProcessAAD((uint8_t*) &algorithm_selection, sizeof(uint64_t), cc);
	ippsAES_GCMProcessAAD((uint8_t*) header, sizeof(uint64_t) * 4, cc);
	ippsAES_GCMProcessAAD(iv, 12, cc);
	ippsAES_GCMProcessAAD(salt, header[3], cc);

	delete[] salt;

	// UP TO HERE SUBTOL PREPARATION IS EXACTLY THE SAME!
	// NOW DIFFERENTIATE ACCORDING TO THE ALGORITHM

	// create ORAM allocator
	bool invalid = false;
	obl::oram_factory *allocator = nullptr;

	switch(cfg.base_oram)
	{
		case OBL_CIRCUIT_ORAM:
			allocator = new obl::coram_factory(cfg.Z, cfg.stash_size);
			break;
		
		case OBL_RING_ORAM:
			allocator = new obl::roram_factory(cfg.Z, cfg.S, cfg.A, cfg.stash_size);
			break;
		
		case OBL_PATH_ORAM:
			allocator = new obl::path_factory(cfg.Z, cfg.stash_size);
			break;
		
		default:
			invalid = true;
	}

	// create subtol context
	subtol_context_t *session = nullptr;

	switch(algo)
	{
		case 0: // SUBTOL_SA_PSI
			allocator = new opt_allocator(allocator, linear_break_even);
			session = new sa_psi_context_t(fb, header[0], header[1], allocator, cc);
			break;
		
		case 1: // SUBTOL_NBWT -- alternate version
			allocator = new opt_allocator(allocator, linear_break_even);
			session = new n_bwt_context_b_t(fb, header[0], header[1], allocator, cc);
			break;
		
		case 2: // SUBTOL_VBWT
			session = new bwt_context_t(fb, header[0], header[1], allocator, cc, cfg.csize);
			break;
		
		default:
			invalid = true;
	}

	if(!invalid)
	{
		if(has_sa)
			session->load_sa(cfg.csize, cfg.sa_block);

		session->init();
		bool success = session->verify_mac(mac);
		
		if(!success)
		{
			delete session;
			session = nullptr;
		}
	}
	
	return session;

	// deallocated by subtol_context
	//delete allocator;
	//free(cc);
}
