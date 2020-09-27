#include <cstdint>
#include <cstring>
#include <cassert>

#include "init.h"

#include "sa_psi_context.h"
#include "bwt_context.h"
#include "n_bwt_context.h"

#include <ipp/ippcp.h>
#include <wolfcrypt/pbkdf.h>

ref_context_t* init_ref_context(std::filebuf &fb, char *pwd)
{
	std::uint8_t aes_key[16];
	// AES-GCM material
	std::uint8_t iv[12];
	std::uint8_t mac[16];
	std::uint8_t *salt;
	IppsAES_GCMState *cc;
	int gcm_state_size;
	// header
	std::uint64_t algo;
	std::uint64_t header[4];

	// get headers
	fb.sgetn((char*) &algo, sizeof(std::uint64_t));
	fb.sgetn((char*) header, 4 * sizeof(std::uint64_t));
	// for now only 4-bytes integers are supported
	assert(algo < 4);
	assert(header[2] == sizeof(std::int32_t));

	// get aes-gcm IV which is suggested to be 12-bytes in size
	fb.sgetn((char*) iv, 12);
	// dump the salt
	salt = new std::uint8_t[header[3]];
	fb.sgetn((char*) salt, header[3]);
	wc_PBKDF2(aes_key, (unsigned char*)pwd, strlen(pwd), salt, header[3], 16384, 16, WC_HASH_TYPE_SHA256);

	// initialize crypto stuff and authenticate unencrypted data
	// taken from sgx_tcrypto sdk code
	ippsAES_GCMGetSize(&gcm_state_size);
	cc = (IppsAES_GCMState*) malloc(gcm_state_size);
	ippsAES_GCMInit(aes_key, 16, cc, gcm_state_size);

	ippsAES_GCMReset(cc);
	ippsAES_GCMProcessIV(iv, 12, cc);

	// authenticate unencrypted data
	ippsAES_GCMProcessAAD((std::uint8_t*) &algo, sizeof(std::uint64_t), cc);
	ippsAES_GCMProcessAAD((std::uint8_t*) header, sizeof(std::uint64_t) * 4, cc);
	ippsAES_GCMProcessAAD(iv, 12, cc);
	ippsAES_GCMProcessAAD(salt, header[3], cc);

	delete[] salt;

	// UP TO HERE SUBTOL PREPARATION IS EXACTLY THE SAME!
	// NOW DIFFERENTIATE ACCORDING TO THE ALGORITHM

	// create ref context
	ref_context_t *session;

	switch(algo)
	{
		case 0: // REF_SA_PSI
			session = new sa_psi_context_t(fb, header[0], header[1], cc);
			break;
		case 1: // REF_NBWT
			session = new n_bwt_context_t(fb, header[0], header[1], cc);
			break;
		case 2: // REF_VBWT
			session = new bwt_context_t(fb, header[0], header[1], cc);
			break;
		default:
			assert(0);
	}

	session->init();

	// verify MAC
	fb.sgetn((char*) mac, 16);
	session->verify_mac(mac);

	return session;
}
