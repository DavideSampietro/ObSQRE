#ifndef OBL_TYPES_H
#define OBL_TYPES_H

#include <cstdint>

#define OBL_AESGCM_IV_SIZE 12
#define OBL_AESGCM_MAC_SIZE 16
#define OBL_AESGCM_KEY_SIZE 16

#define OBL_AESCTR_IV_SIZE 16

namespace obl {

	// crypto defs for AES-GCM
	typedef std::uint8_t obl_aes_gcm_128bit_iv_t[OBL_AESGCM_IV_SIZE];
	typedef std::uint8_t obl_aes_gcm_128bit_tag_t[OBL_AESGCM_MAC_SIZE];
	typedef std::uint8_t obl_aes_gcm_128bit_key_t[OBL_AESGCM_KEY_SIZE];

	// crypto defs for AES-CTR
	typedef std::uint8_t obl_aes_ctr_128bit_iv_t[OBL_AESCTR_IV_SIZE];

	// struct for ORAMs embedding a Merkle-tree
	struct auth_data_t {
		obl_aes_gcm_128bit_tag_t left_mac;
		obl_aes_gcm_128bit_tag_t right_mac;
		bool valid_l;
		bool valid_r;
	} __attribute__ ((aligned(8)));

}

#endif // OBL_TYPES_H
