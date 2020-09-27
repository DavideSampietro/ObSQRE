/*
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFCRYPT_AES_H
#define WOLFCRYPT_AES_H

#include <wolfcrypt/common.h>

extern "C"
{
  enum
  {
    AES_128_KEY_SIZE = 16,
    AES_192_KEY_SIZE = 24,
    AES_256_KEY_SIZE = 32,
    AES_IV_SIZE = 16,
  };
  enum
  {
    AES_ENC_TYPE = WC_CIPHER_AES,
    AES_ENCRYPTION = 0,
    AES_DECRYPTION = 1,
    AES_BLOCK_SIZE = 16,
    KEYWRAP_BLOCK_SIZE = 8,
    GCM_NONCE_MAX_SZ = 16,
    GCM_NONCE_MID_SZ = 12,
    GCM_NONCE_MIN_SZ = 8,
    CCM_NONCE_MIN_SZ = 7,
    CCM_NONCE_MAX_SZ = 13,
    CTR_SZ = 4,
    AES_IV_FIXED_SZ = 4,
  };
  typedef struct Aes
  {
    __attribute__ ((aligned (16))) word32 key[60];
    word32 rounds;
    int keylen;
    __attribute__ ((aligned (16))) word32 reg[AES_BLOCK_SIZE /
					      sizeof (word32)];
    __attribute__ ((aligned (16))) word32 tmp[AES_BLOCK_SIZE /
					      sizeof (word32)];
    word32 invokeCtr[2];
    word32 nonceSz;
    __attribute__ ((aligned (16))) byte H[AES_BLOCK_SIZE];
    byte use_aesni;
    word32 left;
    void *heap;
  } Aes;
  typedef struct Gmac
  {
    Aes aes;
  } Gmac;
  typedef int (*wc_AesAuthEncryptFunc) (Aes * aes, byte * out,
					const byte * in, word32 sz,
					const byte * iv, word32 ivSz,
					byte * authTag, word32 authTagSz,
					const byte * authIn, word32 authInSz);
  typedef int (*wc_AesAuthDecryptFunc) (Aes * aes, byte * out,
					const byte * in, word32 sz,
					const byte * iv, word32 ivSz,
					const byte * authTag,
					word32 authTagSz, const byte * authIn,
					word32 authInSz);
  int wc_AesSetKey (Aes * aes, const byte * key, word32 len, const byte * iv,
		    int dir);
  int wc_AesSetIV (Aes * aes, const byte * iv);
  int wc_AesCtrEncrypt (Aes * aes, byte * out, const byte * in, word32 sz);
  void wc_AesEncryptDirect (Aes * aes, byte * out, const byte * in);
  void wc_AesDecryptDirect (Aes * aes, byte * out, const byte * in);
  int wc_AesSetKeyDirect (Aes * aes, const byte * key, word32 len,
			  const byte * iv, int dir);
  int wc_AesGcmSetKey (Aes * aes, const byte * key, word32 len);
  int wc_AesGcmEncrypt (Aes * aes, byte * out,
			const byte * in, word32 sz,
			const byte * iv, word32 ivSz,
			byte * authTag, word32 authTagSz,
			const byte * authIn, word32 authInSz);
  int wc_AesGcmDecrypt (Aes * aes, byte * out,
			const byte * in, word32 sz,
			const byte * iv, word32 ivSz,
			const byte * authTag, word32 authTagSz,
			const byte * authIn, word32 authInSz);
  int wc_GmacSetKey (Gmac * gmac, const byte * key, word32 len);
  int wc_GmacUpdate (Gmac * gmac, const byte * iv, word32 ivSz,
		     const byte * authIn, word32 authInSz,
		     byte * authTag, word32 authTagSz);
  void GHASH (Aes * aes, const byte * a, word32 aSz, const byte * c,
	      word32 cSz, byte * s, word32 sSz);
  int wc_AesGetKeySize (Aes * aes, word32 * keySize);
  int wc_AesInit (Aes * aes, void *heap, int devId);
  void wc_AesFree (Aes * aes);
}

#endif
