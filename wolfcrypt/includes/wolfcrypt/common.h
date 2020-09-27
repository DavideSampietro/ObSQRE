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

#ifndef WOLFCRYPT_COMMON_H
#define WOLFCRYPT_COMMON_H

extern "C"
{
#include <time.h>
  char *mystrnstr (const char *s1, const char *s2, unsigned int n);
}
extern "C"
{
  typedef unsigned char byte;
  typedef unsigned short word16;
  typedef unsigned int word32;
  typedef byte word24[3];
  typedef unsigned long word64;
  typedef word64 wolfssl_word;
  enum
  {
    WOLFSSL_WORD_SIZE = sizeof (wolfssl_word),
    WOLFSSL_BIT_SIZE = 8,
    WOLFSSL_WORD_BITS = WOLFSSL_WORD_SIZE * WOLFSSL_BIT_SIZE
  };
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
  enum
  {
    DYNAMIC_TYPE_CA = 1,
    DYNAMIC_TYPE_CERT = 2,
    DYNAMIC_TYPE_KEY = 3,
    DYNAMIC_TYPE_FILE = 4,
    DYNAMIC_TYPE_SUBJECT_CN = 5,
    DYNAMIC_TYPE_PUBLIC_KEY = 6,
    DYNAMIC_TYPE_SIGNER = 7,
    DYNAMIC_TYPE_NONE = 8,
    DYNAMIC_TYPE_BIGINT = 9,
    DYNAMIC_TYPE_RSA = 10,
    DYNAMIC_TYPE_METHOD = 11,
    DYNAMIC_TYPE_OUT_BUFFER = 12,
    DYNAMIC_TYPE_IN_BUFFER = 13,
    DYNAMIC_TYPE_INFO = 14,
    DYNAMIC_TYPE_DH = 15,
    DYNAMIC_TYPE_DOMAIN = 16,
    DYNAMIC_TYPE_SSL = 17,
    DYNAMIC_TYPE_CTX = 18,
    DYNAMIC_TYPE_WRITEV = 19,
    DYNAMIC_TYPE_OPENSSL = 20,
    DYNAMIC_TYPE_DSA = 21,
    DYNAMIC_TYPE_CRL = 22,
    DYNAMIC_TYPE_REVOKED = 23,
    DYNAMIC_TYPE_CRL_ENTRY = 24,
    DYNAMIC_TYPE_CERT_MANAGER = 25,
    DYNAMIC_TYPE_CRL_MONITOR = 26,
    DYNAMIC_TYPE_OCSP_STATUS = 27,
    DYNAMIC_TYPE_OCSP_ENTRY = 28,
    DYNAMIC_TYPE_ALTNAME = 29,
    DYNAMIC_TYPE_SUITES = 30,
    DYNAMIC_TYPE_CIPHER = 31,
    DYNAMIC_TYPE_RNG = 32,
    DYNAMIC_TYPE_ARRAYS = 33,
    DYNAMIC_TYPE_DTLS_POOL = 34,
    DYNAMIC_TYPE_SOCKADDR = 35,
    DYNAMIC_TYPE_LIBZ = 36,
    DYNAMIC_TYPE_ECC = 37,
    DYNAMIC_TYPE_TMP_BUFFER = 38,
    DYNAMIC_TYPE_DTLS_MSG = 39,
    DYNAMIC_TYPE_X509 = 40,
    DYNAMIC_TYPE_TLSX = 41,
    DYNAMIC_TYPE_OCSP = 42,
    DYNAMIC_TYPE_SIGNATURE = 43,
    DYNAMIC_TYPE_HASHES = 44,
    DYNAMIC_TYPE_SRP = 45,
    DYNAMIC_TYPE_COOKIE_PWD = 46,
    DYNAMIC_TYPE_USER_CRYPTO = 47,
    DYNAMIC_TYPE_OCSP_REQUEST = 48,
    DYNAMIC_TYPE_X509_EXT = 49,
    DYNAMIC_TYPE_X509_STORE = 50,
    DYNAMIC_TYPE_X509_CTX = 51,
    DYNAMIC_TYPE_URL = 52,
    DYNAMIC_TYPE_DTLS_FRAG = 53,
    DYNAMIC_TYPE_DTLS_BUFFER = 54,
    DYNAMIC_TYPE_SESSION_TICK = 55,
    DYNAMIC_TYPE_PKCS = 56,
    DYNAMIC_TYPE_MUTEX = 57,
    DYNAMIC_TYPE_PKCS7 = 58,
    DYNAMIC_TYPE_AES_BUFFER = 59,
    DYNAMIC_TYPE_WOLF_BIGINT = 60,
    DYNAMIC_TYPE_ASN1 = 61,
    DYNAMIC_TYPE_LOG = 62,
    DYNAMIC_TYPE_WRITEDUP = 63,
    DYNAMIC_TYPE_PRIVATE_KEY = 64,
    DYNAMIC_TYPE_HMAC = 65,
    DYNAMIC_TYPE_ASYNC = 66,
    DYNAMIC_TYPE_ASYNC_NUMA = 67,
    DYNAMIC_TYPE_ASYNC_NUMA64 = 68,
    DYNAMIC_TYPE_CURVE25519 = 69,
    DYNAMIC_TYPE_ED25519 = 70,
    DYNAMIC_TYPE_SECRET = 71,
    DYNAMIC_TYPE_DIGEST = 72,
    DYNAMIC_TYPE_RSA_BUFFER = 73,
    DYNAMIC_TYPE_DCERT = 74,
    DYNAMIC_TYPE_STRING = 75,
    DYNAMIC_TYPE_PEM = 76,
    DYNAMIC_TYPE_DER = 77,
    DYNAMIC_TYPE_CERT_EXT = 78,
    DYNAMIC_TYPE_ALPN = 79,
    DYNAMIC_TYPE_ENCRYPTEDINFO = 80,
    DYNAMIC_TYPE_DIRCTX = 81,
    DYNAMIC_TYPE_HASHCTX = 82,
    DYNAMIC_TYPE_SEED = 83,
    DYNAMIC_TYPE_SYMMETRIC_KEY = 84,
    DYNAMIC_TYPE_ECC_BUFFER = 85,
    DYNAMIC_TYPE_QSH = 86,
    DYNAMIC_TYPE_SALT = 87,
    DYNAMIC_TYPE_HASH_TMP = 88,
    DYNAMIC_TYPE_BLOB = 89,
    DYNAMIC_TYPE_NAME_ENTRY = 90,
  };
  enum
  {
    MIN_STACK_BUFFER = 8
  };
  enum wc_AlgoType
  {
    WC_ALGO_TYPE_NONE = 0,
    WC_ALGO_TYPE_HASH = 1,
    WC_ALGO_TYPE_CIPHER = 2,
    WC_ALGO_TYPE_PK = 3,
    WC_ALGO_TYPE_RNG = 4,
    WC_ALGO_TYPE_SEED = 5,
    WC_ALGO_TYPE_HMAC = 6,
    WC_ALGO_TYPE_MAX = WC_ALGO_TYPE_HMAC
  };
  enum wc_HashType
  {
    WC_HASH_TYPE_NONE = 0,
    WC_HASH_TYPE_MD2 = 1,
    WC_HASH_TYPE_MD4 = 2,
    WC_HASH_TYPE_MD5 = 3,
    WC_HASH_TYPE_SHA = 4,
    WC_HASH_TYPE_SHA224 = 5,
    WC_HASH_TYPE_SHA256 = 6,
    WC_HASH_TYPE_SHA384 = 7,
    WC_HASH_TYPE_SHA512 = 8,
    WC_HASH_TYPE_MD5_SHA = 9,
    WC_HASH_TYPE_SHA3_224 = 10,
    WC_HASH_TYPE_SHA3_256 = 11,
    WC_HASH_TYPE_SHA3_384 = 12,
    WC_HASH_TYPE_SHA3_512 = 13,
    WC_HASH_TYPE_BLAKE2B = 14,
    WC_HASH_TYPE_MAX = WC_HASH_TYPE_BLAKE2B
  };
  enum wc_CipherType
  {
    WC_CIPHER_NONE = 0,
    WC_CIPHER_AES = 1,
    WC_CIPHER_AES_CBC = 2,
    WC_CIPHER_AES_GCM = 3,
    WC_CIPHER_AES_CTR = 4,
    WC_CIPHER_AES_XTS = 5,
    WC_CIPHER_AES_CFB = 6,
    WC_CIPHER_DES3 = 7,
    WC_CIPHER_DES = 8,
    WC_CIPHER_CHACHA = 9,
    WC_CIPHER_HC128 = 10,
    WC_CIPHER_IDEA = 11,
    WC_CIPHER_MAX = WC_CIPHER_HC128
  };
  enum wc_PkType
  {
    WC_PK_TYPE_NONE = 0,
    WC_PK_TYPE_RSA = 1,
    WC_PK_TYPE_DH = 2,
    WC_PK_TYPE_ECDH = 3,
    WC_PK_TYPE_ECDSA_SIGN = 4,
    WC_PK_TYPE_ECDSA_VERIFY = 5,
    WC_PK_TYPE_ED25519 = 6,
    WC_PK_TYPE_CURVE25519 = 7,
    WC_PK_TYPE_RSA_KEYGEN = 8,
    WC_PK_TYPE_EC_KEYGEN = 9,
    WC_PK_TYPE_MAX = WC_PK_TYPE_EC_KEYGEN
  };
  enum
  {
    CTC_SETTINGS = 0x1
  };
  word32 CheckRunTimeSettings (void);
}

#endif
