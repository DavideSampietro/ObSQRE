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

#ifndef WOLFCRYPT_PBKDF_H
#define WOLFCRYPT_PBKDF_H

#include <wolfcrypt/common.h>

extern "C"
{
  int wc_PBKDF1_ex (byte * key, int keyLen, byte * iv, int ivLen,
		    const byte * passwd, int passwdLen,
		    const byte * salt, int saltLen, int iterations,
		    int hashType, void *heap);
  int wc_PBKDF1 (byte * output, const byte * passwd, int pLen,
		 const byte * salt, int sLen, int iterations, int kLen,
		 int typeH);
  int wc_PBKDF2 (byte * output, const byte * passwd, int pLen,
		 const byte * salt, int sLen, int iterations, int kLen,
		 int typeH);
}

#endif
