/**
 * Copyright (C) 2012-2014 Gary Lin <glin@suse.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
#ifndef __PASSWORD_CRYPT_H__
#define __PASSWORD_CRYPT_H__

#include <stdint.h>

/* The max salt size (in characters [./0-9A-Za-z]) */
#define T_DES_SALT_MAX 2
#define E_BSI_DES_SALT_MAX 4
#define MD5_SALT_MAX 8
#define SHA256_SALT_MAX 16
#define SHA512_SALT_MAX 16
#define BLOWFISH_SALT_MAX 22

typedef enum {
	TRADITIONAL_DES = 0,
	EXTEND_BSDI_DES,
	MD5_BASED,
	SHA256_BASED,
	SHA512_BASED,
	BLOWFISH_BASED
} HashMethod;

typedef struct {
	uint16_t method;
	uint64_t iter_count;
	uint16_t salt_size;
	uint8_t  salt[32];
	uint8_t  hash[128];
} __attribute__ ((packed)) pw_crypt_t;

#define PASSWORD_CRYPT_SIZE sizeof(pw_crypt_t)

#define MD5_B64_LENGTH 22
#define SHA256_B64_LENGTH 43
#define SHA512_B64_LENGTH 86

uint16_t get_pw_salt_size (const HashMethod method);
int get_pw_hash_size (const HashMethod method);
const char *get_crypt_prefix (const HashMethod method);
int decode_pass (const char *crypt_pass, pw_crypt_t *pw_crypt);
int b64_to_int (const char c);

#endif /* __PASSWORD_CRYPT_H__ */
