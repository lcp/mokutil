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
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "password-crypt.h"

#define MIN(a,b) ((a)<(b)?(a):(b))

#define TRAD_DES_HASH_SIZE 13 /* (64/6+1) + (12/6) */
#define BSDI_DES_HASH_SIZE 20 /* (64/6+1) + (24/6) + 4 + 1 */
#define BLOWFISH_HASH_SIZE 31 /* 184 / 6 + 1 */

#define SHA256_DEFAULT_ROUNDS 5000
#define SHA512_DEFAULT_ROUNDS 5000

static const char md5_prefix[] = "$1$";

static const char sha256_prefix[] = "$5$";
static const char sha512_prefix[] = "$6$";

static const char bf_a_prefix[] = "$2a$";
static const char bf_x_prefix[] = "$2x$";
static const char bf_y_prefix[] = "$2y$";

static const char sha_rounds_prefix[] = "rounds=";

static int restore_md5_array (const char *string, uint8_t *hash);
static int restore_sha256_array (const char *string, uint8_t *hash);
static int restore_sha512_array (const char *string, uint8_t *hash);

static uint16_t
gen_salt_size (uint16_t min, uint16_t max)
{
	struct timeval tv;
	uint16_t diff;

	(void) gettimeofday (&tv, NULL);
	srandom (tv.tv_sec ^ tv.tv_usec ^ getpid ());

	diff = random () % (max - min + 1);

	return (min + diff);
}

uint16_t
get_pw_salt_size (const HashMethod method) {
	switch (method) {
	case TRADITIONAL_DES:
		return T_DES_SALT_MAX;
	case EXTEND_BSDI_DES:
		return E_BSI_DES_SALT_MAX;
	case MD5_BASED:
		return MD5_SALT_MAX;
	case SHA256_BASED:
	case SHA512_BASED:
		return gen_salt_size (8, 16);
	case BLOWFISH_BASED:
		return BLOWFISH_SALT_MAX;
	}

	return -1;
}

int
get_pw_hash_size (const HashMethod method)
{
	switch (method) {
	case TRADITIONAL_DES:
		return TRAD_DES_HASH_SIZE;
	case EXTEND_BSDI_DES:
		return BSDI_DES_HASH_SIZE;
	case MD5_BASED:
		return MD5_DIGEST_LENGTH;
	case SHA256_BASED:
		return SHA256_DIGEST_LENGTH;
	case SHA512_BASED:
		return SHA512_DIGEST_LENGTH;
	case BLOWFISH_BASED:
		return BLOWFISH_HASH_SIZE;
	}

	return -1;
}

const char *
get_crypt_prefix (const HashMethod method)
{
	switch (method) {
	case TRADITIONAL_DES:
		return ""; /* per "man crypt" */
	case EXTEND_BSDI_DES:
		return "_"; /* per "man crypt" */
	case MD5_BASED:
		return "$1$";
	case SHA256_BASED:
		return "$5$";
	case SHA512_BASED:
		return "$6$";
	case BLOWFISH_BASED:
		return "$2y$10$"; /* FIXME change the count */
	}

	return NULL;
}

static int
decode_trad_des_pass (const char *string, pw_crypt_t *pw_crypt)
{
	/* Expected string: [./0-9A-Za-z]{13} */
	pw_crypt->iter_count = 25;
	pw_crypt->salt_size = 2;
	memcpy (pw_crypt->salt, string, 2);
	pw_crypt->salt[2] = '\0';
	memcpy (pw_crypt->hash, string, TRAD_DES_HASH_SIZE);
	pw_crypt->hash[TRAD_DES_HASH_SIZE] = '\0';

	return 0;
}

static int
decode_md5_pass (const char *string, pw_crypt_t *pw_crypt)
{
	/* Expected string: [./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22} */
	char *tmp, *ptr = (char *)string;
	char b64_hash[MD5_B64_LENGTH + 1];
	int count = 0;

	pw_crypt->iter_count = 1000;

	/* get salt */
	for (tmp = ptr; *tmp != '$'; tmp++) {
		if (*tmp == '\0')
			return -1;
		count++;
	}
	count = MIN(count, MD5_SALT_MAX);
	memcpy (pw_crypt->salt, ptr, count);
	pw_crypt->salt_size = count;
	ptr = tmp + 1;

	/* get hash */
	if (strlen(ptr) != MD5_B64_LENGTH)
		return -1;
	memcpy (b64_hash, ptr, MD5_B64_LENGTH);
	b64_hash[MD5_B64_LENGTH] = '\0';

	if (restore_md5_array (b64_hash, pw_crypt->hash) < 0)
		return -1;

	return 0;
}

static int
decode_sha256_pass (const char *string, pw_crypt_t *pw_crypt)
{
	/* Expected string: (rounds=[0-9]{1,9}\$)?([./0-9A-Za-z]{1,16})?\$[./0-9A-Za-z]{43} */
	char *tmp, *ptr = (char *)string;
	char b64_hash[SHA256_B64_LENGTH + 1];
	int count = 0;

	/* get rounds */
	pw_crypt->iter_count = SHA256_DEFAULT_ROUNDS;
	if (strncmp (ptr, sha_rounds_prefix, sizeof(sha_rounds_prefix) - 1) == 0) {
		const char *num = ptr + sizeof(sha_rounds_prefix) - 1;
		char *endp;
		unsigned long int srounds = strtoul (num, &endp, 10);
		if (*endp == '$') {
			ptr = endp + 1;
			pw_crypt->iter_count = (uint32_t)srounds;
		} else {
			return -1;
		}
	}

	/* get salt */
	tmp = ptr;
	if (strlen (ptr) > SHA256_B64_LENGTH) {
		while (*tmp != '$') {
			if (*tmp == '\0')
				return -1;
			count++;
			tmp++;
		}

		count = MIN(count, SHA256_SALT_MAX);
		memcpy (pw_crypt->salt, ptr, count);
		pw_crypt->salt_size = count;
		ptr = tmp + 1;
	} else {
		pw_crypt->salt_size = 0;
	}

	/* get hash */
	if (strlen(ptr) < SHA256_B64_LENGTH)
		return -1;
	memcpy (b64_hash, ptr, SHA256_B64_LENGTH);
	b64_hash[SHA256_B64_LENGTH] = '\0';

	if (restore_sha256_array (b64_hash, pw_crypt->hash) < 0)
		return -1;

	return 0;
}

static int
decode_sha512_pass (const char *string, pw_crypt_t *pw_crypt)
{
	/* Expected string: (rounds=[0-9]{1,9}\$)?([./0-9A-Za-z]{1,16})?\$[./0-9A-Za-z]{86} */
	char *tmp, *ptr = (char *)string;
	char b64_hash[SHA512_B64_LENGTH + 1];
	int count = 0;

	/* get rounds */
	pw_crypt->iter_count = SHA512_DEFAULT_ROUNDS;
	if (strncmp (ptr, sha_rounds_prefix, sizeof(sha_rounds_prefix) - 1) == 0) {
		const char *num = ptr + sizeof(sha_rounds_prefix) - 1;
		char *endp;
		unsigned long int srounds = strtoul (num, &endp, 10);
		if (*endp == '$') {
			ptr = endp + 1;
			pw_crypt->iter_count = (uint32_t)srounds;
		} else {
			return -1;
		}
	}

	/* get salt */
	tmp = ptr;
	if (strlen (ptr) > SHA512_B64_LENGTH) {
		while (*tmp != '$') {
			if (*tmp == '\0')
				return -1;
			count++;
			tmp++;
		}

		count = MIN(count, SHA512_SALT_MAX);
		memcpy (pw_crypt->salt, ptr, count);
		pw_crypt->salt_size = count;
		ptr = tmp + 1;
	} else {
		pw_crypt->salt_size = 0;
	}

	/* get hash */
	if (strlen(ptr) < SHA512_B64_LENGTH)
		return -1;
	memcpy (b64_hash, ptr, SHA512_B64_LENGTH);
	b64_hash[SHA512_B64_LENGTH] = '\0';

	if (restore_sha512_array (b64_hash, pw_crypt->hash) < 0)
		return -1;

	return 0;
}

static int
decode_blowfish_pass (const char *string, pw_crypt_t *pw_crypt)
{
	/* Expected string: \$2[axy]\$[0-9]{2}\$[./A-Za-z0-9]{53} */
	/* Store the first (22+7) bytes in salt[] and the rest in hash */

	if (strlen(string) != (53 + 7))
		return -1;

	if (string[0] != '$' ||
	    string[1] != '2' ||
	    (string[2] != 'a' && string[2] != 'x' && string[2] != 'y') ||
	    string[3] != '$' ||
	    string[4] < '0' || string[4] > '3' ||
	    string[5] < '0' || string[5] > '9' ||
	    (string[4] == '3' && string[5] > '1') ||
	    string[6] != '$') {
		return -1;
        }

	pw_crypt->iter_count = 0;

	memcpy (pw_crypt->salt, string, (22 + 7));
	pw_crypt->salt[22 + 7] = '\0';
	pw_crypt->salt_size = 22 + 7 + 1;

	memcpy (pw_crypt->hash, string + 22 + 7, BLOWFISH_HASH_SIZE);

	return 0;
}

int
decode_pass (const char *crypt_pass, pw_crypt_t *pw_crypt)
{
	if (!pw_crypt)
		return -1;

	if (strncmp (crypt_pass, md5_prefix, 3) == 0) {
		pw_crypt->method = MD5_BASED;
		return decode_md5_pass (crypt_pass + strlen (md5_prefix), pw_crypt);
	}

	if (strncmp (crypt_pass, sha256_prefix, 3) == 0) {
		pw_crypt->method = SHA256_BASED;
		return decode_sha256_pass (crypt_pass + strlen (sha256_prefix), pw_crypt);
	}

	if (strncmp (crypt_pass, sha512_prefix, 3) == 0) {
		pw_crypt->method = SHA512_BASED;
		return decode_sha512_pass (crypt_pass + strlen (sha512_prefix), pw_crypt);
	}

	if (strncmp (crypt_pass, bf_a_prefix, 4) == 0 ||
	    strncmp (crypt_pass, bf_x_prefix, 4) == 0 ||
	    strncmp (crypt_pass, bf_y_prefix, 4) == 0) {
		pw_crypt->method = BLOWFISH_BASED;
		return decode_blowfish_pass (crypt_pass, pw_crypt);
	}

	if (strlen (crypt_pass) == TRAD_DES_HASH_SIZE) {
		pw_crypt->method = TRADITIONAL_DES;
		return decode_trad_des_pass (crypt_pass, pw_crypt);
	}

	return -1;
}

int
b64_to_int (const char c)
{
	if (c == '.')
		return 0;

	if (c == '/')
		return 1;

	if (c >= '0' && c <= '9')
		return (c - '0' + 2);

	if (c >= 'A' && c <= 'Z')
		return (c - 'A' + 12);

	if (c >= 'a' && c <= 'z')
		return (c - 'a' + 38);

	return -1;
}

static int
split_24bit (const char *string, uint8_t *hash, int start, int n,
	     uint32_t b2, uint32_t b1, uint32_t b0)
{
	uint32_t tmp = 0;
	int i, value;

	for (i = start; i < start + n; i++) {
		value = b64_to_int (string[i]);
		if (value < 0)
			return -1;
		tmp |= value << (6*(i - start));
	}

	hash[b0] = (uint8_t)(tmp & 0xff);
	hash[b1] = (uint8_t)((tmp >> 8) & 0xff);
	hash[b2] = (uint8_t)((tmp >> 16) & 0xff);

	return 0;
}

static int
restore_md5_array (const char *string, uint8_t *hash)
{
	uint32_t tmp = 0;
	int value1, value2;

	if (strlen (string) != MD5_B64_LENGTH)
		return -1;

	if (split_24bit (string, hash,  0, 4, 0, 6, 12) < 0)
		return -1;

	if (split_24bit (string, hash,  4, 4, 1, 7, 13) < 0)
		return -1;

	if (split_24bit (string, hash,  8, 4, 2, 8, 14) < 0)
		return -1;

	if (split_24bit (string, hash, 12, 4, 3, 9, 15) < 0)
		return -1;

	if (split_24bit (string, hash, 16, 4, 4, 10, 5) < 0)
		return -1;

	value1 = b64_to_int (string[21]);
	if (value1 < 0)
		return -1;
	value2 = b64_to_int (string[20]);
	if (value2 < 0)
		return -1;
	tmp = (value1 << 6) | value2;
	hash[11] = (uint8_t)tmp;

	return 0;
}

static int
restore_sha256_array (const char *string, uint8_t *hash)
{
	uint32_t tmp = 0;
	int i, value;

	if (strlen (string) != SHA256_B64_LENGTH)
		return -1;

	if (split_24bit (string, hash,  0, 4, 0, 10, 20) < 0)
		return -1;
	if (split_24bit (string, hash,  4, 4, 21, 1, 11) < 0)
		return -1;
	if (split_24bit (string, hash,  8, 4, 12, 22, 2) < 0)
		return -1;
	if (split_24bit (string, hash, 12, 4, 3, 13, 23) < 0)
		return -1;
	if (split_24bit (string, hash, 16, 4, 24, 4, 14) < 0)
		return -1;
	if (split_24bit (string, hash, 20, 4, 15, 25, 5) < 0)
		return -1;
	if (split_24bit (string, hash, 24, 4, 6, 16, 26) < 0)
		return -1;
	if (split_24bit (string, hash, 28, 4, 27, 7, 17) < 0)
		return -1;
	if (split_24bit (string, hash, 32, 4, 18, 28, 8) < 0)
		return -1;
	if (split_24bit (string, hash, 36, 4, 9, 19, 29) < 0)
		return -1;

	for (i = 40; i < 43 ; i++) {
		value = b64_to_int (string[i]);
		if (value < 0)
			return -1;
		tmp |= value << (6*(i - 40));
	}

	hash[30] = (uint8_t)(tmp & 0xff);
	hash[31] = (uint8_t)((tmp >> 8) & 0xff);

	return 0;
}

static int
restore_sha512_array (const char *string, uint8_t *hash)
{
	uint32_t tmp = 0;
	int value1, value2;

	if (strlen (string) != SHA512_B64_LENGTH)
		return -1;

	if (split_24bit (string, hash,  0, 4, 0, 21, 42) < 0)
		return -1;
	if (split_24bit (string, hash,  4, 4, 22, 43, 1) < 0)
		return -1;
	if (split_24bit (string, hash,  8, 4, 44, 2, 23) < 0)
		return -1;
	if (split_24bit (string, hash, 12, 4, 3, 24, 45) < 0)
		return -1;
	if (split_24bit (string, hash, 16, 4, 25, 46, 4) < 0)
		return -1;
	if (split_24bit (string, hash, 20, 4, 47, 5, 26) < 0)
		return -1;
	if (split_24bit (string, hash, 24, 4, 6, 27, 48) < 0)
		return -1;
	if (split_24bit (string, hash, 28, 4, 28, 49, 7) < 0)
		return -1;
	if (split_24bit (string, hash, 32, 4, 50, 8, 29) < 0)
		return -1;
	if (split_24bit (string, hash, 36, 4, 9, 30, 51) < 0)
		return -1;
	if (split_24bit (string, hash, 40, 4, 31, 52, 10) < 0)
		return -1;
	if (split_24bit (string, hash, 44, 4, 53, 11, 32) < 0)
		return -1;
	if (split_24bit (string, hash, 48, 4, 12, 33, 54) < 0)
		return -1;
	if (split_24bit (string, hash, 52, 4, 34, 55, 13) < 0)
		return -1;
	if (split_24bit (string, hash, 56, 4, 56, 14, 35) < 0)
		return -1;
	if (split_24bit (string, hash, 60, 4, 15, 36, 57) < 0)
		return -1;
	if (split_24bit (string, hash, 64, 4, 37, 58, 16) < 0)
		return -1;
	if (split_24bit (string, hash, 68, 4, 59, 17, 38) < 0)
		return -1;
	if (split_24bit (string, hash, 72, 4, 18, 39, 60) < 0)
		return -1;
	if (split_24bit (string, hash, 76, 4, 40, 61, 19) < 0)
		return -1;
	if (split_24bit (string, hash, 80, 4, 62, 20, 41) < 0)
		return -1;

	value1 = b64_to_int (string[85]);
	if (value1 < 0)
		return -1;
	value2 = b64_to_int (string[84]);
	if (value2 < 0)
		return -1;
	tmp = (value1 << 6) | value2;
	hash[63] = (uint8_t)tmp;

	return 0;
}
