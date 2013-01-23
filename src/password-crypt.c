#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "password-crypt.h"

#define MIN(a,b) ((a)<(b)?(a):(b))

#define SHA256_DEFAULT_ROUNDS 5000

static const char b64t[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static const char sha256_prefix[] = "$5$";
static const char sha512_prefix[] = "$6$";

static const char sha256_rounds_prefix[] = "rounds=";

static int restore_sha256_array (const char *string, uint8_t *hash);

int
get_hash_size (int method)
{
	switch (method) {
	case TRANDITIONAL_DES:
		return 64 / 8; /* per "man crypt" */
	case EXTEND_BSDI_DES:
		return 64 / 8; /* per "man crypt" */
	case MD5_BASED:
		return MD5_DIGEST_LENGTH;
	case SHA256_BASED:
		return SHA256_DIGEST_LENGTH;
	case SHA512_BASED:
		return SHA512_DIGEST_LENGTH;
	case BLOWFISH_BASED:
		return 184 / 8; /* per "man crypt" */
	}

	return -1;
}

const char *
get_crypt_prefix (int method)
{
	switch (method) {
	case TRANDITIONAL_DES:
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
		return "$2y$"; /* per "man crypt" */
	}

	return NULL;
}

static int
decode_sha256_pass (const char *string, pw_crypt_t *pw_crypt)
{
	/* Expected string: (rounds=[0-9]{1,9}\$)?([./0-9A-Za-z]{1,16})?\$[./0-9A-Za-z]{43} */
	char *tmp, *ptr = (char *)string;
	char *b64_hash;
	int count = 0;

	/* get rounds */
	pw_crypt->iter_count = SHA256_DEFAULT_ROUNDS;
	if (strncmp (ptr, sha256_rounds_prefix, sizeof(sha256_rounds_prefix) - 1) == 0) {
		const char *num = ptr + sizeof(sha256_rounds_prefix) - 1;
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
	for (tmp = ptr; *tmp != '$'; tmp++) {
		if (tmp == '\0')
			return -1;
		count++;
	}
	count = MIN(count, SHA256_SALT_MAX);
	memcpy (pw_crypt->salt, ptr, count);
	pw_crypt->salt_size = count;
	ptr = tmp + 1;

	/* get hash */
	if (strlen(ptr) < SHA256_B64_LENGTH)
		return -1;
	b64_hash = malloc (SHA256_B64_LENGTH + 1);
	if (!b64_hash)
		return -1;
	memcpy (b64_hash, ptr, SHA256_B64_LENGTH);
	b64_hash[SHA256_B64_LENGTH] = '\0';

	if (restore_sha256_array (b64_hash, pw_crypt->hash) < 0)
		return -1;

	free (b64_hash);

	return 0;
}

int
decode_pass (const char *crypt_pass, pw_crypt_t *pw_crypt)
{
	if (!pw_crypt)
		return -1;

	if (strncmp (crypt_pass, sha256_prefix, 3) == 0) {
		pw_crypt->method = SHA256_BASED;
		return decode_sha256_pass (crypt_pass + 3, pw_crypt);
	}

	return -1;
}

char
int_to_b64 (const int i)
{
	return b64t[i & 0x3f];
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

int
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


