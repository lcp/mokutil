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

enum HashMethod {
	TRADITIONAL_DES = 0,
	EXTEND_BSDI_DES,
	MD5_BASED,
	SHA256_BASED,
	SHA512_BASED,
	BLOWFISH_BASED
};

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

int get_hash_size (int method);
const char *get_crypt_prefix (int method);
int decode_pass (const char *crypt_pass, pw_crypt_t *pw_crypt);
char int_to_b64 (const int i);
int b64_to_int (const char c);

#endif /* __PASSWORD_CRYPT_H__ */
