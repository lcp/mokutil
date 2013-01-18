#ifndef __PASSWORD_HASH_H__
#define __PASSWORD_HASH_H__

#include <sys/types.h>

#define PASSWORD_HASH_SIZE 88

/* The max salt size (in bits) */
#define T_DES_SALT_MAX 12
#define E_BSI_DES_SALT_MAX 24
#define MD5_SALT_MAX 48
#define SHA256_SALT_MAX 96
#define SHA512_SALT_MAX 96
#define BLOWFISH_SALT_MAX 128

enum HashMethod {
	Tranditional_DES = 0,
	Extend_BSDI_DES,
	MD5_BASED,
	SHA256_BASED,
	SHA512_BASED,
	BLOWFISH_BASED
};

typedef struct {
	uint16_t method;
	uint32_t iter_count;
	uint16_t salt_size;
	uint8_t  salt[16];
	uint8_t  hash[64];
} __attribute__ ((packed)) pw_hash_t;

#endif /* __PASSWORD_HASH_H__ */
