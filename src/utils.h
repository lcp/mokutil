#ifndef __UTIL_H__
#define __UTIL_H__

#include <ctype.h>
#include <efivar.h>

#include "signature.h"
#include "password-crypt.h"

/* The password length */
#define PASSWORD_MAX 256
#define PASSWORD_MIN 1

/* For the password hash generation */
#define DEFAULT_CRYPT_METHOD SHA512_BASED
#define DEFAULT_SALT_SIZE    SHA512_SALT_MAX
#define SETTINGS_LEN         (DEFAULT_SALT_SIZE*2)

#define EFI_NV_RT EFI_VARIABLE_NON_VOLATILE | \
		  EFI_VARIABLE_BOOTSERVICE_ACCESS | \
		  EFI_VARIABLE_RUNTIME_ACCESS

typedef wchar_t efi_char16_t;		/* UNICODE character */

typedef enum {
	DELETE_MOK = 0,
	ENROLL_MOK,
	DELETE_BLACKLIST,
	ENROLL_BLACKLIST,
} MokRequest;

typedef struct {
	EFI_SIGNATURE_LIST *header;
	uint32_t            mok_size;
	void               *mok;
} MokListNode;

uint32_t efi_hash_size (const efi_guid_t *hash_type);
uint32_t signature_size (const efi_guid_t *hash_type);

void allocate_x509_sig (void *dest, const uint8_t *cert,
			const uint32_t cert_size);

int test_and_delete_var (const char *var_name);

unsigned long efichar_from_char (efi_char16_t *dest, const char *src,
				 size_t dest_len);

int match_hash_array (const efi_guid_t *hash_type, const void *hash,
		      const void *hash_array, const uint32_t array_size);

MokListNode* build_mok_list (void *data, unsigned long data_size,
			     uint32_t *mok_num);

int delete_from_pending_request (const efi_guid_t *type, void *data,
				 uint32_t data_size, MokRequest req);

int is_duplicate (const efi_guid_t *type, const void *data,
		  const uint32_t data_size, const efi_guid_t *vendor,
		  const char *db_name);

int is_valid_request (const efi_guid_t *type, void *mok, uint32_t mok_size,
		      MokRequest req);

int is_valid_cert (void *cert, uint32_t cert_size);

int get_password_from_shadow (pw_crypt_t *pw_crypt);

void generate_salt (char salt[], unsigned int salt_size);
int generate_hash (pw_crypt_t *pw_crypt, const char *password,
		   const unsigned int pw_len);
int generate_auth (void *new_list, int list_len, char *password,
		   unsigned int pw_len, uint8_t *auth);

int create_authvar (const char *auth_name, const char *password,
		    const uint8_t root_pw);

char *get_x509_time_str (ASN1_TIME *time);
const char *get_x509_name_str (X509_NAME *X509name, int nid);
char *get_x509_serial_str (X509 *X509cert);
const char *get_x509_sig_alg_str (X509 *X509cert);
char *get_x509_ext_str (const X509 *X509cert, const uint32_t nid);

#endif /* __UTIL_H__ */
