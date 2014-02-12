/**
 * Copyright (C) 2012-2013 Gary Lin <glin@suse.com>
 * Copyright (C) 2012 Matthew Garrett <mjg@redhat.com>
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <getopt.h>
#include <shadow.h>
#include <sys/time.h>

#include <openssl/sha.h>
#include <openssl/x509.h>

#include <crypt.h>

#include "efi.h"
#include "signature.h"
#include "password-crypt.h"

#define SHIM_LOCK_GUID \
EFI_GUID (0x605dab50, 0xe046, 0x4300, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23)

#define PASSWORD_MAX 256
#define PASSWORD_MIN 1
#define SB_PASSWORD_MAX 16
#define SB_PASSWORD_MIN 8

#define HELP               (1 << 0)
#define LIST_ENROLLED      (1 << 1)
#define LIST_NEW           (1 << 2)
#define LIST_DELETE        (1 << 3)
#define IMPORT             (1 << 4)
#define DELETE             (1 << 5)
#define REVOKE_IMPORT      (1 << 6)
#define REVOKE_DELETE      (1 << 7)
#define EXPORT             (1 << 8)
#define PASSWORD           (1 << 9)
#define CLEAR_PASSWORD     (1 << 10)
#define DISABLE_VALIDATION (1 << 11)
#define ENABLE_VALIDATION  (1 << 12)
#define SB_STATE           (1 << 13)
#define TEST_KEY           (1 << 14)
#define RESET              (1 << 15)
#define GENERATE_PW_HASH   (1 << 16)
#define SIMPLE_HASH        (1 << 17)
#define IGNORE_DB          (1 << 18)
#define USE_DB             (1 << 19)
#define MOKX               (1 << 20)
#define IMPORT_HASH        (1 << 21)
#define DELETE_HASH        (1 << 22)
#define VERBOSITY          (1 << 23)

#define DEFAULT_CRYPT_METHOD SHA512_BASED
#define DEFAULT_SALT_SIZE    SHA512_SALT_MAX
#define SETTINGS_LEN         (DEFAULT_SALT_SIZE*2)

static int use_simple_hash;

typedef enum {
	DELETE_MOK = 0,
	ENROLL_MOK,
	DELETE_BLACKLIST,
	ENROLL_BLACKLIST
} MokRequest;

typedef enum {
	MOK_LIST_RT = 0,
	MOK_LIST_X_RT,
	PK,
	KEK,
	DB,
	DBX,
} DBName;

typedef struct {
	EFI_SIGNATURE_LIST *header;
	uint32_t            mok_size;
	void               *mok;
} MokListNode;

typedef struct {
	uint32_t mok_toggle_state;
	uint32_t password_length;
	uint16_t password[SB_PASSWORD_MAX];
} MokToggleVar;

static void
print_help ()
{
	printf ("Usage:\n");
	printf ("  mokutil OPTIONS [ARGS...]\n");
	printf ("\n");
	printf ("Options:\n");
	printf ("  --help\t\t\t\tShow help\n");
	printf ("  --list-enrolled\t\t\tList the enrolled keys\n");
	printf ("  --list-new\t\t\t\tList the keys to be enrolled\n");
	printf ("  --list-delete\t\t\t\tList the keys to be deleted\n");
	printf ("  --import <der file...>\t\tImport keys\n");
	printf ("  --delete <der file...>\t\tDelete specific keys\n");
	printf ("  --revoke-import\t\t\tRevoke the import request\n");
	printf ("  --revoke-delete\t\t\tRevoke the delete request\n");
	printf ("  --export\t\t\t\tExport enrolled keys to files\n");
	printf ("  --password\t\t\t\tSet MOK password\n");
	printf ("  --clear-password\t\t\tClear MOK password\n");
	printf ("  --disable-validation\t\t\tDisable signature validation\n");
	printf ("  --enable-validation\t\t\tEnable signature validation\n");
	printf ("  --sb-state\t\t\t\tShow SecureBoot State\n");
	printf ("  --test-key <der file>\t\t\tTest if the key is enrolled or not\n");
	printf ("  --reset\t\t\t\tReset MOK list\n");
	printf ("  --generate-hash[=password]\t\tGenerate the password hash\n");
	printf ("  --ignore-db\t\t\t\tIgnore DB for validation\n");
	printf ("  --use-db\t\t\t\tUse DB for validation\n");
	printf ("  --import-hash <hash>\t\t\tImport a hash into MOK or MOKX\n");
	printf ("  --delete-hash <hash>\t\t\tDelete a hash in MOK or MOKX\n");
	printf ("  --set-verbosity <true/false>\t\tSet the verbosity bit for shim\n");
	printf ("  --pk\t\t\t\t\tList the keys in PK\n");
	printf ("  --kek\t\t\t\t\tList the keys in KEK\n");
	printf ("  --db\t\t\t\t\tList the keys in db\n");
	printf ("  --dbx\t\t\t\t\tList the keys in dbx\n");
	printf ("\n");
	printf ("Supplimentary Options:\n");
	printf ("  --hash-file <hash file>\t\tUse the specific password hash\n");
	printf ("  --root-pw\t\t\t\tUse the root password\n");
	printf ("  --simple-hash\t\t\t\tUse the old password hash method\n");
	printf ("  --mokx\t\t\t\tManipulate the MOK blacklist\n");
}

static int
test_and_delete_var (const char *var_name)
{
	efi_variable_t var;

	memset (&var, 0, sizeof(var));
	var.VariableName = var_name;

	var.VendorGuid = SHIM_LOCK_GUID;

	if (test_variable (&var) == EFI_SUCCESS) {
		if (delete_variable (&var) != EFI_SUCCESS) {
			fprintf (stderr, "Failed to unset %s\n", var_name);
			return -1;
		}
	}

	return 0;
}

static const char*
efi_hash_to_string (efi_guid_t hash_type)
{
	if (efi_guidcmp (hash_type, EfiHashSha1Guid) == 0) {
		return "SHA1";
	} else if (efi_guidcmp (hash_type, EfiHashSha224Guid) == 0) {
		return "SHA224";
	} else if (efi_guidcmp (hash_type, EfiHashSha256Guid) == 0) {
		return "SHA256";
	} else if (efi_guidcmp (hash_type, EfiHashSha384Guid) == 0) {
		return "SHA384";
	} else if (efi_guidcmp (hash_type, EfiHashSha512Guid) == 0) {
		return "SHA512";
	}

	return NULL;
}

static uint32_t
efi_hash_size (efi_guid_t hash_type)
{
	if (efi_guidcmp (hash_type, EfiHashSha1Guid) == 0) {
		return SHA_DIGEST_LENGTH;
	} else if (efi_guidcmp (hash_type, EfiHashSha224Guid) == 0) {
		return SHA224_DIGEST_LENGTH;
	} else if (efi_guidcmp (hash_type, EfiHashSha256Guid) == 0) {
		return SHA256_DIGEST_LENGTH;
	} else if (efi_guidcmp (hash_type, EfiHashSha384Guid) == 0) {
		return SHA384_DIGEST_LENGTH;
	} else if (efi_guidcmp (hash_type, EfiHashSha512Guid) == 0) {
		return SHA512_DIGEST_LENGTH;
	}

	return 0;
}

static uint32_t
signature_size (efi_guid_t hash_type)
{
	uint32_t hash_size;

	hash_size = efi_hash_size (hash_type);
	if (hash_size)
		return (hash_size + sizeof(efi_guid_t));

	return 0;
}

static MokListNode*
build_mok_list (void *data, unsigned long data_size, uint32_t *mok_num)
{
	MokListNode *list = NULL;
	EFI_SIGNATURE_LIST *CertList = data;
	EFI_SIGNATURE_DATA *Cert;
	unsigned long dbsize = data_size;
	unsigned long count = 0;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if ((efi_guidcmp (CertList->SignatureType, EfiCertX509Guid) != 0) &&
		    (efi_guidcmp (CertList->SignatureType, EfiHashSha1Guid) != 0) &&
		    (efi_guidcmp (CertList->SignatureType, EfiHashSha224Guid) != 0) &&
		    (efi_guidcmp (CertList->SignatureType, EfiHashSha256Guid) != 0) &&
		    (efi_guidcmp (CertList->SignatureType, EfiHashSha384Guid) != 0) &&
		    (efi_guidcmp (CertList->SignatureType, EfiHashSha512Guid) != 0)) {
			dbsize -= CertList->SignatureListSize;
			CertList = (EFI_SIGNATURE_LIST *)((uint8_t *) CertList +
						  CertList->SignatureListSize);
			continue;
		}

		if ((efi_guidcmp (CertList->SignatureType, EfiCertX509Guid) != 0) &&
		    (CertList->SignatureSize != signature_size (CertList->SignatureType))) {
			dbsize -= CertList->SignatureListSize;
			CertList = (EFI_SIGNATURE_LIST *)((uint8_t *) CertList +
						  CertList->SignatureListSize);
			continue;
		}

		Cert = (EFI_SIGNATURE_DATA *) (((uint8_t *) CertList) +
		  sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);

		list = realloc(list, sizeof(MokListNode) * (count + 1));

		if (!list) {
			fprintf(stderr, "Unable to allocate MOK list\n");
			return NULL;
		}

		list[count].header = CertList;
		if (efi_guidcmp (CertList->SignatureType, EfiCertX509Guid) == 0) {
			/* X509 certificate */
			list[count].mok_size = CertList->SignatureSize -
					       sizeof(efi_guid_t);
			list[count].mok = (void *)Cert->SignatureData;
		} else {
			/* hash array */
			list[count].mok_size = CertList->SignatureListSize -
					       sizeof(EFI_SIGNATURE_LIST) -
					       CertList->SignatureHeaderSize;
			list[count].mok = (void *)Cert;
		}

		count++;
		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((uint8_t *) CertList +
						  CertList->SignatureListSize);
	}

	*mok_num = count;

	return list;
}

static int
print_x509 (char *cert, int cert_size)
{
	X509 *X509cert;
	BIO *cert_bio;
	SHA_CTX ctx;
	uint8_t fingerprint[SHA_DIGEST_LENGTH];
	int i;

	cert_bio = BIO_new (BIO_s_mem ());
	BIO_write (cert_bio, cert, cert_size);
	if (cert_bio == NULL) {
		fprintf (stderr, "Failed to write BIO\n");
		return -1;
	}

	X509cert = d2i_X509_bio (cert_bio, NULL);
	if (X509cert == NULL) {
		fprintf (stderr, "Invalid X509 certificate\n");
		return -1;
	}

	SHA1_Init (&ctx);
	SHA1_Update (&ctx, cert, cert_size);
	SHA1_Final (fingerprint, &ctx);

	printf ("SHA1 Fingerprint: ");
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		printf ("%02x", fingerprint[i]);
		if (i < SHA_DIGEST_LENGTH - 1)
			printf (":");
	}
	printf ("\n");
	X509_print_fp (stdout, X509cert);

	BIO_free (cert_bio);

	return 0;
}

static int
print_hash_array (efi_guid_t hash_type, void *hash_array, uint32_t array_size)
{
	uint32_t hash_size, remain;
	uint32_t sig_size;
	uint8_t *hash;
	const char *name;
	int i;

	if (!hash_array || array_size == 0) {
		fprintf (stderr, "invalid hash array\n");
		return -1;
	}

	name = efi_hash_to_string (hash_type);
	hash_size = efi_hash_size (hash_type);
	sig_size = hash_size + sizeof(efi_guid_t);

	if (!name) {
		fprintf (stderr, "unknown hash type\n");
		return -1;
	}

	printf ("  [%s]\n", name);
	remain = array_size;
	hash = (uint8_t *)hash_array;

	while (remain > 0) {
		if (remain < sig_size) {
			fprintf (stderr, "invalid array size\n");
			return -1;
		}

		printf ("  ");
		hash += sizeof(efi_guid_t);
		for (i = 0; i<hash_size; i++)
			printf ("%02x", *(hash + i));
		printf ("\n");
		hash += hash_size;
		remain -= sig_size;
	}

	return 0;
}

static int
list_keys (efi_variable_t *var)
{
	uint32_t mok_num;
	MokListNode *list;
	int i;

	list = build_mok_list (var->Data, var->DataSize, &mok_num);
	if (list == NULL) {
		return -1;
	}

	for (i = 0; i < mok_num; i++) {
		printf ("[key %d]\n", i+1);
		if (efi_guidcmp (list[i].header->SignatureType, EfiCertX509Guid) == 0) {
			print_x509 ((char *)list[i].mok, list[i].mok_size);
		} else {
			print_hash_array (list[i].header->SignatureType,
					  list[i].mok, list[i].mok_size);
		}
		if (i < mok_num - 1)
			printf ("\n");
	}

	free (list);

	return 0;
}

/* match the hash in the hash array and return the index if matched */
static int
match_hash_array (efi_guid_t hash_type, const void *hash,
		  const void *hash_array, const uint32_t array_size)
{
	uint32_t hash_size, hash_count;
	uint32_t sig_size;
	int i;
	void *ptr;

	hash_size = efi_hash_size (hash_type);
	if (!hash_size)
		return -1;

	sig_size = hash_size + sizeof(efi_guid_t);
	if ((array_size % sig_size) != 0) {
		fprintf (stderr, "invalid hash array size\n");
		return -1;
	}

	ptr = (void *)hash_array;
	hash_count = array_size / sig_size;
	for (i = 0; i < hash_count; i++) {
		ptr += sizeof(efi_guid_t);
		if (memcmp (ptr, hash, hash_size) == 0)
			return i;
		ptr += hash_size;
	}

	return -1;
}

static int
delete_data_from_list (efi_guid_t type, void *data, uint32_t data_size,
		       const char *var_name, efi_guid_t guid)
{
	efi_variable_t var;
	MokListNode *list;
	uint32_t mok_num, total, remain;
	void *end, *start = NULL;
	int i, del_ind, ret = 0;
	uint32_t sig_list_size, sig_size;

	if (!var_name || !data || data_size == 0)
		return 0;

	memset (&var, 0, sizeof(var));
	var.VariableName = var_name;
	var.VendorGuid = guid;

	if (read_variable (&var) != EFI_SUCCESS)
		return 0;

	total = var.DataSize;

	list = build_mok_list (var.Data, var.DataSize, &mok_num);
	if (list == NULL)
		goto done;

	remain = total;
	for (i = 0; i < mok_num; i++) {
		remain -= list[i].header->SignatureListSize;
		if (efi_guidcmp (list[i].header->SignatureType, type) != 0)
			continue;

		sig_list_size = list[i].header->SignatureListSize;

		if (efi_guidcmp (type, EfiCertX509Guid) == 0) {
			if (list[i].mok_size != data_size)
				continue;

			if (memcmp (list[i].mok, data, data_size) == 0) {
				/* Remove this key */
				start = (void *)list[i].header;
				end = start + sig_list_size;
				total -= sig_list_size;
				break;
			}
		} else {
			del_ind = match_hash_array (type, data, list[i].mok,
						    list[i].mok_size);
			if (del_ind < 0)
				continue;

			start = (void *)list[i].header;
			sig_size = signature_size (type);
			if (sig_list_size == (sizeof(EFI_SIGNATURE_LIST) + sig_size)) {
				/* Only one hash in the list */
				end = start + sig_list_size;
				total -= sig_list_size;
			} else {
				/* More than one hash in the list */
				start += sizeof(EFI_SIGNATURE_LIST) + sig_size * del_ind;
				end = start + sig_size;
				total -= sig_size;
				list[i].header->SignatureListSize -= sig_size;
				remain += sig_list_size - sizeof(EFI_SIGNATURE_LIST) -
					  (del_ind + 1) * sig_size;
			}
			break;
		}
	}

	/* the key or hash is not in this list */
	if (start == NULL)
		return 0;

	/* all keys are removed */
	if (total == 0) {
		test_and_delete_var (var_name);

		/* delete the password */
		if (strcmp (var_name, "MokNew") == 0)
			test_and_delete_var ("MokAuth");
		else if (strcmp (var_name, "MokXNew") == 0)
			test_and_delete_var ("MokXAuth");
		else if (strcmp (var_name, "MokDel") == 0)
			test_and_delete_var ("MokDelAuth");
		else if (strcmp (var_name, "MokXDel") == 0)
			test_and_delete_var ("MokXDelAuth");

		ret = 1;
		goto done;
	}

	/* remove the key or hash  */
	if (remain > 0)
		memmove (start, end, remain);

	var.DataSize = total;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_protected_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to write %s\n", var_name);
		goto done;
	}

	ret = 1;
done:
	if (list)
		free (list);
	free (var.Data);

	return ret;
}

static int
list_keys_in_var (const char *var_name, const efi_guid_t guid)
{
	efi_variable_t var;
	efi_status_t status;
	int ret;

	memset (&var, 0, sizeof(var));
	var.VariableName = var_name;
	var.VendorGuid = guid;

	status = read_variable (&var);
	if (status != EFI_SUCCESS) {
		if (status == EFI_NOT_FOUND) {
			printf ("%s is empty\n", var_name);
			return 0;
		}

		fprintf (stderr, "Failed to read %s\n", var_name);
		return -1;
	}

	ret = list_keys (&var);
	free (var.Data);

	return ret;
}

static int
read_hidden_line (char **line, size_t *n)
{
	struct termios old, new;
	int nread;
	int isTTY = isatty(fileno (stdin));

	if (isTTY) {
		/* Turn echoing off and fail if we can't. */
		if (tcgetattr (fileno (stdin), &old) != 0)
			return -1;

		new = old;
		new.c_lflag &= ~ECHO;

		if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
			return -1;
	}

	/* Read the password. */
	nread = getline (line, n, stdin);

	if (isTTY) {
		/* Restore terminal. */
		(void) tcsetattr (fileno (stdin), TCSAFLUSH, &old);
	}

	/* Remove the newline */
	(*line)[nread-1] = '\0';

	return nread-1;
}

static int
get_password (char **password, int *len, int min, int max)
{
	char *password_1, *password_2;
	int len_1, len_2, fail, ret = -1;
	size_t n;

	password_1 = password_2 = NULL;

	fail = 0;

	while (fail < 3) {
		printf ("input password: ");
		len_1 = read_hidden_line (&password_1, &n);
		printf ("\n");

		if (len_1 > max || len_1 < min) {
			fail++;
			fprintf (stderr, "password should be %d~%d characters\n",
				 min, max);
		} else {
			break;
		}
	}

	if (fail >= 3) {
		if (password_1)
			free (password_1);
		goto error;
	}

	fail = 0;

	while (fail < 3) {
		printf ("input password again: ");
		len_2 = read_hidden_line (&password_2, &n);
		printf ("\n");

		if (len_1 != len_2 || strcmp (password_1, password_2) != 0) {
			fail++;
			fprintf (stderr, "password doesn't match\n");
		} else {
			break;
		}
	}

	if (fail >= 3)
		goto error;

	*password = password_1;
	*len = len_1;

	ret = 0;
error:
	if (password_2)
		free (password_2);

	return ret;
}

static int
generate_auth (void *new_list, int list_len, char *password, int pw_len,
	       uint8_t *auth)
{
	efi_char16_t efichar_pass[PASSWORD_MAX+1];
	unsigned long efichar_len;
	SHA256_CTX ctx;

	if (!password || !auth)
		return -1;

	efichar_len = efichar_from_char (efichar_pass, password,
					 (PASSWORD_MAX+1)*sizeof(efi_char16_t));

	SHA256_Init (&ctx);

	if (new_list)
		SHA256_Update (&ctx, new_list, list_len);

	SHA256_Update (&ctx, efichar_pass, efichar_len);

	SHA256_Final (auth, &ctx);

	return 0;
}

static void
generate_salt (char salt[], unsigned int salt_size)
{
	struct timeval tv;
	char *rand_str;
	int remain = salt_size;

	salt[0] = '\0';

	(void) gettimeofday (&tv, NULL);
	srandom (tv.tv_sec ^ tv.tv_usec ^ getpid ());

	do {
		rand_str = l64a (random());
		strncat (salt, rand_str, remain);
		remain = remain - strlen(rand_str);
	} while (remain > 0);

	salt[salt_size] = '\0';
}

static int
generate_hash (pw_crypt_t *pw_crypt, char *password, int pw_len)
{
	pw_crypt_t new_crypt;
	char settings[SETTINGS_LEN];
	char *crypt_string;
	const char *prefix;
	int hash_len, prefix_len;

	if (!password || !pw_crypt)
		return -1;

	prefix = get_crypt_prefix (pw_crypt->method);
	if (!prefix)
		return -1;
	prefix_len = strlen(prefix);

	pw_crypt->salt_size = get_salt_size (pw_crypt->method);
	generate_salt ((char *)pw_crypt->salt, pw_crypt->salt_size);

	strncpy (settings, prefix, prefix_len);
	strncpy (settings + prefix_len, (const char *)pw_crypt->salt,
		 pw_crypt->salt_size);
	settings[pw_crypt->salt_size + prefix_len] = '\0';

	crypt_string = crypt (password, settings);
	if (!crypt_string)
		return -1;

	if (decode_pass (crypt_string, &new_crypt) < 0)
		return -1;

	hash_len = get_hash_size (new_crypt.method);
	if (hash_len < 0)
		return -1;
	memcpy (pw_crypt->hash, new_crypt.hash, hash_len);
	pw_crypt->iter_count = new_crypt.iter_count;

	if (pw_crypt->method == BLOWFISH_BASED) {
		pw_crypt->salt_size = new_crypt.salt_size;
		memcpy (pw_crypt->salt, new_crypt.salt, new_crypt.salt_size);
	}

	return 0;
}

static int
get_hash_from_file (const char *file, pw_crypt_t *pw_crypt)
{
	char string[300];
	ssize_t read_len = 0;
	int fd;

	fd = open (file, O_RDONLY);
	if (fd < 0) {
		fprintf (stderr, "Failed to open %s\n", file);
		return -1;
	}

	while (read_len < 300) {
		int rc = read (fd, string + read_len, 300 - read_len);
		if (rc == EAGAIN)
			continue;
		if (rc < 0) {
			fprintf (stderr, "Failed to read %s: %m\n", file);
			close (fd);
			return -1;
		}
		if (rc == 0)
			break;
		read_len += rc;
	}
	close (fd);

	if (string[read_len-1] != '\0') {
		fprintf (stderr, "corrupted string\n");
		return -1;
	}

	if (decode_pass (string, pw_crypt) < 0) {
		fprintf (stderr, "Failed to parse the string\n");
		return -1;
	}

	return 0;
}

static int
get_password_from_shadow (pw_crypt_t *pw_crypt)
{
	struct spwd *pw_ent;

	pw_ent = getspnam ("root");
	if (!pw_ent)
		return -1;

	if (decode_pass (pw_ent->sp_pwdp, pw_crypt) < 0)
		return -1;

	return 0;
}

static int
update_request (void *new_list, int list_len, MokRequest req,
		const char *hash_file, const int root_pw)
{
	efi_variable_t var;
	const char *req_name, *auth_name;
	pw_crypt_t pw_crypt;
	uint8_t auth[SHA256_DIGEST_LENGTH];
	char *password = NULL;
	int pw_len;
	int auth_ret;
	int ret = -1;

	bzero (&pw_crypt, sizeof(pw_crypt_t));
	pw_crypt.method = DEFAULT_CRYPT_METHOD;

	switch (req) {
	case ENROLL_MOK:
		req_name = "MokNew";
		auth_name = "MokAuth";
		break;
	case DELETE_MOK:
		req_name = "MokDel";
		auth_name = "MokDelAuth";
		break;
	case ENROLL_BLACKLIST:
		req_name = "MokXNew";
		auth_name = "MokXAuth";
		break;
	case DELETE_BLACKLIST:
		req_name = "MokXDel";
		auth_name = "MokXDelAuth";
		break;
	default:
		return -1;
	}

	if (hash_file) {
		if (get_hash_from_file (hash_file, &pw_crypt) < 0) {
			fprintf (stderr, "Failed to read hash\n");
			goto error;
		}
	} else if (root_pw) {
		if (get_password_from_shadow (&pw_crypt) < 0) {
			fprintf (stderr, "Failed to get root password hash\n");
			goto error;
		}
	} else {
		if (get_password (&password, &pw_len, PASSWORD_MIN, PASSWORD_MAX) < 0) {
			fprintf (stderr, "Abort\n");
			goto error;
		}

		if (!use_simple_hash) {
			auth_ret = generate_hash (&pw_crypt, password, pw_len);
		} else {
			auth_ret = generate_auth (new_list, list_len, password,
						  pw_len, auth);
		}
		if (auth_ret < 0) {
			fprintf (stderr, "Couldn't generate hash\n");
			goto error;
		}
	}

	if (new_list) {
		/* Write MokNew, MokDel, MokXNew, or MokXDel*/
		var.Data = new_list;
		var.DataSize = list_len;
		var.VariableName = req_name;

		var.VendorGuid = SHIM_LOCK_GUID;
		var.Attributes = EFI_VARIABLE_NON_VOLATILE
			| EFI_VARIABLE_BOOTSERVICE_ACCESS
			| EFI_VARIABLE_RUNTIME_ACCESS;

		if (edit_variable (&var) != EFI_SUCCESS) {
			switch (req) {
			case ENROLL_MOK:
				fprintf (stderr, "Failed to enroll new keys\n");
				break;
			case ENROLL_BLACKLIST:
				fprintf (stderr, "Failed to enroll blacklist\n");
				break;
			case DELETE_MOK:
				fprintf (stderr, "Failed to delete keys\n");
				break;
			case DELETE_BLACKLIST:
				fprintf (stderr, "Failed to delete blacklist\n");
				break;
			}
			goto error;
		}
	} else {
		test_and_delete_var (req_name);
	}

	/* Write MokAuth, MokDelAuth, MokXAuth, or MokXDelAuth */
	if (!use_simple_hash) {
		var.Data = (void *)&pw_crypt;
		var.DataSize = PASSWORD_CRYPT_SIZE;
	} else {
		var.Data = (void *)auth;
		var.DataSize = SHA256_DIGEST_LENGTH;
	}
	var.VariableName = auth_name;

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_protected_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to write %s\n", auth_name);
		test_and_delete_var (req_name);
		goto error;
	}

	ret = 0;
error:
	if (password)
		free (password);
	return ret;
}

static int
is_valid_cert (void *cert, uint32_t cert_size)
{
	X509 *X509cert;
	BIO *cert_bio;

	cert_bio = BIO_new (BIO_s_mem ());
	BIO_write (cert_bio, cert, cert_size);
	if (cert_bio == NULL) {
		return 0;
	}

	X509cert = d2i_X509_bio (cert_bio, NULL);
	if (X509cert == NULL) {
		BIO_free (cert_bio);
		return 0;
	}

	BIO_free (cert_bio);

	return 1;
}

static int
is_duplicate (efi_guid_t type, const void *data, const uint32_t data_size,
	      efi_guid_t vendor, const char *db_name)
{
	efi_variable_t var;
	uint32_t node_num;
	MokListNode *list;
	int i, ret = 0;

	if (!data || data_size == 0 || !db_name)
		return 0;

	memset (&var, 0, sizeof(var));
	var.VariableName = db_name;
	var.VendorGuid = vendor;

	if (read_variable (&var) != EFI_SUCCESS)
		return 0;

	list = build_mok_list (var.Data, var.DataSize, &node_num);
	if (list == NULL) {
		goto done;
	}

	for (i = 0; i < node_num; i++) {
		if (efi_guidcmp (list[i].header->SignatureType, type) != 0)
			continue;

		if (efi_guidcmp (type, EfiCertX509Guid) == 0) {
			if (list[i].mok_size != data_size)
				continue;

			if (memcmp (list[i].mok, data, data_size) == 0) {
				ret = 1;
				break;
			}
		} else {
			if (match_hash_array (type, data, list[i].mok,
					      list[i].mok_size) >= 0) {
				ret = 1;
				break;
			}
		}
	}

done:
	if (list)
		free (list);
	free (var.Data);

	return ret;
}

static int
is_valid_request (efi_guid_t type, void *mok, uint32_t mok_size, MokRequest req)
{
	switch (req) {
	case ENROLL_MOK:
		if (is_duplicate (type, mok, mok_size, EFI_GLOBAL_VARIABLE, "PK") ||
		    is_duplicate (type, mok, mok_size, EFI_GLOBAL_VARIABLE, "KEK") ||
		    is_duplicate (type, mok, mok_size, EFI_IMAGE_SECURITY_DATABASE_GUID, "db") ||
		    is_duplicate (type, mok, mok_size, SHIM_LOCK_GUID, "MokListRT") ||
		    is_duplicate (type, mok, mok_size, SHIM_LOCK_GUID, "MokNew")) {
			return 0;
		}
		break;
	case DELETE_MOK:
		if (!is_duplicate (type, mok, mok_size, SHIM_LOCK_GUID, "MokListRT") ||
		    is_duplicate (type, mok, mok_size, SHIM_LOCK_GUID, "MokDel")) {
			return 0;
		}
		break;
	case ENROLL_BLACKLIST:
		if (is_duplicate (type, mok, mok_size, SHIM_LOCK_GUID, "MokListXRT") ||
		    is_duplicate (type, mok, mok_size, SHIM_LOCK_GUID, "MokXNew")) {
			return 0;
		}
		break;
	case DELETE_BLACKLIST:
		if (!is_duplicate (type, mok, mok_size, SHIM_LOCK_GUID, "MokListXRT") ||
		    is_duplicate (type, mok, mok_size, SHIM_LOCK_GUID, "MokXDel")) {
			return 0;
		}
		break;
	}

	return 1;
}

static int
in_pending_request (efi_guid_t type, void *data, uint32_t data_size,
		    MokRequest req)
{
	efi_variable_t authvar;
	const char *var_name;

	if (!data || data_size == 0)
		return 0;

	memset (&authvar, 0, sizeof(authvar));
	authvar.VendorGuid = SHIM_LOCK_GUID;

	switch (req) {
	case ENROLL_MOK:
		var_name = "MokDel";
		authvar.VariableName = "MokDelAuth";
		break;
	case DELETE_MOK:
		var_name = "MokNew";
		authvar.VariableName = "MokAuth";
		break;
	case ENROLL_BLACKLIST:
		var_name = "MokXDel";
		authvar.VariableName = "MokXDelAuth";
		break;
	case DELETE_BLACKLIST:
		var_name = "MokXNew";
		authvar.VariableName = "MokXAuth";
		break;
	default:
		return 0;
	}

	if (read_variable (&authvar) != EFI_SUCCESS) {
		return 0;
	}

	free (authvar.Data);
	/* Check if the password hash is in the old format */
	if (authvar.DataSize == SHA256_DIGEST_LENGTH)
		return 0;

	if (delete_data_from_list (type, data, data_size, var_name,
				   SHIM_LOCK_GUID))
			return 1;

	return 0;
}

static int
issue_mok_request (char **files, uint32_t total, MokRequest req,
		   const char *hash_file, const int root_pw)
{
	efi_variable_t old_req;
	const char *req_name;
	const char *reverse_req;
	void *new_list = NULL;
	void *ptr;
	struct stat buf;
	unsigned long list_size = 0;
	unsigned long real_size = 0;
	uint32_t *sizes = NULL;
	int fd = -1;
	ssize_t read_size;
	int i, ret = -1;
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *CertData;

	if (!files)
		return -1;

	switch (req) {
	case ENROLL_MOK:
		req_name = "MokNew";
		reverse_req = "MokDel";
		break;
	case DELETE_MOK:
		req_name = "MokDel";
		reverse_req = "MokNew";
		break;
	case ENROLL_BLACKLIST:
		req_name = "MokXNew";
		reverse_req = "MokXDel";
		break;
	case DELETE_BLACKLIST:
		req_name = "MokXDel";
		reverse_req = "MokXNew";
		break;
	default:
		return -1;
	}

	sizes = malloc (total * sizeof(uint32_t));

	memset (&old_req, 0, sizeof(old_req));

	if (!sizes) {
		fprintf (stderr, "Failed to allocate space for sizes\n");
		goto error;
	}

	/* get the sizes of the key files */
	for (i = 0; i < total; i++) {
		if (stat (files[i], &buf) != 0) {
			fprintf (stderr, "Failed to get file status, %s\n",
			         files[i]);
			goto error;
		}

		sizes[i] = buf.st_size;
		list_size += buf.st_size;
	}

	list_size += sizeof(EFI_SIGNATURE_LIST) * total;
	list_size += sizeof(efi_guid_t) * total;

	old_req.VariableName = req_name;
	old_req.VendorGuid = SHIM_LOCK_GUID;
	if (read_variable (&old_req) == EFI_SUCCESS)
		list_size += old_req.DataSize;

	new_list = malloc (list_size);
	if (!new_list) {
		fprintf (stderr, "Failed to allocate space for %s\n", req_name);
		goto error;
	}
	ptr = new_list;

	for (i = 0; i < total; i++) {
		CertList = ptr;
		CertData = (EFI_SIGNATURE_DATA *)(((uint8_t *)ptr) +
						  sizeof(EFI_SIGNATURE_LIST));

		CertList->SignatureType = EfiCertX509Guid;
		CertList->SignatureListSize = sizes[i] +
		   sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1;
		CertList->SignatureHeaderSize = 0;
		CertList->SignatureSize = sizes[i] + sizeof(efi_guid_t);
		CertData->SignatureOwner = SHIM_LOCK_GUID;

		fd = open (files[i], O_RDONLY);
		if (fd == -1) {
			fprintf (stderr, "Failed to open %s\n", files[i]);
			goto error;
		}

		ptr = CertData->SignatureData;

		/* Mok */
		read_size = read (fd, ptr, sizes[i]);
		if (read_size < 0 || read_size != sizes[i]) {
			fprintf (stderr, "Failed to read %s\n", files[i]);
			goto error;
		}
		if (!is_valid_cert (ptr, read_size)) {
			fprintf (stderr, "Warning!!! %s is not a valid x509 certificate in DER format\n",
			         files[i]);
		}

		if (is_valid_request (EfiCertX509Guid, ptr, sizes[i], req)) {
			ptr += sizes[i];
			real_size += sizes[i] + sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t);
		} else if (in_pending_request (EfiCertX509Guid, ptr, sizes[i], req)) {
			printf ("Removed %s from %s\n", files[i], reverse_req);
			ptr -= sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t);
		} else {
			printf ("Skip %s\n", files[i]);
			ptr -= sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t);
		}

		close (fd);
	}

	/* All keys are in the list, nothing to do here... */
	if (real_size == 0) {
		ret = 0;
		goto error;
	}

	/* append the keys to the previous request */
	if (old_req.Data) {
		memcpy (new_list + real_size, old_req.Data, old_req.DataSize);
		real_size += old_req.DataSize;
	}

	if (update_request (new_list, real_size, req, hash_file, root_pw) < 0) {
		goto error;
	}

	ret = 0;
error:
	if (old_req.Data)
		free (old_req.Data);
	if (sizes)
		free (sizes);
	if (new_list)
		free (new_list);

	return ret;
}

static int
identify_hash_type (const char *hash_str, efi_guid_t *type)
{
	int len = strlen (hash_str);
	int hash_size;
	int i;

	for (i = 0; i < len; i++) {
		if ((hash_str[i] > '9' || hash_str[i] < '0') &&
		    (hash_str[i] > 'f' || hash_str[i] < 'a') &&
		    (hash_str[i] > 'F' || hash_str[i] < 'A'))
		return -1;
	}

	switch (len) {
	case SHA_DIGEST_LENGTH*2:
		*type = EfiHashSha1Guid;
		hash_size = SHA_DIGEST_LENGTH;
		break;
	case SHA224_DIGEST_LENGTH*2:
		*type = EfiHashSha224Guid;
		hash_size = SHA224_DIGEST_LENGTH;
		break;
	case SHA256_DIGEST_LENGTH*2:
		*type = EfiHashSha256Guid;
		hash_size = SHA256_DIGEST_LENGTH;
		break;
	case SHA384_DIGEST_LENGTH*2:
		*type = EfiHashSha384Guid;
		hash_size = SHA384_DIGEST_LENGTH;
		break;
	case SHA512_DIGEST_LENGTH*2:
		*type = EfiHashSha512Guid;
		hash_size = SHA512_DIGEST_LENGTH;
		break;
	default:
		return -1;
	}

	return hash_size;
}

static int
hex_str_to_binary (const char *hex_str, uint8_t *array, int len)
{
	char *pos;
	int i;

	if (!hex_str || !array)
		return -1;

	pos = (char *)hex_str;
	for (i = 0; i < len; i++) {
		sscanf (pos, "%2hhx", &array[i]);
		pos += 2;
	}

	return 0;
}

static int
issue_hash_request (const char *hash_str, MokRequest req,
		    const char *hash_file, const int root_pw)
{
	efi_variable_t old_req;
	const char *req_name;
	const char *reverse_req;
	void *new_list = NULL;
	void *ptr;
	unsigned long list_size = 0;
	uint32_t sig_size, sig_list_size;
	int ret = -1;
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *CertData;
	efi_guid_t hash_type;
	uint8_t db_hash[SHA512_DIGEST_LENGTH];
	int hash_size;
	int merge_ind = -1;
	uint8_t valid = 0;
	MokListNode *mok_list = NULL;
	uint32_t mok_num;

	if (!hash_str)
		return -1;

	hash_size = identify_hash_type (hash_str, &hash_type);
	if (hash_size < 0)
		return -1;

	if (hex_str_to_binary (hash_str, db_hash, hash_size) < 0)
		return -1;

	memset (&old_req, 0, sizeof(old_req));

	switch (req) {
	case ENROLL_MOK:
		req_name = "MokNew";
		reverse_req = "MokDel";
		break;
	case DELETE_MOK:
		req_name = "MokDel";
		reverse_req = "MokNew";
		break;
	case ENROLL_BLACKLIST:
		req_name = "MokXNew";
		reverse_req = "MokXDel";
		break;
	case DELETE_BLACKLIST:
		req_name = "MokXDel";
		reverse_req = "MokXNew";
		break;
	default:
		return -1;
	}

	if (is_valid_request (hash_type, db_hash, hash_size, req)) {
		valid = 1;
	} else if (in_pending_request (hash_type, db_hash, hash_size, req)) {
		printf ("Removed hash from %s\n", reverse_req);
	} else {
		printf ("Skip hash\n");
	}

	if (!valid) {
		ret = 0;
		goto error;
	}

	old_req.VariableName = req_name;
	old_req.VendorGuid = SHIM_LOCK_GUID;

	list_size = sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t) + hash_size;

	if (read_variable (&old_req) == EFI_SUCCESS) {
		int i;
		list_size += old_req.DataSize;

		mok_list = build_mok_list (old_req.Data, old_req.DataSize,
					   &mok_num);
		if (mok_list == NULL)
			goto error;

		/* Check if there is a signature list with the same type */
		for (i = 0; i < mok_num; i++) {
			if (efi_guidcmp (mok_list[i].header->SignatureType,
					 hash_type) == 0) {
				merge_ind = i;
				list_size -= sizeof(EFI_SIGNATURE_LIST);
				break;
			}
		}
	}

	new_list = malloc (list_size);
	if (!new_list) {
		fprintf (stderr, "Failed to allocate space for %s\n", req_name);
		goto error;
	}
	ptr = new_list;

	if (merge_ind < 0) {
		/* Create a new signature list for the hash */
		sig_list_size = sizeof(EFI_SIGNATURE_LIST) +
				sizeof(efi_guid_t) + hash_size;
		CertList = ptr;
		CertList->SignatureType = hash_type;
		CertList->SignatureListSize = sig_list_size;
		CertList->SignatureHeaderSize = 0;
		CertList->SignatureSize = hash_size + sizeof(efi_guid_t);

		CertData = (EFI_SIGNATURE_DATA *)(((uint8_t *)ptr) +
						  sizeof(EFI_SIGNATURE_LIST));
		CertData->SignatureOwner = SHIM_LOCK_GUID;
		memcpy (CertData->SignatureData, db_hash, hash_size);

		/* prepend the hash to the previous request */
		ptr += sig_list_size;
		if (old_req.Data) {
			memcpy (ptr, old_req.Data, old_req.DataSize);
		}
	} else {
		/* Merge the hash into an existed signature list */
		int i;

		for (i = 0; i < merge_ind; i++) {
			sig_list_size = mok_list[i].header->SignatureListSize;
			memcpy (ptr, (void *)mok_list[i].header, sig_list_size);
			ptr += sig_list_size;
		}

		/* Append the hash to the list */
		i = merge_ind;
		sig_list_size = mok_list[i].header->SignatureListSize;
		sig_size = hash_size + sizeof(efi_guid_t);
		mok_list[i].header->SignatureListSize += sig_size;
		memcpy (ptr, (void *)mok_list[i].header, sig_list_size);
		ptr += sig_list_size;
		memcpy (ptr, (void *)&hash_type, sizeof(efi_guid_t));
		ptr += sizeof(efi_guid_t);
		memcpy (ptr, db_hash, hash_size);
		ptr += hash_size;

		for (i = merge_ind + 1; i < mok_num; i++) {
			sig_list_size = mok_list[i].header->SignatureListSize;
			memcpy (ptr, (void *)mok_list[i].header, sig_list_size);
			ptr += sig_list_size;
		}
	}

	if (update_request (new_list, list_size, req, hash_file, root_pw) < 0) {
		goto error;
	}

	ret = 0;
error:
	if (old_req.Data)
		free (old_req.Data);
	if (mok_list)
		free (mok_list);
	if (new_list)
		free (new_list);

	return ret;
}

static int
revoke_request (MokRequest req)
{
	switch (req) {
	case ENROLL_MOK:
		if (test_and_delete_var ("MokNew") < 0)
			return -1;
		if (test_and_delete_var ("MokAuth") < 0)
			return -1;
		break;
	case DELETE_MOK:
		if (test_and_delete_var ("MokDel") < 0)
			return -1;
		if (test_and_delete_var ("MokDelAuth") < 0)
			return -1;
		break;
	case ENROLL_BLACKLIST:
		if (test_and_delete_var ("MokXNew") < 0)
			return -1;
		if (test_and_delete_var ("MokXAuth") < 0)
			return -1;
		break;
	case DELETE_BLACKLIST:
		if (test_and_delete_var ("MokXDel") < 0)
			return -1;
		if (test_and_delete_var ("MokXDelAuth") < 0)
			return -1;
		break;
	}

	return 0;
}

static int
export_moks ()
{
	efi_variable_t var;
	efi_status_t status;
	char filename[PATH_MAX];
	uint32_t mok_num;
	MokListNode *list;
	int i, fd;
	mode_t mode;
	ssize_t write_size;
	int ret = -1;

	memset (&var, 0, sizeof(var));
	var.VariableName = "MokListRT";
	var.VendorGuid = SHIM_LOCK_GUID;

	status = read_variable (&var);
	if (status != EFI_SUCCESS) {
		if (status == EFI_NOT_FOUND) {
			printf ("MokListRT is empty\n");
			return 0;
		}

		fprintf (stderr, "Failed to read MokListRT\n");
		return -1;
	}

	list = build_mok_list (var.Data, var.DataSize, &mok_num);
	if (list == NULL) {
		return -1;
	}

	/* mode 644 */
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	for (i = 0; i < mok_num; i++) {
		if (efi_guidcmp (list[i].header->SignatureType, EfiCertX509Guid) != 0)
			continue;

		/* Dump X509 certificate to files */
		snprintf (filename, PATH_MAX, "MOK-%04d.der", i+1);
		fd = open (filename, O_CREAT | O_WRONLY, mode);
		if (fd == -1) {
			fprintf (stderr, "Failed to open %s\n", filename);
			goto error;
		}

		write_size = write (fd, list[i].mok, list[i].mok_size);
		if (write_size != list[i].mok_size) {
			fprintf (stderr, "Failed to write %s\n", filename);
			close (fd);
			goto error;
		}

		close (fd);
	}

	ret = 0;
error:
	free (list);
	free (var.Data);

	return ret;
}

static int
set_password (const char *hash_file, const int root_pw, const int clear)
{
	efi_variable_t var;
	pw_crypt_t pw_crypt;
	uint8_t auth[SHA256_DIGEST_LENGTH];
	char *password = NULL;
	int pw_len;
	int auth_ret;
	int ret = -1;

	memset (&pw_crypt, 0, sizeof(pw_crypt_t));
	memset (auth, 0, SHA256_DIGEST_LENGTH);

	if (hash_file) {
		if (get_hash_from_file (hash_file, &pw_crypt) < 0) {
			fprintf (stderr, "Failed to read hash\n");
			goto error;
		}
	} else if (root_pw) {
		if (get_password_from_shadow (&pw_crypt) < 0) {
			fprintf (stderr, "Failed to get root password hash\n");
			goto error;
		}
	} else if (!clear) {
		if (get_password (&password, &pw_len, PASSWORD_MIN, PASSWORD_MAX) < 0) {
			fprintf (stderr, "Abort\n");
			goto error;
		}

		if (!use_simple_hash) {
			pw_crypt.method = DEFAULT_CRYPT_METHOD;
			auth_ret = generate_hash (&pw_crypt, password, pw_len);
		} else {
			auth_ret = generate_auth (NULL, 0, password, pw_len,
						  auth);
		}
		if (auth_ret < 0) {
			fprintf (stderr, "Couldn't generate hash\n");
			goto error;
		}
	}

	if (!use_simple_hash) {
		var.Data = (void *)&pw_crypt;
		var.DataSize = PASSWORD_CRYPT_SIZE;
	} else {
		var.Data = (void *)auth;
		var.DataSize = SHA256_DIGEST_LENGTH;
	}
	var.VariableName = "MokPW";

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_protected_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to write MokPW\n");
		goto error;
	}

	ret = 0;
error:
	if (password)
		free (password);
	return ret;
}

static int
set_toggle (const char * VarName, uint32_t state)
{
	efi_variable_t var;
	MokToggleVar tvar;
	char *password = NULL;
	int pw_len;
	efi_char16_t efichar_pass[SB_PASSWORD_MAX];
	int ret = -1;

	printf ("password length: %d~%d\n", SB_PASSWORD_MIN, SB_PASSWORD_MAX);
        if (get_password (&password, &pw_len, SB_PASSWORD_MIN, SB_PASSWORD_MAX) < 0) {
		fprintf (stderr, "Abort\n");
		goto error;
	}

	tvar.password_length = pw_len;

	efichar_from_char (efichar_pass, password,
			   SB_PASSWORD_MAX * sizeof(efi_char16_t));

	memcpy(tvar.password, efichar_pass,
	       SB_PASSWORD_MAX * sizeof(efi_char16_t));

	tvar.mok_toggle_state = state;

	var.VariableName = VarName;
	var.VendorGuid = SHIM_LOCK_GUID;
	var.Data = (void *)&tvar;
	var.DataSize = sizeof(tvar);
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
		| EFI_VARIABLE_BOOTSERVICE_ACCESS
		| EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_protected_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to request new %s state\n", VarName);
		goto error;
	}

	ret = 0;
error:
	if (password)
		free (password);
	return ret;
}

static int
disable_validation()
{
	return set_toggle("MokSB", 0);
}

static int
enable_validation()
{
	return set_toggle("MokSB", 1);
}

static int
sb_state ()
{
	efi_variable_t var;
	char *state;

	memset (&var, 0, sizeof(var));
	var.VariableName = "SecureBoot";
	var.VendorGuid = EFI_GLOBAL_VARIABLE;

	if (read_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to read SecureBoot\n");
		return -1;
	}

	state = (char *)var.Data;
	if (*state == 1) {
		printf ("SecureBoot enabled\n");
	} else if (*state == 0) {
		printf ("SecureBoot disabled\n");
	} else {
		printf ("SecureBoot unknown");
	}

	free (var.Data);

	return 0;
}

static int
disable_db()
{
	return set_toggle("MokDB", 0);
}

static int
enable_db()
{
	return set_toggle("MokDB", 1);
}

static inline int
read_file(int fd, void **bufp, size_t *lenptr) {
	int alloced = 0, size = 0, i = 0;
	void * buf = NULL;

	do {
		size += i;
		if ((size + 1024) > alloced) {
			alloced += 4096;
			buf = realloc (buf, alloced + 1);
		}
	} while ((i = read (fd, buf + size, 1024)) > 0);

	if (i < 0) {
		free (buf);
		return -1;
	}

	*bufp = buf;
	*lenptr = size;

	return 0;
}

static int
test_key (MokRequest req, const char *key_file)
{
	void *key = NULL;
	size_t read_size;
	int fd, rc, ret = -1;

	fd = open (key_file, O_RDONLY);
	if (fd < 0) {
		fprintf (stderr, "Failed to open %s\n", key_file);
		goto error;
	}

	rc = read_file (fd, &key, &read_size);
	if (rc < 0) {
		fprintf (stderr, "Failed to read %s\n", key_file);
		goto error;
	}

	if (is_valid_request (EfiCertX509Guid, key, read_size, req)) {
		printf ("%s is not enrolled\n", key_file);
		ret = 0;
	} else {
		printf ("%s is already enrolled\n", key_file);
		ret = 1;
	}

error:
	if (key)
		free (key);

	if (fd >= 0)
		close (fd);

	return ret;
}

static int
reset_moks (MokRequest req, const char *hash_file, const int root_pw)
{
	if (update_request (NULL, 0, req, hash_file, root_pw)) {
		fprintf (stderr, "Failed to issue a reset request\n");
		return -1;
	}

	return 0;
}

static int
generate_pw_hash (const char *input_pw)
{
	char settings[SETTINGS_LEN];
	char *password = NULL;
	char *crypt_string;
	const char *prefix;
	int prefix_len;
	int pw_len, salt_size;

	if (input_pw) {
		pw_len = strlen (input_pw);
		if (pw_len > PASSWORD_MAX || pw_len < PASSWORD_MIN) {
			fprintf (stderr, "invalid password length\n");
			return -1;
		}

		password = strdup (input_pw);

		if (!password) {
			fprintf (stderr, "Failed to duplicate string\n");
			return -1;
		}
	} else {
		if (get_password (&password, &pw_len, PASSWORD_MIN, PASSWORD_MAX) < 0) {
			fprintf (stderr, "Abort\n");
			return -1;
		}
	}

	prefix = get_crypt_prefix (DEFAULT_CRYPT_METHOD);
	if (!prefix)
		return -1;
	prefix_len = strlen(prefix);

	strncpy (settings, prefix, prefix_len);
	salt_size = get_salt_size (DEFAULT_CRYPT_METHOD);
	generate_salt ((settings + prefix_len), salt_size);
	settings[DEFAULT_SALT_SIZE + prefix_len] = '\0';

	crypt_string = crypt (password, settings);
	free (password);
	if (!crypt_string) {
		fprintf (stderr, "Failed to generate hash\n");
		return -1;
	}

	printf ("%s\n", crypt_string);

	return 0;
}

static int
set_verbosity (uint8_t verbosity)
{
	efi_variable_t var;

	if (verbosity) {
		var.VariableName = "SHIM_VERBOSE";
		var.VendorGuid = SHIM_LOCK_GUID;
		var.Data = (void *)&verbosity;
		var.DataSize = sizeof(uint8_t);
		var.Attributes = EFI_VARIABLE_NON_VOLATILE
			| EFI_VARIABLE_BOOTSERVICE_ACCESS
			| EFI_VARIABLE_RUNTIME_ACCESS;

		if (edit_protected_variable (&var) != EFI_SUCCESS) {
			fprintf (stderr, "Failed to set SHIM_VERBOSE\n");
			return -1;
		}
	} else {
		return test_and_delete_var ("SHIM_VERBOSE");
	}

	return 0;
}

static inline int
list_db (DBName db_name)
{
	switch (db_name) {
		case MOK_LIST_RT:
			return list_keys_in_var ("MokListRT", SHIM_LOCK_GUID);
		case MOK_LIST_X_RT:
			return list_keys_in_var ("MokListXRT", SHIM_LOCK_GUID);
		case PK:
			return list_keys_in_var ("PK", EFI_GLOBAL_VARIABLE);
		case KEK:
			return list_keys_in_var ("KEK", EFI_GLOBAL_VARIABLE);
		case DB:
			return list_keys_in_var ("db", EFI_IMAGE_SECURITY_DATABASE_GUID);
		case DBX:
			return list_keys_in_var ("dbx", EFI_IMAGE_SECURITY_DATABASE_GUID);
	}

	return -1;
}

int
main (int argc, char *argv[])
{
	char **files = NULL;
	char *key_file = NULL;
	char *hash_file = NULL;
	char *input_pw = NULL;
	char *hash_str = NULL;
	const char *option;
	int c, i, f_ind, total = 0;
	unsigned int command = 0;
	int use_root_pw = 0;
	uint8_t verbosity = 0;
	DBName db_name = MOK_LIST_RT;
	int ret = -1;

	use_simple_hash = 0;

	while (1) {
		static struct option long_options[] = {
			{"help",               no_argument,       0, 'h'},
			{"list-enrolled",      no_argument,       0, 'l'},
			{"list-new",	       no_argument,       0, 'N'},
			{"list-delete",	       no_argument,       0, 'D'},
			{"import",             required_argument, 0, 'i'},
			{"delete",             required_argument, 0, 'd'},
			{"revoke-import",      no_argument,       0, 0  },
			{"revoke-delete",      no_argument,       0, 0  },
			{"export",             no_argument,       0, 'x'},
			{"password",           no_argument,       0, 'p'},
			{"clear-password",     no_argument,       0, 'c'},
			{"disable-validation", no_argument,       0, 0  },
			{"enable-validation",  no_argument,       0, 0  },
			{"sb-state",           no_argument,       0, 0  },
			{"test-key",           required_argument, 0, 't'},
			{"reset",              no_argument,       0, 0  },
			{"hash-file",          required_argument, 0, 'f'},
			{"generate-hash",      optional_argument, 0, 'g'},
			{"root-pw",            no_argument,       0, 'P'},
			{"simple-hash",        no_argument,       0, 's'},
			{"ignore-db",          no_argument,       0, 0  },
			{"use-db",             no_argument,       0, 0  },
			{"mokx",               no_argument,       0, 'X'},
			{"import-hash",        required_argument, 0, 0  },
			{"delete-hash",        required_argument, 0, 0  },
			{"set-verbosity",      required_argument, 0, 0  },
			{"pk",                 no_argument,       0, 0  },
			{"kek",                no_argument,       0, 0  },
			{"db",                 no_argument,       0, 0  },
			{"dbx",                no_argument,       0, 0  },
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long (argc, argv, "cd:f:g::hi:lpst:xDNPX",
				 long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			option = long_options[option_index].name;
			if (strcmp (option, "revoke-import") == 0) {
				command |= REVOKE_IMPORT;
			} else if (strcmp (option, "revoke-delete") == 0) {
				command |= REVOKE_DELETE;
			} else if (strcmp (option, "disable-validation") == 0) {
				command |= DISABLE_VALIDATION;
			} else if (strcmp (option, "enable-validation") == 0) {
				command |= ENABLE_VALIDATION;
			} else if (strcmp (option, "sb-state") == 0) {
				command |= SB_STATE;
			} else if (strcmp (option, "reset") == 0) {
				command |= RESET;
			} else if (strcmp (option, "ignore-db") == 0) {
				command |= IGNORE_DB;
			} else if (strcmp (option, "use-db") == 0) {
				command |= USE_DB;
			} else if (strcmp (option, "import-hash") == 0) {
				command |= IMPORT_HASH;
				if (hash_str) {
					command |= HELP;
					break;
				}
				hash_str = strdup (optarg);
				if (hash_str == NULL) {
					fprintf (stderr, "Could not allocate space: %m\n");
					exit(1);
				}
			} else if (strcmp (option, "delete-hash") == 0) {
				command |= DELETE_HASH;
				if (hash_str) {
					command |= HELP;
					break;
				}
				hash_str = strdup (optarg);
				if (hash_str == NULL) {
					fprintf (stderr, "Could not allocate space: %m\n");
					exit(1);
				}
			} else if (strcmp (option, "set-verbosity") == 0) {
				command |= VERBOSITY;
				if (strcmp (optarg, "true") == 0)
					verbosity = 1;
				else if (strcmp (optarg, "false") == 0)
					verbosity = 0;
				else
					command |= HELP;
			} else if (strcmp (option, "pk") == 0) {
				if (db_name != MOK_LIST_RT) {
					command |= HELP;
				} else {
					command |= LIST_ENROLLED;
					db_name = PK;
				}
			} else if (strcmp (option, "kek") == 0) {
				if (db_name != MOK_LIST_RT) {
					command |= HELP;
				} else {
					command |= LIST_ENROLLED;
					db_name = KEK;
				}
			} else if (strcmp (option, "db") == 0) {
				if (db_name != MOK_LIST_RT) {
					command |= HELP;
				} else {
					command |= LIST_ENROLLED;
					db_name = DB;
				}
			} else if (strcmp (option, "dbx") == 0) {
				if (db_name != MOK_LIST_RT) {
					command |= HELP;
				} else {
					command |= LIST_ENROLLED;
					db_name = DBX;
				}
			}

			break;
		case 'l':
			command |= LIST_ENROLLED;
			break;
		case 'N':
			command |= LIST_NEW;
			break;
		case 'D':
			command |= LIST_DELETE;
			break;
		case 'd':
		case 'i':
			if (c == 'd')
				command |= DELETE;
			else
				command |= IMPORT;

			if (files) {
				command |= HELP;
				break;
			}

			total = 0;
			for (f_ind = optind - 1;
			     f_ind < argc && *argv[f_ind] != '-';
			     f_ind++) {
				total++;
			}

			if (total == 0) {
				command |= HELP;
				break;
			}

			files = malloc (total * sizeof (char *));
			if (files == NULL) {
				fprintf (stderr, "Could not allocate space: %m\n");
				exit(1);
			}
			for (i = 0; i < total; i++) {
				f_ind = i + optind - 1;
				files[i] = malloc (strlen(argv[f_ind]) + 1);
				strcpy (files[i], argv[f_ind]);
			}

			break;
		case 'f':
			if (hash_file) {
				command |= HELP;
				break;
			}
			hash_file = strdup (optarg);
			if (hash_file == NULL) {
				fprintf (stderr, "Could not allocate space: %m\n");
				exit(1);
			}

			break;
		case 'g':
			if (input_pw) {
				command |= HELP;
				break;
			}
			if (optarg) {
				input_pw = strdup (optarg);
				if (input_pw == NULL) {
					fprintf (stderr, "Could not allocate space: %m\n");
					exit(1);
				}
			}

			command |= GENERATE_PW_HASH;
			break;
		case 'p':
			command |= PASSWORD;
			break;
		case 'c':
			command |= CLEAR_PASSWORD;
			break;
		case 'P':
			use_root_pw = 1;
			break;
		case 't':
			if (key_file) {
				command |= HELP;
				break;
			}
			key_file = strdup (optarg);
			if (key_file == NULL) {
				fprintf (stderr, "Could not allocate space: %m\n");
				exit(1);
			}

			command |= TEST_KEY;
			break;
		case 'x':
			command |= EXPORT;
			break;
		case 's':
			command |= SIMPLE_HASH;
			use_simple_hash = 1;
			break;
		case 'X':
			if (db_name != MOK_LIST_RT) {
				command |= HELP;
			} else {
				command |= MOKX;
				db_name = MOK_LIST_X_RT;
			}
			break;
		case 'h':
		case '?':
			command |= HELP;
			break;
		default:
			abort ();
		}
	}

	if (use_root_pw == 1 && use_simple_hash == 1)
		use_simple_hash = 0;

	if (hash_file && use_root_pw)
		command |= HELP;

	switch (command) {
		case LIST_ENROLLED:
		case LIST_ENROLLED | MOKX:
			ret = list_db (db_name);
			break;
		case LIST_NEW:
			ret = list_keys_in_var ("MokNew", SHIM_LOCK_GUID);
			break;
		case LIST_DELETE:
			ret = list_keys_in_var ("MokDel", SHIM_LOCK_GUID);
			break;
		case IMPORT:
		case IMPORT | SIMPLE_HASH:
			ret = issue_mok_request (files, total, ENROLL_MOK,
						 hash_file, use_root_pw);
			break;
		case DELETE:
		case DELETE | SIMPLE_HASH:
			ret = issue_mok_request (files, total, DELETE_MOK,
						 hash_file, use_root_pw);
			break;
		case IMPORT_HASH:
		case IMPORT_HASH | SIMPLE_HASH:
			ret = issue_hash_request (hash_str, ENROLL_MOK,
						  hash_file, use_root_pw);
			break;
		case DELETE_HASH:
		case DELETE_HASH | SIMPLE_HASH:
			ret = issue_hash_request (hash_str, DELETE_MOK,
						  hash_file, use_root_pw);
			break;
		case REVOKE_IMPORT:
			ret = revoke_request (ENROLL_MOK);
			break;
		case REVOKE_DELETE:
			ret = revoke_request (DELETE_MOK);
			break;
		case EXPORT:
			ret = export_moks ();
			break;
		case PASSWORD:
		case PASSWORD | SIMPLE_HASH:
			ret = set_password (hash_file, use_root_pw, 0);
			break;
		case CLEAR_PASSWORD:
		case CLEAR_PASSWORD | SIMPLE_HASH:
			ret = set_password (NULL, 0, 1);
			break;
		case DISABLE_VALIDATION:
			ret = disable_validation ();
			break;
		case ENABLE_VALIDATION:
			ret = enable_validation ();
			break;
		case SB_STATE:
			ret = sb_state ();
			break;
		case TEST_KEY:
			ret = test_key (ENROLL_MOK, key_file);
			break;
		case RESET:
		case RESET | SIMPLE_HASH:
			ret = reset_moks (ENROLL_MOK, hash_file, use_root_pw);
			break;
		case GENERATE_PW_HASH:
			ret = generate_pw_hash (input_pw);
			break;
		case IGNORE_DB:
			ret = disable_db ();
			break;
		case USE_DB:
			ret = enable_db ();
			break;
		case LIST_NEW | MOKX:
			ret = list_keys_in_var ("MokXNew", SHIM_LOCK_GUID);
			break;
		case LIST_DELETE | MOKX:
			ret = list_keys_in_var ("MokXDel", SHIM_LOCK_GUID);
			break;
		case IMPORT | MOKX:
		case IMPORT | SIMPLE_HASH | MOKX:
			ret = issue_mok_request (files, total, ENROLL_BLACKLIST,
						 hash_file, use_root_pw);
			break;
		case DELETE | MOKX:
		case DELETE | SIMPLE_HASH | MOKX:
			ret = issue_mok_request (files, total, DELETE_BLACKLIST,
						 hash_file, use_root_pw);
			break;
		case IMPORT_HASH | MOKX:
		case IMPORT_HASH | SIMPLE_HASH | MOKX:
			ret = issue_hash_request (hash_str, ENROLL_BLACKLIST,
						  hash_file, use_root_pw);
			break;
		case DELETE_HASH | MOKX:
		case DELETE_HASH | SIMPLE_HASH | MOKX:
			ret = issue_hash_request (hash_str, DELETE_BLACKLIST,
						  hash_file, use_root_pw);
			break;
		case REVOKE_IMPORT | MOKX:
			ret = revoke_request (ENROLL_BLACKLIST);
			break;
		case REVOKE_DELETE | MOKX:
			ret = revoke_request (DELETE_BLACKLIST);
			break;
		case RESET | MOKX:
		case RESET | SIMPLE_HASH | MOKX:
			ret = reset_moks (ENROLL_BLACKLIST, hash_file, use_root_pw);
			break;
		case TEST_KEY | MOKX:
			ret = test_key (ENROLL_BLACKLIST, key_file);
			break;
		case VERBOSITY:
			ret = set_verbosity (verbosity);
			break;
		default:
			print_help ();
			break;
	}

	if (files) {
		for (i = 0; i < total; i++)
			free (files[i]);
		free (files);
	}

	if (key_file)
		free (key_file);

	if (hash_file)
		free (hash_file);

	if (input_pw)
		free (input_pw);

	if (hash_str)
		free (hash_str);

	return ret;
}
