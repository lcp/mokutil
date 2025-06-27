/**
 * Copyright (C) 2012-2020 Gary Lin <glin@suse.com>
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
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <shadow.h>
#include <sys/time.h>

#include <openssl/sha.h>

#include <crypt.h>
#include <efivar.h>

#include "mokutil.h"
#include "signature.h"
#include "efi_hash.h"
#include "efi_x509.h"
#include "keyring.h"
#include "password-crypt.h"
#include "util.h"

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
#define IGNORE_DB          (1 << 17)
#define USE_DB             (1 << 18)
#define MOKX               (1 << 19)
#define IMPORT_HASH        (1 << 20)
#define DELETE_HASH        (1 << 21)
#define VERBOSITY          (1 << 22)
#define TIMEOUT            (1 << 23)
#define LIST_SBAT          (1 << 24)
#define FB_VERBOSITY       (1 << 25)
#define FB_NOREBOOT        (1 << 26)
#define TRUST_MOK          (1 << 27)
#define UNTRUST_MOK        (1 << 28)
#define SET_SBAT           (1 << 29)
#define SET_SSP            (1 << 30)
#define IS_SB_ENABLED      (1 << 31)

#define DEFAULT_CRYPT_METHOD SHA512_BASED
#define DEFAULT_SALT_SIZE    SHA512_SALT_MAX
#define SETTINGS_LEN         (DEFAULT_SALT_SIZE*2)
#define BUF_SIZE             300

static int force_ca_check;
static int check_keyring;
static int opt_verbose_listing;
static int opt_list_all;

static const char* const db_names[] = { "MokListRT", "MokListXRT", "PK", "KEK", "db", "dbx" };

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
	printf ("  --help, -h\t\t\t\tShow help\n");
	printf ("  --list-enrolled, -l\t\t\tList the enrolled keys\n");
	printf ("  --list-new, -N\t\t\tList the keys to be enrolled\n");
	printf ("  --list-delete, -D\t\t\tList the keys to be deleted\n");
	printf ("  --import, -i <der file...>\t\tImport keys\n");
	printf ("  --delete, -D <der file...>\t\tDelete specific keys\n");
	printf ("  --revoke-import\t\t\tRevoke the import request\n");
	printf ("  --revoke-delete\t\t\tRevoke the delete request\n");
	printf ("  --export, -x\t\t\t\tExport keys to files\n");
	printf ("  --password, -p\t\t\tSet MOK password\n");
	printf ("  --clear-password, -c\t\t\tClear MOK password\n");
	printf ("  --disable-validation\t\t\tDisable signature validation\n");
	printf ("  --enable-validation\t\t\tEnable signature validation\n");
	printf ("  --sb-state\t\t\t\tShow SecureBoot State\n");
	printf ("  --is-sb-enabled\t\t\tIndicates if SecureBoot is enabled or not\n");
	printf ("  --test-key, -t <der file>\t\tTest if the key is enrolled or not\n");
	printf ("  --reset\t\t\t\tReset MOK list\n");
	printf ("  --generate-hash[=password], -g\tGenerate the password hash\n");
	printf ("  --ignore-db\t\t\t\tIgnore DB for validation\n");
	printf ("  --use-db\t\t\t\tUse DB for validation\n");
	printf ("  --import-hash <hash>\t\t\tImport a hash into MOK or MOKX\n");
	printf ("  --delete-hash <hash>\t\t\tDelete a hash in MOK or MOKX\n");
	printf ("  --set-verbosity <true/false>\t\tSet the verbosity bit for shim\n");
	printf ("  --set-fallback-verbosity <true/false>"
			"\tSet the verbosity bit for fallback\n");
	printf ("  --set-fallback-noreboot <true/false>"
			"\tPrevent fallback from automatically rebooting\n");
	printf ("  --trust-mok\t\t\t\tTrust MOK keys within the kernel keyring\n");
	printf ("  --untrust-mok\t\t\t\tDo not trust MOK keys\n");
	printf ("  --set-sbat-policy <latest/automatic>"
			"\tApply Latest or Automatic SBAT revocations\n");
	printf ("  --set-ssp-policy <latest/automatic/delete>\n"
			"\t\t\t\t\tApply Latest, Automatic, or delete SkuSiPolicy\n");
	printf ("  --pk\t\t\t\t\tList the keys in PK\n");
	printf ("  --kek\t\t\t\t\tList the keys in KEK\n");
	printf ("  --db\t\t\t\t\tList the keys in db\n");
	printf ("  --dbx\t\t\t\t\tList the keys in dbx\n");
	printf ("  --timeout <-1,0..0x7fff>\t\tSet the timeout for MOK prompt\n");
	printf ("  --list-sbat-revocations\t\tList the entries in SBAT\n");
	printf ("\n");
	printf ("Supplimentary Options:\n");
	printf ("  --hash-file, -f <hash file>\t\tUse the specific password hash\n");
	printf ("  --root-pw, -P\t\t\t\tUse the root password\n");
	printf ("  --mok, -m\t\t\t\tManipulate the MOK list\n");
	printf ("  --mokx, -X\t\t\t\tManipulate the MOK blacklist\n");
	printf ("  --ca-check\t\t\t\tCheck if CA of the key is enrolled/blocked\n");
	printf ("  --ignore-keyring\t\t\tDon't check if the key is the kernel keyring\n");
	printf ("  --short\t\t\t\tWhen listing keys print them in a concise form\n");
	printf ("  --all, -a\t\t\t\tWhen listing keys print all databases\n");
}

static int
list_keys (const uint8_t *data, const size_t data_size)
{
	uint32_t mok_num;
	MokListNode *list;

	list = build_mok_list (data, data_size, &mok_num);
	if (list == NULL) {
		return -1;
	}

	for (unsigned int i = 0; i < mok_num; i++) {
		char *owner_str = NULL;
		int ret;
		if (opt_verbose_listing) {
			printf ("[key %d]\n", i+1);

			ret = efi_guid_to_str(&list[i].owner, &owner_str);
			if (ret > 0) {
				printf ("Owner: %s\n", owner_str);
				free (owner_str);
			}
		}

		efi_guid_t sigtype = list[i].header->SignatureType;
		if (efi_guid_cmp (&sigtype, &efi_guid_x509_cert) == 0) {
			print_x509 (list[i].mok, list[i].mok_size, opt_verbose_listing);
		} else {
			print_hash_array (&sigtype,
					  list[i].mok, list[i].mok_size, opt_verbose_listing);
		}
		if (opt_verbose_listing && i < mok_num - 1)
			printf ("\n");
	}

	free (list);

	return 0;
}

static int
list_keys_in_var (const char *var_name, const efi_guid_t guid)
{
	uint8_t *data = NULL;
	char varname[] = "implausibly-long-mok-variable-name";
	size_t data_sz, i, varname_sz = sizeof(varname);
	uint32_t attributes;
	int ret;

	ret = mok_get_variable(var_name, &data, &data_sz);
	if (ret >= 0) {
		ret = list_keys (data, data_sz);
		free(data);
		if (ret != -1)
			return 0;
		/*
		 * If list_keys() returns -1, then we have problem
		 * with the data from /sys/firmware/efi/mok-variables/.
		 * Continue to try our luck with efivar/efivarfs.
		 */
	}

	for (i = 0; i < SIZE_MAX; i++) {
		if (i == 0) {
			snprintf(varname, varname_sz, "%s", var_name);
		} else {
			snprintf(varname, varname_sz, "%s%zu", var_name, i);
		}

		ret = efi_get_variable (guid, varname, &data, &data_sz,
					&attributes);
		if (ret < 0)
			return 0;

		ret = list_keys (data, data_sz);
		free(data);
		/*
		 * If ret is < 0, the next one will error as well.
		 * If ret is 0, we need to test the next variable.
		 * If it's 1, that's a real answer.
		 */
		if (ret < 0)
			return 0;
		if (ret > 0)
			return ret;
	}

	return 0;
}

static int
get_password (char **password, unsigned int *len,
	      const unsigned int min, const unsigned int max)
{
	char *password_1, *password_2;
	unsigned int len_1, len_2;
	int fail, ret = -1;
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

static void
generate_pw_salt (char salt[], const unsigned int salt_size)
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
generate_pw_crypt (pw_crypt_t *pw_crypt, const char *password,
		   const unsigned int pw_len)
{
	pw_crypt_t new_crypt;
	char settings[SETTINGS_LEN];
	char *next;
	char *crypt_string;
	const char *prefix;
	int hash_len, settings_len = sizeof (settings) - 2;

	if (!password || !pw_crypt || password[pw_len] != '\0')
		return -1;

	prefix = get_crypt_prefix (pw_crypt->method);
	if (!prefix)
		return -1;

	pw_crypt->salt_size = get_pw_salt_size (pw_crypt->method);
	generate_pw_salt ((char *)pw_crypt->salt, pw_crypt->salt_size);

	memset (settings, 0, sizeof (settings));
	next = stpncpy (settings, prefix, settings_len);
	if (pw_crypt->salt_size > settings_len - (next - settings)) {
		errno = EOVERFLOW;
		return -1;
	}
	next = stpncpy (next, (const char *)pw_crypt->salt,
			pw_crypt->salt_size);
	*next = '\0';

	crypt_string = crypt (password, settings);
	if (!crypt_string)
		return -1;

	if (decode_pass (crypt_string, &new_crypt) < 0)
		return -1;

	hash_len = get_pw_hash_size (new_crypt.method);
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
get_pw_hash_from_file (const char *file, pw_crypt_t *pw_crypt)
{
	char string[BUF_SIZE];
	ssize_t read_len = 0;
	int fd;

	fd = open (file, O_RDONLY);
	if (fd < 0) {
		fprintf (stderr, "Failed to open %s\n", file);
		return -1;
	}

	bzero (string, BUF_SIZE);

	while (read_len < BUF_SIZE) {
		ssize_t rc = read (fd, string + read_len,
				   BUF_SIZE - read_len - 1);
		if (rc < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;

			fprintf (stderr, "Failed to read %s: %m\n", file);
			close (fd);
			return -1;
		} else if (rc == 0) {
			break;
		}
		read_len += rc;
	}
	close (fd);

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
update_request (void *new_list, const int list_len, const MokRequest req,
		const char *pw_hash_file, const int root_pw)
{
	const char *req_name, *auth_name;
	pw_crypt_t pw_crypt;
	char *password = NULL;
	unsigned int pw_len;
	int auth_ret;
	int ret = -1;
	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
			      | EFI_VARIABLE_BOOTSERVICE_ACCESS
			      | EFI_VARIABLE_RUNTIME_ACCESS;

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

	if (pw_hash_file) {
		if (get_pw_hash_from_file (pw_hash_file, &pw_crypt) < 0) {
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

		auth_ret = generate_pw_crypt (&pw_crypt, password, pw_len);
		if (auth_ret < 0) {
			fprintf (stderr, "Couldn't generate hash\n");
			goto error;
		}
	}

	if (new_list) {
		/* Write MokNew, MokDel, MokXNew, or MokXDel*/
		ret = efi_set_variable (efi_guid_shim, req_name,
					new_list, list_len, attributes,
					S_IRUSR | S_IWUSR);
		if (ret < 0) {
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
		test_and_delete_mok_var (req_name);
	}

	/* Write MokAuth, MokDelAuth, MokXAuth, or MokXDelAuth */
	ret = efi_set_variable (efi_guid_shim, auth_name, (void *)&pw_crypt,
				PASSWORD_CRYPT_SIZE, attributes,
				S_IRUSR | S_IWUSR);
	if (ret < 0) {
		fprintf (stderr, "Failed to write %s\n", auth_name);
		test_and_delete_mok_var (req_name);
		goto error;
	}

	ret = 0;
error:
	if (password)
		free (password);
	return ret;
}

static int
check_one_duplicate (const efi_guid_t *type,
		     const void *data, const uint32_t data_size,
		     uint8_t *var_data, size_t var_data_size)
{
	uint32_t node_num;
	MokListNode *list;
	int ret = 0;

	if (!data || data_size == 0)
		return 0;

	list = build_mok_list (var_data, var_data_size, &node_num);
	if (list == NULL)
		return -1;

	for (unsigned int i = 0; i < node_num; i++) {
		efi_guid_t sigtype = list[i].header->SignatureType;
		if (efi_guid_cmp (&sigtype, type) != 0)
			continue;

		if (efi_guid_cmp (type, &efi_guid_x509_cert) == 0) {
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

	free (list);

	return ret;
}

static int
is_duplicate (const efi_guid_t *type,
	      const void *data, const uint32_t data_size,
	      const efi_guid_t *vendor, const char *db_name)
{
	uint32_t attributes;
	char varname[] = "implausibly-long-mok-variable-name";
	size_t varname_sz = sizeof(varname);
	int ret = 0;
	size_t i;

	if (!strncmp(db_name, "Mok", 3)) {
		uint8_t *var_data = NULL;
		size_t var_data_size = 0;
		ret = mok_get_variable(db_name, &var_data, &var_data_size);
		if (ret >= 0) {
			ret = check_one_duplicate(type, data, data_size,
						  var_data, var_data_size);
			if (ret >= 0) {
				free (var_data);
				return ret;
			}
			/*
			 * If check_duplicate() returns -1, then we have problem
			 * with the data from /sys/firmware/efi/mok-variables/.
			 * Continue to try our luck with efivar/efivarfs.
			 */
			var_data = NULL;
			var_data_size = 0;
		}
	}

	for (i = 0; i < SIZE_MAX; i++) {
		uint8_t *var_data = NULL;
		size_t var_data_size = 0;
		if (i == 0) {
			snprintf(varname, varname_sz, "%s", db_name);
		} else {
			snprintf(varname, varname_sz, "%s%zu", db_name, i);
		}

		ret = efi_get_variable (*vendor, varname,
					&var_data, &var_data_size,
					&attributes);
		if (ret < 0)
			return 0;

		ret = check_one_duplicate(type, data, data_size,
					  var_data, var_data_size);
		free (var_data);
		/*
		 * If ret is < 0, the next one will error as well.
		 * If ret is 0, we need to test the next variable.
		 * If it's 1, that's a real answer.
		 */
		if (ret < 0)
			return 0;
		if (ret > 0)
			return ret;
	}

	return 0;
}

static int
is_valid_request (const efi_guid_t *type, const void *mok,
		  const uint32_t mok_size, const MokRequest req)
{
	switch (req) {
	case ENROLL_MOK:
		if (is_duplicate (type, mok, mok_size, &efi_guid_security, "db") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokListRT") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokNew")) {
			return 0;
		}
		/* Also check the blocklists */
		if (is_duplicate (type, mok, mok_size, &efi_guid_security, "dbx") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokListXRT"))
			return 0;
		break;
	case DELETE_MOK:
		if (!is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokListRT") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokDel")) {
			return 0;
		}
		break;
	case ENROLL_BLACKLIST:
		if (is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokListXRT") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokXNew")) {
			return 0;
		}
		break;
	case DELETE_BLACKLIST:
		if (!is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokListXRT") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokXDel")) {
			return 0;
		}
		break;
	}

	return 1;
}

static int
is_ca_in_db (const void *cert, const uint32_t cert_size,
	     const efi_guid_t *vendor, const char *db_name)
{
	uint8_t *var_data = NULL;
	size_t var_data_size;
	uint32_t attributes;
	uint32_t node_num;
	MokListNode *list;
	int ret = 0;

	if (!cert || cert_size == 0 || !vendor || !db_name)
		return 0;

	ret = efi_get_variable (*vendor, db_name, &var_data, &var_data_size,
				&attributes);
	if (ret < 0)
		return 0;

	list = build_mok_list (var_data, var_data_size, &node_num);
	if (list == NULL) {
		goto done;
	}

	for (unsigned int i = 0; i < node_num; i++) {
		efi_guid_t sigtype = list[i].header->SignatureType;
		if (efi_guid_cmp (&sigtype, &efi_guid_x509_cert) != 0)
			continue;

		if (is_immediate_ca (cert, cert_size, list[i].mok,
				     list[i].mok_size)) {
			ret = 1;
			break;
		}
	}

done:
	if (list)
		free (list);
	free (var_data);

	return ret;
}

/* Check whether the CA cert is already enrolled */
static int
is_ca_enrolled (const void *mok, const uint32_t mok_size, const MokRequest req)
{
	switch (req) {
	case ENROLL_MOK:
		if (is_ca_in_db (mok, mok_size, &efi_guid_shim, "MokListRT"))
			return 1;
		break;
	case ENROLL_BLACKLIST:
		if (is_ca_in_db (mok, mok_size, &efi_guid_shim, "MokListXRT"))
			return 1;
		break;
	default:
		return 0;
	}

	return 0;
}

/* Check whether the CA cert is blocked */
static int
is_ca_blocked (const void *mok, const uint32_t mok_size, const MokRequest req)
{
	switch (req) {
	case ENROLL_MOK:
		if (is_ca_in_db (mok, mok_size, &efi_guid_security, "dbx") ||
		    is_ca_in_db (mok, mok_size, &efi_guid_shim, "MokListXRT"))
			return 1;
		break;
	default:
		return 0;
	}

	return 0;
}

/* Check whether the key is already in the kernel trusted keyring */
static int
is_in_trusted_keyring (const void *cert, const uint32_t cert_size)
{
	char *skid = NULL;
	int ret;

	if (get_cert_skid (cert, cert_size, &skid) < 0)
		return 0;

	ret = match_skid_in_trusted_keyring (skid);
	if (ret < 0)
		ret = 0;

	free (skid);

	return ret;
}

static int
in_reverse_pending_request (const efi_guid_t *type, const void *data,
			    uint32_t data_size, const MokRequest req)
{
	MokRequest reverse_req = get_reverse_req (req);

	if (!data || data_size == 0)
		return 0;

	return delete_data_from_req_var (reverse_req, type, data, data_size);
}

static void
print_skip_message (const char *filename, const void *mok,
		    const uint32_t mok_size, const MokRequest req)
{
	switch (req) {
	case ENROLL_MOK:
		if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				  &efi_guid_security, "db"))
			printf ("%s is already in db\n", filename);
		else if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				       &efi_guid_shim, "MokListRT"))
			printf ("%s is already enrolled\n", filename);
		else if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				       &efi_guid_shim, "MokNew"))
			printf ("%s is already in the enrollment request\n", filename);
		else if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				       &efi_guid_security, "dbx"))
			printf ("%s is blocked in dbx\n", filename);
		else if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				       &efi_guid_shim, "MokListXRT"))
			printf ("%s is blocked in MokListX\n", filename);
		break;
	case DELETE_MOK:
		if (!is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				   &efi_guid_shim, "MokListRT"))
			printf ("%s is not in MokList\n", filename);
		else if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				       &efi_guid_shim, "MokDel"))
			printf ("%s is already in the deletion request\n", filename);
		break;
	case ENROLL_BLACKLIST:
		if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				  &efi_guid_shim, "MokListXRT"))
			printf ("%s is already in MokListX\n", filename);
		else if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				       &efi_guid_shim, "MokXNew"))
			printf ("%s is already in the MokX enrollment request\n", filename);
		break;
	case DELETE_BLACKLIST:
		if (!is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				   &efi_guid_shim, "MokListXRT"))
			printf ("%s is not in MokListX\n", filename);
		else if (is_duplicate (&efi_guid_x509_cert, mok, mok_size,
				       &efi_guid_shim, "MokXDel"))
			printf ("%s is already in the MokX deletion request\n", filename);
		break;
	}
}

static int
issue_mok_request (char **files, const uint32_t total, const MokRequest req,
		   const char *pw_hash_file, const int root_pw)
{
	uint8_t *old_req_data = NULL;
	size_t old_req_data_size = 0;
	uint32_t attributes;
	void *new_list = NULL;
	void *ptr;
	struct stat buf;
	unsigned long list_size = 0;
	unsigned long real_size = 0;
	uint32_t *sizes = NULL;
	int fd = -1;
	ssize_t read_size;
	int ret = -1;
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *CertData;
	const char *var_name = get_req_var_name (req);

	if (!files)
		return -1;

	sizes = malloc (total * sizeof(uint32_t));
	if (!sizes) {
		fprintf (stderr, "Failed to allocate space for sizes\n");
		goto error;
	}

	/* get the sizes of the key files */
	for (unsigned int i = 0; i < total; i++) {
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

	ret = efi_get_variable (efi_guid_shim, var_name, &old_req_data,
				&old_req_data_size, &attributes);
	if (ret < 0) {
		if (errno != ENOENT) {
			fprintf (stderr, "Failed to read variable \"%s\": %m\n",
				 var_name);
			goto error;
		}
	} else {
		list_size += old_req_data_size;
	}
	ret = -1;

	new_list = malloc (list_size);
	if (!new_list) {
		fprintf (stderr, "Failed to allocate space for %s\n",
			 var_name);
		goto error;
	}
	ptr = new_list;

	for (unsigned int i = 0; i < total; i++) {
		CertList = ptr;
		CertData = (EFI_SIGNATURE_DATA *)(((uint8_t *)ptr) +
						  sizeof(EFI_SIGNATURE_LIST));

		CertList->SignatureType = efi_guid_x509_cert;
		CertList->SignatureListSize = sizes[i] +
		   sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1;
		CertList->SignatureHeaderSize = 0;
		CertList->SignatureSize = sizes[i] + sizeof(efi_guid_t);
		CertData->SignatureOwner = efi_guid_shim;

		fd = open (files[i], O_RDONLY);
		if (fd == -1) {
			fprintf (stderr, "Failed to open %s\n", files[i]);
			goto error;
		}

		ptr = CertData->SignatureData;

		/* Mok */
		read_size = read (fd, ptr, sizes[i]);
		if (read_size < 0 || read_size != (int64_t)sizes[i]) {
			fprintf (stderr, "Failed to read %s\n", files[i]);
			close (fd);
			goto error;
		}

		const void *mok = ptr;
		const uint32_t mok_size = sizes[i];

		if (!is_valid_cert (mok, mok_size)) {
			fprintf (stderr, "Abort!!! %s is not a valid x509 certificate in DER format\n",
			         files[i]);
			close (fd);
			goto error;
		}

		/* Check whether the key is already in the trusted keyring */
		if (req == ENROLL_MOK && check_keyring &&
		    is_in_trusted_keyring (mok, mok_size)) {
			printf ("Already in kernel trusted keyring. Skip %s\n",
				files[i]);
			close (fd);
			continue;
		}

		/* Check whether CA is already enrolled */
		if (force_ca_check && is_ca_enrolled (mok, mok_size, req)) {
			printf ("CA enrolled. Skip %s\n", files[i]);
			close (fd);
			continue;
		}

		/* Check whether CA is blocked */
		if (force_ca_check && is_ca_blocked (mok, mok_size, req)) {
			printf ("CA blocked. Skip %s\n", files[i]);
			close (fd);
			continue;
		}

		if (is_valid_request (&efi_guid_x509_cert, mok, mok_size, req)) {
			ptr += mok_size;
			real_size += mok_size + sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t);
		} else if (in_reverse_pending_request (&efi_guid_x509_cert, mok, mok_size, req)) {
			printf ("Removed %s from %s\n", files[i],
				get_reverse_req_var_name (req));
			ptr -= sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t);
		} else {
			printf ("SKIP: ");
			print_skip_message (files[i], mok, mok_size, req);
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
	if (old_req_data && old_req_data_size) {
		memcpy (new_list + real_size, old_req_data, old_req_data_size);
		real_size += old_req_data_size;
	}

	if (update_request (new_list, real_size, req, pw_hash_file, root_pw) < 0) {
		goto error;
	}

	ret = 0;
error:
	if (sizes)
		free (sizes);
	if (old_req_data)
		free (old_req_data);
	if (new_list)
		free (new_list);

	return ret;
}

static int
hex_str_to_binary (const char *hex_str, uint8_t *array, const unsigned int len)
{
	char *pos;

	if (!hex_str || !array)
		return -1;

	pos = (char *)hex_str;
	for (unsigned int i = 0; i < len; i++) {
		sscanf (pos, "%2hhx", &array[i]);
		pos += 2;
	}

	return 0;
}

static int
issue_hash_request (const char *hash_str, const MokRequest req,
		    const char *pw_hash_file, const int root_pw)
{
	uint8_t *old_req_data = NULL;
	size_t old_req_data_size = 0;
	uint32_t attributes;
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
	MokListNode *mok_list = NULL;
	uint32_t mok_num;
	const char *var_name = get_req_var_name (req);

	if (!hash_str)
		return -1;

	hash_size = identify_hash_type (hash_str, &hash_type);
	if (hash_size < 0)
		return -1;

	if (hex_str_to_binary (hash_str, db_hash, hash_size) < 0)
		return -1;

	if (is_valid_request (&hash_type, db_hash, hash_size, req) == 0) {
		printf ("Skip hash\n");
		ret = 0;
		goto error;
	} else if (in_reverse_pending_request (&hash_type, db_hash, hash_size, req)) {
		printf ("Removed hash from %s\n", get_reverse_req_var_name (req));
		ret = 0;
		goto error;
	}

	list_size = sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t) + hash_size;

	ret = efi_get_variable (efi_guid_shim, var_name, &old_req_data,
				&old_req_data_size, &attributes);
	if (ret < 0) {
		if (errno != ENOENT) {
			fprintf (stderr, "Failed to read variable \"%s\": %m\n",
				 var_name);
			goto error;
		}
	} else {
		list_size += old_req_data_size;
		mok_list = build_mok_list (old_req_data, old_req_data_size,
					   &mok_num);
		if (mok_list == NULL)
			goto error;
		/* Check if there is a signature list with the same type */
		for (unsigned int i = 0; i < mok_num; i++) {
			efi_guid_t sigtype = mok_list[i].header->SignatureType;
			if (efi_guid_cmp (&sigtype, &hash_type) == 0) {
				merge_ind = i;
				list_size -= sizeof(EFI_SIGNATURE_LIST);
				break;
			}
		}
	}
	ret = -1;

	new_list = malloc (list_size);
	if (!new_list) {
		fprintf (stderr, "Failed to allocate space for %s: %m\n",
			 var_name);
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
		CertData->SignatureOwner = efi_guid_shim;
		memcpy (CertData->SignatureData, db_hash, hash_size);

		/* prepend the hash to the previous request */
		ptr += sig_list_size;
		if (old_req_data) {
			memcpy (ptr, old_req_data, old_req_data_size);
		}
	} else {
		/* Merge the hash into an existed signature list */
		unsigned int i;

		for (i = 0; i < (unsigned int)merge_ind; i++) {
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

		for (i = (unsigned int)merge_ind + 1; i < mok_num; i++) {
			sig_list_size = mok_list[i].header->SignatureListSize;
			memcpy (ptr, (void *)mok_list[i].header, sig_list_size);
			ptr += sig_list_size;
		}
	}

	if (update_request (new_list, list_size, req, pw_hash_file, root_pw) < 0) {
		goto error;
	}

	ret = 0;
error:
	if (old_req_data)
		free (old_req_data);
	if (mok_list)
		free (mok_list);
	if (new_list)
		free (new_list);

	return ret;
}

static int
revoke_request (const MokRequest req)
{
	if (test_and_delete_mok_var (get_req_var_name(req)) < 0)
		return -1;
	if (test_and_delete_mok_var (get_req_auth_var_name(req)) < 0)
		return -1;

	return 0;
}

static int
export_db_keys (const DBName db_name)
{
	const char *db_var_name;
	uint8_t *data = NULL;
	size_t data_size = 0;
	uint32_t attributes;
	char filename[PATH_MAX];
	uint32_t mok_num;
	efi_guid_t guid = efi_guid_shim;
	MokListNode *list;
	int fd;
	mode_t mode;
	int ret = -1;

	switch (db_name) {
		case MOK_LIST_RT:
		case MOK_LIST_X_RT:
			guid = efi_guid_shim;
			break;
		case PK:
		case KEK:
			guid = efi_guid_global;
			break;
		case DB:
		case DBX:
			guid = efi_guid_security;
			break;
		case _DB_NAME_MAX:
			return -1;
	};

	db_var_name = get_db_var_name(db_name);

	ret = efi_get_variable (guid, db_var_name, &data, &data_size,
				&attributes);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf ("%s is empty\n", db_var_name);
			return 0;
		}

		fprintf (stderr, "Failed to read %s: %m\n", db_var_name);
		return -1;
	}
	ret = -1;

	list = build_mok_list (data, data_size, &mok_num);
	if (list == NULL) {
		free(data);
		return -1;
	}

	/* mode 644 */
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	for (unsigned i = 0; i < mok_num; i++) {
		off_t offset = 0;
		ssize_t write_size;
		efi_guid_t sigtype = list[i].header->SignatureType;

		if (efi_guid_cmp (&sigtype, &efi_guid_x509_cert) != 0)
			continue;

		/* Dump X509 certificate to files */
		snprintf (filename, PATH_MAX, "%s-%04d.der",
			  get_db_friendly_name(db_name), i+1);
		fd = open (filename, O_CREAT | O_WRONLY, mode);
		if (fd < 0) {
			fprintf (stderr, "Failed to open %s: %m\n", filename);
			goto error;
		}

		while (offset < (int64_t)list[i].mok_size) {
			write_size = write (fd, list[i].mok + offset,
						list[i].mok_size - offset);
			if (write_size < 0) {
				fprintf (stderr, "Failed to write %s: %m\n",
					 filename);
				close (fd);
				goto error;
			}
			offset += write_size;
		}

		close (fd);
	}

	ret = 0;
error:
	free (list);
	free (data);

	return ret;
}

static int
set_password (const char *pw_hash_file, const int root_pw, const int clear)
{
	pw_crypt_t pw_crypt;
	char *password = NULL;
	unsigned int pw_len;
	int auth_ret;
	int ret = -1;

	memset (&pw_crypt, 0, sizeof(pw_crypt_t));

	if (pw_hash_file) {
		if (get_pw_hash_from_file (pw_hash_file, &pw_crypt) < 0) {
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

		pw_crypt.method = DEFAULT_CRYPT_METHOD;
		auth_ret = generate_pw_crypt (&pw_crypt, password, pw_len);
		if (auth_ret < 0) {
			fprintf (stderr, "Couldn't generate hash\n");
			goto error;
		}
	}

	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
			      | EFI_VARIABLE_BOOTSERVICE_ACCESS
			      | EFI_VARIABLE_RUNTIME_ACCESS;
	ret = efi_set_variable (efi_guid_shim, "MokPW", (void *)&pw_crypt,
				PASSWORD_CRYPT_SIZE, attributes,
				S_IRUSR | S_IWUSR);
	if (ret < 0) {
		fprintf (stderr, "Failed to write MokPW: %m\n");
		goto error;
	}

	ret = 0;
error:
	if (password)
		free (password);
	return ret;
}

static int
set_toggle (const char * VarName, const uint32_t state)
{
	uint32_t attributes;
	MokToggleVar tvar;
	char *password = NULL;
	unsigned int pw_len;
	efi_char16_t efichar_pass[SB_PASSWORD_MAX+1];
	int ret = -1;

	printf ("password length: %d~%d\n", SB_PASSWORD_MIN, SB_PASSWORD_MAX);
        if (get_password (&password, &pw_len, SB_PASSWORD_MIN, SB_PASSWORD_MAX) < 0) {
		fprintf (stderr, "Abort\n");
		goto error;
	}

	tvar.password_length = pw_len;

	efichar_from_char (efichar_pass, password,
			   SB_PASSWORD_MAX * sizeof(efi_char16_t));

	memcpy(tvar.password, efichar_pass, sizeof(tvar.password));

	tvar.mok_toggle_state = state;

	attributes = EFI_VARIABLE_NON_VOLATILE
		     | EFI_VARIABLE_BOOTSERVICE_ACCESS
		     | EFI_VARIABLE_RUNTIME_ACCESS;
	ret = efi_set_variable (efi_guid_shim, VarName, (uint8_t *)&tvar,
			  sizeof(tvar), attributes, S_IRUSR | S_IWUSR);
	if (ret < 0) {
		fprintf (stderr, "Failed to request new %s state\n", VarName);
		goto error;
	}

	ret = 0;
error:
	if (password)
		free (password);
	return ret;
}

static inline int
disable_validation(void)
{
	return set_toggle("MokSB", 0);
}

static inline int
enable_validation(void)
{
	return set_toggle("MokSB", 1);
}

static int
sb_state_internal ()
{
	uint8_t *data = NULL;
	size_t data_size;
	uint32_t attributes;
	int32_t secureboot = -1;
	int32_t setupmode = -1;
	int32_t moksbstate = -1;
	int ret = 0;

	if (efi_get_variable (efi_guid_global, "SecureBoot", &data, &data_size,
			      &attributes) < 0) {
		fprintf (stderr, "Failed to read \"SecureBoot\" "
				 "variable: %m\n");
		return -1;
	}

	if (data_size != 1) {
		printf ("Strange data size %zd for \"SecureBoot\" variable\n",
			data_size);
	}
	if (data_size == 4 || data_size == 2 || data_size == 1) {
		secureboot = 0;
		memcpy(&secureboot, data, data_size);
	}
	free (data);

	data = NULL;
	if (efi_get_variable (efi_guid_global, "SetupMode", &data, &data_size,
			      &attributes) < 0) {
		fprintf (stderr, "Failed to read \"SetupMode\" "
				 "variable: %m\n");
		return -1;
	}

	if (data_size != 1) {
		printf ("Strange data size %zd for \"SetupMode\" variable\n",
			data_size);
	}
	if (data_size == 4 || data_size == 2 || data_size == 1) {
		setupmode = 0;
		memcpy(&setupmode, data, data_size);
	}
	free (data);

	data = NULL;
	if (efi_get_variable (efi_guid_shim, "MokSBStateRT", &data, &data_size,
			      &attributes) >= 0) {
		moksbstate = 1;
		free (data);
	}

	if (secureboot == 1 && setupmode == 0) {
		printf ("SecureBoot enabled\n");
		ret = 0;
		if (moksbstate == 1)
			printf ("SecureBoot validation is disabled in shim\n");
	} else if (secureboot == 0 || setupmode == 1) {
		printf ("SecureBoot disabled\n");
		ret = 1;
		if (setupmode == 1)
			printf ("Platform is in Setup Mode\n");
	} else {
		printf ("Cannot determine secure boot state.\n");
	}

	return ret;
}

static int
sb_state ()
{
	int ret = sb_state_internal ();

	/* in this case, ignore the ret value except on failure */
	return (ret < 0)? ret: 0;
}

static int
is_sb_enabled ()
{
	return sb_state_internal ();
}

static inline int
disable_db(void)
{
	return set_toggle("MokDB", 0);
}

static inline int
enable_db(void)
{
	return set_toggle("MokDB", 1);
}

static int
trust_mok_keys()
{
	return set_toggle("MokListTrustedNew", 0);
}

static int
untrust_mok_keys()
{
	return set_toggle("MokListTrustedNew", 1);
}

static inline int
read_file(const int fd, void **bufp, size_t *lenptr)
{
	int alloced = 0, size = 0, i = 0;
	void *buf = NULL;
	void *buf_new = NULL;

	do {
		size += i;
		if ((size + 1024) > alloced) {
			alloced += 4096;
			buf_new = realloc (buf, alloced + 1);
			if (buf_new) {
				buf = buf_new;
			} else {
				if (buf)
					free (buf);
				return -1;
			}
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
test_key (const MokRequest req, const char *key_file)
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

	if (!is_valid_cert (key, read_size)) {
		fprintf (stderr, "Not a valid x509 certificate\n");
		goto error;
	}

	if (check_keyring && is_in_trusted_keyring (key, read_size)) {
		fprintf (stderr, "%s is already in the built-in trusted keyring\n",
			 key_file);
		goto error;
	}

	if (force_ca_check && is_ca_enrolled (key, read_size, req)) {
		fprintf (stderr, "CA of %s is already enrolled\n",
			 key_file);
		goto error;
	}

	if (force_ca_check && is_ca_blocked (key, read_size, req)) {
		fprintf (stderr, "CA of %s is blocked\n",
			 key_file);
		goto error;
	}

	if (is_valid_request (&efi_guid_x509_cert, key, read_size, req)) {
		printf ("%s is not enrolled\n", key_file);
		ret = 1;
	} else {
		print_skip_message (key_file, key, read_size, req);
		ret = 0;
	}

error:
	if (key)
		free (key);

	if (fd >= 0)
		close (fd);

	return ret;
}

static int
reset_moks (const MokRequest req, const char *pw_hash_file, const int root_pw)
{
	if (update_request (NULL, 0, req, pw_hash_file, root_pw)) {
		fprintf (stderr, "Failed to issue a reset request\n");
		return -1;
	}

	return 0;
}

static int
generate_pw_hash (const char *input_pw)
{
	char settings[SETTINGS_LEN];
	char *next;
	char *password = NULL;
	char *crypt_string;
	const char *prefix;
	size_t settings_len = sizeof (settings) - 2;
	unsigned int pw_len, salt_size;

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

	memset (settings, 0, sizeof (settings));
	next = stpncpy (settings, prefix, settings_len);
	salt_size = get_pw_salt_size (DEFAULT_CRYPT_METHOD);
	if (salt_size > settings_len - (next - settings)) {
		free(password);
		errno = EOVERFLOW;
		return -1;
	}
	generate_pw_salt (next, salt_size);
	next += salt_size;
	*next = '\0';

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
set_timeout (const char *t)
{
	int timeout = strtol(t, NULL, 10);

	if (errno == ERANGE || timeout > 0x7fff)
		timeout = 0x7fff;
	if (timeout < 0)
		timeout = -1;

	if (timeout != 10) {
		uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
				      | EFI_VARIABLE_BOOTSERVICE_ACCESS
				      | EFI_VARIABLE_RUNTIME_ACCESS;
		if (efi_set_variable (efi_guid_shim, "MokTimeout",
				      (uint8_t *)&timeout, sizeof (timeout),
				      attributes, S_IRUSR | S_IWUSR) < 0) {
			fprintf (stderr, "Failed to set MokTimeout\n");
			return -1;
		}
	} else {
		return test_and_delete_mok_var ("MokTimeout");
	}

	return 0;
}

static int
print_var_content (const char *var_name, const efi_guid_t guid)
{
	uint8_t *data = NULL;
	size_t data_size;
	uint32_t attributes;
	int ret;

	ret = efi_get_variable (guid, var_name, &data, &data_size, &attributes);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf ("%s is empty\n", var_name);
			return 0;
		}

		fprintf (stderr, "Failed to read %s: %m\n", var_name);
		return -1;
	}

	printf ("%s", data);
	free (data);

	return ret;
}

static int
set_verbosity (const uint8_t verbosity)
{
	if (verbosity) {
		uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
				      | EFI_VARIABLE_BOOTSERVICE_ACCESS
				      | EFI_VARIABLE_RUNTIME_ACCESS;
		if (efi_set_variable (efi_guid_shim, "SHIM_VERBOSE",
				      (uint8_t *)&verbosity, sizeof (verbosity),
				      attributes, S_IRUSR | S_IWUSR) < 0) {
			fprintf (stderr, "Failed to set SHIM_VERBOSE\n");
			return -1;
		}
	} else {
		return test_and_delete_mok_var ("SHIM_VERBOSE");
	}

	return 0;
}

static int
set_fallback_verbosity (const uint8_t verbosity)
{
	if (verbosity) {
		uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
				      | EFI_VARIABLE_BOOTSERVICE_ACCESS
				      | EFI_VARIABLE_RUNTIME_ACCESS;
		if (efi_set_variable (efi_guid_shim, "FALLBACK_VERBOSE",
				      (uint8_t *)&verbosity, sizeof (verbosity),
				      attributes, S_IRUSR | S_IWUSR) < 0) {
			fprintf (stderr, "Failed to set FALLBACK_VERBOSE\n");
			return -1;
		}
	} else {
		return test_and_delete_mok_var ("FALLBACK_VERBOSE");
	}

	return 0;
}

static int
set_fallback_noreboot (const uint8_t noreboot)
{
	if (noreboot) {
		uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
				      | EFI_VARIABLE_BOOTSERVICE_ACCESS
				      | EFI_VARIABLE_RUNTIME_ACCESS;
		if (efi_set_variable (efi_guid_shim, "FB_NO_REBOOT",
				      (uint8_t *)&noreboot, sizeof (noreboot),
				      attributes, S_IRUSR | S_IWUSR) < 0) {
			fprintf (stderr, "Failed to set FB_NO_REBOOT\n");
			return -1;
		}
	} else {
		return test_and_delete_mok_var ("FB_NO_REBOOT");
	}

	return 0;
}

static inline int
list_db (const DBName db_name)
{
	switch (db_name) {
		case MOK_LIST_RT:
			return list_keys_in_var ("MokListRT", efi_guid_shim);
		case MOK_LIST_X_RT:
			return list_keys_in_var ("MokListXRT", efi_guid_shim);
		case PK:
			return list_keys_in_var ("PK", efi_guid_global);
		case KEK:
			return list_keys_in_var ("KEK", efi_guid_global);
		case DB:
			return list_keys_in_var ("db", efi_guid_security);
		case DBX:
			return list_keys_in_var ("dbx", efi_guid_security);
		case _DB_NAME_MAX:
			return -1;
	}

	return -1;
}

static int
manage_policy (unsigned int command, const uint8_t policy)
{
	const char *varname;
	if (command == SET_SBAT)
		varname = "SbatPolicy";
	if (command == SET_SSP)
		varname = "SSPPolicy";

	if (policy) {
		uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
				      | EFI_VARIABLE_BOOTSERVICE_ACCESS
				      | EFI_VARIABLE_RUNTIME_ACCESS;
		if (efi_set_variable (efi_guid_shim, varname,
				      (uint8_t *)&policy,
				      sizeof (policy),
				      attributes, S_IRUSR | S_IWUSR) < 0) {
			fprintf (stderr, "Failed to set SbatPolicy\n");
			return -1;
		}
	} else {
		return test_and_delete_mok_var (varname);
	}
	return 0;
}

int
main (int argc, char *argv[])
{
	char **files = NULL;
	char *key_file = NULL;
	char *pw_hash_file = NULL;
	char *input_pw = NULL;
	char *hash_str = NULL;
	char *timeout = NULL;
	const char *option;
	int c, i, f_ind, total = 0;
	unsigned int command = 0;
	int use_root_pw = 0;
	uint8_t verbosity = 0;
	uint8_t fb_verbosity = 0;
	uint8_t fb_noreboot = 0;
	uint8_t policy = 0;
	DBName db_name = MOK_LIST_RT;
	int ret = -1;
	int sb_check;

	force_ca_check = 0;
	check_keyring = 1;
	opt_verbose_listing = 1;

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
			{"is-sb-enabled",      no_argument,       0, 0  },
			{"test-key",           required_argument, 0, 't'},
			{"reset",              no_argument,       0, 0  },
			{"hash-file",          required_argument, 0, 'f'},
			{"generate-hash",      optional_argument, 0, 'g'},
			{"root-pw",            no_argument,       0, 'P'},
			{"ignore-db",          no_argument,       0, 0  },
			{"use-db",             no_argument,       0, 0  },
			{"mok",                no_argument,       0, 'm'},
			{"mokx",               no_argument,       0, 'X'},
			{"import-hash",        required_argument, 0, 0  },
			{"delete-hash",        required_argument, 0, 0  },
			{"set-verbosity",      required_argument, 0, 0  },
			{"set-fallback-verbosity", required_argument, 0, 0  },
			{"set-fallback-noreboot", required_argument, 0, 0  },
			{"trust-mok",          no_argument,       0, 0  },
			{"untrust-mok",        no_argument,       0, 0  },
			{"set-sbat-policy",    required_argument, 0, 0  },
			{"set-ssp-policy",     required_argument, 0, 0  },
			{"pk",                 no_argument,       0, 0  },
			{"kek",                no_argument,       0, 0  },
			{"db",                 no_argument,       0, 0  },
			{"dbx",                no_argument,       0, 0  },
			{"list-sbat-revocations", no_argument,       0, 0  },
			{"sbat",               no_argument,       0, 0  },
			{"timeout",            required_argument, 0, 0  },
			{"ca-check",           no_argument,       0, 0  },
			{"ignore-keyring",     no_argument,       0, 0  },
			{"version",            no_argument,       0, 'v'},
			{"short",              no_argument,       0, 0  },
			{"all",                no_argument,       0, 'a'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long (argc, argv, "acd:f:g::hi:lmpt:xDNPXv",
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
			} else if (strcmp (option, "is-sb-enabled") == 0) {
				command |= IS_SB_ENABLED;
			} else if (strcmp (option, "reset") == 0) {
				command |= RESET;
			} else if (strcmp (option, "ignore-db") == 0) {
				command |= IGNORE_DB;
			} else if (strcmp (option, "use-db") == 0) {
				command |= USE_DB;
			} else if (strcmp (option, "trust-mok") == 0) {
				command |= TRUST_MOK;
			} else if (strcmp (option, "untrust-mok") == 0) {
				command |= UNTRUST_MOK;
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
			} else if (strcmp (option, "set-fallback-verbosity") == 0) {
				command |= FB_VERBOSITY;
				if (strcmp (optarg, "true") == 0)
					fb_verbosity = 1;
				else if (strcmp (optarg, "false") == 0)
					fb_verbosity = 0;
				else
					command |= HELP;
			} else if (strcmp (option, "set-fallback-noreboot") == 0) {
				command |= FB_NOREBOOT;
				if (strcmp (optarg, "true") == 0)
					fb_noreboot = 1;
				else if (strcmp (optarg, "false") == 0)
					fb_noreboot = 0;
				else
					command |= HELP;
			} else if (strcmp (option, "set-sbat-policy") == 0) {
				command |= SET_SBAT;
				if (strcmp (optarg, "latest") == 0)
					policy = 1;
				else if ((strcmp (optarg, "previous") == 0) ||
					 (strcmp (optarg, "automatic") == 0))
					policy = 2;
				else if (strcmp (optarg, "delete") == 0)
					policy = 3;
				else
					command |= HELP;
			} else if (strcmp (option, "set-ssp-policy") == 0) {
				command |= SET_SSP;
				if (strcmp (optarg, "latest") == 0)
					policy = 1;
				else if ((strcmp (optarg, "previous") == 0) ||
					 (strcmp (optarg, "automatic") == 0))
					policy = 2;
				else if (strcmp (optarg, "delete") == 0)
					policy = 3;
				else
					command |= HELP;
			} else if (strcmp (option, "pk") == 0) {
				if (db_name != MOK_LIST_RT) {
					command |= HELP;
				} else {
					db_name = PK;
				}
			} else if (strcmp (option, "kek") == 0) {
				if (db_name != MOK_LIST_RT) {
					command |= HELP;
				} else {
					db_name = KEK;
				}
			} else if (strcmp (option, "db") == 0) {
				if (db_name != MOK_LIST_RT) {
					command |= HELP;
				} else {
					db_name = DB;
				}
			} else if (strcmp (option, "dbx") == 0) {
				if (db_name != MOK_LIST_RT) {
					command |= HELP;
				} else {
					db_name = DBX;
				}
			}  else if (strcmp (option, "list-sbat-revocations") == 0) {
				command |= LIST_SBAT;
			}  else if (strcmp (option, "sbat") == 0) {
				command |= LIST_SBAT;
			} else if (strcmp (option, "timeout") == 0) {
				command |= TIMEOUT;
				timeout = strdup (optarg);
			} else if (strcmp (option, "ca-check") == 0) {
				force_ca_check = 1;
			} else if (strcmp (option, "ignore-keyring") == 0) {
				check_keyring = 0;
			} else if (strcmp (option, "short") == 0) {
				opt_verbose_listing = 0;
			}

			break;
		case 'a':
			opt_list_all = 1;
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
				if (files[i] == NULL) {
					fprintf (stderr, "Could not allocate space: %m\n");
					exit(1);
				}
				strcpy (files[i], argv[f_ind]);
			}

			break;
		case 'f':
			if (pw_hash_file) {
				command |= HELP;
				break;
			}
			pw_hash_file = strdup (optarg);
			if (pw_hash_file == NULL) {
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
		case 'm':
			db_name = MOK_LIST_RT;
			break;
		case 'X':
			if (db_name != MOK_LIST_RT) {
				command |= HELP;
			} else {
				command |= MOKX;
				db_name = MOK_LIST_X_RT;
			}
			break;
		case 'v':
			printf ("%s\n", VERSION);
			ret = 0;
			goto out;
		case 'h':
		case '?':
		default:
			command |= HELP;
			break;
		}
	}

	if (pw_hash_file && use_root_pw)
		command |= HELP;


	if (db_name != MOK_LIST_RT && !(command & ~MOKX))
		command |= LIST_ENROLLED;

	/* no matter if mokutil is supported (EFI) or not (BIOS) in the system, print
	   the help menu if no command line arguments provided or explicit help
	   requested */
	if (!command || (command & HELP)) {
		print_help ();
		ret = 0;
		goto out;
	}

	/* check if EFI variable is supported on the system */
	if (!efi_variables_supported ()) {
		fprintf (stderr, "EFI variables are not supported on this system\n");
		exit (1);
	}

	sb_check = !(command & HELP || command & TEST_KEY ||
		     command & VERBOSITY || command & TIMEOUT ||
		     command & FB_VERBOSITY || command & FB_NOREBOOT);
	if (sb_check) {
		/* Check whether the machine supports Secure Boot or not */
		int rc;
		uint8_t *data = NULL;
		size_t data_size;
		uint32_t attributes;

		rc = efi_get_variable (efi_guid_global, "SecureBoot",
				       &data, &data_size, &attributes);
		if (rc < 0) {
			fprintf(stderr, "This system doesn't support Secure Boot\n");
			ret = -1;
			goto out;
		}
		free (data);
	}

	switch (command) {
		case LIST_ENROLLED:
		case LIST_ENROLLED | MOKX:
			if (opt_list_all) {
				ret = 0;
				for (DBName db = MOK_LIST_RT; db < _DB_NAME_MAX; ++db) {
					int r;
					printf("[%s]\n", db_names[db]);
					r = list_db (db);
					if (r)
						ret = r;
				}
			} else {
				ret = list_db (db_name);
			}
			break;
		case LIST_NEW:
			ret = list_keys_in_var ("MokNew", efi_guid_shim);
			break;
		case LIST_DELETE:
			ret = list_keys_in_var ("MokDel", efi_guid_shim);
			break;
		case IMPORT:
			ret = issue_mok_request (files, total, ENROLL_MOK,
						 pw_hash_file, use_root_pw);
			break;
		case DELETE:
			ret = issue_mok_request (files, total, DELETE_MOK,
						 pw_hash_file, use_root_pw);
			break;
		case IMPORT_HASH:
			ret = issue_hash_request (hash_str, ENROLL_MOK,
						  pw_hash_file, use_root_pw);
			break;
		case DELETE_HASH:
			ret = issue_hash_request (hash_str, DELETE_MOK,
						  pw_hash_file, use_root_pw);
			break;
		case REVOKE_IMPORT:
			ret = revoke_request (ENROLL_MOK);
			break;
		case REVOKE_DELETE:
			ret = revoke_request (DELETE_MOK);
			break;
		case EXPORT:
		case EXPORT | MOKX:
			ret = export_db_keys (db_name);
			break;
		case PASSWORD:
			ret = set_password (pw_hash_file, use_root_pw, 0);
			break;
		case CLEAR_PASSWORD:
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
		case IS_SB_ENABLED:
			ret = is_sb_enabled ();
			break;
		case TEST_KEY:
			ret = test_key (ENROLL_MOK, key_file);
			break;
		case RESET:
			ret = reset_moks (ENROLL_MOK, pw_hash_file, use_root_pw);
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
		case TRUST_MOK:
			ret = trust_mok_keys ();
			break;
		case UNTRUST_MOK:
			ret = untrust_mok_keys ();
			break;
		case LIST_NEW | MOKX:
			ret = list_keys_in_var ("MokXNew", efi_guid_shim);
			break;
		case LIST_DELETE | MOKX:
			ret = list_keys_in_var ("MokXDel", efi_guid_shim);
			break;
		case IMPORT | MOKX:
			ret = issue_mok_request (files, total, ENROLL_BLACKLIST,
						 pw_hash_file, use_root_pw);
			break;
		case DELETE | MOKX:
			ret = issue_mok_request (files, total, DELETE_BLACKLIST,
						 pw_hash_file, use_root_pw);
			break;
		case IMPORT_HASH | MOKX:
			ret = issue_hash_request (hash_str, ENROLL_BLACKLIST,
						  pw_hash_file, use_root_pw);
			break;
		case DELETE_HASH | MOKX:
			ret = issue_hash_request (hash_str, DELETE_BLACKLIST,
						  pw_hash_file, use_root_pw);
			break;
		case REVOKE_IMPORT | MOKX:
			ret = revoke_request (ENROLL_BLACKLIST);
			break;
		case REVOKE_DELETE | MOKX:
			ret = revoke_request (DELETE_BLACKLIST);
			break;
		case RESET | MOKX:
			ret = reset_moks (ENROLL_BLACKLIST, pw_hash_file, use_root_pw);
			break;
		case TEST_KEY | MOKX:
			ret = test_key (ENROLL_BLACKLIST, key_file);
			break;
		case VERBOSITY:
			ret = set_verbosity (verbosity);
			break;
		case FB_VERBOSITY:
			ret = set_fallback_verbosity (fb_verbosity);
			break;
		case FB_NOREBOOT:
			ret = set_fallback_noreboot (fb_noreboot);
			break;
		case TIMEOUT:
			ret = set_timeout (timeout);
			break;
		case LIST_SBAT:
			ret = print_var_content ("SbatLevelRT", efi_guid_shim);
			break;
		case SET_SBAT:
		case SET_SSP:
			ret = manage_policy(command, policy);
			break;
		default:
			print_help ();
			ret = 0;
			break;
	}

out:
	if (files) {
		for (i = 0; i < total; i++)
			free (files[i]);
		free (files);
	}

	if (timeout)
		free (timeout);

	if (key_file)
		free (key_file);

	if (pw_hash_file)
		free (pw_hash_file);

	if (input_pw)
		free (input_pw);

	if (hash_str)
		free (hash_str);

	return ret;
}
