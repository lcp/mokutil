#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <getopt.h>

#include <openssl/sha.h>
#include <openssl/x509.h>

#include "efi.h"
#include "signature.h"

#define SHIM_LOCK_GUID \
EFI_GUID (0x605dab50, 0xe046, 0x4300, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23)

#define PASSWORD_MAX 16
#define PASSWORD_MIN 8

#define SALT_SIZE 16

#define HELP               0x1
#define LIST_ENROLLED      0x2
#define LIST_NEW           0x4
#define IMPORT             0x8
#define DELETE             0x10
#define REVOKE             0x20
#define EXPORT             0x40
#define PASSWORD           0x80
#define DISABLE_VALIDATION 0x100
#define ENABLE_VALIDATION  0x200
#define SB_STATE           0x400
#define TEST_KEY           0x800
#define RESET              0x1000
#define HASH_FILE          0x2000

typedef struct {
	uint32_t mok_size;
	void    *mok;
} MokListNode;

typedef struct {
	uint32_t mok_sb_state;
	uint32_t password_length;
	uint16_t password[PASSWORD_MAX];
} MokSBVar;

static void
print_help ()
{
	printf("Usage:\n");
	printf("List the enrolled keys:\n");
	printf("  mokutil --list-enrolled\n\n");

	printf("List the keys to be enrolled:\n");
	printf("  mokutil --list-new\n\n");

	printf("Import keys:\n");
	printf("  mokutil --import <der file>...\n\n");

	printf("Request to delete specific keys\n");
	printf("  mokutil --delete <der file>...\n\n");

	printf("Revoke the request:\n");
	printf("  mokutil --revoke\n\n");

	printf("Export enrolled keys to files:\n");
	printf("  mokutil --export\n\n");

	printf("Set MOK password:\n");
	printf("  mokutil --password\n\n");

	printf("Disable signature validation:\n");
	printf("  mokutil --disable-validation\n\n");

	printf("Enable signature validation:\n");
	printf("  mokutil --enable-validation\n\n");

	printf("SecureBoot State:\n");
	printf("  mokutil --sb-state\n\n");

	printf("Test if the key is enrolled or not:\n");
	printf("  mokutil --test-key <der file>\n\n");

	printf("Reset MOK list:\n");
	printf("  mokutil --reset\n\n");
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

static MokListNode*
build_mok_list (void *data, unsigned long data_size, uint32_t *mok_num)
{
	MokListNode *list;
	EFI_SIGNATURE_LIST *CertList = data;
	EFI_SIGNATURE_DATA *Cert;
	efi_guid_t CertType = EfiCertX509Guid;
	efi_guid_t HashType = EfiHashSha256Guid;
	unsigned long dbsize = data_size;
	unsigned long count = 0;

	list = malloc(sizeof(MokListNode));

	if (!list) {
		fprintf(stderr, "Unable to allocate MOK list\n");
		return NULL;
	}

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if ((efi_guidcmp (CertList->SignatureType, CertType) != 0) &&
		    (efi_guidcmp (CertList->SignatureType, HashType) != 0)) {
			dbsize -= CertList->SignatureListSize;
			CertList = (EFI_SIGNATURE_LIST *)((uint8_t *) CertList +
						  CertList->SignatureListSize);
			continue;
		}

		if ((efi_guidcmp (CertList->SignatureType, HashType) == 0) &&
		    (CertList->SignatureSize != 48)) {
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

		list[count].mok_size = CertList->SignatureSize - sizeof(efi_guid_t);
                list[count].mok = (void *)Cert->SignatureData;

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
		print_x509 ((char *)list[i].mok, list[i].mok_size);
		if (i < mok_num - 1)
			printf ("\n");
	}

	free (list);

	return 0;
}

static int
list_enrolled_keys ()
{
	efi_variable_t var;
	int ret;

	memset (&var, 0, sizeof(var));
	var.VariableName = "MokListRT";

	var.VendorGuid = SHIM_LOCK_GUID;

	if (read_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to read MokListRT\n");
		return -1;
	}

	ret = list_keys (&var);
	free (var.Data);

	return ret;
}

static int
list_new_keys ()
{
	efi_variable_t var;
	int ret;

	memset (&var, 0, sizeof(var));
	var.VariableName = "MokNew";

	var.VendorGuid = SHIM_LOCK_GUID;

	if (read_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to read MokNew\n");
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
		printf ("input password (%d~%d characters): ", min, max);
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
generate_salt (uint8_t salt[], unsigned int salt_len)
{
	int i;

	srand (time (NULL));

	for (i = 0; i < salt_len; i++)
		salt[i] = rand() % 256;
}

static int
generate_hash (void *salt, unsigned int salt_len, char *password,
	       int pw_len, uint8_t *auth)
{
	efi_char16_t efichar_pass[PASSWORD_MAX+1];
	unsigned long efichar_len;
	SHA256_CTX ctx;

	if (!password || !auth)
		return -1;

	efichar_len = efichar_from_char (efichar_pass, password,
					 (PASSWORD_MAX+1)*sizeof(efi_char16_t));

	SHA256_Init (&ctx);

	if (salt)
		SHA256_Update (&ctx, salt, salt_len);

	SHA256_Update (&ctx, efichar_pass, efichar_len);

	SHA256_Final (auth, &ctx);

	return 0;
}

static int
char_to_int (const char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');

	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);

	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);

	return -1;
}

static int
read_hex_array (const char *string, char *out, int len)
{
	int i, digit_1, digit_2;

	for (i = 0; i < len; i++) {
		digit_1 = char_to_int (string[2*i]);
		digit_2 = char_to_int (string[2*i + 1]);
		if (digit_1 < 0 || digit_2 < 0)
			return -1;

		out[i] = (char)digit_1 * 16 + (char)digit_2;
	}

	return 0;
}

static int
get_hash_from_file (const char *file, void *salt, void *hash)
{
	FILE *fptr;
	char salt_string[2*SALT_SIZE];
	char hash_string[2*SHA256_DIGEST_LENGTH];

	fptr = fopen (file, "r");
	if (fptr == NULL) {
		fprintf (stderr, "Failed to open %s\n", file);
		return -1;
	}

	memset (salt_string, 0, 2*SALT_SIZE);
	memset (hash_string, 0, 2*SHA256_DIGEST_LENGTH);

	fscanf (fptr, "%32c.%64c", salt_string, hash_string);

	fclose (fptr);

	if (read_hex_array (salt_string, salt, SALT_SIZE) < 0) {
		fprintf (stderr, "Corrupted salt\n");
		return -1;
	}

	if (read_hex_array (hash_string, hash, SHA256_DIGEST_LENGTH) < 0) {
		fprintf (stderr, "Corrupted hash\n");
		return -1;
	}

	return 0;
}

static int
update_request (void *new_list, int list_len, uint8_t import,
		const char *hash_file)
{
	efi_variable_t var;
	const char *req_name, *auth_name;
	uint8_t salt[SALT_SIZE];
	uint8_t hash[SHA256_DIGEST_LENGTH];
	uint8_t auth[SALT_SIZE + SHA256_DIGEST_LENGTH];
	char *password = NULL;
	int pw_len;
	int ret = -1;

	if (import) {
		req_name = "MokNew";
		auth_name = "MokAuth";
	} else {
		req_name = "MokDel";
		auth_name = "MokDelAuth";
	}

	if (hash_file) {
		if (get_hash_from_file (hash_file, salt, hash) < 0) {
			fprintf (stderr, "Failed to read hash\n");
			goto error;
		}
	} else {
		if (get_password (&password, &pw_len, PASSWORD_MIN, PASSWORD_MAX) < 0) {
			fprintf (stderr, "Abort\n");
			goto error;
		}

		generate_salt (salt, SALT_SIZE);
		if (generate_hash (salt, SALT_SIZE, password, pw_len, hash) < 0) {
			fprintf (stderr, "Couldn't generate hash\n");
			goto error;
		}
	}
	memcpy (auth, salt, SALT_SIZE);
	memcpy (auth + SALT_SIZE, hash, SHA256_DIGEST_LENGTH);

	if (new_list) {
		/* Write MokNew*/
		var.Data = new_list;
		var.DataSize = list_len;
		var.VariableName = req_name;

		var.VendorGuid = SHIM_LOCK_GUID;
		var.Attributes = EFI_VARIABLE_NON_VOLATILE
			| EFI_VARIABLE_BOOTSERVICE_ACCESS
			| EFI_VARIABLE_RUNTIME_ACCESS;

		if (edit_variable (&var) != EFI_SUCCESS) {
			fprintf (stderr, "Failed to %s keys\n",
				 import ? "enroll new" : "delete");
			goto error;
		}
	} else {
		test_and_delete_var (req_name);
	}

	/* Write MokAuth */
	var.Data = auth;
	var.DataSize = SHA256_DIGEST_LENGTH + SALT_SIZE;
	var.VariableName = auth_name;

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_variable (&var) != EFI_SUCCESS) {
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
is_duplicate (const void *cert, const uint32_t cert_size, const char *db_name,
	      efi_guid_t guid)
{
	efi_variable_t var;
	uint32_t mok_num;
	MokListNode *list;
	int i, ret = 0;

	if (!cert || cert_size == 0 || !db_name)
		return 0;

	memset (&var, 0, sizeof(var));
	var.VariableName = db_name;
	var.VendorGuid = guid;

	if (read_variable (&var) != EFI_SUCCESS)
		return 0;

	list = build_mok_list (var.Data, var.DataSize, &mok_num);
	if (list == NULL) {
		goto done;
	}

	for (i = 0; i < mok_num; i++) {
		if (list[i].mok_size != cert_size)
			continue;

		if (memcmp (list[i].mok, cert, cert_size) == 0) {
			ret = 1;
			break;
		}
	}

done:
	free (var.Data);

	return ret;
}

static int
is_valid_request (void *mok, uint32_t mok_size, uint8_t import)
{
	if (import) {
		if (is_duplicate (mok, mok_size, "PK", EFI_GLOBAL_VARIABLE) ||
		    is_duplicate (mok, mok_size, "KEK", EFI_GLOBAL_VARIABLE) ||
		    is_duplicate (mok, mok_size, "db", EFI_IMAGE_SECURITY_DATABASE_GUID) ||
		    is_duplicate (mok, mok_size, "MokListRT", SHIM_LOCK_GUID) ||
		    is_duplicate (mok, mok_size, "MokNew", SHIM_LOCK_GUID)) {
			return 0;
		}
	} else {
		if (!is_duplicate (mok, mok_size, "MokListRT", SHIM_LOCK_GUID) ||
		    is_duplicate (mok, mok_size, "MokDel", SHIM_LOCK_GUID)) {
			return 0;
		}
	}

	return 1;
}

static int
issue_mok_request (char **files, uint32_t total, uint8_t import,
		   const char *hash_file)
{
	efi_variable_t old_req;
	const char *req_name;
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

	if (import)
		req_name = "MokNew";
	else
		req_name = "MokDel";

	sizes = malloc (total * sizeof(uint32_t));

	memset (&old_req, 0, sizeof(old_req));

	if (!sizes) {
		fprintf (stderr, "Failed to allocate space for sizes\n");
		goto error;
	}

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

		if (is_valid_request (ptr, sizes[i], import)) {
			ptr += sizes[i];
			real_size += sizes[i] + sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t);
		} else {
			printf ("Skip %s\n", files[i]);
			ptr -= sizeof(EFI_SIGNATURE_LIST) + sizeof(efi_guid_t);
		}

		close (fd);
	}

	/* All keys are enrolled, nothing to do here... */
	if (real_size == 0) {
		ret = 0;
		goto error;
	}

	/* append the keys to the previous request */
	if (old_req.Data) {
		memcpy (new_list + real_size, old_req.Data, old_req.DataSize);
		real_size += old_req.DataSize;
	}

	if (update_request (new_list, real_size, import, hash_file) < 0) {
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
import_moks (char **files, uint32_t total, const char *hash_file)
{
	return issue_mok_request (files, total, 1, hash_file);
}

static int
delete_moks (char **files, uint32_t total, const char *hash_file)
{
	return issue_mok_request (files, total, 0, hash_file);
}

static int
revoke_request ()
{
	if (test_and_delete_var ("MokNew") < 0)
		return -1;

	if (test_and_delete_var ("MokAuth") < 0)
		return -1;

	return 0;
}

static int
export_moks ()
{
	efi_variable_t var;
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

	if (read_variable (&var) != EFI_SUCCESS) {
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
	free (var.Data);

	return ret;
}

static int
set_password (const char *hash_file)
{
	efi_variable_t var;
	uint8_t salt[SALT_SIZE];
	uint8_t hash[SHA256_DIGEST_LENGTH];
	uint8_t auth[SHA256_DIGEST_LENGTH + SALT_SIZE];
	char *password = NULL;
	int pw_len;
	int ret = -1;

	if (hash_file) {
		if (get_hash_from_file (hash_file, salt, hash) < 0) {
			fprintf (stderr, "Failed to read hash\n");
			goto error;
		}
	} else {
		if (get_password (&password, &pw_len, PASSWORD_MIN, PASSWORD_MAX) < 0) {
			fprintf (stderr, "Abort\n");
			goto error;
		}

		generate_salt (salt, SALT_SIZE);
		if (generate_hash (salt, SALT_SIZE, password, pw_len, hash) < 0) {
			fprintf (stderr, "Couldn't generate hash\n");
			goto error;
		}
	}
	memcpy (auth, salt, SALT_SIZE);
	memcpy (auth + SALT_SIZE, hash, SHA256_DIGEST_LENGTH);

	var.Data = auth;
	var.DataSize = SHA256_DIGEST_LENGTH + SALT_SIZE;
	var.VariableName = "MokPW";

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_variable (&var) != EFI_SUCCESS) {
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
set_validation (uint32_t state)
{
	efi_variable_t var;
	MokSBVar sbvar;
	char *password = NULL;
	int pw_len;
	efi_char16_t efichar_pass[PASSWORD_MAX];
	int ret = -1;

        if (get_password (&password, &pw_len, PASSWORD_MIN, PASSWORD_MAX) < 0) {
		fprintf (stderr, "Abort\n");
		goto error;
	}

	sbvar.password_length = pw_len;

	efichar_from_char (efichar_pass, password,
			   PASSWORD_MAX * sizeof(efi_char16_t));

	memcpy(sbvar.password, efichar_pass,
	       PASSWORD_MAX * sizeof(efi_char16_t));

	sbvar.mok_sb_state = state;

	var.VariableName = "MokSB";
	var.VendorGuid = SHIM_LOCK_GUID;
	var.Data = (void *)&sbvar;
	var.DataSize = sizeof(sbvar);
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
		| EFI_VARIABLE_BOOTSERVICE_ACCESS
		| EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to request new SB state\n");
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
	return set_validation(0);
}

static int
enable_validation()
{
	return set_validation(1);
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
test_key (const char *key_file)
{
	struct stat buf;
	void *key = NULL;
	ssize_t read_size;
	int fd, ret = -1;

	if (stat (key_file, &buf) != 0) {
		fprintf (stderr, "Failed to get file status, %s\n", key_file);
		return -1;
	}

	key = malloc (buf.st_size);

	fd = open (key_file, O_RDONLY);
	if (fd < 0) {
		fprintf (stderr, "Failed to open %s\n", key_file);
		goto error;
	}

	read_size = read (fd, key, buf.st_size);
	if (read_size < 0 || read_size != buf.st_size) {
		fprintf (stderr, "Failed to read %s\n", key_file);
		goto error;
	}

	if (!is_duplicate (key, read_size, "PK", EFI_GLOBAL_VARIABLE) &&
	    !is_duplicate (key, read_size, "KEK", EFI_GLOBAL_VARIABLE) &&
	    !is_duplicate (key, read_size, "db", EFI_GLOBAL_VARIABLE) &&
	    !is_duplicate (key, read_size, "MokListRT", SHIM_LOCK_GUID) &&
	    !is_duplicate (key, read_size, "MokNew", SHIM_LOCK_GUID)) {
		printf ("%s is not enrolled\n", key_file);
		ret = 0;
	} else {
		printf ("%s is already enrolled\n", key_file);
		ret = 1;
	}

error:
	if (key)
		free (key);

	close (fd);

	return ret;
}

static int
reset_moks (const char *hash_file)
{
	if (update_request (NULL, 0, 1, hash_file)) {
		fprintf (stderr, "Failed to issue a reset request\n");
		return -1;
	}

	return 0;
}

int
main (int argc, char *argv[])
{
	char **files = NULL;
	char *key_file = NULL;
	char *hash_file = NULL;
	const char *option;
	int c, i, f_ind, total = 0;
	unsigned int command = 0;
	int ret = -1;

	while (1) {
		static struct option long_options[] = {
			{"help",               no_argument,       0, 'h'},
			{"list-enrolled",      no_argument,       0, 0  },
			{"list-new",	       no_argument,       0, 0  },
			{"import",             required_argument, 0, 'i'},
			{"delete",             required_argument, 0, 'd'},
			{"revoke",             no_argument,       0, 0  },
			{"export",             no_argument,       0, 'x'},
			{"password",           no_argument,       0, 'p'},
			{"disable-validation", no_argument,       0, 0  },
			{"enable-validation",  no_argument,       0, 0  },
			{"sb-state",           no_argument,       0, 0  },
			{"test-key",           required_argument, 0, 't'},
			{"reset",              no_argument,       0, 0  },
			{"hash-file",          required_argument, 0, 'f'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long (argc, argv, "d:f:hi:pt:x",
				 long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			option = long_options[option_index].name;
			if (strcmp (option, "list-enrolled") == 0) {
				command |= LIST_ENROLLED;
			} else if (strcmp (option, "list-new") == 0) {
				command |= LIST_NEW;
			} else if (strcmp (option, "revoke") == 0) {
				command |= REVOKE;
			} else if (strcmp (option, "disable-validation") == 0) {
				command |= DISABLE_VALIDATION;
			} else if (strcmp (option, "enable-validation") == 0) {
				command |= ENABLE_VALIDATION;
			} else if (strcmp (option, "sb-state") == 0) {
				command |= SB_STATE;
			} else if (strcmp (option, "reset") == 0) {
				command |= RESET;
			}
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

			files = malloc (total * sizeof (char *));
			for (i = 0; i < total; i++) {
				f_ind = i + optind - 1;
				files[i] = malloc (strlen(argv[f_ind]) + 1);
				strcpy (files[i], argv[f_ind]);
			}

			break;
		case 'f':
			hash_file = strdup (optarg);

			command |= HASH_FILE;
			break;
		case 'p':
			command |= PASSWORD;
			break;
		case 't':
			key_file = strdup (optarg);

			command |= TEST_KEY;
			break;
		case 'x':
			command |= EXPORT;
			break;
		case 'h':
		case '?':
			command |= HELP;
			break;
		default:
			abort ();
		}
	}

	switch (command) {
		case LIST_ENROLLED:
			ret = list_enrolled_keys ();
			break;
		case LIST_NEW:
			ret = list_new_keys ();
			break;
		case IMPORT:
		case IMPORT | HASH_FILE:
			ret = import_moks (files, total, hash_file);
			break;
		case DELETE:
		case DELETE | HASH_FILE:
			ret = delete_moks (files, total, hash_file);
			break;
		case REVOKE:
			ret = revoke_request ();
			break;
		case EXPORT:
			ret = export_moks ();
			break;
		case PASSWORD:
		case PASSWORD | HASH_FILE:
			ret = set_password (hash_file);
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
			ret = test_key (key_file);
			break;
		case RESET:
		case RESET | HASH_FILE:
			ret = reset_moks (hash_file);
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

	return ret;
}
