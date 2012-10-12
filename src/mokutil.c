#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

#include <openssl/sha.h>
#include <openssl/x509.h>

#include "efi.h"

#define SHIM_LOCK_GUID \
EFI_GUID (0x605dab50, 0xe046, 0x4300, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23)

#define PASSWORD_MAX 16
#define PASSWORD_MIN 8

typedef struct {
	uint32_t mok_size;
	void    *mok;
} MokListNode;

enum Command {
	COMMAND_LIST_ENROLLED,
	COMMAND_LIST_NEW,
	COMMAND_IMPORT,
	COMMAND_DELETE,
	COMMAND_REVOKE,
	COMMAND_EXPORT,
};

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
	printf("Request to delete all keys\n");
	printf("  mokutil --delete-all\n\n");
	printf("Revoke the request:\n");
	printf("  mokutil --revoke\n\n");
	printf("Export enrolled keys to files:\n");
	printf("  mokutil --export\n\n");
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
	long long remain = data_size;
	uint32_t num, i;
	void *ptr;

	if (data_size < sizeof(uint32_t))
		return NULL;

	memcpy (&num, data, sizeof(uint32_t));

	if (num == 0)
		return NULL;

	remain -= sizeof(uint32_t);
	if (remain <= 0) {
		fprintf(stderr, "the list was corrupted\n");
		return NULL;
	}

	ptr = data + sizeof(uint32_t);

	list = malloc(sizeof(MokListNode) * num);

	if (!list) {
		fprintf(stderr, "Unable to allocate MOK list\n");
		return NULL;
	}

	for (i = 0; i < num; i++) {
		memcpy (&list[i].mok_size, ptr, sizeof(uint32_t));
		remain -= sizeof(uint32_t) + list[i].mok_size;

		if (remain < 0) {
			fprintf(stderr, "the list was corrupted\n");
			free (list);
			return NULL;
		}

		ptr += sizeof(uint32_t);
		list[i].mok = ptr;
		ptr += list[i].mok_size;
	}

	*mok_num = num;

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

	/* Turn echoing off and fail if we can't. */
	if (tcgetattr (fileno (stdin), &old) != 0)
		return -1;

	new = old;
	new.c_lflag &= ~ECHO;

	if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
		return -1;

	/* Read the password. */
	nread = getline (line, n, stdin);

	/* Restore terminal. */
	(void) tcsetattr (fileno (stdin), TCSAFLUSH, &old);

	/* Remove the newline */
	(*line)[nread-1] = '\0';

	return nread-1;
}

static int
get_password (char **password, int *len)
{
	char *password_1, *password_2;
	int len_1, len_2;
	size_t n;

	password_1 = password_2 = NULL;

	printf ("input password (%d~%d characters): ",
		PASSWORD_MIN, PASSWORD_MAX);
	len_1 = read_hidden_line (&password_1, &n);
	printf ("\n");

	if (len_1 > PASSWORD_MAX || len_1 < PASSWORD_MIN) {
		free (password_1);
		fprintf (stderr, "password should be %d~%d characters\n",
			 PASSWORD_MIN, PASSWORD_MAX);
		return -1;
	}

	printf ("input password again: ");
	len_2 = read_hidden_line (&password_2, &n);
	printf ("\n");

	if (len_1 != len_2 || strcmp (password_1, password_2) != 0) {
		free (password_1);
		free (password_2);
		fprintf (stderr, "password doesn't match\n");
		return -1;
	}

	*password = password_1;
	*len = len_1;

	free (password_2);

	return 0;
}

static int
generate_auth (void *new_list, int list_len, char *password, int pw_len,
	       uint8_t *auth)
{
	efi_char16_t efichar_pass[PASSWORD_MAX+1];
	unsigned long efichar_len;
	SHA256_CTX ctx;

	if (!new_list || !password || !auth)
		return -1;

	efichar_len = efichar_from_char (efichar_pass, password,
					 (PASSWORD_MAX+1)*sizeof(efi_char16_t));

	SHA256_Init (&ctx);

	SHA256_Update (&ctx, new_list, list_len);

	SHA256_Update (&ctx, efichar_pass, efichar_len);

	SHA256_Final (auth, &ctx);

	return 0;
}

static int
update_request (void *new_list, int list_len)
{
	efi_variable_t var;
	uint8_t auth[SHA256_DIGEST_LENGTH];
	char *password = NULL;
	int pw_len, fail = 0;
	int ret = -1;

	while (fail < 3 && get_password (&password, &pw_len) < 0)
		fail++;

	if (fail >= 3) {
		fprintf (stderr, "Abort\n");
		goto error;
	}

	generate_auth (new_list, list_len, password, pw_len, auth);

	/* Write MokNew*/
	var.Data = new_list;
	var.DataSize = list_len;
	var.VariableName = "MokNew";

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to enroll new keys\n");
		goto error;
	}

	/* Write MokAuth */
	var.Data = auth;
	var.DataSize = SHA256_DIGEST_LENGTH;
	var.VariableName = "MokAuth";

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (edit_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to write MokAuth\n");
		test_and_delete_var ("MokNew");
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
import_moks (char **files, uint32_t total)
{
	void *new_list = NULL;
	void *ptr;
	struct stat buf;
	unsigned long list_size;
	uint32_t *sizes = NULL;
	int fd = -1;
	ssize_t read_size;
	int i, ret = -1;

	if (!files)
		return -1;

	/* sizeof(MokNum) */
	list_size = sizeof(uint32_t);
	sizes = malloc (total * sizeof(uint32_t));

	for (i = 0; i < total; i++) {
		if (stat (files[i], &buf) != 0) {
			fprintf (stderr, "Failed to get file status, %s\n",
			         files[i]);
			goto error;
		}

		sizes[i] = buf.st_size;
		/* sizeof(MokSize) + sizeof(Mok) */
		list_size += sizeof(uint32_t) + buf.st_size;
	}

	new_list = malloc (list_size);
	if (!new_list) {
		fprintf (stderr, "Failed to allocate space for MokNew\n");
		goto error;
	}
	ptr = new_list;

	/* MokNum */
	memcpy (ptr, &total, sizeof(uint32_t));
	ptr += sizeof(uint32_t);

	for (i = 0; i < total; i++) {
		/* MokSize */
		memcpy (ptr, &sizes[i], sizeof(uint32_t));
		ptr += sizeof(uint32_t);

		fd = open (files[i], O_RDONLY);
		if (fd == -1) {
			fprintf (stderr, "Failed to open %s\n", files[i]);
			goto error;
		}

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
		ptr += sizes[i];

		close (fd);
	}

	if (update_request (new_list, list_size) < 0) {
		goto error;
	}

	ret = 0;
error:
	if (sizes)
		free (sizes);
	if (new_list)
		free (new_list);

	return ret;
}

static int
delete_all ()
{
	uint32_t mok_num = 0;

	if (update_request (&mok_num, sizeof(mok_num))) {
		fprintf (stderr, "Failed to issue an delete request\n");
		return -1;
	}

	return 0;
}

static int
revoke_request ()
{
	/* TODO request the old password? */

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

int
main (int argc, char *argv[])
{
	char **files = NULL;
	int i, total;
	int command;

	if (argc < 2) {
		print_help ();
		return 0;
	}

	if (strcmp (argv[1], "-h") == 0 ||
	    strcmp (argv[1], "--help") == 0) {

		print_help ();
		return 0;

	} else if (strcmp (argv[1], "-le") == 0 ||
	           strcmp (argv[1], "--list-enrolled") == 0) {

		command = COMMAND_LIST_ENROLLED;

	} else if (strcmp (argv[1], "-ln") == 0 ||
	           strcmp (argv[1], "--list-new") == 0) {

		command = COMMAND_LIST_NEW;

	} else if (strcmp (argv[1], "-i") == 0 ||
	           strcmp (argv[1], "--import") == 0) {

		if (argc < 3) {
			print_help ();
			return -1;
		}
		total = argc - 2;

		files = malloc (total * sizeof(char *));
		if (!files) {
			fprintf (stderr, "Failed to allocate file list\n");
			return -1;
		}

		for (i = 0; i < total; i++)
			files[i] = argv[i+2];

		command = COMMAND_IMPORT;

	} else if (strcmp (argv[1], "-D") == 0 ||
	           strcmp (argv[1], "--delete-all") == 0) {

		command = COMMAND_DELETE;

	} else if (strcmp (argv[1], "-r") == 0 ||
	           strcmp (argv[1], "--revoke") == 0) {

		command = COMMAND_REVOKE;

	} else if (strcmp (argv[1], "-x") == 0 ||
	           strcmp (argv[1], "--export") == 0) {

		command = COMMAND_EXPORT;

	} else {
		fprintf (stderr, "Unknown argument: %s\n\n", argv[1]);
		print_help ();
		return -1;
	}

	switch (command) {
		case COMMAND_LIST_ENROLLED:
			list_enrolled_keys ();
			break;
		case COMMAND_LIST_NEW:
			list_new_keys ();
			break;
		case COMMAND_IMPORT:
			import_moks (files, total);
			break;
		case COMMAND_DELETE:
			delete_all ();
			break;
		case COMMAND_REVOKE:
			revoke_request ();
			break;
		case COMMAND_EXPORT:
			export_moks ();
			break;
		default:
			fprintf (stderr, "Unknown command\n");
			break;
	}

	if (files)
		free (files);

	return 0;
}
