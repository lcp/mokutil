#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

#include <openssl/sha.h>

#include "efi.h"

#define SHIM_LOCK_GUID \
EFI_GUID (0x605dab50, 0xe046, 0x4300, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23)

#define PASSWORD_MAX 16
#define PASSWORD_MIN 8

enum Command {
	COMMAND_LIST_ENROLLED,
	COMMAND_LIST_NEW,
	COMMAND_ENROLL,
	COMMAND_DELETE,
	COMMAND_ERASE,
	COMMAND_REVOKE,
};

static void
print_help ()
{
	printf("Usage:\n");
	printf("List the enrolled keys:\n");
	printf("  mokutil --list-enrolled\n\n");
	printf("List the keys to be enrolled:\n");
	printf("  mokutil --list-new\n\n");
	printf("Import a new key:\n");
	printf("  mokutil --enroll <der file>\n\n");
	printf("Delete a key:\n");
	printf("  mokutil --delete <key number>\n\n");
	printf("Erase all keys\n");
	printf("  mokutil --erase\n\n");
	printf("Revoke the request:\n");
	printf("  mokutil --revoke\n\n");
}

static int
test_and_delete_var (char *var_name)
{
	efi_variable_t var, testvar;
	char name[PATH_MAX];

	memset (&var, 0, sizeof(var));
	efichar_from_char (var.VariableName, var_name,
			   sizeof(var.VariableName));

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Status = EFI_SUCCESS;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	variable_to_name (&var, name);

	if (read_variable (name, &testvar) == EFI_SUCCESS) {
		if (delete_variable (&var) != EFI_SUCCESS) {
			fprintf (stderr, "Failed to unset %s\n", var_name);
			return -1;
		}
	}

	return 0;
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

	printf ("input password again: ",
		PASSWORD_MIN, PASSWORD_MAX);
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

	memcpy (var.Data, new_list, list_len);
	var.DataSize = list_len;

	/* Write MokNew*/
	efichar_from_char (var.VariableName, "MokNew",
			   sizeof(var.VariableName));

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Status = EFI_SUCCESS;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (create_or_edit_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to enroll new keys\n");
		goto error;
	}

	/* Write MokAuth */
	memcpy (var.Data, auth, SHA256_DIGEST_LENGTH);
	var.DataSize = SHA256_DIGEST_LENGTH;
	efichar_from_char (var.VariableName, "MokAuth",
			   sizeof(var.VariableName));

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Status = EFI_SUCCESS;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	if (create_or_edit_variable (&var) != EFI_SUCCESS) {
		fprintf (stderr, "Failed to write MokAuth\n");
		/* TODO delete MokNew */
		goto error;
	}

	ret = 0;
error:
	if (password)
		free (password);
	return ret;
}

static int
enroll_mok (char *filename)
{
	void *new_list = NULL, *ptr;
	int list_len, extra;
	uint32_t mok_num, key_size;
	int fd = -1;
	struct stat buf;
	ssize_t read_size;
	int ret = -1;

	if (!filename) {
		fprintf (stderr, "Invalid filename\n");
		return -1;
	}

	fd = open (filename, O_RDONLY);
	if (fd == -1) {
		fprintf (stderr, "Failed to open %s\n", filename);
		goto error;
	}

	if (fstat (fd, &buf) != 0) {
		fprintf (stderr, "Failed to get file stat\n");
		goto error;
	}

	/* the current data limit in kernel is 1024 */
	if (buf.st_size > 1024) {
		fprintf (stderr, "The file is larger than 1024 bytes\n");
		goto error;
	}

	mok_num = 1;
	extra = sizeof(mok_num) + mok_num*sizeof(key_size);
	new_list = malloc (buf.st_size + extra);
	if (new_list == NULL) {
		goto error;
	}

	ptr = new_list;
	memcpy ((void *)ptr, (void *)&mok_num, sizeof(mok_num));
	ptr += sizeof(mok_num);
	key_size = buf.st_size;
	memcpy ((void *)ptr, (void *)&key_size, sizeof(key_size));
	ptr += sizeof(key_size);
	read_size = read (fd, ptr, buf.st_size);
	if (read_size < 0 || read_size != buf.st_size) {
		fprintf (stderr, "Failed to read %s\n", filename);
		goto error;
	}
	list_len = read_size + sizeof(mok_num) + sizeof(key_size);

	if (update_request (new_list, list_len) < 0) {
		goto error;
	}

	ret = 0;
error:
	close (fd);
	if (new_list)
		free (new_list);

	return ret;
}

static int
erase_all ()
{
	uint32_t mok_num = 0;

	if (update_request (&mok_num, sizeof(mok_num))) {
		fprintf (stderr, "Failed to issue an erase operation\n");
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

int
main (int argc, char *argv[])
{
	char *filename;
	int command;
	long delete;

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

	} else if (strcmp (argv[1], "-e") == 0 ||
	           strcmp (argv[1], "--enroll") == 0) {

		/* TODO allow multiple files to be enrolled at one time */
		if (argc < 3) {
			print_help ();
			return -1;
		}
		filename = argv[2];
		command = COMMAND_ENROLL;

	} else if (strcmp (argv[1], "-d") == 0 ||
	           strcmp (argv[1], "--delete") == 0) {

		if (argc < 3) {
			print_help ();
			return -1;
		}
		delete = atoi(argv[2]);
		command = COMMAND_DELETE;

	} else if (strcmp (argv[1], "-e") == 0 ||
	           strcmp (argv[1], "--erase") == 0) {

		command = COMMAND_ERASE;

	} else if (strcmp (argv[1], "-r") == 0 ||
	           strcmp (argv[1], "--revoke") == 0) {

		command = COMMAND_REVOKE;

	} else {
		fprintf (stderr, "Unknown argument: %s\n\n", argv[1]);
		print_help ();
		return -1;
	}

	switch (command) {
		case COMMAND_LIST_ENROLLED:
			/* TODO list MokListRT */
			break;
		case COMMAND_LIST_NEW:
			/* TODO list MokNew */
			break;
		case COMMAND_ENROLL:
			enroll_mok (filename);
			break;
		case COMMAND_DELETE:
			/* TODO search the key in MokListRT and MokNew
			   and create a new MokNew */
			break;
		case COMMAND_ERASE:
			erase_all();
			break;
		case COMMAND_REVOKE:
			revoke_request ();
			break;
		default:
			fprintf (stderr, "Unknown command\n");
			break;
	}

	return 0;
}
