#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "efi.h"

#define SHIM_LOCK_GUID \
EFI_GUID (0x605dab50, 0xe046, 0x4300, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23)

#define COMMAND_SHOW   (0x01<<0)
#define COMMAND_HIDE   (0x01<<1)
#define COMMAND_ENROLL (0x01<<2)
#define COMMAND_REVOKE (0x01<<3)

static void
print_help ()
{
	printf("Usage:\n");
	printf("  mokutil --show-shell\n");
	printf("  mokutil --hide-shell\n");
	printf("  mokutil --enroll <der file>\n");
	printf("  mokutil --revoke\n");
}

static int
show_mok_shell ()
{
	efi_variable_t var;
	efi_status_t status;

	memset (&var, 0, sizeof(var));
	var.Data[0] = 1;
	var.DataSize = 1;
	efichar_from_char (var.VariableName, "MokMgmt",
			   sizeof(var.VariableName));

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Status = EFI_SUCCESS;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	status = create_or_edit_variable (&var);
	if (status != EFI_SUCCESS) {
		printf ("Failed to show the shell\n");
		return -1;
	}

	return 0;
}

static int
hide_mok_shell ()
{
	efi_variable_t var, testvar;
	efi_status_t status;
	char name[PATH_MAX];

	memset (&var, 0, sizeof(var));
	efichar_from_char (var.VariableName, "MokMgmt",
			   sizeof(var.VariableName));

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Status = EFI_SUCCESS;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	variable_to_name (&var, name);

	if (read_variable (name, &testvar) == EFI_SUCCESS) {
		if (status = delete_variable (&var) != EFI_SUCCESS) {
			printf ("Failed to revoke the key\n");
			return -1;
		}
	}

	return 0;
}

static int
enroll_mok (char *filename)
{
	efi_variable_t var;
	efi_status_t status;
	int i, fd = -1;
	struct stat buf;
	ssize_t read_size;

	if (!filename) {
		printf ("Invalid filename\n");
		return -1;
	}

	fd = open (filename, O_RDONLY);
	if (fd == -1) {
		printf ("Failed to open %s\n", filename);
		return -1;
	}

	if (fstat (fd, &buf) != 0) {
		printf ("Failed to get file stat\n");
		return -1;
	}

	/* the current data limit in kernel is 1024 */
	if (buf.st_size > 1024) {
		printf ("The file is larger than 1024 bytes\n");
		return -1;
	}

	read_size = read (fd, var.Data, buf.st_size);
	if (read_size < 0 || read_size != buf.st_size) {
		printf ("Failed to read %s\n", filename);
		return -1;
	}
	var.DataSize = read_size;

	efichar_from_char (var.VariableName, "MokNew",
			   sizeof(var.VariableName));

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Status = EFI_SUCCESS;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	status = create_or_edit_variable (&var);
	if (status != EFI_SUCCESS) {
		printf ("Failed to enroll the key\n");
		return -1;
	}

	return 0;
}

static int
revoke_mok ()
{
	efi_variable_t var, testvar;
	efi_status_t status;
	char name[PATH_MAX];

	memset (&var, 0, sizeof(var));
	efichar_from_char (var.VariableName, "MokNew",
			   sizeof(var.VariableName));

	var.VendorGuid = SHIM_LOCK_GUID;
	var.Status = EFI_SUCCESS;
	var.Attributes = EFI_VARIABLE_NON_VOLATILE
			 | EFI_VARIABLE_BOOTSERVICE_ACCESS
			 | EFI_VARIABLE_RUNTIME_ACCESS;

	variable_to_name (&var, name);

	if (read_variable (name, &testvar) == EFI_SUCCESS) {
		if (status = delete_variable (&var) != EFI_SUCCESS) {
			printf ("Failed to revoke the key\n");
			return -1;
		}
	}

	return 0;
}

int
main (int argc, char *argv[])
{
	efi_variable_t var;
	efi_status_t status;
	char *filename;
	int i, fd = -1;
	struct stat buf;
	ssize_t read_size;
	int command = 0;

	if (argc < 2) {
		print_help ();
		return 0;
	}

	for (i = 1; i < argc; i++) {
		if (strcmp (argv[i], "-s") == 0 ||
		    strcmp (argv[i], "--show-shell") == 0) {
			command |= COMMAND_SHOW;
		} else if (strcmp (argv[i], "-h") == 0 ||
		           strcmp (argv[i], "--hide-shell") == 0) {
			command |= COMMAND_HIDE;
		} else if (strcmp (argv[i], "-e") == 0 ||
		           strcmp (argv[i], "--enroll") == 0) {
			if (i+1 >= argc) {
				print_help ();
				return -1;
			}
			filename = argv[++i];
			command |= COMMAND_ENROLL;
		} else if (strcmp (argv[i], "-r") == 0 ||
		           strcmp (argv[i], "--revoke") == 0) {
			command |= COMMAND_REVOKE;
		} else {
			printf ("Unknown argument: %s\n\n", argv[i]);
			print_help ();
			return -1;
		}
	}

	if ((command & COMMAND_SHOW) && (command & COMMAND_HIDE)) {
		command &= ~COMMAND_SHOW;
		command &= ~COMMAND_HIDE;
	}

	if ((command & COMMAND_ENROLL) && (command & COMMAND_REVOKE)) {
		command &= ~COMMAND_ENROLL;
		command &= ~COMMAND_REVOKE;
	}

	while (command != 0) {
		if (command & COMMAND_SHOW) {
			if (show_mok_shell () < 0)
				break;
			command &= ~COMMAND_SHOW;

		} else if (command & COMMAND_HIDE) {
			if (hide_mok_shell () < 0)
				break;
			command &= ~COMMAND_HIDE;

		} else if (command & COMMAND_ENROLL) {
			if (enroll_mok (filename) < 0)
				break;
			command &= ~COMMAND_ENROLL;

		} else if (command & COMMAND_REVOKE) {
			if (revoke_mok () < 0)
				break;
			command &= ~COMMAND_REVOKE;

		} else {
			printf ("Unknown command\n");
			break;
		}
	}

	if (fd > 0)
		close (fd);

	return 0;
}
