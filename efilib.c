#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "efi.h"

#define SYSFS_DIR_EFI_VARS "/sys/firmware/efi/vars"

char *
efi_guid_unparse (efi_guid_t *guid, char *out)
{
	sprintf (out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	guid->b[3], guid->b[2], guid->b[1], guid->b[0],
	guid->b[5], guid->b[4], guid->b[7], guid->b[6],
	guid->b[8], guid->b[9], guid->b[10], guid->b[11],
	guid->b[12], guid->b[13], guid->b[14], guid->b[15]);
	return out;
}

int
efichar_strlen (const efi_char16_t *p, int max)
{
	int len=0;
	const efi_char16_t *start = p;

	if (!p || !*p)
		return 0;

	while ((max < 0 || p - start < max) && *(p+len)) {
		++len;
	}
	return len;
}

unsigned long
efichar_from_char (efi_char16_t *dest, const char *src, size_t dest_len)
{
	int i, src_len = strlen(src);
	for (i=0; i < src_len && i < (dest_len/sizeof(*dest)) - 1; i++) {
		dest[i] = src[i];
	}
	dest[i] = 0;
	return i * sizeof(*dest);
}

unsigned long
efichar_to_char (char *dest, const efi_char16_t *src, size_t dest_len)
{
	int i, src_len = efichar_strlen (src, -1);
	for (i=0; i < src_len && i < (dest_len/sizeof(*dest)) - 1; i++) {
		dest[i] = src[i];
	}
	dest[i] = 0;
	return i;
}

efi_status_t
read_variable (const char *name, efi_variable_t *var)
{
	char filename[PATH_MAX];
	int fd;
	size_t readsize;
	char buffer[PATH_MAX+40];

	if (!name || !var)
		return EFI_INVALID_PARAMETER;
	memset (buffer, 0, sizeof(buffer));

	snprintf (filename, PATH_MAX-1, "%s/%s/raw_var", SYSFS_DIR_EFI_VARS, name);
	fd = open (filename, O_RDONLY);
	if (fd == -1) {
		return EFI_NOT_FOUND;
	}
	readsize = read (fd, var, sizeof(*var));
	if (readsize != sizeof(*var)) {
		close (fd);
		return EFI_INVALID_PARAMETER;
	}
	close (fd);
	return var->Status;
}

efi_status_t
write_variable (const char *filename, efi_variable_t *var)
{       
	int fd;
	size_t writesize;
	char buffer[PATH_MAX+40];
        
	if (!filename || !var)
		return EFI_INVALID_PARAMETER;
	memset (buffer, 0, sizeof(buffer));

	fd = open (filename, O_WRONLY);
	if (fd == -1) {
		return EFI_INVALID_PARAMETER;
	}
	writesize = write (fd, var, sizeof(*var));
	if (writesize != sizeof(*var)) {
		close (fd);
		return EFI_INVALID_PARAMETER;
	}
	close (fd);
	return EFI_SUCCESS;
}

int     
variable_to_name (efi_variable_t *var, char *name)
{       
	char *p = name;
	efichar_to_char (p, var->VariableName, PATH_MAX);
	p += strlen (p);
	p += sprintf (p, "-");
	efi_guid_unparse (&var->VendorGuid, p);
	return strlen (name);
}

efi_status_t
edit_variable (efi_variable_t *var)
{
	char name[PATH_MAX];
	char filename[PATH_MAX];
	if (!var)
		return EFI_INVALID_PARAMETER;

	variable_to_name(var, name);

	snprintf(filename, PATH_MAX-1, "%s/%s/raw_var", SYSFS_DIR_EFI_VARS, name);
	return write_variable (filename, var);
}

efi_status_t
create_variable (efi_variable_t *var)
{
	char filename[PATH_MAX];
	if (!var)
		return EFI_INVALID_PARAMETER;
	snprintf (filename, PATH_MAX-1, "%s/%s", SYSFS_DIR_EFI_VARS, "new_var");
	return write_variable (filename, var);
}

efi_status_t
delete_variable(efi_variable_t *var)
{
	char filename[PATH_MAX];
	if (!var)
		return EFI_INVALID_PARAMETER;
	snprintf(filename, PATH_MAX-1, "%s/%s", SYSFS_DIR_EFI_VARS,"del_var");
	return write_variable(filename, var);
}

efi_status_t
create_or_edit_variable (efi_variable_t *var)
{
	efi_variable_t testvar;
	char name[PATH_MAX];

	memcpy (&testvar, var, sizeof(*var));
	variable_to_name (var, name);

	if (read_variable (name, &testvar) == EFI_SUCCESS)
		return edit_variable (var);
	else
		return create_variable (var);
}
