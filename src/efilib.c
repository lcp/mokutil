#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "efi.h"

#define SYSFS_DIR_EFI_VARS "/sys/firmware/efi/efivars"

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
test_variable (efi_variable_t *var)
{
	char name[PATH_MAX];
	char filename[PATH_MAX];
	struct stat buf;

	if (!var->VariableName) {
		return EFI_INVALID_PARAMETER;
	}

	variable_to_name(var, name);

	snprintf (filename, PATH_MAX-1, "%s/%s", SYSFS_DIR_EFI_VARS, name);

	if (stat (filename, &buf) == 0)
		return EFI_SUCCESS;

	return EFI_NOT_FOUND;
}

efi_status_t
read_variable (const char *name, efi_variable_t *var)
{
	char filename[PATH_MAX];
	int fd;
	struct stat buf;
	size_t readsize, datasize;
	void *buffer;

	if (!name || !var)
		return EFI_INVALID_PARAMETER;

	snprintf (filename, PATH_MAX-1, "%s/%s", SYSFS_DIR_EFI_VARS, name);
	fd = open (filename, O_RDONLY);
	if (fd == -1) {
		return EFI_NOT_FOUND;
	}

	if (fstat (fd, &buf) != 0) {
		return EFI_INVALID_PARAMETER;
	}

	readsize = read (fd, &var->Attributes, sizeof(uint32_t));
	if (readsize != sizeof(uint32_t)) {
		close (fd);
		return EFI_INVALID_PARAMETER;
	}

	datasize = buf.st_size - sizeof(uint32_t);

	buffer = malloc (datasize);
	if (buffer == NULL) {
		close (fd);
		return EFI_OUT_OF_RESOURCES;
	}

	readsize = read (fd, buffer, datasize);
	if (readsize != datasize) {
		close (fd);
		free (buffer);
		return EFI_INVALID_PARAMETER;
	}
	var->Data = buffer;
	var->DataSize = datasize;

	close (fd);
	return EFI_SUCCESS;
}

efi_status_t
write_variable (const char *filename, efi_variable_t *var)
{
	int fd, flag;
	mode_t mode;
	size_t writesize;
	void *buffer;
	unsigned long total;

	if (!filename || !var)
		return EFI_INVALID_PARAMETER;

	buffer = malloc (var->DataSize + sizeof(uint32_t));
	if (buffer == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	memcpy (buffer, &var->Attributes, sizeof(uint32_t));
	memcpy (buffer + sizeof(uint32_t), var->Data, var->DataSize);
	total = var->DataSize + sizeof(uint32_t);

	flag = O_WRONLY | O_CREAT;
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	fd = open (filename, flag, mode);
	if (fd == -1) {
		free (buffer);
		return EFI_INVALID_PARAMETER;
	}
	writesize = write (fd, buffer, total);
	if (writesize != total) {
		close (fd);
		free (buffer);
		return EFI_INVALID_PARAMETER;
	}
	close (fd);
	free (buffer);
	return EFI_SUCCESS;
}

int
variable_to_name (efi_variable_t *var, char *name)
{
	char *p = name;

	if (!var->VariableName)
		return -1;

	strcpy (p, var->VariableName);
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

	snprintf(filename, PATH_MAX-1, "%s/%s", SYSFS_DIR_EFI_VARS, name);
	return write_variable (filename, var);
}

efi_status_t
delete_variable(efi_variable_t *var)
{
	char name[PATH_MAX];
	char filename[PATH_MAX];
	if (!var)
		return EFI_INVALID_PARAMETER;

	variable_to_name(var, name);

	snprintf(filename, PATH_MAX-1, "%s/%s", SYSFS_DIR_EFI_VARS, name);

	if (unlink (filename) == 0)
		return EFI_SUCCESS;

	return EFI_OUT_OF_RESOURCES;
}
