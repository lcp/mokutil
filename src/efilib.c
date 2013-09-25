/**
 * Copyright (C) 2012-2013 Gary Lin <glin@suse.com>
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
 *
 * A part of the source code is copied from efibootmgr
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
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
read_variable (efi_variable_t *var)
{
	char name[PATH_MAX];
	char filename[PATH_MAX];
	int fd;
	struct stat buf;
	size_t readsize, datasize;
	void *buffer;

	if (!var)
		return EFI_INVALID_PARAMETER;

	variable_to_name (var, name);
	snprintf (filename, PATH_MAX-1, "%s/%s", SYSFS_DIR_EFI_VARS, name);
	fd = open (filename, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return EFI_NOT_FOUND;
		return EFI_INVALID_PARAMETER;
	}

	if (fstat (fd, &buf) != 0) {
		close (fd);
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

efi_status_t
edit_protected_variable (efi_variable_t *var)
{
	char name[PATH_MAX];
	char filename[PATH_MAX];
	int ret;
	if (!var)
		return EFI_INVALID_PARAMETER;

	variable_to_name(var, name);

	snprintf(filename, PATH_MAX-1, "%s/%s", SYSFS_DIR_EFI_VARS, name);
	ret = write_variable (filename, var);
	if (ret != EFI_SUCCESS)
		return ret;

	if (chmod (filename, S_IRUSR | S_IWUSR) < 0)
		return EFI_UNSUPPORTED;

	return EFI_SUCCESS;
}
