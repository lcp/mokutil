/**
 * Copyright (C) 2020 Gary Lin <glin@suse.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>

#include "efi_hash.h"
#include "util.h"

int
mok_get_variable(const char *name, uint8_t **datap, size_t *data_sizep)
{
	char filename[] = "/sys/firmware/efi/mok-variables/implausibly-long-mok-variable-name";
	size_t filename_sz = sizeof(filename);
	int fd, rc;
	struct stat sb = { 0, };
	uint8_t *buf;
	size_t bufsz, pos = 0;
	ssize_t ssz;

	*datap = 0;
	*data_sizep = 0;

	snprintf(filename, filename_sz, "/sys/firmware/efi/mok-variables/%s", name);

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return fd;

	rc = fstat(fd, &sb);
	if (rc < 0)
		goto done;

	if (sb.st_size == 0) {
		errno = ENOENT;
		rc = -1;
		goto done;
	}

	bufsz = sb.st_size;
	buf = calloc(1, bufsz);
	if (!buf) {
		rc = -1;
		goto done;
	}

	while (pos < bufsz) {
		ssz = read(fd, &buf[pos], bufsz - pos);
		if (ssz < 0) {
			if (errno == EAGAIN ||
			    errno == EWOULDBLOCK ||
			    errno == EINTR)
				continue;
			free(buf);
			rc = -1;
			goto done;
		}

		pos += ssz;
	}
	*datap = buf;
	*data_sizep = pos;
	rc = 0;
done:
	close(fd);
	return rc;
}

MokListNode*
build_mok_list (const void *data, const uintptr_t data_size,
		uint32_t *mok_num)
{
	MokListNode *list = NULL;
	MokListNode *list_new = NULL;
	EFI_SIGNATURE_LIST *CertList = (void *)data;
	EFI_SIGNATURE_DATA *Cert;
	unsigned long dbsize = data_size;
	unsigned long count = 0;
	const void *end = data + data_size;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if ((void *)(CertList + 1) > end ||
		    CertList->SignatureListSize == 0 ||
		    CertList->SignatureListSize <= CertList->SignatureSize) {
			fprintf (stderr, "Corrupted signature list\n");
			if (list)
				free (list);
			return NULL;
		}

		efi_guid_t sigtype = CertList->SignatureType;

		if ((efi_guid_cmp (&sigtype, &efi_guid_x509_cert) != 0) &&
		    (efi_guid_cmp (&sigtype, &efi_guid_sha1) != 0) &&
		    (efi_guid_cmp (&sigtype, &efi_guid_sha224) != 0) &&
		    (efi_guid_cmp (&sigtype, &efi_guid_sha256) != 0) &&
		    (efi_guid_cmp (&sigtype, &efi_guid_sha384) != 0) &&
		    (efi_guid_cmp (&sigtype, &efi_guid_sha512) != 0)) {
			dbsize -= CertList->SignatureListSize;
			CertList = (EFI_SIGNATURE_LIST *)((uint8_t *) CertList +
						  CertList->SignatureListSize);
			continue;
		}

		if ((efi_guid_cmp (&sigtype, &efi_guid_x509_cert) != 0) &&
		    (CertList->SignatureSize != signature_size (&sigtype))) {
			dbsize -= CertList->SignatureListSize;
			CertList = (EFI_SIGNATURE_LIST *)((uint8_t *) CertList +
						  CertList->SignatureListSize);
			continue;
		}

		Cert = (EFI_SIGNATURE_DATA *) (((uint8_t *) CertList) +
		  sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);

		if ((void *)(Cert + 1) > end ||
		    CertList->SignatureSize <= sizeof(efi_guid_t)) {
			if (list)
				free (list);
			fprintf (stderr, "Corrupted signature\n");
			return NULL;
		}

		list_new = realloc(list, sizeof(MokListNode) * (count + 1));
		if (list_new) {
			list = list_new;
		} else {
			if (list)
				free (list);
			fprintf(stderr, "Unable to allocate MOK list\n");
			return NULL;
		}

		list[count].header = CertList;
		list[count].owner  = Cert->SignatureOwner;
		if (efi_guid_cmp (&sigtype, &efi_guid_x509_cert) == 0) {
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

		if (list[count].mok_size > (unsigned long)end -
					   (unsigned long)list[count].mok) {
			fprintf (stderr, "Corrupted data\n");
			free (list);
			return NULL;
		}

		count++;
		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((uint8_t *) CertList +
						  CertList->SignatureListSize);
	}

	*mok_num = count;

	return list;
}

int
test_and_delete_mok_var (const char *var_name)
{
	size_t size;
	int ret;

	ret = efi_get_variable_size (efi_guid_shim, var_name, &size);
	if (ret < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf (stderr, "Failed to access variable \"%s\": %m\n",
			 var_name);
	}

	/* Attempt to delete it no matter what, problem efi_get_variable_size()
	 * had, unless it just doesn't exist anyway. */
	if (!(ret < 0 && errno == ENOENT)) {
		if (efi_del_variable (efi_guid_shim, var_name) < 0)
			fprintf (stderr, "Failed to unset \"%s\": %m\n", var_name);
	}

	return ret;
}

int
delete_data_from_req_var (const MokRequest req, const efi_guid_t *type,
			  const void *data, const uint32_t data_size)
{
	const efi_guid_t *var_guid = &efi_guid_shim;
	const char *var_name = get_req_var_name (req);
	const char *authvar_name = get_req_auth_var_name (req);
	uint8_t *var_data = NULL;
	size_t var_data_size = 0;
	uint32_t attributes;
	MokListNode *list;
	uint32_t mok_num, total, remain;
	void *end, *start = NULL;
	int del_ind, ret = 0;
	uint32_t sig_list_size, sig_size;

	if (!var_name || !data || data_size == 0)
		return 0;

	ret = efi_get_variable (*var_guid, var_name, &var_data, &var_data_size,
				&attributes);
	if (ret < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf (stderr, "Failed to read variable \"%s\": %m\n",
			 var_name);
		return -1;
	}

	total = var_data_size;

	list = build_mok_list (var_data, var_data_size, &mok_num);
	if (list == NULL)
		goto done;

	remain = total;
	for (unsigned int i = 0; i < mok_num; i++) {
		remain -= list[i].header->SignatureListSize;
		efi_guid_t sigtype = list[i].header->SignatureType;
		if (efi_guid_cmp (&sigtype, type) != 0)
			continue;

		sig_list_size = list[i].header->SignatureListSize;

		if (efi_guid_cmp (type, &efi_guid_x509_cert) == 0) {
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
	if (start == NULL) {
		ret = 0;
		goto done;
	}

	/* all keys are removed */
	if (total == 0) {
		if (test_and_delete_mok_var (var_name) != 0)
			goto done;
		if (test_and_delete_mok_var (authvar_name) != 0)
			goto done;
		ret = 1;
		goto done;
	}

	/* remove the key or hash  */
	if (remain > 0)
		memmove (start, end, remain);

	attributes = EFI_VARIABLE_NON_VOLATILE
		     | EFI_VARIABLE_BOOTSERVICE_ACCESS
		     | EFI_VARIABLE_RUNTIME_ACCESS;
	ret = efi_set_variable (*var_guid, var_name,
				var_data, total, attributes,
				S_IRUSR | S_IWUSR);
	if (ret < 0) {
		fprintf (stderr, "Failed to write variable \"%s\": %m\n",
			 var_name);
		goto done;
	}
	efi_chmod_variable(*var_guid, var_name, S_IRUSR | S_IWUSR);

	ret = 1;
done:
	if (list)
		free (list);
	free (var_data);

	return ret;
}

unsigned long
efichar_from_char (efi_char16_t *dest, const char *src, size_t dest_len)
{
	unsigned int i, src_len = strlen(src);
	for (i=0; i < src_len && i < (dest_len/sizeof(*dest)) - 1; i++) {
		dest[i] = src[i];
	}
	dest[i] = 0;
	return i * sizeof(*dest);
}

int
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

const char *
get_db_var_name (const DBName db_name)
{
	const char *db_var_names[] = {
		[MOK_LIST_RT]   = "MokListRT",
		[MOK_LIST_X_RT] = "MokListXRT",
		[PK]            = "PK",
		[KEK]           = "KEK",
		[DB]            = "db",
		[DBX]           = "dbx",
	};

	return db_var_names[db_name];
}

const char *
get_db_friendly_name (const DBName db_name)
{
	const char *db_friendly_names[] = {
		[MOK_LIST_RT]   = "MOK",
		[MOK_LIST_X_RT] = "MOKX",
		[PK]            = "PK",
		[KEK]           = "KEK",
		[DB]            = "DB",
		[DBX]           = "DBX",
	};

	return db_friendly_names[db_name];
}

const char *
get_req_var_name (const MokRequest req)
{
	const char *var_names[] = {
		[DELETE_MOK] = "MokDel",
		[ENROLL_MOK] = "MokNew",
		[DELETE_BLACKLIST] = "MokXDel",
		[ENROLL_BLACKLIST] = "MokXNew"
	};

	return var_names[req];
}

const char *
get_req_auth_var_name (const MokRequest req)
{
	const char *auth_var_names[] = {
		[DELETE_MOK] = "MokDelAuth",
		[ENROLL_MOK] = "MokAuth",
		[DELETE_BLACKLIST] = "MokXDelAuth",
		[ENROLL_BLACKLIST] = "MokXAuth"
	};

	return auth_var_names[req];
}

MokRequest
get_reverse_req (const MokRequest req)
{
	const MokRequest reverse_reqs[] = {
		[DELETE_MOK] = ENROLL_MOK,
		[ENROLL_MOK] = DELETE_MOK,
		[DELETE_BLACKLIST] = ENROLL_BLACKLIST,
		[ENROLL_BLACKLIST] = DELETE_BLACKLIST,
	};

	return reverse_reqs[req];
}

const char *
get_reverse_req_var_name (const MokRequest req)
{
	const MokRequest reverse_req = get_reverse_req (req);

	return get_req_var_name (reverse_req);
}
