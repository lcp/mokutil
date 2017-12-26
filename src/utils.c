/**
 * Copyright (C) 2017 Gary Lin <glin@suse.com>
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

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <crypt.h>
#include <shadow.h>

#include "utils.h"

uint32_t
efi_hash_size (const efi_guid_t *hash_type)
{
	if (efi_guid_cmp (hash_type, &efi_guid_sha1) == 0) {
		return SHA_DIGEST_LENGTH;
	} else if (efi_guid_cmp (hash_type, &efi_guid_sha224) == 0) {
		return SHA224_DIGEST_LENGTH;
	} else if (efi_guid_cmp (hash_type, &efi_guid_sha256) == 0) {
		return SHA256_DIGEST_LENGTH;
	} else if (efi_guid_cmp (hash_type, &efi_guid_sha384) == 0) {
		return SHA384_DIGEST_LENGTH;
	} else if (efi_guid_cmp (hash_type, &efi_guid_sha512) == 0) {
		return SHA512_DIGEST_LENGTH;
	}

	return 0;
}

uint32_t
signature_size (const efi_guid_t *hash_type)
{
	uint32_t hash_size;

	hash_size = efi_hash_size (hash_type);
	if (hash_size)
		return (hash_size + sizeof(efi_guid_t));

	return 0;
}

void
allocate_x509_sig (void *dest, const uint8_t *cert, const uint32_t cert_size)
{
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *CertData;

	CertList = dest;
	CertData = (EFI_SIGNATURE_DATA *)(((uint8_t *)dest) +
					  sizeof(EFI_SIGNATURE_LIST));
	CertList->SignatureType = efi_guid_x509_cert;
	CertList->SignatureListSize = cert_size +
	   sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1;
	CertList->SignatureHeaderSize = 0;
	CertList->SignatureSize = cert_size + sizeof(efi_guid_t);
	CertData->SignatureOwner = efi_guid_shim;

	CertData = (EFI_SIGNATURE_DATA *)(((uint8_t *)dest) +
					  sizeof(EFI_SIGNATURE_LIST));
	memcpy (CertData->SignatureData, cert, cert_size);
}

int
test_and_delete_var (const char *var_name)
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

/* match the hash in the hash array and return the index if matched */
int
match_hash_array (const efi_guid_t *hash_type, const void *hash,
		  const void *hash_array, const uint32_t array_size)
{
	uint32_t hash_size, hash_count;
	uint32_t sig_size;
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
	for (unsigned int i = 0; i < hash_count; i++) {
		ptr += sizeof(efi_guid_t);
		if (memcmp (ptr, hash, hash_size) == 0)
			return i;
		ptr += hash_size;
	}

	return -1;
}

MokListNode*
build_mok_list (void *data, unsigned long data_size, uint32_t *mok_num)
{
	MokListNode *list = NULL;
	MokListNode *list_new = NULL;
	EFI_SIGNATURE_LIST *CertList = data;
	EFI_SIGNATURE_DATA *Cert;
	unsigned long dbsize = data_size;
	unsigned long count = 0;
	void *end = data + data_size;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if ((void *)(CertList + 1) > end ||
		    CertList->SignatureListSize == 0 ||
		    CertList->SignatureListSize <= CertList->SignatureSize) {
			fprintf (stderr, "Corrupted signature list\n");
			if (list)
				free (list);
			return NULL;
		}

		if ((efi_guid_cmp (&CertList->SignatureType, &efi_guid_x509_cert) != 0) &&
		    (efi_guid_cmp (&CertList->SignatureType, &efi_guid_sha1) != 0) &&
		    (efi_guid_cmp (&CertList->SignatureType, &efi_guid_sha224) != 0) &&
		    (efi_guid_cmp (&CertList->SignatureType, &efi_guid_sha256) != 0) &&
		    (efi_guid_cmp (&CertList->SignatureType, &efi_guid_sha384) != 0) &&
		    (efi_guid_cmp (&CertList->SignatureType, &efi_guid_sha512) != 0)) {
			dbsize -= CertList->SignatureListSize;
			CertList = (EFI_SIGNATURE_LIST *)((uint8_t *) CertList +
						  CertList->SignatureListSize);
			continue;
		}

		if ((efi_guid_cmp (&CertList->SignatureType, &efi_guid_x509_cert) != 0) &&
		    (CertList->SignatureSize != signature_size (&CertList->SignatureType))) {
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
		if (efi_guid_cmp (&CertList->SignatureType, &efi_guid_x509_cert) == 0) {
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

static int
delete_data_from_list (const efi_guid_t *var_guid, const char *var_name,
		       const efi_guid_t *type, void *data, uint32_t data_size)
{
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
		if (efi_guid_cmp (&list[i].header->SignatureType, type) != 0)
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

int
delete_from_pending_request (const efi_guid_t *type, void *data,
			     uint32_t data_size, MokRequest req)
{
	uint8_t *authvar_data;
	size_t authvar_data_size;
	uint32_t attributes;
	int ret;

	/* Search the list in opposite to the request:
	 *  DELETE_MOK -> MokNew
	 *  ENROLL_MOK -> MokDel
	 *  DELETE_BLACKLIST -> MokXNew
	 *  ENROLL_BLACKLIST -> MokXDel
	 * */
	const char *authvar_names[] = {
		[DELETE_MOK] = "MokAuth",
		[ENROLL_MOK] = "MokDelAuth",
		[DELETE_BLACKLIST] = "MokXAuth",
		[ENROLL_BLACKLIST] = "MokXDelAuth"
	};
	const char *var_names[] = {
		[DELETE_MOK] = "MokNew",
		[ENROLL_MOK] = "MokDel",
		[DELETE_BLACKLIST] = "MokXNew",
		[ENROLL_BLACKLIST] = "MokXDel"
	};

	if (!data || data_size == 0)
		return 0;

	if (efi_get_variable (efi_guid_shim, authvar_names[req], &authvar_data,
			      &authvar_data_size, &attributes) < 0)
		return 0;

	free (authvar_data);
	/* Check if the password hash is in the old format */
	if (authvar_data_size == SHA256_DIGEST_LENGTH)
		return 0;

	ret = delete_data_from_list (&efi_guid_shim, var_names[req],
				     type, data, data_size);
	if (ret < 0)
		return -1;

	return ret;
}

int
is_duplicate (const efi_guid_t *type, const void *data, const uint32_t data_size,
	      const efi_guid_t *vendor, const char *db_name)
{
	uint8_t *var_data;
	size_t var_data_size;
	uint32_t attributes;
	uint32_t node_num;
	MokListNode *list;
	int ret = 0;

	if (!data || data_size == 0 || !db_name)
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
		if (efi_guid_cmp (&list[i].header->SignatureType, type) != 0)
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

done:
	if (list)
		free (list);
	free (var_data);

	return ret;
}

int
is_valid_request (const efi_guid_t *type, void *mok, uint32_t mok_size,
		  MokRequest req)
{
	switch (req) {
	case ENROLL_MOK:
		if (is_duplicate (type, mok, mok_size, &efi_guid_global, "PK") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_global, "KEK") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_security, "db") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokListRT") ||
		    is_duplicate (type, mok, mok_size, &efi_guid_shim, "MokNew")) {
			return 0;
		}
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

int
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

int
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

void
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

int
generate_hash (pw_crypt_t *pw_crypt, const char *password,
	       const unsigned int pw_len)
{
	pw_crypt_t new_crypt;
	char settings[SETTINGS_LEN];
	char *crypt_string;
	const char *prefix;
	int hash_len, prefix_len;

	if (!password || !pw_crypt || password[pw_len] != '\0')
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

int
generate_auth (void *new_list, int list_len, char *password,
	       unsigned int pw_len, uint8_t *auth)
{
	efi_char16_t efichar_pass[PASSWORD_MAX+1];
	unsigned long efichar_len;
	SHA256_CTX ctx;

	if (!password || !auth)
		return -1;

	efichar_len = efichar_from_char (efichar_pass, password,
					 pw_len * sizeof(efi_char16_t));

	SHA256_Init (&ctx);

	if (new_list)
		SHA256_Update (&ctx, new_list, list_len);

	SHA256_Update (&ctx, efichar_pass, efichar_len);

	SHA256_Final (auth, &ctx);

	return 0;
}

/* Create the variable to store the password hash */
int
create_authvar (const char *auth_name, const char *password,
		const uint8_t root_pw)
{
	pw_crypt_t pw_crypt;
	int ret;

	bzero (&pw_crypt, sizeof(pw_crypt_t));
	pw_crypt.method = DEFAULT_CRYPT_METHOD;

	/* Generate the password hash */
	if (!root_pw)
		ret = generate_hash (&pw_crypt, password, strlen(password));
	else
		ret = get_password_from_shadow (&pw_crypt);
	if (ret < 0)
		return ret;

	return efi_set_variable (efi_guid_shim, auth_name, (void *)&pw_crypt,
				 PASSWORD_CRYPT_SIZE, EFI_NV_RT,
				 S_IRUSR | S_IWUSR);
}

int
read_file_to_buffer (const char *filename, uint8_t **buffer,
		     uint32_t *buf_size)
{
	struct stat f_stat;
	ssize_t read_size;
	int fd = 0, ret = -1;

	if (stat (filename, &f_stat) != 0)
			goto out;

	*buffer = (uint8_t *)malloc (f_stat.st_size);
	if (*buffer == NULL)
		return -1;

	fd = open (filename, O_RDONLY);
	if (fd == -1)
		return -1;

	read_size = read (fd, *buffer, f_stat.st_size);
	if (read_size < 0 || read_size != f_stat.st_size)
		goto out;

	*buf_size = (uint32_t)read_size;
	ret = 0;
out:
	if (fd > 0)
		close (fd);

	return ret;
}

/* === X509 util functions === */
char *
get_x509_time_str (ASN1_TIME *time)
{
	BIO *bio = BIO_new (BIO_s_mem());
	char *time_str;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	uint64_t num_write;
#else
	unsigned long num_write;
#endif

	ASN1_TIME_print (bio, time);
	num_write = BIO_number_written (bio);
	time_str = (char *)calloc (num_write + 1, 1);
	if (time_str == NULL)
		return NULL;
	BIO_read (bio, time_str, num_write);
	BIO_free (bio);

	return time_str;
}

const char *
get_x509_name_str (X509_NAME *X509name, int nid)
{
	X509_NAME_ENTRY *cn_entry = NULL;
	ASN1_STRING *cn_asn1 = NULL;
	int cn_loc = -1;

	cn_loc = X509_NAME_get_index_by_NID (X509name, nid, -1);
	if (cn_loc < 0)
		return NULL;

	cn_entry = X509_NAME_get_entry (X509name, cn_loc);
	if (cn_entry == NULL)
		return NULL;

	cn_asn1 = X509_NAME_ENTRY_get_data (cn_entry);
	if (cn_asn1 == NULL)
		return NULL;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	return (const char *)ASN1_STRING_get0_data (cn_asn1);
#else
	return (const char *)ASN1_STRING_data (cn_asn1);;
#endif
}

char *
get_x509_serial_str (X509 *X509cert)
{
	ASN1_INTEGER *serial;
	BIGNUM *bnser;
	unsigned char *hexbuf = NULL;
	int i, n;
	char *serial_str = NULL, *ptr;

	serial = X509_get_serialNumber (X509cert);
	if (serial == NULL)
		return NULL;

	bnser = ASN1_INTEGER_to_BN(serial, NULL);

	hexbuf = (unsigned char *)malloc (BN_num_bytes(bnser));
	if (hexbuf == NULL)
		goto out;

	n = BN_bn2bin(bnser, hexbuf);
	serial_str = (char *)calloc (n*3 + 3, 1);
	if (serial_str == NULL)
		goto out;

	if (n == 1) {
		sprintf (serial_str, "0x%x", hexbuf[0]);
		goto out;
	}

	ptr = serial_str;
	for (i = 0; i < n; i++) {
		sprintf (ptr, "%02x", hexbuf[i]);
		ptr += 2;
		if (i < n-1) {
			sprintf (ptr, ":");
			ptr++;
		}
	}
out:
	if (hexbuf)
		free (hexbuf);
	return serial_str;
}

const char *
get_x509_sig_alg_str (X509 *X509cert)
{
	const X509_ALGOR *tsig_alg;
	const char *str;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	tsig_alg = X509_get0_tbs_sigalg(X509cert);
#else
	tsig_alg = X509cert->cert_info->signature;
#endif

	str = OBJ_nid2ln (OBJ_obj2nid (tsig_alg->algorithm));

	return str;
}

char *
get_x509_ext_str (const X509 *X509cert, const uint32_t nid)
{
	const STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ext;
	int loc;
	char *str;
	BIO *out;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	uint64_t num_write;
#else
	unsigned long num_write;
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	exts = X509_get0_extensions (X509cert);
#else
	exts = X509cert->cert_info->extensions;
#endif
	loc = X509v3_get_ext_by_NID (exts, nid, -1);
	ext = X509v3_get_ext (exts, loc);

	if (!ext)
		return NULL;

	out = BIO_new (BIO_s_mem());
	if (!X509V3_EXT_print (out, ext, 0, 0))
		return NULL;

	num_write = BIO_number_written (out);
	str = (char *)calloc (num_write + 1, 1);
	if (str == NULL)
		return NULL;

	BIO_read (out, str, num_write);
	BIO_free (out);

	return str;
}
