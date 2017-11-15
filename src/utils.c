#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include <openssl/sha.h>
#include <openssl/x509.h>

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
generate_hash (pw_crypt_t *pw_crypt, char *password, unsigned int pw_len)
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
