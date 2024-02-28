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
#include <openssl/sha.h>

#include "efi_hash.h"

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
print_hash_array (const efi_guid_t *hash_type, const void *hash_array,
		  const uint32_t array_size, int verbose)
{
	uint32_t hash_size, remain;
	uint32_t sig_size;
	uint8_t *hash;
	char *name;

	if (!hash_array || array_size == 0) {
		fprintf (stderr, "invalid hash array\n");
		return -1;
	}

	int rc = efi_guid_to_name ((efi_guid_t *)hash_type, &name);
	if (rc < 0 || isxdigit(name[0])) {
		if (name)
			free(name);
		fprintf (stderr, "unknown hash type\n");
		return -1;
	}

	hash_size = efi_hash_size (hash_type);
	sig_size = hash_size + sizeof(efi_guid_t);

	if (verbose)
		printf ("  [%s]\n", name);

	remain = array_size;
	hash = (uint8_t *)hash_array;

	while (remain > 0) {
		if (remain < sig_size) {
			fprintf (stderr, "invalid array size\n");
			goto err;
		}

		if (verbose) {
			printf ("  ");
			hash += sizeof(efi_guid_t);
			for (unsigned int i = 0; i<hash_size; i++)
				printf ("%02x", *(hash + i));
			printf ("\n");
		} else {
			hash += sizeof(efi_guid_t);
			for (unsigned int i = 0; i<5; i++)
				printf ("%02x", *(hash + i));
			printf (" (%s)\n", name);
		}

		hash += hash_size;
		remain -= sig_size;
	}

	return 0;

err:
	free(name);
	return -1;
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

/* Return the hash type and size of a given hash string */
int
identify_hash_type (const char *hash_str, efi_guid_t *type)
{
	unsigned int len = strlen (hash_str);
	int hash_size;

	for (unsigned int i = 0; i < len; i++) {
		if ((hash_str[i] > '9' || hash_str[i] < '0') &&
		    (hash_str[i] > 'f' || hash_str[i] < 'a') &&
		    (hash_str[i] > 'F' || hash_str[i] < 'A'))
		return -1;
	}

	switch (len) {
	case SHA224_DIGEST_LENGTH*2:
		*type = efi_guid_sha224;
		hash_size = SHA224_DIGEST_LENGTH;
		break;
	case SHA256_DIGEST_LENGTH*2:
		*type = efi_guid_sha256;
		hash_size = SHA256_DIGEST_LENGTH;
		break;
	case SHA384_DIGEST_LENGTH*2:
		*type = efi_guid_sha384;
		hash_size = SHA384_DIGEST_LENGTH;
		break;
	case SHA512_DIGEST_LENGTH*2:
		*type = efi_guid_sha512;
		hash_size = SHA512_DIGEST_LENGTH;
		break;
	default:
		return -1;
	}

	return hash_size;
}
