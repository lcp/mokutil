/**
 * Copyright (C) 2016-2017 Gary Lin <glin@suse.com>
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <getopt.h>

#include <efivar.h>

#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "svlist.h"

#define MAX_NODES 1000

#define OPT_HELP      (1 << 0)
#define OPT_BIN_INPUT (1 << 1)
#define OPT_TXT_INPUT (1 << 2)
#define OPT_EXPORT    (1 << 3)
#define OPT_SHOW      (1 << 4)
#define OPT_SIGNATURE (1 << 5)
#define OPT_IMPORT    (1 << 6)
#define OPT_FORCE     (1 << 7)
#define OPT_CERT      (1 << 8)
#define OPT_VERIFY    (1 << 9)

#define OPT_INPUT            (OPT_BIN_INPUT | OPT_TXT_INPUT)
#define OPT_SHOW_OR_EXPORT   (OPT_SHOW | OPT_EXPORT)
#define OPT_VERIFY_OR_IMPORT (OPT_VERIFY | OPT_IMPORT)

typedef int (*read_func_ptr)(const void *, const off_t, void **, uint64_t *);

static void
print_help ()
{
	printf ("Usage:\n");
	printf ("  svlist OPTIONS [ARGS...]\n");
	printf ("\n");
	printf ("Options:\n");
	printf ("  --help\t\t\tShow help\n");
	printf ("  --bin <binary list>\t\tUse the binary list\n");
	printf ("  --txt <text list>\t\tUse the text list\n");
	printf ("  --show\t\t\tShow the list in text form\n");
	printf ("  --export <binary list>\tExport the list to a binary list\n");
	printf ("  --force\t\t\tOverwrite the file forcibly\n");
	printf ("  --signature <PKCS#7>\t\tUse the PKCS7 signature\n");
	printf ("  --verify\t\t\tVerify the signature\n");
	printf ("  --cert <certificate>\t\tUse this ceritifcate as the signer\n");
	printf ("  --import\t\t\tImport the list into the EFI variables\n");
	printf ("\n");
	printf ("Convert the text list into the binary list:\n");
	printf (" svlist --txt list.csv -e list.bin\n");
	printf ("\n");
	printf ("Import the list:\n");
	printf (" svlist -i --bin list.bin -s list.sig -c signer.der\n");
	printf ("\n");
	printf ("Verify the list:\n");
	printf (" svlist -V --bin list.bin -s list.sig -c signer.der\n");
}

static int
read_efi_security_list_rt (void **var, uint64_t *var_size)
{
	uint32_t attributes;
	int ret;

	ret = efi_get_variable (efi_guid_shim, "SVListRT", (uint8_t **)var,
				var_size, &attributes);
	return ret;
}

static int
read_file (const char *filename, void **var, uint64_t *var_size,
	   read_func_ptr read_func)
{
	int fd, ret;
	struct stat stat;
	void *content;

	if (filename == NULL || var == NULL || var_size == NULL) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return -1;
	}

	ret = -1;

	fd = open (filename, O_RDONLY);
	if (fd < 0) {
		fprintf (stderr, "Failed to open %s\n", filename);
		return -1;
	}
	if (fstat (fd, &stat) < 0) {
		fprintf (stderr, "Failed to get the stat of %s\n", filename);
		goto exit;
	}

	content = mmap (NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (content == MAP_FAILED) {
		fprintf (stderr, "Failed to map %s\n", filename);
		goto exit;
	}

	if (read_func (content, stat.st_size, var, var_size) < 0) {
		fprintf (stderr, "Failed to read %s\n", filename);
		goto exit;
	}

	ret = 0;
exit:
	if (content != MAP_FAILED)
		munmap (&content, stat.st_size);

	close (fd);

	return ret;

}

static int
merge_list (void **var, uint64_t *var_size, svlist_t *list)
{
	svlist_t *lptr, *lptr_new;
	svnode_t *node1, *node2;
	void *old_var, *new_var;
	uint64_t offset;
	uint32_t i, j, extra;
	uint8_t *skip, found;

	if (var == NULL || var_size == NULL || list == NULL)
		return -1;

	old_var = *var;

	/* Search the old list */
	offset = 0;
	found = 0;
	while (offset < *var_size) {
		lptr = (svlist_t *)(old_var + offset);

		if (memcmp (list->signer, lptr->signer, 4) == 0) {
			found = 1;
			break;
		}
		offset += lptr->size;
	}

	if (!found) {
		/* Append list to var */
		new_var = realloc (old_var, *var_size + list->size);
		if (new_var == NULL)
			return -1;
		memcpy (new_var + *var_size, (void *)list, list->size);
		*var_size += list->size;
		*var = new_var;

		return 0;
	}

	const uint32_t lptr_n = count_nodes (lptr);
	const uint32_t list_n = count_nodes (list);

	/* Start to merge the list */
	skip = (unsigned char *)alloca (list_n * sizeof(uint8_t));
	memset (skip, 0, list_n * sizeof(uint8_t));
	extra = list_n;
	for (i = 0; i < lptr_n; i++) {
		node1 = lptr->nodes + i;
		for (j = 0; j < list_n; j++) {
			if (skip[j] == 1)
				continue;

			node2 = list->nodes + j;

			if (node1->dv == node2->dv) {
				/* Found a higher security version */
				if (node1->sv < node2->sv)
					node1->sv = node2->sv;

				skip[j] = 1;
				extra--;
			}
		}
	}

	if (extra == 0)
		return 0;

	if (lptr_n + extra > MAX_NODES)
		return -1;

	/* Allocate a new var */
	new_var = malloc (*var_size + sizeof(svnode_t) * extra);
	if (new_var == NULL)
		return -1;

	/* Copy the first part of the old var */
	memcpy (new_var, old_var, offset + lptr->size);

	/* Copy the new nodes */
	lptr_new = (svlist_t *)(new_var + offset);
	lptr_new->size += extra * sizeof(svnode_t);
	j = lptr_n;
	for (i = 0; i < list_n; i++) {
		if (skip[i] == 1)
			continue;
		node1 = lptr_new->nodes + j;
		node2 = list->nodes + i;

		memcpy (node1, node2, sizeof(svnode_t));
		j++;
	}

	/* Copy the rest of the old var */
	offset += lptr->size;
	if (offset < *var_size) {
		memcpy (new_var + offset + sizeof(svnode_t) * extra,
			old_var + offset, *var_size - offset);
	}

	free (old_var);
	*var = new_var;
	*var_size += sizeof(svnode_t) * extra;

	return 0;
}

static int
parse_uint (const char *line, const uint64_t length, uint64_t *offset,
	    const uint64_t limit, uint64_t *value)
{
	uint64_t i, number, tmp;

	if (line == NULL || offset == NULL || value == NULL) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return -1;
	}

	if (!isdigit(line[0])) {
		return -1;
	}

	for (i = 0; isdigit (line[i]) && i < length; i++);
	*offset = i;

	number = 0;
	for (i = 0; i < *offset; i++) {
		tmp = (line[i] - '0') + number * 10;
		if (number >= limit || tmp < number)
			return -1;
		number = tmp;
	}

	*value = number;

	return 0;
}

static int
beyond_next_comma (const char *line, const uint64_t length, uint64_t *offset)
{
	uint64_t i;

	for (i = 0; i < length; i++) {
		if (line[i] == ',')
			break;
		else if (!isblank (line[i]))
			return -1;
	}

	if (line[i] != ',')
		return -1;

	for (i = i + 1; isblank (line[i]) && i < length; i++);

	*offset = i;

	return 0;
}

static int
get_uint (const char *line, const off_t length, uint64_t *offset,
	  const uint64_t limit, uint64_t *value)
{
	char *ptr;
	uint64_t skip, rest;

	ptr = (char *)line;
	*offset = 0;

	if (beyond_next_comma (ptr, length, &skip) < 0)
		return -1;
	*offset += skip;
	ptr += skip;
	rest = length - skip;

	if (parse_uint (ptr, rest, &skip, limit, value) < 0)
		return -1;
	*offset += skip;

	return 0;
}

static int
parse_line (const char *line, const uint64_t length, svlist_t **list)
{
	svlist_t *lptr;
	svnode_t node;
	uint64_t count, list_size, value;
	uint64_t i, j, k, start, end, offset;
	uint8_t found;

	if (line == NULL || length == 0 || list == NULL) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return -1;
	}

	/* Count commas to calculate the length of the list */
	count = 0;
	for (i = 0; i < length; i++) {
		if (line[i] == ',')
			count++;
	}
	if (count % 2 != 0) {
		fprintf (stderr, "Invalid format\n");
		return -1;
	}
	const uint64_t list_n = (count / 2);

	if (list_n > MAX_NODES) {
		fprintf (stderr, "Exceed the max number of nodes: %u\n",
				 MAX_NODES);
		return -1;
	}

	/* Allocate the list */
	list_size = sizeof(svlist_t) + sizeof(svnode_t) * list_n;
	lptr = malloc (list_size);
	if (lptr == NULL) {
		fprintf (stderr, "Failed to allocate list\n");
		return -1;
	}
	lptr->size = (uint32_t)list_size;

	/* Find the signer */
	for (start = 0; !isalnum(line[start]) && start < length; start++);
	for (end = start; isalnum(line[end]) && end < length; end++);
	if ((end - start) != 4) {
		fprintf (stderr, "signer must be 4 characters\n");
		goto error;
	}

	/* Assign the signer */
	memcpy (lptr->signer, (char *)line + start, 4);

	start = end;

	/* Parse distro versions and security versions */
	j = 0;
	for (i = 0; i < list_n && start < length; i++) {
		/* Get the distro version */
		if (get_uint ((char *)line + start, length - start, &offset,
			      USHRT_MAX, &value) < 0) {
			fprintf (stderr, "Failed to get distro version\n");
			goto error;
		}
		node.dv = (uint16_t)value;
		start += offset;

		/* Get the security version */
		if (get_uint ((char *)line + start, length - start, &offset,
			      USHRT_MAX, &value) < 0) {
			fprintf (stderr, "Failed to get secuirty version\n");
			goto error;
		}
		node.sv = (uint16_t)value;
		start += offset;

		/* Find duplicate distro version */
		found = 0;
		for (k = 0; k < j; k++) {
			if (lptr->nodes[k].dv == node.dv) {
				found = 1;
				break;
			}
		}

		if (!found) {
			memcpy (&(lptr->nodes[j]), &node, sizeof(svnode_t));
			j++;
		} else {
			if (lptr->nodes[k].sv < node.sv)
				lptr->nodes[k].sv = node.sv;
		}
	}

	/* Adjust the size if necessary */
	if (j < list_n) {
		lptr->size = sizeof(svlist_t) + sizeof(svnode_t) * j;
	}

	*list = lptr;

	return 0;
error:
	if (lptr != NULL) {
		free (lptr);
		*list = NULL;
	}

	return -1;
}

static int
parse_txt_list (const void *content, const off_t size, void **var,
		uint64_t *var_size)
{
	void *new_var;
	svlist_t *list;
	uint64_t i, length, new_size;
	char *start, *end;

	if (size < 0 || var == NULL || var_size == NULL) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return -1;
	}

	new_var = NULL;
	new_size = 0;
	list = NULL;

	for (i = 0; i < (uint64_t)size; i += length + 1) {
		start = (char *)content + i;
		length = 0;
		end = start;
		while (i + length < (uint64_t)size && *end != '\n') {
			end++;
			length++;
		}
		if (parse_line (start, length, &list) < 0) {
			fprintf (stderr, "Failed to parse the line\n");
			goto error;
		}

		if (new_var == NULL) {
			new_var = malloc (list->size);
			if (new_var == NULL) {
				fprintf (stderr, "Failed to allocate new_var\n");
				goto error;
			}
			memcpy (new_var, list, list->size);
			new_size = list->size;
		} else {
			if (merge_list (&new_var, &new_size, list) < 0) {
				fprintf (stderr, "Failed to merge list\n");
				goto error;
			}
			free (list);
		}
	}

	*var = new_var;
	*var_size = new_size;

	return 0;

error:
	if (list)
		free (list);

	if (new_var)
		free (new_var);

	*var_size = 0;

	return -1;
}


static int
read_txt_list (const char *filename, void **var, uint64_t *var_size)
{
	return read_file (filename, var, var_size, &parse_txt_list);
}

static int
parse_bin_list (const void *content, const off_t size, void **var,
		uint64_t *var_size)
{
	void *new_var, *ptr;
	svlist_t *list;
	off_t offset;
	uint64_t new_size;
	int ret;

	new_var = NULL;
	ret = -1;

	/* Check the content of the binary list */
	ptr = (void *)content;

	offset = 0;
	while (offset < size) {
		list = (svlist_t *)ptr;

		offset += list->size;
		ptr += list->size;
	}

	if (offset != size) {
		fprintf (stderr, "The binary list is corrupted\n");
		return -1;
	}

	/* Go through the binary list and merge the duplicate nodes */
	offset = 0;
	ptr = (void *)content;
	while (offset < size) {
		list = (svlist_t *)ptr;

		if (new_var == NULL) {
			new_var = malloc (list->size);
			if (new_var == NULL) {
				fprintf (stderr, "Failed to allocate new_var\n");
				goto error;
			}
			memcpy (new_var, list, list->size);
			new_size = list->size;
		} else {
			if (merge_list (&new_var, &new_size, list) < 0) {
				fprintf (stderr, "Failed to merge list\n");
				goto error;
			}
		}
		offset += list->size;
		ptr += list->size;
	}

	*var = new_var;
	*var_size = new_size;

	ret = 0;
error:

	return ret;
}

static int
read_bin_list (const char *filename, void **var, uint64_t *var_size)
{
	return read_file (filename, var, var_size, &parse_bin_list);
}

static int
export_bin_list (const char  *filename, const void *var,
		 const uint64_t var_size, const uint8_t force)
{
	void *ptr;
	int fd, ret;
	uint64_t rest;
	ssize_t count;

	if (filename == NULL || var == NULL) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return -1;
	}

	ret = -1;

	/* Check if the file already existed */
	if (!force) {
		if (access (filename, F_OK) == 0) {
			fprintf (stderr, "File already exists\n");
			return -1;
		}
	}

	/* Open the file and write */
	fd = open (filename, O_WRONLY | O_CREAT);
	if (fd < 0) {
		fprintf (stderr, "Failed to open %s\n", filename);
		return -1;
	}

	ptr = (void *)var;
	rest = var_size;
	while (rest > 0) {
		count = write (fd, ptr, rest);
		if (count < 0 && errno == EAGAIN) {
			continue;
		} else if (count < 0) {
			fprintf (stderr, "Failed to write %s\n", filename);
			goto exit;
		}

		ptr += count;
		rest -= count;
	}

	ret = 0;
exit:
	close (fd);

	return ret;
}

static int
copy_data (const void *content, const off_t size, void **data, uint64_t *data_size)
{
	void *ptr;

	ptr = malloc (size);
	if (ptr == NULL) {
		fprintf (stderr, "Failed to alloacte memory\n");
		return -1;
	}

	memcpy (ptr, content, size);

	*data = ptr;
	*data_size = size;

	return 0;
}

static int
read_sig (const char *filename, void **sig, uint64_t *sig_size)
{
	return read_file (filename, sig, sig_size, &copy_data);
}

static int
read_cert (const char *filename, void **cert, uint64_t *cert_size)
{
	return read_file (filename, cert, cert_size, &copy_data);
}

static int
wrap_pkcs7_data (const uint8_t *p7data, const uint64_t p7_size, uint8_t *flag,
		 uint8_t **wrap, uint64_t *wrap_size)
{
	uint8_t wrapped, *signed_data;
	uint8_t oid[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

	wrapped = 0;
	if ((p7data[4] == 0x06 && p7data[5] == 0x09) &&
	    (memcmp (p7data + 6, oid, sizeof(oid)) == 0) &&
	    (p7data[15] == 0xA0 && p7data[16] == 0x82)) {
		wrapped = 1;
	}

	if (wrapped) {
		*wrap = (uint8_t *)p7data;
		*wrap_size = p7_size;
		goto exit;
	}

	/* Wrap PKCS#7 signeddata to a ContentInfo structure:
	 * add a header in 19 bytes*/

	*wrap_size = p7_size + 19;
	*wrap = malloc (*wrap_size);
	if (wrap == NULL)
		return -1;

	signed_data = *wrap;

	/* Part1: 0x30, 0x82 */
	signed_data[0] = 0x30;
	signed_data[1] = 0x82;

	/* Part2: Length1 = p7_size + 19 - 4, in big endian */
	signed_data[2] = (uint8_t) (((uint16_t) (*wrap_size - 4)) >> 8);
	signed_data[3] = (uint8_t) (((uint16_t) (*wrap_size - 4)) & 0xff);

	/* Part3: 0x06, 0x09 */
	signed_data[4] = 0x06;
	signed_data[5] = 0x09;

	/* Part4: OID value -- 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x02 */
	memcpy (signed_data + 6, oid, sizeof(oid));

	/* Part5: 0xA0, 0x82 */
	signed_data[15] = 0xA0;
	signed_data[16] = 0x82;

	/* Part6: Length2 = p7_size, in big endian */
	signed_data[17] = (uint8_t) (((uint16_t) (p7_size)) >> 8);
	signed_data[18] = (uint8_t) (((uint16_t) (p7_size)) & 0xff);

	/* Part7: P7Data */
	memcpy (signed_data + 19, p7data, p7_size);

exit:
	*flag = wrapped;
	return 0;
}

/*
 * This function is based on Pkcs7Verify() in the edk2 project since shim
 * merges the code to verify the signature.
 * (CryptoPkg/Library/BaseCryptLib/Pk/CryptPkcs7Verify.c)
 *
 * The only difference is that X509_V_FLAG_NO_CHECK_TIME is not used in
 * function since openssl 1.0.2j doesn't include the flag.
 */
static int
verify_sig (const void *req, const uint64_t req_size, const void *sig,
	    const uint64_t sig_size, const void *cert, const uint64_t cert_size)
{
	PKCS7 *pkcs7;
	BIO *req_bio;
	X509 *x509_cert;
	X509_STORE *cert_store;
	uint8_t *signed_data;
	uint64_t signed_data_size;
	uint8_t wrapped;
	const uint8_t *tmp;
	int ret;

	if (req == NULL || sig == NULL || cert == NULL ||
	    req_size > INT_MAX || sig_size > INT_MAX || cert_size > INT_MAX) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return -1;
	}

	pkcs7 = NULL;
	req_bio = NULL;
	x509_cert = NULL;
	cert_store = NULL;

	/* Register necessary digest algorithms */
	if (!EVP_add_digest (EVP_sha256 ()) ||
	    !EVP_add_digest (EVP_sha384 ()) ||
	    !EVP_add_digest (EVP_sha512 ())) {
		return -1;
	}

	if (wrap_pkcs7_data (sig, sig_size, &wrapped, &signed_data,
			     &signed_data_size) < 0)
		return -1;

	ret = -1;

	/* Retrieve PKCS#7 Data (DER encoding) */
	if (signed_data_size > INT_MAX)
		goto exit;

	tmp = signed_data;
	pkcs7 = d2i_PKCS7 (NULL, &tmp, (int) signed_data_size);
	if (pkcs7 == NULL)
		goto exit;

	/* Check if it's PKCS#7 Signed Data */
	if (!PKCS7_type_is_signed (pkcs7))
		goto exit;

	/* Read DER-encoded root certificate and Construct X509 Certificate */
	tmp = cert;
	x509_cert = d2i_X509 (NULL, &tmp, cert_size);
	if (x509_cert == NULL)
		goto exit;

	/* Setup X509 store for trusted certificate */
	cert_store = X509_STORE_new ();
	if (cert_store == NULL)
		goto exit;

	if (!X509_STORE_add_cert (cert_store, x509_cert))
		goto exit;

	/* For generic PKCS#7 handling, req may be NULL if the content is present
	 * in PKCS#7 structure. So ignore NULL checking here. */
	req_bio = BIO_new (BIO_s_mem ());
	if (req_bio == NULL)
		goto exit;

	if (BIO_write (req_bio, req, (int)req_size) <=0)
		goto exit;

	/* Allow partial certificate chains, terminated by a non-self-signed but
	 * still trusted intermediate certificate.
	 * NOTE: In edk2, it also disables time check. */
	X509_STORE_set_flags (cert_store, X509_V_FLAG_PARTIAL_CHAIN);

	/* OpenSSL PKCS7 Verification by default checks for SMIME (email signing)
	 * and doesn't support the extended key usage for Authenticode Code Signing.
	 * Bypass the certificate purpose checking by enabling any purposes setting.
	 * */
	X509_STORE_set_purpose (cert_store, X509_PURPOSE_ANY);

	/* Verifies the PKCS#7 signedData structure */
	if(PKCS7_verify (pkcs7, NULL, cert_store, req_bio, NULL, PKCS7_BINARY))
		ret = 0;
exit:
	BIO_free (req_bio);
	X509_free (x509_cert);
	X509_STORE_free (cert_store);
	PKCS7_free (pkcs7);

	if (!wrapped)
		OPENSSL_free (signed_data);

	return ret;
}

static int
set_security_variables (const void *req, const uint64_t req_size, const void *sig,
			const uint64_t sig_size)
{
	uint32_t attributes;

	if (req == NULL || sig == NULL) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return -1;
	}

	if (!efi_variables_supported ()) {
		fprintf (stderr, "EFI variables are not supported on this system\n");
		return -1;
	}

	attributes = EFI_VARIABLE_NON_VOLATILE
		     | EFI_VARIABLE_BOOTSERVICE_ACCESS
		     | EFI_VARIABLE_RUNTIME_ACCESS;

	if (efi_set_variable (efi_guid_shim, "SVListRequest", (uint8_t *)req,
			      req_size, attributes, S_IRUSR | S_IWUSR) < 0) {
		fprintf (stderr, "Failed to set SVListRequest\n");
		return -1;
	}

	if (efi_set_variable (efi_guid_shim, "SVListSig",
			      (uint8_t *)sig, sig_size, attributes,
			      S_IRUSR | S_IWUSR) < 0) {
		fprintf (stderr, "Failed to set SVListRequest\n");
		return -1;
	}

	return 0;
}

static void
print_var (const void *var, const uint64_t var_size)
{
	svlist_t *list;
	svnode_t *node;
	uint32_t i, list_n;
	uint64_t offset;

	if (var == NULL) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return;
	}

	offset = 0;
	while (offset < var_size) {
		list = (svlist_t *)(var + offset);
		list_n = count_nodes (list);
		printf ("%c%c%c%c", list->signer[0], list->signer[1],
				    list->signer[2], list->signer[3]);
		for (i = 0; i < list_n; i++) {
			node = list->nodes + i;
			printf (", %u, %u", node->dv, node->sv);
		}
		putchar ('\n');

		offset += list->size;
	}
}

int
main (int argc, char *argv[])
{
	uint32_t command;
	int opt, ret;
	int option_index;
	char *bin_in, *txt_in, *sig_in, *cert_in, *bin_out;
	void *req, *sig, *cert;
	uint64_t req_size, sig_size, cert_size;
	uint8_t force;

	bin_in = NULL;
	txt_in = NULL;
	sig_in = NULL;
	cert_in = NULL;
	bin_out = NULL;
	req = NULL;
	sig = NULL;
	command = 0;
	force = 0;
	ret = 1;

	while (1) {
		static struct option long_options[] = {
			{"help",      no_argument,       0, 'h'},
			{"bin",       required_argument, 0,  0 },
			{"txt",       required_argument, 0,  1 },
			{"export",    required_argument, 0, 'e'},
			{"show",      no_argument,       0,  2 },
			{"signature", required_argument, 0, 's'},
			{"import",    no_argument,       0, 'i'},
			{"force",     no_argument,       0, 'f'},
			{"verify",    no_argument,       0, 'V'},
			{"cert",      required_argument, 0, 'c'},
			{0, 0, 0, 0}
		};

		option_index = 0;
		opt = getopt_long (argc, argv, "c:fhe:s:Vw",
				   long_options, &option_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 0: /* bin */
			bin_in = strdup (optarg);
			command |= OPT_BIN_INPUT;
			break;
		case 1: /* txt */
			txt_in = strdup (optarg);
			command |= OPT_TXT_INPUT;
			break;
		case 'e': /* export */
			bin_out = strdup (optarg);
			command |= OPT_EXPORT;
			break;
		case 2: /* show */
			command |= OPT_SHOW;
			break;
		case 's': /* signature */
			sig_in = strdup (optarg);
			command |= OPT_SIGNATURE;
			break;
		case 'i': /* import */
			command |= OPT_VERIFY_OR_IMPORT;
			break;
		case 'f': /* force */
			force = 1;
			break;
		case 'V': /* verify */
			command |= OPT_VERIFY;
			break;
		case 'c': /* cert */
			cert_in = strdup (optarg);
			command |= OPT_CERT;
			break;
		case 'h': /* help */
		default:
			command |= OPT_HELP;
			break;
		}
	}

	if (command & OPT_HELP) {
		print_help ();
		goto exit;
	}

	/* Filter out the illegal commands */
	if ((command & OPT_INPUT) == OPT_INPUT) {
		fprintf (stderr, "Please use either the binary list "
				 "or the text list\n");
		goto exit;
	}

	if (command & OPT_VERIFY_OR_IMPORT) {
		if (!(command & OPT_SIGNATURE)) {
			fprintf (stderr, "Signature not available\n");
			goto exit;
		} else if (!(command & OPT_INPUT)) {
			fprintf (stderr, "Security List not available\n");
			goto exit;
		} else if (!(command & OPT_CERT)) {
			fprintf (stderr, "Certificate not available\n");
			goto exit;
		}
	}

	/* Execute the commands */
	if ((command & OPT_SHOW_OR_EXPORT) && !(command & OPT_INPUT)){
		if (read_efi_security_list_rt (&req, &req_size) < 0) {
			fprintf (stderr, "Failed to read SVListRT\n");
			goto exit;
		}
	}

	if (command & OPT_BIN_INPUT) {
		if (read_bin_list (bin_in, &req, &req_size) < 0) {
			fprintf (stderr, "Failed to read binary list: %s\n",
					 bin_in);
			goto exit;
		}
	}

	if (command & OPT_TXT_INPUT) {
		if (read_txt_list (txt_in, &req, &req_size) < 0) {
			fprintf (stderr, "Failed to read text list: %s\n",
					 txt_in);
			goto exit;
		}
	}

	if (command & OPT_EXPORT) {
		if (export_bin_list (bin_out, req, req_size, force) < 0) {
			fprintf (stderr, "Failed to export binary list: %s\n",
					 bin_out);
			goto exit;
		}
	}

	if (command & OPT_SIGNATURE) {
		if (read_sig (sig_in, &sig, &sig_size) < 0) {
			fprintf (stderr, "Failed to read signature: %s\n", sig_in);
			goto exit;
		}
	}

	if (command & OPT_CERT) {
		if (read_cert (cert_in, &cert, &cert_size) < 0) {
			fprintf (stderr, "Failed to read certificate: %s\n",
					 cert_in);
			goto exit;
		}
	}

	if (command & OPT_VERIFY) {
		if (verify_sig (req, req_size, sig, sig_size, cert, cert_size) < 0) {
			printf ("Signature does not match\n");
			goto exit;
		}
		printf ("Signature matches\n");
	}

	if (command & OPT_IMPORT) {
		if (set_security_variables (req, req_size, sig, sig_size) < 0) {
			fprintf (stderr, "Failed to set variables\n");
			goto exit;
		}
	}

	if (command & OPT_SHOW)
		print_var (req, req_size);

	ret = 0;
exit:
	if (bin_in)
		free (bin_in);

	if (txt_in)
		free (txt_in);

	if (sig_in)
		free (sig_in);

	if (cert_in)
		free (cert_in);

	if (bin_out)
		free (bin_out);

	if (req)
		free (req);

	if (sig)
		free (sig);

	if (cert)
		free (cert);

	return ret;
}
