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
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "efi_x509.h"

static int
x509_calculate_fingerprint(const uint8_t *cert, const int cert_size,
		unsigned char* ret_fingerprint, unsigned int *ret_md_len)
{
	const EVP_MD *md;
	EVP_MD_CTX *ctx;

	md = EVP_get_digestbyname ("SHA1");
	if(md == NULL) {
		fprintf (stderr, "Failed to get SHA1 digest\n");
		goto err;
	}

	ctx = EVP_MD_CTX_create ();
	if (ctx == NULL) {
		fprintf (stderr, "Failed to create digest context\n");
	        goto err;
	}

	if (!EVP_DigestInit_ex (ctx, md, NULL)) {
		fprintf (stderr, "Failed to initialize digest context\n");
		goto cleanup_ctx;
	}

	if (!EVP_DigestUpdate (ctx, cert, cert_size)) {
		fprintf (stderr, "Failed to hash into the digest context\n");
		goto cleanup_ctx;
	}

	if (!EVP_DigestFinal_ex (ctx, ret_fingerprint, ret_md_len)) {
		fprintf (stderr, "Failed to get digest value\n");
		goto cleanup_ctx;
	}

	return 0;

cleanup_ctx:
	EVP_MD_CTX_destroy (ctx);
err:
	return -1;
}


int
print_x509 (const uint8_t *cert, const int cert_size, int verbose)
{
	X509 *X509cert;
	unsigned int md_len;
	const unsigned char *in = (const unsigned char *)cert;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];

	if (x509_calculate_fingerprint(cert, cert_size, fingerprint, &md_len) < 0)
		return -1;

	X509cert = d2i_X509 (NULL, &in, cert_size);
	if (X509cert == NULL) {
		fprintf (stderr, "Invalid X509 certificate\n");
		return -1;
	}

	if (verbose) {
		printf ("SHA1 Fingerprint: ");
		for (unsigned int i = 0; i < md_len; i++) {
			printf ("%02x", fingerprint[i]);
			if (i < md_len - 1)
				printf (":");
		}
		printf ("\n");
		X509_print_fp (stdout, X509cert);
	} else {
		X509_NAME* nm = X509_get_subject_name(X509cert);
		int r = X509_NAME_get_index_by_NID(nm, NID_commonName, -1);

		for (unsigned int i = 0; i < 5; i++)
			printf ("%02x", fingerprint[i]);
		fputs(" ", stdout);

		if (r == -1)
			X509_NAME_print_ex_fp(stdout, nm, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB & ~XN_FLAG_SPC_EQ);
		else {
			X509_NAME_ENTRY *e;
			e = X509_NAME_get_entry(nm, r);
			ASN1_STRING *val = X509_NAME_ENTRY_get_data(e);
			ASN1_STRING_print_ex_fp(stdout, val, ASN1_STRFLGS_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
		}
		fputs("\n", stdout);
	}

	X509_free (X509cert);

	return 0;
}

int
is_valid_cert (const uint8_t *cert, const uint32_t cert_size)
{
	X509 *X509cert;

	if (cert == NULL)
		return 0;

	X509cert = d2i_X509 (NULL, &cert, cert_size);
	if (X509cert == NULL)
		return 0;

	X509_free (X509cert);

	return 1;
}

/**
 * Check whether the given CA cert is the immediate CA of the given cert
 **/
int
is_immediate_ca (const uint8_t *cert, const uint32_t cert_size,
		 const uint8_t *ca_cert, const uint32_t ca_cert_size)
{
	X509 *X509cert = NULL;
	X509 *X509ca = NULL;
	X509_STORE *cert_store = NULL;
	X509_STORE_CTX *cert_ctx = NULL;
	int ret = 0;

	if (cert == NULL || ca_cert == NULL)
		return 0;

	if (EVP_add_digest (EVP_md5 ()) == 0)
		return 0;
	if (EVP_add_digest (EVP_sha1 ()) == 0)
		return 0;
	if (EVP_add_digest (EVP_sha256 ()) == 0)
		return 0;

	X509cert = d2i_X509 (NULL, &cert, cert_size);
	if (X509cert == NULL)
		return 0;

	X509ca = d2i_X509 (NULL, &ca_cert, ca_cert_size);
	if (X509ca == NULL)
		goto err;

	cert_store = X509_STORE_new ();
	if (cert_store == NULL)
		goto err;

	if (X509_STORE_add_cert (cert_store, X509ca) == 0)
		goto err;

	/* Follow edk2 CryptoPkg to allow partial certificate chains and
	 * disable time checks */
	X509_STORE_set_flags (cert_store,
			      X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_NO_CHECK_TIME);

	cert_ctx = X509_STORE_CTX_new ();
	if (cert_ctx == NULL)
		goto err;

	if (X509_STORE_CTX_init (cert_ctx, cert_store, X509cert, NULL) == 0)
		goto err;

	/* Verify the cert */
	ret = X509_verify_cert (cert_ctx);
	/* Treat the exceptional error as FALSE */
	if (ret < 0)
		ret = 0;
	X509_STORE_CTX_cleanup (cert_ctx);

err:
	if (X509cert)
		X509_free (X509cert);

	if (X509ca)
		X509_free (X509ca);

	if (cert_store)
		X509_STORE_free (cert_store);

	if (cert_store)
		X509_STORE_CTX_free (cert_ctx);

	return ret;
}

/**
 * Get the Subject Key Identifier of the given certificate
 *
 * This function allocates the SKID string and the caller is responsible to
 * free the string.
 *
 * Return value:
 * -  0 : Success
 * - -1 : Error
 */
int
get_cert_skid(const uint8_t *cert, const uint32_t cert_size, char **skid)
{
	X509 *X509cert;
	const ASN1_OCTET_STRING *asn1_id;
	const uint8_t *data;
	int data_len, i;
	char *id_str, *ptr;
	int ret = -1;

	X509cert = d2i_X509 (NULL, &cert, cert_size);
	if (X509cert == NULL) {
		fprintf (stderr, "invalid x509 certificate\n");
		goto out;
	}

	asn1_id = X509_get0_subject_key_id (X509cert);
	if (asn1_id == NULL) {
		fprintf (stderr, "Failed to get Subject Key ID\n");
		goto out;
	}

	data = ASN1_STRING_get0_data (asn1_id);
	data_len = ASN1_STRING_length (asn1_id);

	id_str = malloc (data_len*2 + 1);
	if (id_str == NULL) {
		fprintf (stderr, "Failed to allocated id string\n");
		goto out;
	}

	ptr = id_str;
	for (i = 0; i < data_len; i++) {
		snprintf (ptr, 3, "%02x", data[i]);
		ptr += 2;
	}

	*skid = id_str;
	ret = 0;
out:
	if (X509cert)
		X509_free (X509cert);

	return ret;
}
