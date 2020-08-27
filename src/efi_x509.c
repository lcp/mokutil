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

#include "efi_x509.h"

int
print_x509 (const char *cert, const int cert_size)
{
	X509 *X509cert;
	BIO *cert_bio;
	SHA_CTX ctx;
	uint8_t fingerprint[SHA_DIGEST_LENGTH];

	cert_bio = BIO_new (BIO_s_mem ());
	BIO_write (cert_bio, cert, cert_size);
	if (cert_bio == NULL) {
		fprintf (stderr, "Failed to write BIO\n");
		return -1;
	}

	X509cert = d2i_X509_bio (cert_bio, NULL);
	if (X509cert == NULL) {
		fprintf (stderr, "Invalid X509 certificate\n");
		return -1;
	}

	SHA1_Init (&ctx);
	SHA1_Update (&ctx, cert, cert_size);
	SHA1_Final (fingerprint, &ctx);

	printf ("SHA1 Fingerprint: ");
	for (unsigned int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		printf ("%02x", fingerprint[i]);
		if (i < SHA_DIGEST_LENGTH - 1)
			printf (":");
	}
	printf ("\n");
	X509_print_fp (stdout, X509cert);

	BIO_free (cert_bio);

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
		return 0;

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
