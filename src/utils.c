#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/sha.h>

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
