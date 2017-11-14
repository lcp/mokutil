#ifndef __MOKUTIL_H__
#define __MOKUTIL_H__

#include <ctype.h>
#include <efivar.h>

#include "signature.h"

typedef struct {
	EFI_SIGNATURE_LIST *header;
	uint32_t            mok_size;
	void               *mok;
} MokListNode;

uint32_t efi_hash_size (const efi_guid_t *hash_type);
uint32_t signature_size (const efi_guid_t *hash_type);
MokListNode* build_mok_list (void *data, unsigned long data_size, uint32_t *mok_num);
#endif
