/**
 * Copyright (C) 2012-2014 Gary Lin <glin@suse.com>
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
#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <efivar.h>

typedef struct {
	///
	/// An identifier which identifies the agent which added the signature to the list.
	///
	efi_guid_t          SignatureOwner;
	///
	/// The format of the signature is defined by the SignatureType.
	///
	uint8_t             SignatureData[1];
} __attribute__ ((packed)) EFI_SIGNATURE_DATA;

typedef struct {
	///
	/// Type of the signature. GUID signature types are defined in below.
	///
	efi_guid_t            SignatureType;
	///
	/// Total size of the signature list, including this header.
	///
	uint32_t             SignatureListSize;
	///
	/// Size of the signature header which precedes the array of signatures.
	///
	uint32_t            SignatureHeaderSize;
	///
	/// Size of each signature.
	///
	uint32_t              SignatureSize; 
	///
	/// Header before the array of signatures. The format of this header is specified 
	/// by the SignatureType.
	/// UINT8           SignatureHeader[SignatureHeaderSize];
	///
	/// An array of signatures. Each signature is SignatureSize bytes in length. 
	/// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
	///
} __attribute__ ((packed)) EFI_SIGNATURE_LIST;

#endif /* SIGNATURE_H */
