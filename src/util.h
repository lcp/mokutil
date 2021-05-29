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

#ifndef __UTIL_H__
#define __UTIL_H__

#include <efivar.h>
#include "mokutil.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int mok_get_variable(const char *name, uint8_t **datap, size_t *data_sizep);
MokListNode *build_mok_list (const void *data, const uintptr_t data_size,
			     uint32_t *mok_num);
int test_and_delete_mok_var (const char *var_name);
int delete_data_from_req_var (const MokRequest req, const efi_guid_t *type,
			      const void *data, const uint32_t data_size);
unsigned long efichar_from_char (efi_char16_t *dest, const char *src,
				 size_t dest_len);
int read_hidden_line (char **line, size_t *n);
const char *get_db_var_name (const DBName db);
const char *get_db_friendly_name (const DBName db);
const char *get_req_var_name (const MokRequest req);
const char *get_req_auth_var_name (const MokRequest req);
MokRequest get_reverse_req (const MokRequest req);
const char *get_reverse_req_var_name (const MokRequest req);

#endif /* __UTIL_H__ */
