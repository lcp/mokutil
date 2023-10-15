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
#include <errno.h>
#include <string.h>

#include <keyutils.h>

#include "keyring.h"

/**
 * Match the x509v3 Subject Key ID in the descriptions of the kernel built-in
 * trusted keys keyring
 *
 * return value
 *   -  0 : not matched
 *   -  1 : matched
 *   - -1 : error
 */
int
match_skid_in_trusted_keyring (const char *skid)
{
	key_serial_t ring_id, key_id, *key_ptr;
	void *keylist = NULL;
	int count;
	char buffer[1024];
	char *ptr;
	long buf_size;
	int ret = -1;

	if (skid == NULL)
		return -1;

	/* Find the keyring ID of the kernel trusted keys */
	ring_id = find_key_by_type_and_desc("keyring", ".builtin_trusted_keys", 0);
	if (ring_id < 0) {
		fprintf(stderr, "Failed to access kernel trusted keyring: %m\n");
		goto out;
	}

	count = keyctl_read_alloc(ring_id, &keylist);
	if (count < 0) {
		fprintf(stderr, "Failed to read kernel trusted keyring\n");
		goto out;
	}

	count /= sizeof(key_serial_t);
	if (count == 0) {
		/* The keyring is empty */
		ret = 0;
		goto out;
	}

	/* Iterate the keylist and match SKID */
	key_ptr = keylist;
	do {
		key_id = *key_ptr++;

		buf_size = keyctl_describe(key_id, buffer, sizeof(buffer));
		if (buf_size < 0) {
			fprintf(stderr, "key %X inaccessible %m\n", key_id);
			goto out;
		}

		/* Check if SKID is in the description */
		ptr = strstr(buffer, skid);
		if (ptr && *(ptr + strlen(skid)) == '\0') {
			/* Matched */
			ret = 1;
			goto out;
		}
	} while (--count);

	ret = 0;
out:
	if (keylist)
		free(keylist);

	return ret;

}
