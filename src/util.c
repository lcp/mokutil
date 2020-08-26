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

#include <termios.h>

#include "util.h"

int
test_and_delete_mok_var (const char *var_name)
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

int
read_hidden_line (char **line, size_t *n)
{
	struct termios old, new;
	int nread;
	int isTTY = isatty(fileno (stdin));

	if (isTTY) {
		/* Turn echoing off and fail if we can't. */
		if (tcgetattr (fileno (stdin), &old) != 0)
			return -1;

		new = old;
		new.c_lflag &= ~ECHO;

		if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
			return -1;
	}

	/* Read the password. */
	nread = getline (line, n, stdin);

	if (isTTY) {
		/* Restore terminal. */
		(void) tcsetattr (fileno (stdin), TCSAFLUSH, &old);
	}

	/* Remove the newline */
	(*line)[nread-1] = '\0';

	return nread-1;
}

const char *
get_req_var_name (MokRequest req)
{
	const char *var_name[] = {
		[DELETE_MOK] = "MokDel",
		[ENROLL_MOK] = "MokNew",
		[DELETE_BLACKLIST] = "MokXDel",
		[ENROLL_BLACKLIST] = "MokXNew"
	};

	return var_name[req];
}

const char *
get_req_auth_var_name (MokRequest req)
{
	const char *auth_var_name[] = {
		[DELETE_MOK] = "MokDelAuth",
		[ENROLL_MOK] = "MokAuth",
		[DELETE_BLACKLIST] = "MokXDelAuth",
		[ENROLL_BLACKLIST] = "MokXAuth"
	};

	return auth_var_name[req];
}
