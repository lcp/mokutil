/**
 * Copyright (C) 2016 Gary Lin <glin@suse.com>
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

#include "sbversion.h"

#define MAX_NODES 1000

#define OPT_HELP      (1 << 0)
#define OPT_BIN_INPUT (1 << 1)
#define OPT_TXT_INPUT (1 << 2)
#define OPT_EXPORT    (1 << 3)
#define OPT_SHOW      (1 << 4)
#define OPT_SIGNATURE (1 << 5)
#define OPT_WRITE     (1 << 6)
#define OPT_FORCE     (1 << 7)

typedef int (*import_func_ptr)(const void *, const off_t, void **, uint64_t *);

static void
print_help ()
{
	printf ("Usage:\n");
	printf ("  sblist OPTIONS [ARGS...]\n");
	printf ("\n");
	printf ("Options:\n");
	printf ("  --help\t\t\t\tShow help\n");
}

static int
import_list (const char *filename, void **var, uint64_t *var_size,
	     import_func_ptr import_func)
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

	if (import_func (content, stat.st_size, var, var_size) < 0) {
		fprintf (stderr, "Failed to import %s\n", filename);
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
merge_list (void **var, uint64_t *var_size, sblist_t *list)
{
	sblist_t *lptr, *lptr_new;
	sbnode_t *node1, *node2;
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
		lptr = (sblist_t *)(old_var + offset);

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

			if (node1->distro == node2->distro) {
				/* Found a higher sb version, update it */
				if (node1->sb < node2->sb)
					node1->sb = node2->sb;

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
	new_var = malloc (*var_size + sizeof(sbnode_t) * extra);
	if (new_var == NULL)
		return -1;

	/* Copy the first part of the old var */
	memcpy (new_var, old_var, offset + lptr->size);

	/* Copy the new nodes */
	lptr_new = (sblist_t *)(new_var + offset);
	lptr_new->size += extra * sizeof(sbnode_t);
	j = lptr_n;
	for (i = 0; i < list_n; i++) {
		if (skip[i] == 1)
			continue;
		node1 = lptr_new->nodes + j;
		node2 = list->nodes + i;

		memcpy (node1, node2, sizeof(sbnode_t));
		j++;
	}

	/* Copy the rest of the old var */
	offset += lptr->size;
	if (offset < *var_size) {
		memcpy (new_var + offset + sizeof(sbnode_t) * extra,
			old_var + offset, *var_size - offset);
	}

	free (old_var);
	*var = new_var;
	*var_size += sizeof(sbnode_t) * extra;

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
parse_line (const char *line, const uint64_t length, sblist_t **list)
{
	sblist_t *lptr;
	sbnode_t node;
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
	list_size = sizeof(sblist_t) + sizeof(sbnode_t) * list_n;
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

	/* Parse distro versions and sb versions */
	j = 0;
	for (i = 0; i < list_n && start < length; i++) {
		/* Get the distro version */
		if (get_uint ((char *)line + start, length - start, &offset,
			      USHRT_MAX, &value) < 0) {
			fprintf (stderr, "Failed to get distro version\n");
			goto error;
		}
		node.distro = (uint16_t)value;
		start += offset;

		/* Get the sb version */
		if (get_uint ((char *)line + start, length - start, &offset,
			      USHRT_MAX, &value) < 0) {
			fprintf (stderr, "Failed to get sb version\n");
			goto error;
		}
		node.sb = (uint16_t)value;
		start += offset;

		/* Find duplicate distro version */
		found = 0;
		for (k = 0; k < j; k++) {
			if (lptr->nodes[k].distro == node.distro) {
				found = 1;
				break;
			}
		}

		if (!found) {
			memcpy (&(lptr->nodes[j]), &node, sizeof(sbnode_t));
			j++;
		} else {
			if (lptr->nodes[k].sb < node.sb)
				lptr->nodes[k].sb = node.sb;
		}
	}

	/* Adjust the size if necessary */
	if (j < list_n) {
		lptr->size = sizeof(sblist_t) + sizeof(sbnode_t) * j;
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
	sblist_t *list;
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
import_txt_list (const char *filename, void **var, uint64_t *var_size)
{
	return import_list (filename, var, var_size, &parse_txt_list);
}

static int
parse_bin_list (const void *content, const off_t size, void **var,
		uint64_t *var_size)
{
	void *new_var, *ptr;
	sblist_t *list;
	off_t offset;
	uint64_t new_size;
	int ret;

	new_var = NULL;
	ret = -1;

	/* Check the content of the binary list */
	ptr = (void *)content;

	offset = 0;
	while (offset < size) {
		list = (sblist_t *)ptr;

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
		list = (sblist_t *)ptr;

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
import_bin_list (const char *filename, void **var, uint64_t *var_size)
{
	return import_list (filename, var, var_size, &parse_bin_list);
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

	if (efi_set_variable (efi_guid_shim, "SecurityListRequest",
			      (uint8_t *)req, req_size, attributes,
			      S_IRUSR | S_IWUSR) < 0) {
		fprintf (stderr, "Failed to set SecurityListRequest\n");
		return -1;
	}

	if (efi_set_variable (efi_guid_shim, "SecurityListSig",
			      (uint8_t *)sig, sig_size, attributes,
			      S_IRUSR | S_IWUSR) < 0) {
		fprintf (stderr, "Failed to set SecurityListRequest\n");
		return -1;
	}

	return 0;
}

static void
print_var (const void *var, const uint64_t var_size)
{
	sblist_t *list;
	sbnode_t *node;
	uint32_t i, list_n;
	uint64_t offset;

	if (var == NULL) {
		fprintf (stderr, "%s: invalid argument\n", __FUNCTION__);
		return;
	}

	offset = 0;
	while (offset < var_size) {
		list = (sblist_t *)(var + offset);
		list_n = count_nodes (list);
		printf ("%c%c%c%c", list->signer[0], list->signer[1],
				    list->signer[2], list->signer[3]);
		for (i = 0; i < list_n; i++) {
			node = list->nodes + i;
			printf (", %u, %u", node->distro, node->sb);
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
	char *bin_in, *txt_in, *bin_out;
	void *req, *sig;
	uint64_t req_size, sig_size;
	uint8_t force;

	bin_in = NULL;
	txt_in = NULL;
	bin_out = NULL;
	req = NULL;
	sig = NULL;
	command = 0;
	force = 0;
	ret = 1;

	while (1) {
		static struct option long_options[] = {
			{"help",            no_argument,       0, 'h'},
			{"bin",             required_argument, 0,  0 },
			{"txt",             required_argument, 0,  1 },
			{"export",          required_argument, 0, 'e'},
			{"show",            no_argument,       0,  2 },
			{"signature",       required_argument, 0, 's'},
			{"write-variables", no_argument,       0, 'w'},
			{"force",           no_argument,       0, 'f'},
			{0, 0, 0, 0}
		};

		option_index = 0;
		opt = getopt_long (argc, argv, "b:fhe:s:t:w",
				   long_options, &option_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'h': /* help */
			command |= OPT_HELP;
			break;
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
			break;
		case 'w': /* write-variables */
			command |= OPT_WRITE;
			break;
		case 'f': /* force */
			force = 1;
			break;
		default:
			command |= OPT_HELP;
			break;
		}
	}

	if (command & OPT_HELP) {
		print_help ();
		goto exit;
	}

	if (command & OPT_BIN_INPUT) {
		if (import_bin_list (bin_in, &req, &req_size) < 0) {
			fprintf (stderr, "Failed to import binary list: %s\n",
					 bin_in);
			goto exit;
		}
	}

	if (command & OPT_TXT_INPUT) {
		if (import_txt_list (txt_in, &req, &req_size) < 0) {
			fprintf (stderr, "Failed to import text list: %s\n",
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

	if (command & OPT_WRITE) {
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

	if (bin_out)
		free (bin_out);

	if (req)
		free (req);

	if (sig)
		free (sig);

	return ret;
}
