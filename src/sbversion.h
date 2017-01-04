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

#ifndef __SBVERSION_H__
#define __SBVERSION_H__

#include <stdint.h>

typedef struct {
	uint16_t distro;
	uint16_t sb;
} __attribute__((packed)) sbnode_t;

typedef struct {
	uint32_t size;
	char signer[4];
	sbnode_t nodes[0];
} __attribute__((packed)) sblist_t;

static inline uint32_t
count_nodes (const sblist_t *list)
{
	return (list->size - sizeof(sblist_t)) / sizeof(sbnode_t);
}

#endif /* __SBVERSION_H__ */
