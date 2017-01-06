/**
 * Copyright (C) 2016-2017 Gary Lin <glin@suse.com>
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

#ifndef __SVERSION_H__
#define __SVERSION_H__

#include <stdint.h>

typedef struct {
	uint16_t dv;
	uint16_t sv;
} __attribute__((packed)) svnode_t;

typedef struct {
	uint32_t size;
	char signer[4];
	svnode_t nodes[0];
} __attribute__((packed)) svlist_t;

static inline uint32_t
count_nodes (const svlist_t *list)
{
	return (list->size - sizeof(svlist_t)) / sizeof(svnode_t);
}

#endif /* __SVERSION_H__ */
