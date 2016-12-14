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
