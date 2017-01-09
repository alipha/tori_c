#ifndef HASHSET_H
#define HASHSET_H

#include <stddef.h>

#define HASHSET_ERROR_ALLOC_BUCKETS 1
#define HASHSET_ERROR_ALLOC_NODES 2
#define HASHSET_ERROR_ID_NOT_FOUND 3


typedef struct hashset_node {
	struct hashset_node *next;
	unsigned char data[1];
} hashset_node;


typedef struct hashset {
	size_t id_offset;
	size_t id_size;
	size_t data_size;
	size_t node_size;
	size_t bucket_bitmask;
	size_t count;
	size_t max_count;
	hashset_node **buckets;
	hashset_node *freed_nodes;
	unsigned char *nodes;
} hashset;


int hashset_create(hashset *set, size_t id_offset, size_t id_size, size_t data_size, size_t bucket_bits, size_t max_count);
void hashset_free(hashset *set);

void* hashset_alloc(hashset *set, const unsigned char *id);
int hashset_remove(hashset *set, const unsigned char *id);
void* hashset_get(hashset *set, const unsigned char *id);

#endif
