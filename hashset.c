#include "hashset.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>


int hashset_create(hashset *set, size_t id_offset, size_t id_size, size_t data_size, size_t bucket_bits, size_t max_count) {
	assert(set);
	assert(set->id_size >= sizeof(size_t));
	assert(set->id_offset + set->id_size <= set->data_size);
	assert(set->bucket_bits < 30);

	hashset_node node;
	size_t node_size = (node.data - (unsigned char *)&node) + data_size;

	size_t bucket_count = (1U << bucket_bits);

	set->id_offset = id_offset;
	set->id_size = id_size;
	set->data_size = data_size;
	set->node_size = node_size;
	set->bucket_bitmask = bucket_count - 1;
	set->count = 0;
	set->max_count = max_count;
	set->freed_nodes = NULL;

	set->buckets = malloc(bucket_count * sizeof *set->buckets);

	if(!set->buckets)
		return HASHSET_ERROR_ALLOC_BUCKETS;

	set->nodes = malloc(max_count * node_size);

	if(!set->nodes) {
		free(set->buckets);
		return HASHSET_ERROR_ALLOC_NODES;
	}

	return 0;
}


void hashset_free(hashset *set) {
	assert(set);

	free(set->buckets);
	free(set->nodes);
}


void* hashset_alloc(hashset *set, const unsigned char *id) {
	assert(set);
	assert(set->buckets);
	assert(set->nodes);
	assert(p);
	assert(id);
	assert(set->count <= set->max_count);
	assert(!hashset_get(set, id));

	if(set->count >= set->max_count)
		return NULL;

	size_t bucket_id = *(const size_t*)id & set->bucket_bitmask;
	hashset_node *node = set->freed_nodes;

	if(node)
		set->freed_nodes = set->freed_nodes->next;
	else
		node = (hashset_node*)&set->nodes[set->node_size * set->count];

	if(set->buckets[bucket_id])
		node->next = set->buckets[bucket_id];
	else
		node->next = NULL;

	set->buckets[bucket_id] = node;
	set->count++;
	return node->data;
}


int hashset_remove(hashset *set, const unsigned char *id) {
	assert(set);
	assert(set->buckets);
	assert(set->nodes);
	assert(id);

	size_t bucket_id = *(const size_t*)id & set->bucket_bitmask;
	hashset_node *prev = NULL;
	hashset_node *node = set->buckets[bucket_id];

	while(node) {
		if(memcmp(node->data + set->id_offset, id, set->id_size) == 0)
			break;
		prev = node;
		node = node->next;
	}

	if(!node)
		return HASHSET_ERROR_ID_NOT_FOUND;

	assert(set->count > 0);

	if(prev)
		prev->next = node->next;
	else
		set->buckets[bucket_id] = node->next;

	node->next = set->freed_nodes;
	set->freed_nodes = node;
	set->count--;
	return 0;
}


void* hashset_get(hashset *set, const unsigned char *id) {
	assert(set);
	assert(set->buckets);
	assert(set->nodes);
	assert(id);

	size_t bucket_id = *(const size_t*)id & set->bucket_bitmask;
	hashset_node *node = set->buckets[bucket_id];

	while(node) {
		if(memcmp(node->data + set->id_offset, id, set->id_size) == 0)
			break;
		node = node->next;
	}

	if(node)
		return node->data;
	else
		return NULL;
}
