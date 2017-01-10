#include "../hashset.h"
#include "../packet.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>


typedef struct test_struct {
	char name[128];
	uint64_t id;
	int age;
} test_struct;


/* nodes need: */
hashset clients; /* index by client_info.id */
hashset nodes;	 /* index by node_info.id */

/* clients need: */
hashset routes;  /* index by route_info.encrypted_route_id */
hashset packets; /* index by packet_info.hash_value and keep another circular array ordered by send time */


hashset test_set;


int main(void) {
	int error = 0;
	test_struct *p;
	test_struct alice = {"Alice", 0x1234567890abcdef, 21};
	test_struct bob   = {"Bob",   0x1122334455667788, 35};
	test_struct chris = {"Chris", 0x11223344aabbccdd, 40};
	test_struct dave  = {"Dave",  0x0102030455667788, 42};
	test_struct eve   = {"Eve",   0x1234567890abcdef, 18};

	/* both of these could actually succeed */
	if((error = hashset_create(&test_set, 0, 4, 8, 28, 100))) {
		assert(error == HASHSET_ERROR_ALLOC_BUCKETS);
		puts("Large bucket alloc failed (expected)");
	} else {
		hashset_free(&test_set);
		puts("Large bucket alloc succeeded");
	}

	if((error = hashset_create(&test_set, 4, 2, 6, 8, 1 << 28))) {
		assert(error == HASHSET_ERROR_ALLOC_NODES);
		puts("Large element alloc failed (expected)");
	} else {
		hashset_free(&test_set);
		puts("Large element alloc succeeded");
	}

	if((error = hashset_create(&test_set, offsetof(test_struct, id), sizeof(uint64_t), sizeof(test_struct), 6, 100))) {
		printf("create error: %d\n", error);
		return 1;
	}

	assert(test_set.id_offset == 128);
	assert(test_set.id_size == sizeof(uint64_t));
	assert(test_set.data_size == sizeof(test_struct));
	assert(test_set.node_size == sizeof(hashset_node*) + sizeof(test_struct));
	assert(test_set.bucket_bitmask == 63);
	assert(test_set.count == 0);
	assert(test_set.max_count == 100);
	assert(test_set.buckets);
	assert(!test_set.freed_nodes);
	assert(test_set.nodes);

	p = hashset_alloc(&test_set, &alice.id);
	assert(p);
	memcpy(p, &alice, sizeof alice);

	if(!test_set.buckets[0x2f]) {
		assert(test_set.buckets[0x38]);
		puts("Big endian");
		return 2;
	}

	assert(test_set.count == 1);
	assert(p == (test_struct*)test_set.buckets[0x2f]->data);
	assert(test_set.buckets[0x2f] == (hashset_node*)test_set.nodes);
	assert(!test_set.freed_nodes);

	

	hashset_free(&test_set);
	return 0;
}
