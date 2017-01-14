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
	uint64_t null_id = 0;
	uint64_t unused_id = 0x4444444444444444;
	uint64_t unused_id2 = 0x3333333333333333;
	test_struct *p;
	test_struct *alice_p;
	test_struct *bob_p;
	test_struct *chris_p;
	test_struct *dave_p;
	test_struct *fred_p;
	test_struct *holly_p;
	test_struct alice = {"Alice", 0x1234567890abcdef, 21};
	test_struct bob   = {"Bob",   0x1122334455667788, 35};
	test_struct chris = {"Chris", 0x11223344aabbccdd, 40};
	test_struct dave  = {"Dave",  0x0102030455667788, 42};
	test_struct eve   = {"Eve",   0x1234567890abcdef, 18};
	test_struct fred  = {"Fred",  0x0122334455667788, 50};
	test_struct greg  = {"Greg",  0x1122334455abcdef, 65};
	test_struct holly = {"Holly", 0x0000000000000000, 13};

	/* Test hashset_create */

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


	/* Test hashset_alloc */

	alice_p = p = hashset_alloc(&test_set, &alice.id);
	assert(p);
	memcpy(p, &alice, sizeof alice);

	if(!test_set.buckets[0x2f]) {
		assert(test_set.buckets[0x38]);
		puts("Big endian");
		return 2;
	}

	assert(test_set.count == 1);
	assert(test_set.buckets[0x2f]);
	assert(!test_set.buckets[0x2f]->next);
	assert(p == (test_struct*)test_set.buckets[0x2f]->data);
	assert(test_set.buckets[0x2f] == (hashset_node*)test_set.nodes);
	assert(!test_set.freed_nodes);


	bob_p = p = hashset_alloc(&test_set, &bob.id);
	assert(p);
	memcpy(p, &bob, sizeof bob);

	assert(test_set.count == 2);
	assert(test_set.buckets[0x08]);
	assert(!test_set.buckets[0x08]->next);
	assert(p == (test_struct*)test_set.buckets[0x08]->data);
	assert(test_set.buckets[0x08] == (hashset_node*)&test_set.nodes[test_set.node_size]);
	assert(!test_set.freed_nodes);

	
	chris_p = p = hashset_alloc(&test_set, &chris.id);
	assert(p);
	memcpy(p, &chris, sizeof chris);

	assert(test_set.count == 3);
	assert(test_set.buckets[0x1d]);
	assert(!test_set.buckets[0x1d]->next);
	assert(p == (test_struct*)test_set.buckets[0x1d]->data);
	assert(test_set.buckets[0x1d] == (hashset_node*)&test_set.nodes[2 * test_set.node_size]);
	assert(!test_set.freed_nodes);


	dave_p = p = hashset_alloc(&test_set, &dave.id);
	assert(p);
	memcpy(p, &dave, sizeof dave);

	assert(test_set.count == 4);
	assert(test_set.buckets[0x08]);
	assert(test_set.buckets[0x08]->next);
	assert(!test_set.buckets[0x08]->next->next);
	assert(p == (test_struct*)test_set.buckets[0x08]->data);
	assert(bob_p == (test_struct*)test_set.buckets[0x08]->next->data);
	assert(test_set.buckets[0x08] == (hashset_node*)&test_set.nodes[3 * test_set.node_size]);
	assert(!test_set.freed_nodes);

	
	p = hashset_alloc(&test_set, &eve.id);
	assert(!p);


	fred_p = p = hashset_alloc(&test_set, &fred.id);
	assert(p);
	memcpy(p, &fred, sizeof fred);

	assert(test_set.count == 5);
	assert(test_set.buckets[0x08]);
	assert(test_set.buckets[0x08]->next);
	assert(test_set.buckets[0x08]->next->next);
	assert(!test_set.buckets[0x08]->next->next->next);
	assert(p == (test_struct*)test_set.buckets[0x08]->data);
	assert(dave_p == (test_struct*)test_set.buckets[0x08]->next->data);
	assert(bob_p == (test_struct*)test_set.buckets[0x08]->next->next->data);
	assert(test_set.buckets[0x08] == (hashset_node*)&test_set.nodes[4 * test_set.node_size]);
	assert(!test_set.freed_nodes);


	assert(memcmp(alice_p, &alice, sizeof alice) == 0);
	assert(memcmp(bob_p, &bob, sizeof bob) == 0);
	assert(memcmp(chris_p, &chris, sizeof chris) == 0);
	assert(memcmp(dave_p, &dave, sizeof dave) == 0);
	assert(memcmp(fred_p, &fred, sizeof fred) == 0);


	/* Test hashset_get */

	assert(alice_p == hashset_get(&test_set, &alice.id));
	assert(bob_p == hashset_get(&test_set, &bob.id));
	assert(chris_p == hashset_get(&test_set, &chris.id));
	assert(dave_p == hashset_get(&test_set, &dave.id));
	assert(alice_p == hashset_get(&test_set, &eve.id));
	assert(fred_p == hashset_get(&test_set, &fred.id));
	assert(!hashset_get(&test_set, &greg.id));
	assert(!hashset_get(&test_set, &null_id));
	assert(!hashset_get(&test_set, &unused_id));


	/* Test hashset_remove */

	assert(hashset_remove(&test_set, &null_id) == HASHSET_ERROR_ID_NOT_FOUND);
	assert(hashset_remove(&test_set, &unused_id2) == HASHSET_ERROR_ID_NOT_FOUND);
	assert(hashset_remove(&test_set, &greg.id) == HASHSET_ERROR_ID_NOT_FOUND);
	assert(test_set.count == 5);


	assert(hashset_remove(&test_set, &bob.id) == 0);

	assert(test_set.count == 4);
	assert(test_set.buckets[0x08]);
	assert(test_set.buckets[0x08]->next);
	assert(fred_p == (test_struct*)test_set.buckets[0x08]->data);
	assert(dave_p == (test_struct*)test_set.buckets[0x08]->next->data);
	assert(!test_set.buckets[0x08]->next->next);
	assert(test_set.freed_nodes);
	assert(!test_set.freed_nodes->next);
	assert(bob_p == (test_struct*)test_set.freed_nodes->data);


	assert(hashset_remove(&test_set, &alice.id) == 0);

	assert(test_set.count == 3);
	assert(!test_set.buckets[0x2f]);
	assert(test_set.freed_nodes);
	assert(test_set.freed_nodes->next);
	assert(!test_set.freed_nodes->next->next);
	assert(alice_p == (test_struct*)test_set.freed_nodes->data);
	assert(bob_p == (test_struct*)test_set.freed_nodes->next->data);


	assert(hashset_remove(&test_set, &fred.id) == 0);

	assert(test_set.count == 2);
	assert(test_set.buckets[0x08]);
	assert(!test_set.buckets[0x08]->next);
	assert(dave_p == (test_struct*)test_set.buckets[0x08]->data);
	assert(test_set.freed_nodes);
	assert(test_set.freed_nodes->next);
	assert(test_set.freed_nodes->next->next);
	assert(!test_set.freed_nodes->next->next->next);
	assert(fred_p == (test_struct*)test_set.freed_nodes->data);
	assert(alice_p == (test_struct*)test_set.freed_nodes->next->data);
	assert(bob_p == (test_struct*)test_set.freed_nodes->next->next->data);


	// TODO: hashset_get, add fred and bob back, add holly
	assert(hashset_remove(&test_set, &bob.id) == HASHSET_ERROR_ID_NOT_FOUND);
	assert(hashset_remove(&test_set, &alice.id) == HASHSET_ERROR_ID_NOT_FOUND);
	assert(hashset_remove(&test_set, &fred.id) == HASHSET_ERROR_ID_NOT_FOUND);


	bob_p = p = hashset_alloc(&test_set, &bob.id);
	assert(p);
	memcpy(p, &bob, sizeof bob);

	assert(test_set.count == 3);
	assert(test_set.buckets[0x08]);
	assert(test_set.buckets[0x08]->next);
	assert(!test_set.buckets[0x08]->next->next);
	assert(p == (test_struct*)test_set.buckets[0x08]->data);
	assert(dave_p == (test_struct*)test_set.buckets[0x08]->next->data);
	assert(p == fred_p);
	assert(test_set.freed_nodes);
	assert(test_set.freed_nodes->next);
	assert(!test_set.freed_nodes->next->next);
	assert(alice_p == (test_struct*)test_set.freed_nodes->data);


	fred_p = p = hashset_alloc(&test_set, &fred.id);
	assert(p);
	memcpy(p, &fred, sizeof fred);

	assert(test_set.count == 4);
	assert(test_set.buckets[0x08]);
	assert(test_set.buckets[0x08]->next);
	assert(test_set.buckets[0x08]->next->next);
	assert(!test_set.buckets[0x08]->next->next->next);
	assert(p == (test_struct*)test_set.buckets[0x08]->data);
	assert(bob_p == (test_struct*)test_set.buckets[0x08]->next->data);
	assert(dave_p == (test_struct*)test_set.buckets[0x08]->next->next->data);
	assert(p == alice_p);
	assert(test_set.freed_nodes);
	assert(!test_set.freed_nodes->next);


	assert(!hashset_get(&test_set, &alice.id));
	assert(bob_p == hashset_get(&test_set, &bob.id));
	assert(chris_p == hashset_get(&test_set, &chris.id));
	assert(dave_p == hashset_get(&test_set, &dave.id));
	assert(fred_p == hashset_get(&test_set, &fred.id));
	assert(memcmp(bob_p, &bob, sizeof bob) == 0);
	assert(memcmp(chris_p, &chris, sizeof chris) == 0);
	assert(memcmp(dave_p, &dave, sizeof dave) == 0);
	assert(memcmp(fred_p, &fred, sizeof fred) == 0);


	holly_p = p = hashset_alloc(&test_set, &holly.id);
	assert(p);
	memcpy(p, &holly, sizeof holly);

	assert(test_set.count == 5);
	assert(test_set.buckets[0]);
	assert(!test_set.buckets[0]->next);
	assert(p == (test_struct*)test_set.buckets[0]->data);
	assert(!test_set.freed_nodes);

	assert(holly_p == hashset_get(&test_set, &holly.id));


	assert(hashset_remove(&test_set, &bob.id) == 0);

	assert(test_set.count == 4);
	assert(test_set.buckets[0x08]);
	assert(test_set.buckets[0x08]->next);
	assert(fred_p == (test_struct*)test_set.buckets[0x08]->data);
	assert(dave_p == (test_struct*)test_set.buckets[0x08]->next->data);
	assert(!test_set.buckets[0x08]->next->next);
	assert(test_set.freed_nodes);
	assert(!test_set.freed_nodes->next);
	assert(bob_p == (test_struct*)test_set.freed_nodes->data);


	hashset_free(&test_set);
	return 0;
}
