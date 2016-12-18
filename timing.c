#include "pack.h"
#include "packet.h"
#include <stdio.h>
#include <stdlib.h>

#define AVAILABLE_NODES 100
#define PACKET_COUNT 10000
#define ROUTES_PER_PACKET (OUTGOING_DATA_MAX / ROUTE_SIZE)


typedef unsigned char packet_bytes[PACKET_SIZE];

node_info available_nodes[AVAILABLE_NODES];
unsigned char node_private_keys[AVAILABLE_NODES][crypto_box_SECRETKEYBYTES];

packet_bytes *packets;



void create_node_keys(void);


int main(void) {
	assert(sizeof node_private_keys[0] == crypto_box_SECRETKEYBYTES);

	packets = malloc(PACKET_COUNT * sizeof *packets);

	if(!packets) {
		puts("Error malloc packets");
		return 2;
	}

	for(size_t i = 0; i < PACKET_COUNT; i++) {
		
	}

	return 0;
}


void create_node_keys(void) {
	node_info *node;

	for(size_t i = 0; i < AVAILABLE_NODES; i++) {
		node = available_nodes[i];
		node->id = i + 10000;
		randombytes_buf(node_private_keys[i], sizeof node_private_keys[i]);

		if(crypto_scalarmult_base(node->public_key, node_private_keys[i])) {
			puts("Error scalarmult_base");
			exit(1);
		}
	}
}

