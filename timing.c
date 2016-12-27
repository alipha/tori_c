#include "pack.h"
#include "packet.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#define AVAILABLE_NODES 100 //4
#define NODE_ID_START 10000

//#define TESTING 1

#ifndef TESTING
#define PACKET_COUNT 10000
#else
#define PACKET_COUNT 1
#endif



typedef unsigned char packet_bytes[DEST_ID_SIZE + PACKET_SIZE];


node_info available_nodes[AVAILABLE_NODES] = {0};
unsigned char node_private_keys[AVAILABLE_NODES][crypto_box_SECRETKEYBYTES] = {0};

route_info *return_routes = 0;

packet_bytes *packets = 0;
packet_bytes *output_packets = 0;
header_info packet_headers[PACKET_COUNT] = {0};

data_info data = {0};
#ifndef TESTING
unsigned char content[OUTGOING_DATA_MAX] = {0};
#else
unsigned char content[OUTGOING_DATA_MAX + 2000] = {0};
#endif

client_connection_info connection = {0};

unsigned char client_id[CLIENT_ID_SIZE] = {0};


int is_blank(const unsigned char *buffer, size_t len);
void print_hex(const unsigned char *buffer, size_t len);
void print_route(const route_info *routes, const char *name, uint32_t route_id);
void allocate(void);
void create_node_keys(void);
void setup_client(void);
void create_outgoing_packets(void);
void process_packets(void);
void verify_outgoing_packets(void);
void create_incoming_packets(void);
void verify_incoming_packets(void);



int main(void) {
	assert(sizeof node_private_keys[0] == crypto_box_SECRETKEYBYTES);
	assert(sizeof *packets == DEST_ID_SIZE + PACKET_SIZE);

	assert(0);

	clock_t start;
	clock_t stop;
	double seconds;
	double pps;

	allocate();
	create_node_keys();
	setup_client();

	start = clock();
	create_outgoing_packets();
	stop = clock();
	seconds = (double)(stop - start) / CLOCKS_PER_SEC;
	pps = PACKET_COUNT / seconds;

	printf("Create %d outgoing route packets: %f ms\n", PACKET_COUNT, seconds * 1000);
	printf("\tPackets per second: %f\n", PACKET_COUNT / seconds);
	printf("\tMax outgoing rate:  %f Mbps\n", pps * PACKET_SIZE * 8 / 1024 / 1024); 
	printf("\tMax incoming rate:  %f Mbps\n", pps * ROUTES_PER_PACKET * INCOMING_DATA_MAX * 8 / 1024 / 1024);

//packets[0][417] = 0;

	start = clock();
	process_packets();
	stop = clock();
	seconds = (double)(stop - start) / CLOCKS_PER_SEC;
	pps = PACKET_COUNT / seconds;

	printf("Process %d packets: %f ms\n", PACKET_COUNT, seconds * 1000);
	printf("\tPackets per second: %f\n", PACKET_COUNT / seconds);
	printf("\tMax outgoing rate:  %f Mbps\n", pps * PACKET_SIZE * 8 / 1024 / 1024); 
	
	
/*
	process_packets();
	process_packets();

	verify_outgoing_packets();
	create_incoming_packets();
	process_packets();
	process_packets();
	verify_incoming_packets();
*/
	return 0;
}


int is_blank(const unsigned char *buffer, size_t len) {
	for(size_t i = 0; i < len; i++)
		if(buffer[i])
			return 0;
	return 1;
}


void print_hex(const unsigned char *buffer, size_t len) {
	const char *digits = "0123456789abcdef";

	for(size_t i = 0; i < len; i++) {
		putchar(digits[buffer[i] >> 4]);
		putchar(digits[buffer[i] & 15]);
	}
}

void print_route(const route_info *routes, const char *name, uint32_t route_id) {
	printf("%s[%d] = {\n", name, route_id);
	printf("\tid = %u,\n", routes[route_id].id);

	for(size_t n = 0; n < ROUTE_NODES_MAX; n++) {
		const route_node_info *node = &routes[route_id].nodes[n];

		printf("\tnodes[%lu] = {\n", n);
		printf("\t\tepk = "); print_hex(node->ephemeral_public_key, sizeof node->ephemeral_public_key); puts("... ,");
		printf("\t\tsk  = "); print_hex(node->symmetric_key, sizeof node->symmetric_key); puts("... ,");
		printf("\t\tnode.id = %lu,\n", node->node->id);
		printf("\t\tnpk = "); print_hex(node->node->public_key, sizeof node->node->public_key); puts("...");
		printf("\t},\n");
	}
}



void allocate(void) {
#ifndef TESTING
	packets = malloc(2 * PACKET_COUNT * sizeof *packets);
#else
	packets = calloc(2 * (PACKET_COUNT + 2), sizeof *packets);
#endif

	if(!packets) {
		puts("Error malloc packets");
		exit(2);
	}
	

#ifndef TESTING
	return_routes = malloc(PACKET_COUNT * ROUTES_PER_PACKET * sizeof *return_routes);
#else
	return_routes = calloc((PACKET_COUNT + 2) * ROUTES_PER_PACKET, sizeof *return_routes);
#endif

	if(!return_routes) {
		puts("Error malloc return_routes");
		exit(7);
	}


#ifndef TESTING
	data.content = content;
#else
	data.content = content + 1000;
	packets++;
	return_routes++;
#endif
	
	output_packets = packets + PACKET_COUNT;
}


void create_node_keys(void) {
	node_info *node;

	for(size_t i = 0; i < AVAILABLE_NODES; i++) {
		node = &available_nodes[i];

		assert(node->id == 0);
		assert(is_blank(node_private_keys[i], sizeof node_private_keys[i]));

		node->id = i + NODE_ID_START;
		randombytes_buf(node_private_keys[i], sizeof node_private_keys[i]);

		if(crypto_scalarmult_base(node->public_key, node_private_keys[i])) {
			puts("Error scalarmult_base");
			exit(1);
		}
	}
}


void setup_client(void) {
	assert(AVAILABLE_NODES > 3);

	randombytes_buf(client_id, sizeof client_id);

	randombytes_buf(connection.exit_client_id, sizeof connection.exit_client_id);
	connection.connection_id = 5;
	connection.exit_node = &available_nodes[3];
	randombytes_buf(connection.exit_node_symmetric_key, sizeof connection.exit_node_symmetric_key);

	printf("client_id:      "); print_hex(client_id, sizeof client_id); puts("");
	printf("exit_client_id: "); print_hex(connection.exit_client_id, sizeof connection.exit_client_id); puts("");
}


void create_outgoing_packets(void) {
	int error = 0;
	uint32_t route_id = 0;

#ifndef TESTING
	route_info out_route;
#else
	route_info test_route[3] = {0};
	#define out_route test_route[1]
#endif

	for(size_t i = 0; i < PACKET_COUNT; i++) {
		connection.next_sequence_id = i;
		assert(route_id == i * ROUTES_PER_PACKET);

		for(size_t r = 0; r < ROUTES_PER_PACKET; r++) {
			if((error = generate_route(&return_routes[route_id], route_id, &connection, available_nodes, AVAILABLE_NODES, 1))) {
				printf("Error generate incoming route: %d\n", error);
				exit(3);
			}
			route_id++;

#ifdef TESTING
			if(i == 0 && r == 0)
				assert(is_blank((unsigned char*)&return_routes[-1], sizeof *return_routes));
			
			assert(is_blank((unsigned char*)&return_routes[route_id], sizeof *return_routes));
	
			if(r == 0 || r == 1)
				print_route(return_routes, "return_routes", route_id - 1);
#endif
		}

		if((error = create_route_list_data(&data, PACKET_COUNT * ROUTES_PER_PACKET, 0, client_id, &return_routes[i * ROUTES_PER_PACKET], ROUTES_PER_PACKET))) {
			printf("Error create_route_list_data: %d\n", error);
			exit(4);
		}

#ifdef TESTING
		assert(data.length == 1033); /* ROUTES_PER_PACKET * ROUTE_SIZE + 13 */
		assert(is_blank(data.content - 1000, 1000));
		assert(is_blank(data.content + data.length, 1000));
		puts("create_route_list_data success");
#endif

		if((error = generate_route(&out_route, 0, &connection, available_nodes, AVAILABLE_NODES, 0))) {
			printf("Error generating outgoing route: %d\n", error);
			exit(5);
		}

#ifdef TESTING
		assert(is_blank((unsigned char*)&test_route[0], sizeof test_route[0]));
		assert(is_blank((unsigned char*)&test_route[2], sizeof test_route[2]));
		print_route(&out_route, "out_route", 0);
		puts("generate outgoing route success");
#endif

		if((error = create_outgoing_packet(packets[i] + DEST_ID_SIZE, &connection, &out_route, 0, 0, &data))) {
			printf("Error create_outgoing_packet: %d\n", error);
			exit(6);
		}

#ifdef TESTING
		if(i == 0)
			assert(is_blank(packets[-1], PACKET_SIZE));

		assert(is_blank(packets[i], DEST_ID_SIZE));
		assert(is_blank(packets[i + 1], PACKET_SIZE));
		puts("create_outgoing_packet success");
#endif

		packet_headers[i].is_incoming = 0;
		packet_headers[i].dest_node_id = out_route.nodes[0].node->id;
		memset(packet_headers[i].dest_client_id, 0, sizeof packet_headers[i].dest_client_id);
	}
}


void process_packets(void) {
	int error = 0;
	packet_bytes *temp;
	node_info *node;
	uint64_t node_index;

	for(size_t i = 0; i < PACKET_COUNT; i++) {
		node_index = packet_headers[i].dest_node_id - NODE_ID_START;
		assert(node_index < AVAILABLE_NODES);

		node = &available_nodes[node_index];

		if((error = process_layer(&packet_headers[i], output_packets[i], packets[i] + DEST_ID_SIZE, node->public_key, node_private_keys[node_index]))) {
			printf("process_layer failed: %d\n", error);
			exit(8);
		}

#ifdef TESTING
		printf("Before process: ");
		print_hex(packets[i], 40); 
		printf("\nAfter process:  ");
		print_hex(output_packets[i], 40); puts("");
		printf("dest_node_id = %lu\n", packet_headers[i].dest_node_id);
#endif
	}

	temp = packets;
	packets = output_packets;
	output_packets = temp;
}


void verify_outgoing_packets(void) {
	for(size_t i = 0; i < PACKET_COUNT; i++) {
	}
}


void create_incoming_packets(void) {
	for(size_t i = 0; i < PACKET_COUNT; i++) {
	}
}


void verify_incoming_packets(void) {
	for(size_t i = 0; i < PACKET_COUNT; i++) {
	}
}

