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
#define PACKET_COUNT 1000
#else
#define PACKET_COUNT 1
#endif



typedef unsigned char packet_bytes[DEST_ID_SIZE + PACKET_SIZE];


node_info available_nodes[AVAILABLE_NODES] = {0};
unsigned char node_private_keys[AVAILABLE_NODES][crypto_box_SECRETKEYBYTES] = {0};

route_list_info *route_lists = 0;
return_route_list_info *return_route_lists = 0;

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
	printf("\tPackets per second: %f\n", pps);
	printf("\tMax outgoing rate:  %f Mbps\n", pps * PACKET_SIZE * 8 / 1024 / 1024); 
	printf("\tMax incoming rate:  %f Mbps\n", pps * ROUTES_PER_PACKET * INCOMING_DATA_MAX * 8 / 1024 / 1024);

//packets[0][417] = 0;

	start = clock();
	process_packets();
	stop = clock();
	seconds = (double)(stop - start) / CLOCKS_PER_SEC;
	pps = PACKET_COUNT / seconds;

	printf("Process %d packets: %f ms\n", PACKET_COUNT, seconds * 1000);
	printf("\tPackets per second: %f\n", pps);
	printf("\tMax transfer rate:  %f Mbps\n", pps * PACKET_SIZE * 8 / 1024 / 1024); 
		
	process_packets();


	/* Exit Node processing */
	start = clock();
	process_packets();

#ifdef TESTING
	verify_outgoing_packets();
#endif

	create_incoming_packets();
	stop = clock();
	seconds = (double)(stop - start) / CLOCKS_PER_SEC;
	pps = PACKET_COUNT * ROUTES_PER_PACKET / seconds;

	printf("Process %d outgoing packets and %d incoming packets: %f ms\n", PACKET_COUNT, PACKET_COUNT * ROUTES_PER_PACKET, seconds * 1000);
	printf("\tIncoming packets per second: %f\n", pps);
	printf("\tMax incoming data rate:      %f Mbps\n", pps * INCOMING_DATA_MAX * 8 / 1024 / 1024);


	process_packets();
	process_packets();
	verify_incoming_packets();
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

void print_route(const route_info *route, const char *name, uint32_t route_id) {
	printf("%s[%d] = {\n", name, route_id);
	printf("\tid = %u,\n", route->id);

	for(size_t n = 0; n < ROUTE_NODES_MAX; n++) {
		const route_node_info *node = &route->nodes[n];

		printf("\tnodes[%lu] = {\n", n);
		printf("\t\tepk = "); print_hex(node->ephemeral_public_key, sizeof node->ephemeral_public_key); puts(",");
		printf("\t\tsk  = "); print_hex(node->symmetric_key, sizeof node->symmetric_key); puts(",");
		printf("\t\tnode.id = %lu,\n", node->node->id);
		printf("\t\tnpk = "); print_hex(node->node->public_key, sizeof node->node->public_key); puts("");
		printf("\t},\n");
	}
}



void allocate(void) {
#ifndef TESTING
	packets = malloc(2 * PACKET_COUNT * sizeof *packets);
	route_lists = malloc(PACKET_COUNT * sizeof *route_lists);
	return_route_lists = malloc(PACKET_COUNT * sizeof *return_route_lists);
#else
	packets = calloc(2 * (PACKET_COUNT + 2), sizeof *packets);
	route_lists = calloc(PACKET_COUNT + 2, sizeof *route_lists);
	return_route_lists = calloc(PACKET_COUNT + 2, sizeof *return_route_lists);
#endif

	if(!packets) {
		puts("Error malloc packets");
		exit(2);
	}

	if(!route_lists) {
		puts("Error malloc route_lists");
		exit(7);
	}

	if(!return_route_lists) {
		puts("Error malloc return_route_lists");
		exit(21);
	}

#ifndef TESTING
	data.content = content;
#else
	data.content = content + 1000;
	packets++;
	route_lists++;
	return_route_lists++;
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
		assert(route_id == i * ROUTES_PER_PACKET);

		connection.next_sequence_id = i;
		route_lists[i].total_count = i * 3; //PACKET_COUNT * ROUTES_PER_PACKET;
		route_lists[i].start_sequence_id = i * 2; //0;
		route_lists[i].count = ROUTES_PER_PACKET;

		for(size_t r = 0; r < ROUTES_PER_PACKET; r++) {
			if((error = generate_route(&route_lists[i].routes[r], route_id, &connection, available_nodes, AVAILABLE_NODES, 1))) {
				printf("Error generate incoming route: %d\n", error);
				exit(3);
			}
			route_id++;

#ifdef TESTING
			if(i == 0 && r == 0)
				assert(is_blank((unsigned char*)&route_lists[-1], sizeof *route_lists));
			
			if(r < ROUTES_PER_PACKET - 1)
				assert(is_blank((unsigned char*)&route_lists[i].routes[r + 1], sizeof route_lists[i].routes[r + 1]));
	
			if(r == 0 || r == 1)
				print_route(&route_lists[i].routes[r], "return_routes", route_id - 1);
#endif
		}

		if((error = create_route_list_data(&data, &route_lists[i], client_id))) {
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
//printf("node_index: %lu\n", node_index);
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
	int error = 0;
	uint32_t route_id = 0;
	uint64_t expected_node_id;

	packet_info packet;
	return_route_list_info route_list;
	return_route_info *route;

	for(size_t i = 0; i < PACKET_COUNT; i++) {
		if((error = read_packet(&packet, packets[i] + DEST_ID_SIZE, 0))) {
			printf("read_packet failed: %d\n", error);
			exit(9);
		}

		if(memcmp(packet.exit_client_id, connection.exit_client_id, sizeof connection.exit_client_id) != 0) {
			printf("Bad client_id\n");
			exit(10);
		}

		if(packet.connection_id != 5) {
			printf("Bad connection_id. Expected 5. Actual: %d\n", packet.connection_id); 
			exit(11);
		}

		if(packet.sequence_id != i) {
			printf("Bad sequence_id. Expected %lu. Actual: %lu\n", i, packet.sequence_id);
			exit(12);
		}

		if(packet.ack_count != 0) {
			printf("Bad ack_count. Expected 0. Actual: %d\n", packet.ack_count);
			exit(13);
		}

		if(packet.data.type != ROUTE_LIST_DATA) {
			printf("Bad data.type. Expected %d. Actual: %d\n", (int)ROUTE_LIST_DATA, packet.data.type);
			exit(14);
		}



		if(((error = read_route_list_data(&route_list, &packet.data)))) {
			printf("read_route_list_data failed: %d]n", error);
			exit(15);
		}

		if(route_list.total_count != i * 3) {
			printf("Bad total_count. Expected %lu. Actual: %d\n", i * 3, route_list.total_count);
			exit(16);
		}

		if(route_list.start_sequence_id != i * 2) {
			printf("Bad start_sequence_id. Expected %lu. Actual: %lu\n", i * 2, route_list.start_sequence_id);
			exit(17);
		}
/*
		if(route_list.total_count != PACKET_COUNT * ROUTES_PER_PACKET) {
			printf("Bad total_count. Expected %d. Actual: %d\n", PACKET_COUNT * ROUTES_PER_PACKET, route_list.total_count);
			exit(16);
		}

		if(route_list.start_sequence_id != 0) {
			printf("Bad start_sequence_id. Expected 0. Actual: %lu\n", route_list.start_sequence_id);
			exit(17);
		}
*/

		if(route_list.count != ROUTES_PER_PACKET) {
			printf("Bad route_list.count. Expected %d. Actual: %d\n", ROUTES_PER_PACKET, route_list.count);
			exit(18);
		}

		for(size_t r = 0; r < route_list.count; r++) {
			route = &route_list.routes[r];
			expected_node_id = route_lists[i].routes[r].nodes[1].node->id;

			if(route->id != route_id) {
				printf("Bad route_id. Expected %d. Actual: %d\n", route_id, route->id);
				exit(19);
			}

			if(route->dest_node_id != expected_node_id) {
				printf("Bad dest_node_id. Expected %lu. Actual: %lu\n", expected_node_id, route->dest_node_id);
				exit(20);
			}

			route_id++;
		}

		free_packet(&packet);
	}
}


void create_incoming_packets(void) {
	size_t i;
	int error = 0;
	packet_bytes *temp;
	exit_node_connection_info exit_connection;
	char data_content[] = "xThis is some secret data";

#ifndef TESTING
	packet_info out_packet;
#else
	packet_info test_packet[3] = {0};
	#define out_packet test_packet[1]
#endif


	exit_connection.connection_id = 15;
	memcpy(exit_connection.symmetric_key, connection.exit_node_symmetric_key, sizeof exit_connection.symmetric_key);

	data.type = CONTENT_DATA;
	data.length = strlen(data_content);
	data.content = (unsigned char*)data_content;


	for(i = 0; i < PACKET_COUNT; i++) {
		if((error = read_packet(&out_packet, packets[i] + DEST_ID_SIZE, 0))) {
			printf("create_incoming_packets: read_packet failed: %d\n", error);
			exit(22);
		}
		if((error = read_route_list_data(&return_route_lists[i], &out_packet.data))) {
			printf("create_incoming_packets: read_route_list_data failed: %d\n", error);
			exit(23);
		}

#ifdef TESTING
		assert(is_blank((unsigned char*)&test_packet[0], sizeof test_packet[0]));
		assert(is_blank((unsigned char*)&test_packet[2], sizeof test_packet[2]));

		if(i == 0)
			assert(is_blank((unsigned char*)&return_route_lists[-1], sizeof *return_route_lists));
		
		assert(is_blank((unsigned char*)&return_route_lists[i + 1], sizeof return_route_lists[i + 1]));
#endif

		packet_headers[i].is_incoming = 1;
		packet_headers[i].dest_node_id = return_route_lists[i].routes[ROUTES_PER_PACKET - 1].dest_node_id;
		memset(packet_headers[i].dest_client_id, 0, sizeof packet_headers[i].dest_client_id);

		free_packet(&out_packet);
	}

//size_t r = ROUTES_PER_PACKET - 1;
	for(size_t r = 0; r < ROUTES_PER_PACKET; r++) {
		for(i = 0; i < PACKET_COUNT; i++) {
			exit_connection.next_packet_id = i;
			exit_connection.next_sequence_id = i * 10000 + r;
			data.content[0] = 'a' + (i & 15) + r;

			if((error = create_incoming_packet(output_packets[i] + DEST_ID_SIZE, &exit_connection, &return_route_lists[i].routes[r], 0, 0, &data))) {
				printf("create_incoming_packet failed: %d\n", error);
				exit(24);
			}

#ifdef TESTING
			if(i == 0)
				assert(is_blank(output_packets[-1], PACKET_SIZE));

			//assert(is_blank(output_packets[i], DEST_ID_SIZE));	// TODO: This should be blank?
#endif
		}
	}

	temp = packets;
	packets = output_packets;
	output_packets = temp;
}


void verify_incoming_packets(void) {
	int error = 0;

	for(size_t i = 0; i < PACKET_COUNT; i++) {
		if((error = decrypt_incoming_packet(packets[i] + DEST_ID_SIZE, i, ))) {
			printf("decrypt_incoming_packet failed: %d\n", error);
			exit(25);
		}
	}
}

