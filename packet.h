#ifndef TORI_PACKET_H
#define TORI_PACKET_H

#define SODIUM_STATIC

#include <stddef.h>
#include <stdint.h>
#include <sodium.h>

#define PACKET_SIZE 1280
#define OUTGOING_DATA_MAX (PACKET_SIZE - 162)
#define INCOMING_DATA_MAX (PACKET_SIZE - 137)
#define ROUTE_NODES_MAX 3
#define OUTGOING_HEADER_LEN 41
#define INCOMING_ROUTE_LEN ((ROUTE_NODES_MAX - 1) * OUTGOING_HEADER_LEN + 8)
#define ROUTE_SIZE ((ROUTE_NODES_MAX - 1) * OUTGOING_HEADER_LEN + 24)
#define ROUTES_PER_PACKET (OUTGOING_DATA_MAX / ROUTE_SIZE)
#define CLIENT_ID_SIZE 16
#define ROUTE_ID_SIZE 16
#define DEST_ID_SIZE sizeof(uint64_t)


typedef enum data_type {
	CONNECT_DATA = 0,
	CONTENT_DATA = 1,
	ROUTE_LIST_DATA = 2,
	STATUS_DATA = 3,
	DATA_TYPE_COUNT = 4
} data_type;

typedef enum address_type {
	IPV4_ADDRESS = 1,
	DOMAIN_NAME_ADDRESS = 3,
	IPV6_ADDRESS = 4
} address_type;


typedef struct node_info {
	uint64_t id;
	address_type addr_type;
	unsigned char ip_address[16];
	char domain_name[256];
	uint16_t port;
	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
} node_info;


/* TODO: client IDs should be public keys so connection requests can be signed
	to prevent a malicious client from using the same client ID */
typedef struct client_connection_info {
	unsigned char exit_client_id[CLIENT_ID_SIZE];
	uint16_t connection_id;
	uint64_t next_sequence_id;
	const node_info *exit_node;
	unsigned char exit_node_symmetric_key[crypto_secretbox_KEYBYTES];
} client_connection_info;


typedef struct exit_node_connection_info {
	uint16_t connection_id;
	uint64_t next_sequence_id;
	uint64_t next_route_id;
	unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
} exit_node_connection_info;


typedef struct route_node_info {
	unsigned char ephemeral_public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
	const node_info *node;
} route_node_info;


typedef struct route_info {
	uint64_t id;
	unsigned char encrypted_route_id[ROUTE_ID_SIZE];
	route_node_info nodes[ROUTE_NODES_MAX];
} route_info;


typedef struct return_route_info {
	uint64_t id;
	uint64_t dest_node_id;
	const unsigned char *data;
} return_route_info;


typedef struct header_info {
	int is_incoming;
	uint64_t dest_node_id;	/* iff 0, dest_client_id is populated */
	unsigned char dest_client_id[CLIENT_ID_SIZE];
} header_info;


typedef struct data_info {
	uint16_t length;
	data_type type;
	unsigned char *content;
} data_info;


typedef struct ack_info {
	uint64_t low_sequence_id;
	uint64_t high_sequence_id;
} ack_info;


typedef struct packet_info {
	unsigned char hash_value[CLIENT_ID_SIZE + sizeof(uint16_t) + sizeof(uint64_t)];	// TODO: populate
	//clock_t send_time;	// TODO: populate
	unsigned char exit_client_id[CLIENT_ID_SIZE];
	uint16_t connection_id;
	uint64_t sequence_id;
	uint16_t ack_count;
	ack_info *acks;
	data_info data;
} packet_info;


typedef struct route_list_info {
	size_t count;	                     /* not stored in the packet */
	route_info routes[ROUTES_PER_PACKET];
} route_list_info;


typedef struct return_route_list_info {
	size_t count;                        /* not stored in the packet */
	return_route_info routes[ROUTES_PER_PACKET];
} return_route_list_info;
	


/* internal helpers */
int in_array(const size_t *array, size_t value, size_t array_len);
void write_data_section(unsigned char *packet, const unsigned char *end_ptr, uint16_t connection_id, uint64_t sequence_id, const ack_info *acks, uint16_t ack_count, const data_info *data);

/* acks + data must be <= OUTGOING_DATA_MAX */
int create_outgoing_packet(unsigned char *packet, const client_connection_info *connection, const route_info *route, const ack_info *acks, uint16_t ack_count, const data_info *data);

/* acks + data must be <= INCOMING_DATA_MAX */
int create_incoming_packet(unsigned char *packet, const exit_node_connection_info *connection, const return_route_info *route, const ack_info *acks, uint16_t ack_count, const data_info *data);

/* the output_layer is prefixed with the dest_node_id (may be 0), so add
   8 to the pointer to get the actual layer content */
int process_layer(header_info *header, unsigned char *output_layer, const unsigned char *layer, const unsigned char *node_public_key, const unsigned char *node_private_key);

int decrypt_incoming_packet(unsigned char *packet, const route_info *route);

/* packet will contain a pointer into decrypted_packet for packet->data.content.
   decrypted_packet will not be modified; it is non-const because packet->data.content is non-const.
   packet->acks will point to allocated memory that needs to be freed with free_packet */
int read_packet(packet_info *packet, unsigned char *decrypted_packet, int is_incoming);
int free_packet(packet_info *packet);

void compute_packet_hash(unsigned char *hash_value, const unsigned char *client_id, uint16_t connection_id, uint64_t sequence_id);

int generate_route(route_info *route, uint64_t route_id, const client_connection_info *connection, const node_info *available_nodes, size_t node_count, int is_incoming); 
int encrypt_route(unsigned char *encrypted_route, const route_info *route, const unsigned char *entry_client_id);

int generate_symmetric_key(unsigned char *symmetric_key, const unsigned char *node_public_key, const unsigned char *node_private_key, const unsigned char *ephemeral_public_key, const unsigned char *ephemeral_private_key);

#endif
