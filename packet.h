#ifndef TORI_PACKET_H
#define TORI_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <sodium.h>

#define PACKET_SIZE 1280
#define OUTGOING_DATA_MAX (PACKET_SIZE - 162)
#define INCOMING_DATA_MAX (PACKET_SIZE - 127)
#define ROUTE_NODES_MAX 3
#define OUTGOING_HEADER_LEN 41
#define INCOMING_ROUTE_LEN ((ROUTE_NODES_MAX - 1) * OUTGOING_HEADER_LEN + 8)
#define ROUTE_SIZE (ROUTE_NODES_MAX * OUTGOING_HEADER_LEN + 7)


typedef enum data_type {
	CONNECT_DATA = 0,
	CONTENT_DATA = 1,
	ROUTE_LIST_DATA = 2,
	STATUS_DATA = 3
} data_type;

typedef enum status_type {
	CLOSE_STATUS = 0,
	DNS_ERROR_STATUS = 1,
	REFUSED_ERROR_STATUS = 2
} status_type;

typedef enum address_type {
	IPV4_ADDRESS = 1,
	DOMAIN_NAME_ADDRESS = 3,
	IPV6_ADDRESS = 4
} address_type;


typedef struct connection_info {
	unsigned char user_id[16];
	uint16_t connection_id;
	uint64_t next_sequence_id;
	uint64_t exit_node_id;
} connection_info;


typedef struct node_info {
	uint64_t id;
	address_type addr_type;
	unsigned char ip_address[16];
	uint16_t port;
	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
} node_info;


typedef struct route_node_info {
	unsigned char ephemeral_public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
	const node_info *node;
} route_node_info;


typedef struct route_info {
	uint32_t id;
	route_node_info nodes[ROUTE_NODES_MAX];
} route_info;


typedef struct header_info {
	int is_incoming;
	uint64_t dest_node_id;	/* iff 0, dest_client_id is populated */
	unsigned char dest_client_id[16];
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


/* internal helpers */
int in_array(const size_t *array, size_t value, size_t array_len);
void write_data_section(unsigned char *packet, const unsigned char *end_ptr, const ack_info *acks, uint16_t ack_count, const data_info *data);

/* acks + data must be <= OUTGOING_DATA_MAX */
int create_outgoing_packet(unsigned char *packet, const connection_info *connection, const route_info *route, const ack_info *acks, uint16_t ack_count, const data_info *data);

int create_route_list_data(unsigned char *data, uint32_t total_route_count, uint64_t start_sequence_id, const route_info *routes, unsigned char route_count);

/* acks + data must be <= INCOMING_DATA_MAX */
int create_incoming_packet(unsigned char *packet, uint64_t *dest_node_id, const unsigned char *route, const ack_info *acks, uint16_t ack_count, const data_info *data);

/* the output_layer is prefixed with the dest_node_id (may be 0), so add
   8 to the pointer to get the actual layer content */
int process_layer(header_info *header, unsigned char *output_layer, const unsigned char *layer, const unsigned char *node_public_key, const unsigned char *node_private_key);

/* symmetric_keys are in order of decryption: entry to exit */
int decrypt_incoming_packet(unsigned char *packet, const unsigned char *symmetric_keys);

int generate_route(route_info *route, uint32_t route_id, const node_info *exit_node, const node_info *available_nodes, size_t node_count, int is_incoming);

int encrypt_route(unsigned char *encrypted_route, const route_info *route, const unsigned char *client_id);

int generate_symmetric_key(unsigned char *symmetric_key, const unsigned char *node_public_key, const unsigned char *node_private_key, const unsigned char *ephemeral_public_key, const unsigned char *ephemeral_private_key);

#endif
