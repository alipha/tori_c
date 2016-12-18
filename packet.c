#include "packet.h"
#include "pack.h"
#include <string.h>
#include <assert.h>

#if crypto_secretbox_MACBYTES != 16
#error "Expected crypto_secretbox_MACBYTES to be 16"
#endif

#if crypto_secretbox_KEYBYTES != 32
#error "Expected crypto_secretbox_KEYBYTES to be 32"
#endif

#if crypto_generichash_BYTES != 32
#error "Expected crypto_generichash_BYTES to be 32"
#endif

#if crypto_stream_KEYBYTES != 32
#error "Expected crypto_stream_KEYBYTES to be 32"
#endif

#if crypto_box_PUBLICKEYBYTES != 32
#error "Expected crypto_box_PUBLICKEYBYTES to be 32"
#endif




static unsigned char data_nonce[crypto_stream_NONCEBYTES] = {0};
static unsigned char route_nonce[crypto_stream_NONCEBYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
static unsigned char padding_nonce[crypto_stream_NONCEBYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254};


int in_array(const size_t *array, size_t value, size_t array_len) {
	assert(array);

	for(size_t i = 0; i < array_len; i++)
		if(array[i] == value)
			return 1;
	return 0;
}


void write_data_section(unsigned char *packet, const unsigned char *end_ptr, const ack_info *acks, uint16_t ack_count, const data_info *data) {
	assert(packet);
	assert(end_ptr);
	assert(acks);
	assert(data);
	assert(sizeof ack_count == sizeof(uint16_t));
	assert(sizeof acks[0].low_sequence_id == sizeof acks[0].high_sequence_id);
	assert(sizeof data->length == sizeof(uint16_t));

	write_uint16(&packet, ack_count);

	for(size_t a = 0; a < ack_count; a++) {
		write_uint64(&packet, acks[a].low_sequence_id);
		write_uint64(&packet, acks[a].high_sequence_id);
	}

	write_byte(&packet, (unsigned char)data->type);
	write_uint16(&packet, data->length);

	assert(end_ptr - packet <= data->length);	// TODO: update data_info if the data is too long or something?

	write_binary(&packet, data->content, data->length);
	memset(packet, 0, end_ptr - packet);	/* padding */
}


int create_outgoing_packet(unsigned char *packet, const connection_info *connection, const route_info *route, const ack_info *acks, uint16_t ack_count, const data_info *data) {
	assert(packet);
	assert(connection);
	assert(route);
	assert(acks);
	assert(data);
	assert(sizeof connection->connection_id == sizeof(uint16_t));
	assert(sizeof connection->next_sequence_id == sizeof(uint64_t));
	assert(sizeof connection->next_sequence_id == sizeof acks[0].low_sequence_id);
	assert(sizeof route->nodes[0].node->id == sizeof(uint64_t));

	unsigned char *layer = packet + ROUTE_NODES_MAX * OUTGOING_HEADER_LEN;
	/* innermost does not have a Dest Node ID, so subtract 8 */
	unsigned char *p = layer - 8;
	unsigned char *encrypted_start;
	unsigned char *end_ptr = packet + PACKET_SIZE - crypto_secretbox_MACBYTES;
	const route_node_info *node;
	unsigned char last_byte;
	int is_innermost = 1;

	write_binary(&p, connection->user_id, sizeof connection->user_id);
	write_uint16(&p, connection->connection_id);
	write_uint64(&p, connection->next_sequence_id);

	write_data_section(p, end_ptr, acks, ack_count, data);

	for(int i = ROUTE_NODES_MAX - 1; i >= 0; i--) {
		layer -= OUTGOING_HEADER_LEN;
		p = layer;
		node = &route->nodes[i];

		write_binary(&p, node->ephemeral_public_key, sizeof node->ephemeral_public_key);

		/* If lowest bit is equal to symmetric_key's lowest bit, then this is the last node in the route.
		   If the 2nd lowest bit is equal to symmetric_key's 2nd lowest bit, then the direction is outgoing.
		   Yes, this reveals 2 bits of the 256-bit key. */
		last_byte = node->symmetric_key[(sizeof node->symmetric_key) - 1];
		write_byte(&p, (last_byte ^ (i < ROUTE_NODES_MAX - 1)) & 3);

		encrypted_start = p;
		
		if(!is_innermost)
			write_uint64(&p, route->nodes[i + 1].node->id);

		if(is_innermost) {
			if(crypto_secretbox_easy(encrypted_start, encrypted_start, end_ptr - encrypted_start, data_nonce, node->symmetric_key))
				return 1;
			end_ptr += crypto_secretbox_MACBYTES;
			is_innermost = 0;
			assert(end_ptr - p == PACKET_SIZE);
		} else {
			if(crypto_stream_xor(encrypted_start, encrypted_start, end_ptr - encrypted_start, data_nonce, node->symmetric_key))
				return 2;
		}
	}

	return 0;
}


int create_route_list_data(unsigned char *data, uint32_t total_route_count, uint64_t start_sequence_id, const route_info *routes, unsigned char route_count) {
	assert(data);
	assert(routes);

	return 0;
}


int create_incoming_packet(unsigned char *packet, uint64_t *dest_node_id, const unsigned char *route, const ack_info *acks, uint16_t ack_count, const data_info *data) {
	assert(packet);
	assert(dest_node_id);
	assert(route);
	assert(acks);
	assert(data);
	assert(sizeof *dest_node_id == sizeof(uint64_t));

	unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
	unsigned char *encrypted_start;
	unsigned char *end_ptr = packet + PACKET_SIZE - crypto_secretbox_MACBYTES;

	route += sizeof(uint32_t);	/* skip past route_id */
	read_binary(symmetric_key, &route, sizeof symmetric_key);
	*dest_node_id = read_uint64(&route);

	write_binary(&packet, route, INCOMING_ROUTE_LEN);

	encrypted_start = packet;

	memset(packet, 0, 16);	/* write id */
	packet += 16;
	write_data_section(packet, end_ptr, acks, ack_count, data);

	if(crypto_secretbox_easy(encrypted_start, encrypted_start, end_ptr - encrypted_start, data_nonce, symmetric_key))
		return 1;

	return 0;
}


int process_layer(header_info *header, unsigned char *output_layer, const unsigned char *layer, const unsigned char *node_public_key, const unsigned char *node_private_key) {
	assert(header);
	assert(output_layer);
	assert(layer);
	assert(node_public_key);
	assert(node_private_key);
	assert(sizeof header->dest_node_id == sizeof(uint64_t));

	unsigned char ephemeral_public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
	unsigned char last_byte;
	unsigned char *out_p = output_layer;
	const unsigned char *client_id_ptr;
	const unsigned char *original_output_layer = output_layer;
	const unsigned char *p = layer;
	const unsigned char *id_ptr = layer + INCOMING_ROUTE_LEN;
	const unsigned char *end_ptr = layer + PACKET_SIZE;
	size_t padding_len = OUTGOING_HEADER_LEN;
	size_t node_id_len = sizeof header->dest_node_id;
	size_t innermost_len = PACKET_SIZE - (ROUTE_NODES_MAX * OUTGOING_HEADER_LEN - node_id_len);
	int has_next_node;

	read_binary(ephemeral_public_key, &p, sizeof ephemeral_public_key);
	last_byte = read_byte(&p);
	
	if(last_byte & ~3)	/* this was not a packet generated by this program if the top bits aren't 0 */
		return 1;

	last_byte ^= symmetric_key[sizeof symmetric_key - 1] & 3; 
	header->is_incoming = (last_byte & 2) != 0;
	has_next_node = last_byte & 1;

	if(generate_symmetric_key(symmetric_key, node_public_key, node_private_key, ephemeral_public_key, 0))
		return 2;


	if(header->is_incoming) {
		if(crypto_stream_xor(out_p, p, id_ptr - p, route_nonce, symmetric_key))
			return 3;
		
		out_p += id_ptr - p;

		if(has_next_node) {
			output_layer += node_id_len;
			assert((output_layer[sizeof ephemeral_public_key] & ~3) == 0);

			if(crypto_stream(out_p, padding_len, padding_nonce, symmetric_key))
				return 4;
		} else { /* last node in route */
			client_id_ptr = original_output_layer;
			read_binary(header->dest_client_id, &client_id_ptr, sizeof header->dest_client_id);

#if DEBUG
			write_uint64(&output_layer, 0);	/* there's no dest_node_id */
#else
			output_layer += node_id_len;
#endif
			memset(out_p, 0, padding_len);	/* make the padding deterministic */

			if(crypto_stream_xor(output_layer, output_layer, INCOMING_ROUTE_LEN, padding_nonce, symmetric_key))
				return 5;

			output_layer[sizeof ephemeral_public_key] &= 3;	/* make this look like all other packets */
		}

		assert(original_output_layer + node_id_len == output_layer);
		output_layer += INCOMING_ROUTE_LEN;
		assert(out_p + padding_len == output_layer);

		if(crypto_stream_xor(output_layer, id_ptr, end_ptr - id_ptr, data_nonce, symmetric_key))
			return 6;
	} else { /* outgoing */
		if(has_next_node) {	
			if(crypto_stream_xor(output_layer, p, end_ptr - p, data_nonce, symmetric_key))
				return 7;
			assert((output_layer[node_id_len + sizeof ephemeral_public_key] & ~3) == 0);

		} else { /* last node in route */
#if DEBUG
			write_uint64(&output_layer, 0);	/* there's no dest_node_id */
#else
			output_layer += node_id_len;
#endif
			if(crypto_secretbox_open_easy(output_layer, p, innermost_len, data_nonce, symmetric_key))
				return 8;
		}
	}

	if(has_next_node)
		header->dest_node_id = read_uint64(&original_output_layer);
	else
		header->dest_node_id = 0;

	return 0;
}


int decrypt_incoming_packet(unsigned char *packet, const unsigned char *symmetric_keys) {
	assert(packet);
	assert(symmetric_keys);

	unsigned char *end_ptr = packet + PACKET_SIZE;

	if(packet[crypto_box_PUBLICKEYBYTES] & ~3)
		return 1;

	packet += INCOMING_ROUTE_LEN;

	for(size_t i = 0; i < ROUTE_NODES_MAX - 1; i++) {
		if(crypto_stream_xor(packet, packet, end_ptr - packet, data_nonce, symmetric_keys))
			return 2;
		symmetric_keys += crypto_stream_KEYBYTES;
	}

	if(crypto_secretbox_easy(packet, packet, end_ptr - packet, data_nonce, symmetric_keys))
		return 3;

	return 0;
}


int generate_route(route_info *route, uint32_t route_id, const node_info *exit_node, const node_info *available_nodes, size_t node_count, int is_incoming) {
	assert(route);
	assert(exit_node);
	assert(available_nodes);
	assert(node_count >= ROUTE_NODES_MAX);

	size_t i = 0;
	size_t nodeIndexes[ROUTE_NODES_MAX] = {SIZE_MAX};
	unsigned char ephemeral_private_key[crypto_box_SECRETKEYBYTES];
	route_node_info *route_node;
	const node_info *node;

	route->id = route_id;

	while(i < ROUTE_NODES_MAX) {
		if((is_incoming && i == 0) || (!is_incoming && i == ROUTE_NODES_MAX - 1)) {
			node = exit_node;
		} else {
			nodeIndexes[i] = randombytes_uniform(node_count);
			node = &available_nodes[nodeIndexes[i]];

			if(node->id == exit_node->id || in_array(nodeIndexes, nodeIndexes[i], i))
				continue;
		}

		route_node = &route->nodes[i];

		if(i == 0 && is_incoming) {
#if DEBUG
			memset(route_node->ephemeral_public_key, 0, sizeof route_node->ephemeral_public_key);
#endif
			randombytes_buf(route_node->symmetric_key, sizeof route_node->symmetric_key);
		} else {
			randombytes_buf(ephemeral_private_key, sizeof ephemeral_private_key);

			if(crypto_scalarmult_base(route_node->ephemeral_public_key, ephemeral_private_key))
				return 1;

			if(generate_symmetric_key(route_node->symmetric_key, node->public_key, 0, route_node->ephemeral_public_key, ephemeral_private_key))
				return 2;
		}

		route_node->node = node;		
		i++;
	}
	
	return 0;
}


int encrypt_route(unsigned char *encrypted_route, const route_info *route, const unsigned char *client_id) {
	assert(encrypted_route);
	assert(route);
	assert(client_id);
	assert(sizeof route->id == sizeof(uint32_t));
	assert(sizeof route->nodes[0].node->id == sizeof(uint64_t));

	unsigned char *p = encrypted_route;
	const unsigned char *end_ptr;
	unsigned char last_byte;
	const route_node_info *route_node = &route->nodes[0];

	write_uint32(&p, route->id);
	write_binary(&p, route_node->symmetric_key, sizeof route_node->symmetric_key);
	end_ptr = p + 8 + INCOMING_ROUTE_LEN;

	for(size_t n = 1; n < ROUTE_NODES_MAX; n++) {
		route_node = &route->nodes[n];
		write_uint64(&p, route_node->node->id);
		write_binary(&p, route_node->ephemeral_public_key, sizeof route_node->ephemeral_public_key);

		last_byte = route_node->symmetric_key[(sizeof route_node->symmetric_key) - 1];
		write_byte(&p, (last_byte ^ (n < ROUTE_NODES_MAX - 1) ^ 2) & 3);
	}

	write_binary(&p, client_id, 16);
	assert(p == end_ptr);

	p -= 16;

	for(size_t i = ROUTE_NODES_MAX - 1; i > 0; i--) {
		if(crypto_stream_xor(p, p, end_ptr - p, route_nonce, route->nodes[i].symmetric_key))
			return 1;
		p -= OUTGOING_HEADER_LEN;
	}

	assert(encrypted_route + sizeof route->id + sizeof route_node->symmetric_key == p);
	return 0;
}


int generate_symmetric_key(unsigned char *symmetric_key, const unsigned char *node_public_key, const unsigned char *node_private_key, const unsigned char *ephemeral_public_key, const unsigned char *ephemeral_private_key) {
	assert(symmetric_key);
	assert(ephemeral_public_key);
	assert(node_private_key || ephemeral_private_key);
	assert(!node_private_key || !ephemeral_private_key);

	crypto_generichash_state h;
	unsigned char q[crypto_scalarmult_BYTES];
	const unsigned char *private_key = node_private_key;
	const unsigned char *public_key = ephemeral_public_key;

	if(!node_private_key) {
		assert(node_public_key);
		private_key = ephemeral_private_key;
		public_key = node_public_key;
	}

	assert(public_key);
	assert(private_key);

	if(crypto_scalarmult(q, private_key, public_key))
		return 1;

	if(crypto_generichash_init(&h, 0, 0, crypto_generichash_BYTES) ||	// TODO: encrypt 64 bytes for two symmetric keys?
		crypto_generichash_update(&h, q, sizeof q) ||
		crypto_generichash_update(&h, ephemeral_public_key, crypto_box_PUBLICKEYBYTES) ||
		crypto_generichash_final(&h, symmetric_key, crypto_secretbox_KEYBYTES))
		return 2;

	return 0;
}

