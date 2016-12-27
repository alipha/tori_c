#include "pack.h"
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>


void read_binary(void *dest, const unsigned char **src, size_t amount) {
	assert(dest);
	assert(src);
	assert(*src);

	memcpy(dest, *src, amount);
	*src += amount;
}

unsigned char read_byte(const unsigned char **src) {
	assert(src);
	assert(*src);

	unsigned char value = **src;
	(*src)++;
	return value;
}

uint16_t read_uint16(const unsigned char **src) {
	assert(src);
	assert(*src);

	uint16_t value = ntohs(*(const uint16_t*)*src);
	*src += sizeof value;
	return value;
}

uint32_t read_uint32(const unsigned char **src) {
	assert(src);
	assert(*src);

	uint32_t value = ntohl(*(const uint32_t*)*src);
	*src += sizeof value;
	return value;
}

uint64_t read_uint64(const unsigned char **src) {
	assert(src);
	assert(*src);

	uint64_t upper = ntohl(*(const uint32_t*)*src);
	*src += 4;
	uint32_t lower = ntohl(*(const uint32_t*)*src);
	*src += 4;

	return (upper << 32) | lower;
}


void write_binary(unsigned char **dest, const void *src, size_t amount) {
	assert(dest);
	assert(*dest);
	assert(src);

	memcpy(*dest, src, amount);
	*dest += amount;
}

void write_byte(unsigned char **dest, unsigned char value) {
	assert(dest);
	assert(*dest);

	**dest = value;
	(*dest)++;
}

void write_uint16(unsigned char **dest, uint16_t value) {
	assert(dest);
	assert(*dest);
	
	*(uint16_t*)*dest = htons(value);
	*dest += sizeof value;
}

void write_uint32(unsigned char **dest, uint32_t value) {
	assert(dest);
	assert(*dest);

	*(uint32_t*)*dest = htonl(value);
	*dest += sizeof value;
}

void write_uint64(unsigned char **dest, uint64_t value) {
	assert(dest);
	assert(*dest);

    *(uint32_t*)*dest = htonl(value >> 32);
	*dest += 4;
	*(uint32_t*)*dest = htonl(value & 0xffffffff);
	*dest += 4;
}


void xor_bytes(unsigned char *dest, const unsigned char *src, size_t amount) {
	assert(dest);
	assert(src);

	for(size_t i = 0; i < amount; i++)
		dest[i] ^= src[i];
}

