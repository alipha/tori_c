#include "pack.h"
#include <string.h>
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

	uint16_t upper = read_byte(src) << 8;
	return upper | read_byte(src);
}

uint32_t read_uint32(const unsigned char **src) {
	assert(src);
	assert(*src);

	uint32_t upper = (uint32_t)read_uint16(src) << 16;
	return upper | read_uint16(src);
}

uint64_t read_uint64(const unsigned char **src) {
	assert(src);
	assert(*src);

	uint64_t upper = (uint64_t)read_uint32(src) << 32;
	return upper | read_uint32(src);
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
	
	write_byte(dest, value >> 8);
	write_byte(dest, value & 0xff);
}

void write_uint32(unsigned char **dest, uint32_t value) {
	assert(dest);
	assert(*dest);

	write_uint16(dest, value >> 16);
	write_uint16(dest, value & 0xffff);
}

void write_uint64(unsigned char **dest, uint64_t value) {
	assert(dest);
	assert(*dest);

	write_uint32(dest, value >> 32);
	write_uint32(dest, value & 0xffffffff);
}


void xor_bytes(unsigned char *dest, const unsigned char *src, size_t amount) {
	assert(dest);
	assert(src);

	for(size_t i = 0; i < amount; i++)
		dest[i] ^= src[i];
}

