#ifndef TORI_PACK_H
#define TORI_PACK_H

#include <stddef.h>
#include <stdint.h>


void read_binary(void *dest, const unsigned char **src, size_t amount);
unsigned char read_byte(const unsigned char **src);
uint16_t read_uint16(const unsigned char **src);
uint32_t read_uint32(const unsigned char **src);
uint64_t read_uint64(const unsigned char **src);

void write_binary(unsigned char **dest, const void *src, size_t amount);
void write_byte(unsigned char **dest, unsigned char value);
void write_uint16(unsigned char **dest, uint16_t value);
void write_uint32(unsigned char **dest, uint32_t value);
void write_uint64(unsigned char **dest, uint64_t value);

void xor_bytes(unsigned char *dest, const unsigned char *src, size_t amount);


#endif
