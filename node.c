#include "packet.h"
#include "data.h"
#include <stdio.h>

#define NODE_COUNT_MAX 100


node_info nodes[NODE_COUNT_MAX];
size_t node_count;

unsigned char private_key[crypto_box_SECRETKEYBYTES];


int read_nodes_file(void);
int read_private_key_file(void);


int main(void) {
	int error;

	if((error = read_nodes_file()))
		return error;

	if((error = read_private_key_file()))
		return error;


	return 0;
}


int read_nodes_file(void) {
	char line[400];
	FILE* fp;

	fp = fopen("nodes.txt", "r");

	if(!fp) {
		fputs("Unable to open nodes.txt\n", stderr);
		return 1;
	}

	while(node_count < NODE_COUNT_MAX && fgets(line, sizeof line, fp)) {
	}

	return 0;
}


int read_private_key_file(void) {
	FILE* fp;

	fp = fopen("private.key", "r");


}


