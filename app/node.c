#include "../packet.h"
#include "../data.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sodium.h>

#define NODE_COUNT_MAX 100
#define DEFAULT_PORT 28833

#if crypto_box_SECRETKEYBYTES != 32
#error "Expected crypto_box_SECRETKEYBYTES to be 32"
#endif

/* TODO: store sensitive data on non-swappable pages and sodium_memzero memory */

node_info nodes[NODE_COUNT_MAX];
size_t node_count;

uint64_t node_id;
uint16_t port;
unsigned char private_key[crypto_box_SECRETKEYBYTES];
unsigned char public_key[crypto_box_PUBLICKEYBYTES];



int read_nodes_file(void);
int parse_node_line(node_info *node, char *line);
int read_private_key_file(int argc, char **argv);
int write_private_key_file(const char *filename);
int help_arg(const char *arg);



int main(int argc, char **argv) {
	int error;

	if(sodium_init() == -1)
		return 1;

	if((error = read_nodes_file()))
		return error;

	if((error = read_private_key_file(argc, argv)))
		return error;


	return 0;
}


/* id hostname:port public_key_hex */
int read_nodes_file(void) {
	char line[400];
	FILE* fp;
	int error = 0;

	fp = fopen("nodes.txt", "r");

	if(!fp) {
		fputs("Unable to open nodes.txt. Please obtain a copy of nodes.txt.\n", stderr);
		return 2;
	}

	while(node_count < NODE_COUNT_MAX && fgets(line, sizeof line, fp)) {
puts("nodes.txt line");
		if((error = parse_node_line(&nodes[node_count], line))) {
			fprintf(stderr, "Error while reading line %lu of nodes.txt\n", node_count + 1);
			return error;
		}
		
		node_count++;
	}

puts("nodes.txt done");
	fclose(fp);
	return 0;
}


int parse_node_line(node_info *node, char *line) {
	int error;
	char *p;
	char *colon;
	unsigned long port_value;
	size_t public_key_len;

	node->id = strtoull(line, &p, 10);

	if(node->id == 0 || node->id >= (uint64_t)-1 || *p != ' ')
		return 8;

	p++;
	colon = strchr(p, ':');

	if(!colon || colon - p >= (int)sizeof node->domain_name)
		return 9;

	*colon = '\0';
	strcpy(node->domain_name, p);
	line = colon + 1;

	port_value = strtoul(line, &p, 10);

	if(port_value == 0 || port_value > 65535 || *p != ' ') 
		return 10;

	node->port = (uint16_t)port;
	p++;
		
	error = sodium_hex2bin(node->public_key, sizeof node->public_key, p, strlen(p), NULL, &public_key_len, NULL);

	if(error || public_key_len != crypto_box_PUBLICKEYBYTES)
		return 11;

	return 0;
}


int read_private_key_file(int argc, char **argv) {
	int values_read;
	int error = 0;
	FILE* fp;
	char private_key_hex[crypto_box_SECRETKEYBYTES * 2 + 1];
	size_t private_key_len = 0;
	const char *filename = "private.settings";

	if(argc > 2 || (argc == 2 && help_arg(argv[1]))) {
		if(argc > 2)
			fprintf(stderr, "Too many arguments to %s\n", argv[0]);
		fprintf(stderr, "\nUsage: %s [settings filename]\n\n", argv[0]);
		fprintf(stderr, "If you do not provide a settings filename, \"%s\" will be used.\n", filename);
		fprintf(stderr, "If the settings file does not exist, you will be prompted to generate one.\n\n");
		return 3;
	}

	if(argc > 1)
		filename = argv[1];

	fp = fopen(filename, "r");

	if(!fp)
		return write_private_key_file(filename);
	

	values_read = fscanf(fp, "%lu %hu %64s", &node_id, &port, private_key_hex);
	fclose(fp);

	if(values_read == 3) {
		error = sodium_hex2bin(private_key, sizeof private_key, private_key_hex, sizeof private_key_hex - 1, NULL, &private_key_len, NULL);
	}

	if(values_read != 3 || node_id == 0 || port == 0 || error || private_key_len != crypto_box_SECRETKEYBYTES) {
		fprintf(stderr, "Error parsing \"%s\". Please delete this file and then rerun this program to regenerate the file.\n", filename);
		return 7;
	}
	
	return 0;
}


int write_private_key_file(const char *filename) {
	FILE *fp;
	unsigned long port_value;
	char *end_ptr;
	char line[100] = "";
	char domain_name[257] = "";
	char node_entry[400];
	char private_key_hex[crypto_box_SECRETKEYBYTES * 2 + 1];
	char public_key_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];


	printf("The settings file \"%s\" does not exist. Create it? Y/n: ", filename);
	
	while(fgets(line, sizeof line, stdin) && line[0] && !strchr("YyNn\n", line[0]))
		printf("Please enter either y or n: ");

	if(!strchr("Yy\n", line[0])) {
		fprintf(stderr, "You must have a valid settings file to run this program.\n");
		return 4;
	}
	
	fp = fopen(filename, "w");

	if(!fp) {
		fprintf(stderr, "Unable to create settings file.\n");
		return 5;
	}



	printf("Which UDP port will this node listen on (default: %d)?: ", DEFAULT_PORT);

	while(fgets(line, sizeof line, stdin) && line[0] && line[0] != '\n') {
		port_value = strtoul(line, &end_ptr, 10);

		if(port_value > 0 && port_value <= 65535 && (*end_ptr == ' ' || *end_ptr == '\n')) {
			port = (uint16_t)port_value;
			break;
		}
		
		printf("Please enter a number between 1 and 65535: ");
	}

	if(port == 0)
		port = DEFAULT_PORT;


	printf("What public IP or domain name will users or other nodes use connect to you?:\n");
	
	/* TODO: validate IP address or look up domain name */
	while(fgets(domain_name, sizeof domain_name, stdin) && domain_name[0] == '\n')
		printf("Please enter your public IP address or your domain name:\n");

	if((end_ptr = strchr(domain_name, '\n')))
		*end_ptr = '\0';


	randombytes_buf(&node_id, sizeof node_id);
	crypto_box_keypair(public_key, private_key);

	sodium_bin2hex(public_key_hex, sizeof public_key_hex, public_key, sizeof public_key);
	sodium_bin2hex(private_key_hex, sizeof private_key_hex, private_key, sizeof private_key);


	if(fprintf(fp, "%lu\n%d\n%s", node_id, port, private_key_hex) <= 0) {
		fprintf(stderr, "An error occurred while attempting to write to settings file.\n");
		fclose(fp);
		return 6;
	}

	fclose(fp);



	printf("Node settings and private key written to \"%s\".\n\n", filename);
	printf("The below should be provided to the maintainer of the master nodes.txt file:\n");

	sprintf(node_entry, "%lu %s:%d %s\n", node_id, domain_name, port, public_key_hex);
	puts(node_entry);

	printf("Do you wish to add this information to your local copy of nodes.txt? Y/n: \n");

	while(fgets(line, sizeof line, stdin) && line[0] && !strchr("YyNn\n", line[0]))
		printf("Please enter either y or n: ");

	if(!strchr("Yy\n", line[0]))
		return 0;
	


	fp = fopen("nodes.txt", "a");

	if(!fp || fputs(node_entry, fp) == EOF)
		fprintf(stderr, "Unable to write to nodes.txt.\n");

	fclose(fp);
	return 0;
}


int help_arg(const char *arg) {
	const char *args[] = {"h", "help", "?", NULL};

	if(arg[0] == '-' || arg[0] == '/')
		arg++;

	for(size_t i = 0; args[i]; i++)
		if(strcasecmp(arg, args[i]) == 0)
			return 1;

	return 0;
}
