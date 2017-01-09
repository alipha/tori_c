#include "data.h"
#include "pack.h"
#include <assert.h>


int create_route_list_data(data_info *data, const route_list_info *route_list, const unsigned char *entry_client_id) {
	assert(data);
	assert(data->content);
	assert(route_list);
	assert(route_list->routes);
	assert(route_list->count > 0 && route_list->count <= ROUTES_PER_PACKET);
	assert(entry_client_id);

	unsigned char *p = data->content;
	size_t route_count = route_list->count;
	const route_info *routes = route_list->routes;
	
	for(size_t i = 0; i < route_count; i++) {
		if(encrypt_route(p, &routes[i], entry_client_id))
			return 1;
		p += ROUTE_SIZE;
	}

	data->type = ROUTE_LIST_DATA;
	data->length = p - data->content;
	return 0;
}


int read_route_list_data(return_route_list_info *route_list, const data_info *data) {
	assert(route_list);
	assert(data);
	assert(data->content);
	assert(data->length <= OUTGOING_DATA_MAX);
	assert(sizeof route_list->routes[0].id == sizeof(uint64_t));
	assert(sizeof route_list->routes[0].dest_node_id == sizeof(uint64_t));

	const unsigned char *p = data->content;
#ifndef NDEBUG
	const unsigned char *end_ptr = p + data->length;
#endif
	size_t route_count = data->length / ROUTE_SIZE;
	return_route_info *route;

	if(route_count == 0)
		return 1;

	route_list->count = route_count;

	if(route_count * ROUTE_SIZE != data->length)
		return 2;

	for(size_t i = 0; i < route_count; i++) {
		route = &route_list->routes[i];
		route->id = read_uint64(&p);
		route->dest_node_id = read_uint64(&p);
		route->data = p;
		p += INCOMING_ROUTE_LEN;
	}

	assert(p == end_ptr);
	return 0;
}



