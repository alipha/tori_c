#ifndef TORI_DATA_H
#define TORI_DATA_H

#include "packet.h"


typedef enum status_type {
	CLOSE_STATUS = 0,
	DNS_ERROR_STATUS = 1,
	REFUSED_ERROR_STATUS = 2
} status_type;


/* data->content must point to a valid buffer to fill */
int create_route_list_data(data_info *data, const route_list_info *route_list, const unsigned char *entry_client_id);

/* route_list will contain pointers into data->content */
int read_route_list_data(return_route_list_info *route_list, const data_info *data);


#endif
