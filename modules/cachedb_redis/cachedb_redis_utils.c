/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2011-09-xx  created (vlad-paiu)
 */

#include "../../dprint.h"
#include "cachedb_redis_dbase.h"
#include "cachedb_redis_utils.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../cachedb/cachedb.h"

#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>
#define is_valid(p,end) ((p) && (p)<(end))

static const uint16_t crc16tab[256]= {
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
    0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
    0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
    0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
    0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
    0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
    0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
    0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
    0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
    0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
    0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
    0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
    0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
    0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
    0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
    0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
    0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
    0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
    0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
    0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
    0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
    0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
    0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
    0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
    0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
    0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
    0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
    0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
    0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
    0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
    0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

uint16_t crc16(const char *buf, int len)
{
    int counter;
    uint16_t crc = 0;
    for (counter = 0; counter < len; counter++)
            crc = (crc<<8) ^ crc16tab[((crc>>8) ^ *buf++)&0x00FF];
    return crc;
}

unsigned int redisHash(redis_con *con, str* key)
{
	return crc16(key->s,key->len) & con->slots_assigned;
}

cluster_node *get_redis_connection(redis_con *con,str *key)
{
	unsigned short hash_slot;
	cluster_node *it;

	if (con->flags & REDIS_SINGLE_INSTANCE) {
		LM_DBG("Single redis connection, returning %p\n",con->nodes);
		return con->nodes;
	} else {
		hash_slot = redisHash(con, key);
		for (it=con->nodes;it;it=it->next) {

			if (it->start_slot <= hash_slot && it->end_slot >= hash_slot) {
				LM_DBG("Redis cluster connection, matched con %p for slot %u \n",it,hash_slot);
				return it;
			}
		}
		return NULL;
	}
}

cluster_node *get_redis_connection_by_endpoint(redis_con *con, redis_moved *redis_info)
{
	cluster_node *it;

	if (con->flags & REDIS_SINGLE_INSTANCE) {
		LM_DBG("Single redis connection, returning %p\n",con->nodes);
		return con->nodes;
	} else {
		for (it=con->nodes;it;it=it->next) {
			if (match_prefix(redis_info->endpoint.s, redis_info->endpoint.len, it->ip, strlen(it->ip))) {
				if (it->port == redis_info->port) {
					// Removed slot comparison as it may be a little too aggressive of a match
					// Code is still here in the event that it needs to be added back in
					//if (it->start_slot <= redis_info->slot && it->end_slot >= redis_info->slot) {
						LM_DBG("Redis cluster connection, matched con %p for endpoint: %.*s:%d slot: [%u] %u [%u] \n", it, redis_info->endpoint.len, redis_info->endpoint.s, redis_info->port, it->start_slot, redis_info->slot, it->end_slot);
						return it;
					//}
				}
			}
		}
		LM_ERR("Redis cluster connection, No match found for endpoint: %.*s:%d slot %u\n", redis_info->endpoint.len, redis_info->endpoint.s, redis_info->port, redis_info->slot);
		return NULL;
	}
}

void destroy_cluster_nodes(redis_con *con)
{
	cluster_node *new,*foo;

	LM_DBG("destroying cluster %p\n",con);

	new = con->nodes;
	while (new) {
		foo = new->next;
		redisFree(new->context);
		new->context = NULL;
		if (use_tls && new->tls_dom)
			tls_api.release_domain(new->tls_dom);
		pkg_free(new);
		new = foo;
	}
}

struct datavalues {
	int count;
	char **redisdata;
};

int chkmalloc1 (char *handle) {
	if ( handle == NULL || handle == 0) {
		LM_ERR("Error1 while parsing cluster redisdata \n");
		return -1;
	}
		return 1;
}
int chkmalloc2 (struct datavalues *handle) {
	if ( handle == NULL || handle == 0) {
		LM_ERR("Error2 while parsing cluster redisdata \n");
		return -1;
	}
		return 1;
}

int chkmalloc3 (struct datavalues **handle) {
	if ( handle == NULL || handle == 0) {
		LM_ERR("Error3 while parsing cluster redisdata \n");
		return -1;
	}
		return 1;
}

int chkmalloc4 (char **handle) {
	if ( handle == NULL || handle == 0) {
		LM_ERR("Error4 while parsing cluster redisdata \n");
		return -1;
	}
		return 1;
}

int explode(char *line, const char *delimeters, struct datavalues **newret) {

	int counter		= 0;
	char *result 	= NULL;
	char *data 		= NULL;

	data = pkg_malloc((strlen(line) * sizeof(char)) +1);
	if (!chkmalloc1(data)) return 0;
	strcpy(data,line);

	result = strtok(data, delimeters);
	while (result != NULL ) {
		newret[0]->redisdata[counter] = pkg_malloc((strlen(result) * sizeof(char) ) +1 );
		if (chkmalloc1(newret[0]->redisdata[counter])) {
			strcpy(newret[0]->redisdata[counter],result);
			counter++;
			result = strtok(NULL, delimeters);
		} else { return 0; }
	}
	newret[0]->count = counter-1;

	pkg_free(data);

	return 1;

}

int build_cluster_nodes(redis_con *con,char *info,int size)
{

	cluster_node *new;
	const char *delimeters = "\n";
	int i		= 0, 	j	= 0;
	int masters = 1, count	= 0;
	char *ip, *block = NULL;
	unsigned short port,start_slot,end_slot;
	int len;
	struct datavalues **newret1, **newret2, **newret3;

	// Define **pointers for new structures 
	newret1 = pkg_malloc(sizeof(struct datavalues *));
	if (!chkmalloc3(newret1)) goto error;
	newret2 = pkg_malloc(sizeof(struct datavalues *));
	if (!chkmalloc3(newret2)) goto error;
	newret3 = pkg_malloc(sizeof(struct datavalues *));
	if (!chkmalloc3(newret3)) goto error;

	// Allocate space for the structures
	newret1[0] = pkg_malloc(sizeof(struct datavalues));
	if (!chkmalloc2(newret1[0])) goto error;
	newret2[0] = pkg_malloc(sizeof(struct datavalues));
	if (!chkmalloc2(newret2[0])) goto error;
	newret3[0] = pkg_malloc(sizeof(struct datavalues));
	if (!chkmalloc2(newret3[0])) goto error;

	// Allocate space for data item "redisdata" within the structures
	newret1[0]->redisdata = pkg_malloc((strlen(info) * sizeof(char)) +1);
	if (!chkmalloc4(newret1[0]->redisdata)) goto error;
	newret2[0]->redisdata = pkg_malloc((strlen(info) * sizeof(char)) +1);
	if (!chkmalloc4(newret2[0]->redisdata)) goto error;
	newret3[0]->redisdata = pkg_malloc((strlen(info) * sizeof(char)) +1);
	if (!chkmalloc4(newret3[0]->redisdata)) goto error;

	// Initialise the counter
	newret1[0]->count = 0;
	newret2[0]->count = 0;
	newret3[0]->count = 0;


	// Redis really only requires two connections ("myself,master" && one other master) || (at least two masters)
	// but this will supply info for upto 1000 masters due to current Opensips design (hopefully representing the total hash slots)
	// will always connect to myself,master
	strstr(info,"myself,master")?(count = 999):(count = 1000);

	// Cluster data into Array
	if (explode(info,delimeters,newret1)) {
		for (i=0;i<=newret1[0]->count;i++) {
			LM_DBG("Nodes : %s\n",newret1[0]->redisdata[i]);

			if ((strstr(newret1[0]->redisdata[i],"master") && (masters <= count)) || strstr(newret1[0]->redisdata[i],"myself,master")) {

				start_slot = end_slot = port = 0;
				ip = NULL;
				masters++;

				// Break up the row 
				if (explode(newret1[0]->redisdata[i]," ",newret2)) {
					for (j=0 ; j <= newret2[0]->count ; j++ ) {

						if (strstr(newret1[0]->redisdata[i],"myself") && strstr(newret2[0]->redisdata[j],"myself")) {
							//myself no ip
							if (ip == NULL) {
								ip = con->id->host;
								port = con->id->port;
								LM_DBG("Myself and no IP, set ip to main host %s\n",con->id->host);
								if (i==0) masters--;
							} else
								LM_DBG("Master already discovered to not be myself, not going to main host \n");

						} else {
							//Get the ip and port of other master
							if (strstr(newret2[0]->redisdata[j],":") && (strlen(newret2[0]->redisdata[j]) > 5)) {

								if (explode(newret2[0]->redisdata[j],":",newret3)) {
									ip = (char *)newret3[0]->redisdata[0];
									port = atoi(newret3[0]->redisdata[1]);
								} else { block = ":parsing ip/port"; goto error;}
							}
						}
						//Get slots
						if (strstr(newret2[0]->redisdata[j],"-") && (strlen(newret2[0]->redisdata[j]) > 2)) {
							if (explode(newret2[0]->redisdata[j],"-",newret3)) {
								start_slot = atoi(newret3[0]->redisdata[0]);
								end_slot   = atoi(newret3[0]->redisdata[1]);
							} else {block = ":parsing slots"; goto error;}

						}
					}

				} else { block = "row to array"; goto error;}

				if ( ip == NULL || !(port > 0) || (start_slot > end_slot) || !(end_slot > 0) ) {block = ":processing row"; goto error;}

				len = strlen(ip);
				new = pkg_malloc(sizeof(cluster_node) + len + 1);
				if (!new) {
					LM_ERR("no more pkg\n");
					goto error;
				}

				memset(new,0,sizeof(cluster_node) + len + 1);

				new->ip = (char *)(new + 1);
				strcpy(new->ip,ip);
				new->port = port;
				new->start_slot = start_slot;
				new->end_slot = end_slot;

				LM_DBG("Saving connection %p for ip %s port %hu start %hu end %hu\n",new,ip,port,start_slot,end_slot);

				if (con->nodes == NULL)
					con->nodes = new;
				else {
					new->next = con->nodes;
					con->nodes = new;
				}
			}
		}

	} else { block = ":initial"; goto error;}

	pkg_free(newret1);
	pkg_free(newret2);
	pkg_free(newret3);

	return 0;

error:
	LM_ERR("Error while parsing cluster nodes in %s\n",block);
	destroy_cluster_nodes(con);
	return -1;
}

/*
 When Redis is operating as a cluster, it is possible (very likely)
 that a MOVED redirection will be returned by the Redis nodes that
 received the request. The general format of the reply from Redis is:
 MOVED slot [IP|FQDN]:port

 This routine will parse the Redis MOVED reply into its components.
 Note that the redisReply struct MUST be released outside of this routine
 to avoid a memory leak. The out->endpoint pointer must not be used after
 the redisReply has been released.

 The parsed data is stored into the following redis_moved struct:
 
 typedef struct {
	int slot;
	const_str endpoint;
	int port;
 } redis_moved;

*/
int parse_moved_reply(redisReply *reply, redis_moved *out) {
	int i;
	int slot = 0;
	const char *p;
	const char *end;
	const char *host_start;
	const char *colon = NULL;
	const char *port_start;
	int port = REDIS_DF_PORT; // Default to Redis standard port

	if (!reply || !reply->str || reply->len < MOVED_PREFIX_LEN || !out)
		return ERR_INVALID_REPLY;

	p = reply->str;
	end = reply->str + reply->len;

	for (i = 0; i < MOVED_PREFIX_LEN; ++i) {
		if (p[i] != MOVED_PREFIX[i]) {
		return ERR_INVALID_REPLY;
		}
	}
	p += MOVED_PREFIX_LEN;

	// Parse slot number
	while (p < end && *p >= '0' && *p <= '9') {
		slot = slot * 10 + (*p - '0');
		p++;
	}
	if (slot == 0 && (p == reply->str + MOVED_PREFIX_LEN || *(p - 1) < '0' || *(p - 1) > '9'))
		return ERR_INVALID_SLOT;

	// Skip spaces
	while (p < end && *p == ' ') p++;

	// Parse host and port
	host_start = p;
	while (p < end) {
		if (*p == ':') {
			colon = p;
			break;
		}
		p++;
	}

	out->endpoint.s = NULL;
	out->endpoint.len = 0;

	if (colon) {
		out->endpoint.s = host_start;
		out->endpoint.len = colon - host_start;

		// Parse port
		port_start = colon + 1;
		p = port_start;
		if (p < end) {
			port = 0;
			while (p < end && *p >= '0' && *p <= '9') {
				port = port * 10 + (*p - '0');
				p++;
			}
			if (port < 0 || port > 65535 || port_start == p)
				return ERR_INVALID_PORT;
		}
	} else if (out->endpoint.s < end) {
		out->endpoint.s = host_start;
		out->endpoint.len = end - host_start;
	}

	// Fill output
	out->slot = slot;
	out->port = port;

	return 0;
}
