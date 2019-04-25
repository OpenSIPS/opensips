/*
 * Hash table functions header file
 *
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef PERM_HASH_H
#define PERM_HASH_H


#include <sys/types.h>
#include "../../ip_addr.h"
#include "../../str.h"
#include "../../mi/mi.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../usr_avp.h"
#include "partitions.h"

#define PERM_HASH_SIZE 128

#define GROUP_ANY 0
#define MASK_ANY 32
#define PORT_ANY 0

/*
 * Structure stored in address hash table
 */
struct address_list {
	struct ip_addr *ip;			/* IP */
	unsigned int grp;			/* Group for the specified IP */
    unsigned int port;			/* Port */
	int proto;                  /* Protocol -- UDP, TCP, TLS, or SCTP */
	char *pattern;              /* Pattern matching From header field */
	char *info;       		    /* Extra information */
	struct address_list *next;  /* Next element in the list */
};


/*
 * Create and initialize a hash table
 */
struct address_list** hash_create(void);


/*
 * Destroy a hash table and release memory
 */
void hash_destroy(struct address_list** table);


/*
 * Add <ip, group, port, proto, pattern> into hash table
 */
int hash_insert(struct address_list** table, struct ip_addr *ip,
		unsigned int grp, unsigned int port, int proto,
		str* pattern, str* info);


/*
 * Check if an entry exists in hash table that has given group, ip,
 * port, protocol value and pattern that matches to From URI.
 */
int hash_match(struct sip_msg *msg, struct address_list** table,
		unsigned int grp, struct ip_addr *ip, unsigned int port, int proto,
		char *pattern, pv_spec_t* info);


/*
 * Print entries stored in hash table
 */
//void hash_print(struct address_list** hash_table, FILE* reply_file);
int hash_mi_print(struct address_list **table, mi_item_t *part_item,
		struct pm_part_struct *pm);

/*
 * Empty hash table
 */
void empty_hash(struct address_list** table);



int find_group_in_hash_table(struct address_list** table,
		struct ip_addr *ip, unsigned int port);



#define PERM_MAX_SUBNETS 128

/*
 * Structure used to store a subnet
 */
struct subnet {
	unsigned int grp;        /* address group, subnet count in last record */
	struct net *subnet;		 /* IP subnet + mask */
	int proto;                  /* Protocol -- UDP, TCP, TLS, or SCTP */
	char *pattern;              /* Pattern matching From header field */
	unsigned int port;       /* port or 0 */
	char *info;				 /* extra information */
};


/*
 * Create a subnet table
 */
struct subnet* new_subnet_table(void);


/*
 * Check if an entry exists in subnet table that matches given group, ip_addr,
 * and port.  Port 0 in subnet table matches any port.
 */
int match_subnet_table(struct sip_msg *msg, struct subnet* table,
		unsigned int group, struct ip_addr *ip, unsigned int port, int proto,
		char *pattern, pv_spec_t* info);


/*
 * Checks if an entry exists in subnet table that matches given ip_addr,
 * and port.  Port 0 in subnet table matches any port.  Returns group of
 * the first match or -1 if no match is found.
 */
int find_group_in_subnet_table(struct subnet* table,
		struct ip_addr *ip, unsigned int port);

/*
 * Empty contents of subnet table
 */
void empty_subnet_table(struct subnet *table);


/*
 * Release memory allocated for a subnet table
 */
void free_subnet_table(struct subnet* table);



/*
 * Add <grp, subnet, mask, port> into subnet table so that table is
 * kept ordered according to subnet, port, grp.
 */
int subnet_table_insert(struct subnet* table, unsigned int grp,
		struct net *subnet, unsigned int port, int proto,
		str* pattern, str *info);


/*
 * Print subnets stored in subnet table
 */
/*void subnet_table_print(struct subnet* table, FILE* reply_file);*/
int subnet_table_mi_print(struct subnet* table, mi_item_t *part_item,
		struct pm_part_struct *pm);



#endif /* PERM_HASH_H */
