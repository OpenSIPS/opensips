/*
 * Header file for address.c implementing allow_address function
 *
 * Copyright (C) 2003-2008 Juha Heinanen
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

#ifndef TRUSTED_H
#define TRUSTED_H

#include "../../parser/msg_parser.h"
#include "partitions.h"

/*
 * Initialize data structures
 */
int init_address(struct pm_partition*);


/*
 * Open database connections if necessary
 */
int init_child_address(int rank);


/*
 * Open database connections if necessary
 */
int mi_init_address(void);


/*
 * Reload address table to new hash table and when done, make new hash table
 * current one.
 */
int reload_address_table(struct pm_part_struct*);


/*
 * Close connections and release memory
 */
void clean_address(struct pm_part_struct*);

int get_source_group(struct sip_msg *msg, char *arg);

/* Checks based on avp's received as parameter */
int check_addr_4(struct sip_msg *msg,
		        char *grp, char *src_ip, char *port, char *proto);

int check_addr_5(struct sip_msg* msg,
		        char *grp, char *src_ip, char *port, char *proto, char *info);

int check_addr_6(struct sip_msg* msg,
		        char *grp, char *src_ip, char *port, char  *proto,
				char *info, char *pattern);

/* Checks based on data from the message */
int check_src_addr_1(struct sip_msg *msg,
		                char *grp);

int check_src_addr_2(struct sip_msg *msg,
		                char *grp, char *info);

int check_src_addr_3(struct sip_msg *msg,
		                char *grp, char *info, char *pattern);


#endif /* TRUSTED_H */
