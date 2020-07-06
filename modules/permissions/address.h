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

extern str def_part;
extern str db_url;        /* Database URL */
extern str address_table; /* Name of address table */
extern str ip_col;        /* Name of IP address column */
extern str proto_col;     /* Name of protocol column */
extern str pattern_col;   /* Name of pattern column */
extern str info_col;      /* Name of context_info column */
extern str grp_col;       /* Name of address group column */
extern str mask_col;      /* Name of mask column */
extern str port_col;      /* Name of port column */
extern str id_col;        /* Name of id column */


int proto_char2int(str *proto);


/*
 * Initialize partitions & load data, if necessary
 */
int init_address(void);


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

int get_source_group(struct sip_msg* msg, pv_spec_t *out_var,
		struct pm_part_struct *part);

/* Checks based on avp's received as parameter */
int check_addr(struct sip_msg* msg, int *grp,
		str* s_ip, int *port, long proto, pv_spec_t *info, char *pattern,
		struct pm_part_struct *part);

/* Checks based on data from the message */
int check_src_addr(struct sip_msg *msg, int *grp,
		pv_spec_t *info, char *pattern, struct pm_part_struct *part);


#endif /* TRUSTED_H */
