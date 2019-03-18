/*
 * registrant module
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
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
 *
 * History:
 * --------
 *  2011-02-11  initial version (Ovidiu Sas)
 */

#ifndef REG_RECORDS
#define REG_RECORDS

#include <stdio.h>
#include <stdlib.h>

#include "../../lock_ops.h"
#include "../../ut.h"
#include "../../mem/shm_mem.h"
#include "../tm/dlg.h"
#include "../tm/tm_load.h"
#include "../../lib/sliblist.h"


#define NOT_REGISTERED_STATE	0
#define REGISTERING_STATE	1
#define AUTHENTICATING_STATE	2
#define REGISTERED_STATE	3
#define REGISTER_TIMEOUT_STATE	4
#define INTERNAL_ERROR_STATE	5
#define WRONG_CREDENTIALS_STATE	6
#define REGISTRAR_ERROR_STATE	7
#define UNREGISTERING_STATE	8
#define AUTHENTICATING_UNREGISTER_STATE	9

#define FORCE_SINGLE_REGISTRATION 0x1

typedef struct uac_reg_map {
	unsigned int hash_code;
	str registrar_uri;		/* registrar */
	str proxy_uri;			/* proxy */
	str to_uri;			/* AOR */
	str from_uri;			/* third party registrant */
	str contact_uri;		/* contact binding */
	str contact_params;		/* contact params */
	str auth_user;			/* authentication user */
	str auth_password;		/* authentication password */
	unsigned int expires;		/* expiration interval */
	struct socket_info *send_sock;	/* socket */
	str cluster_shtag;	/* clustering sharing tag */
	int cluster_id;
	unsigned int flags;	/* record flags */
	struct uac_reg_map *next;
} uac_reg_map_t;




typedef struct reg_record {
	dlg_t td;
	str contact_uri;
	str contact_params;
	str auth_user;
	str auth_password;
	unsigned int state;
	unsigned int expires;
	time_t last_register_sent;
	time_t registration_timeout;
	str cluster_shtag;
	int cluster_id;
	unsigned int flags;
	struct reg_record *prev;
	struct reg_record *next;
} reg_record_t;

typedef struct reg_entry {
	slinkedl_list_t *p_list;
	slinkedl_list_t *s_list;
	gen_lock_t lock;
} reg_entry_t;

typedef reg_entry_t *reg_table_t;

extern reg_table_t reg_htable;
extern unsigned int reg_hsize;

void *reg_alloc(size_t size);
void reg_free(void *ptr);
int init_reg_htable(void);
void destroy_reg_htable(void);

void new_call_id_ftag_4_record(reg_record_t *rec, str *now);
int add_record(uac_reg_map_t *uac, str *now, unsigned int plist);
void reg_print_record(reg_record_t *rec);

#endif
