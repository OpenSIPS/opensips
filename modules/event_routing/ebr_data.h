/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */



#ifndef _MODULE_EBR_H
#define _MODULE_EBR_H

#include "../../locking.h"
#include "../tm/t_lookup.h"

#define EVI_ROUTING_NAME "routing"

#define EBR_SOCKET_SEPARATOR '/'

typedef struct _ebr_filter {
	str key;
	/* possibility to filter by SIP URI param value; use .s = NULL to ignore */
	str uri_param_key;
	str val;
	struct _ebr_filter *next;
} ebr_filter;

struct _ebr_event;

#define EBR_SUBS_TYPE_WAIT  (1<<0)
#define EBR_SUBS_TYPE_NOTY  (1<<1)
#define EBR_DATA_TYPE_ROUT  (1<<2)
#define EBR_DATA_TYPE_FUNC  (1<<3)

typedef struct usr_avp *(*ebr_pack_params_cb) (evi_params_t *params);

typedef struct _ebr_subscription {
	struct _ebr_event *event;
	ebr_filter *filters;
	int proc_no;
	int flags;
	ebr_pack_params_cb pack_params;
	void *data;
	int expire;
	/* Transaction ID data */
	struct tm_id tm ;
	struct _ebr_subscription *next;
} ebr_subscription;


typedef struct _ebr_event {
	str event_name;
	int event_id;
	gen_lock_t lock;
	ebr_subscription *subs;
	struct _ebr_event *next;
} ebr_event;

ebr_event * search_ebr_event( const str *name );

ebr_event * add_ebr_event( const str *name );

int init_ebr_event( ebr_event *ev );

int pack_ebr_filters(struct sip_msg *msg, int filter_avp_id,
                     ebr_filter **filters);
int dup_ebr_filters(const ebr_filter *src, ebr_filter **dst);

int add_ebr_subscription( struct sip_msg *msg, ebr_event *ev,
               ebr_filter *filters, int expire, ebr_pack_params_cb pack_params,
               void *data, int flags);

int notify_ebr_subscriptions( ebr_event *ev, evi_params_t *params);

void handle_ebr_ipc(int sender, void *payload);

int ebr_resume_from_wait(int *fd, struct sip_msg *msg, void *param);

#endif

