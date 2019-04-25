/*
 * tracer module - helper module to trace sip messages
 *
 * Copyright (C) 2006-2009 Voice Sistem S.R.L.
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
 */
#ifndef _TRACER_H
#define _TRACER_H

#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../proto_hep/hep.h"

#define NR_KEYS 14
#define TRACER_TABLE_VERSION 5
#define HEP_PREFIX_LEN (sizeof("hep:") - 1)
#define SIP_TRACE_TYPE_STR "sip"

#define GET_TRACER_CONTEXT \
	((trace_info_p)( current_processing_ctx ? \
	  context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, sl_ctx_idx) : \
	  0 ))

#define SET_TRACER_CONTEXT(st_ctx) \
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, sl_ctx_idx, st_ctx)

enum trace_flags {TRACE_MESSAGE=(1<<0),
				  TRACE_TRANSACTION=(1<<1),
				  TRACE_DIALOG=(1<<2) };


typedef struct st_db_struct {
	str url;

	db_con_t *con;
	db_func_t funcs;
	query_list_t *ins_list;

	str table;
} st_db_struct_t;

typedef struct st_hep_struct {
	str name;
	hid_list_t* hep_id;
} st_hep_struct_t;


enum types { TYPE_HEP=0, TYPE_SIP, TYPE_DB, TYPE_END };
typedef struct tlist_elem {
	str name;          /* name of the partition */
	enum types type;   /* SIP-DB-HEP */
	unsigned int hash; /* hash over the name */
	unsigned int uri_hash; /* hash over the uri*/
	unsigned char *traceable; /* whether or not this id is traceable */
	char dynamic;      /* whether this elem is dynamic or static */

	union {
		st_db_struct_t  *db;
		st_hep_struct_t hep;
		struct sip_uri  uri;
	} el;


	struct tlist_elem *next;
} tlist_elem_t, *tlist_elem_p;


enum trace_filter_types {
	TRACE_FILTER_IP,
	TRACE_FILTER_CALLER,
	TRACE_FILTER_CALLEE
};
struct trace_filter {
	enum trace_filter_types type;
	str match;
	struct trace_filter *next;
	char data[0]; /* different custom data hold by each filter */
};

/* we are using a similar structure to be able to use most of the other
 * functions already in place */
typedef struct tlist_dyn_elem {
	struct tlist_elem elem; /* XXX: always keep this first */
	unsigned int ref;
	unsigned int type;
	unsigned int scope;
	struct trace_filter *filters;
} tlist_dyn_elem_t, *tlist_dyn_elem_p;

typedef struct trace_instance {
	str *trace_attrs;
	int trace_types;
	tlist_elem_p trace_list;

	struct trace_instance *next;
} trace_instance_t, *trace_instance_p;

#define TRACE_INFO_STAT		(1<<0)		/* request already traced */
#define TRACE_INFO_TRAN		(1<<1)		/* registred tm callbacks */
#define TRACE_INFO_DIALOG	(1<<2)		/* registred dialog callbacks */

#define TRACE_FLAG_SET(_ti, _f) ((_ti)->flags |= (_f))
#define TRACE_FLAG_UNSET(_ti, _f) ((_ti)->flags &= ~(_f))
#define TRACE_FLAG_ISSET(_ti, _f) ((_ti)->flags & (_f))

typedef struct trace_info {
	unsigned long flags;

	/* connection id correlationg sip message with transport messages */
	unsigned long long conn_id;

	trace_instance_p instances;
} trace_info_t, *trace_info_p;

/* maximum 32 types to trace; this way we'll
 * be able to know all types by having set bits into an integer value */
#define MAX_TRACE_NAMES (sizeof(int) * 8)
#define MAX_TRACED_PROTOS (sizeof(int) * 8)
#define TRACE_PROTO "proto_hep"

/**
 * structure identifying a protocol that is traced
 * has the traced proto name and it's id which
 * helps the TRACE(proto_hep) protocol identifying
 * the TRACED(mi, xlog, rest...) protocol
 */
struct trace_proto {
	char* proto_name;
	int   proto_id;
};

const struct trace_proto* get_traced_protos(void);
int get_traced_protos_no(void);

/* implementations for trace_api.h message context tracing functions */
int register_traced_type(char* name);
trace_dest get_next_trace_dest(trace_dest last_dest, int hash);
int sip_context_trace_impl(int id, union sockaddr_union* from_su,
		union sockaddr_union* to_su, str* payload,
		int net_proto, str* correlation_id, struct modify_trace* mod_p);

#endif

