/*
 * siptrace module - helper module to trace sip messages
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
#ifndef _SIPTRACE_H
#define _SIPTRACE_H

#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../proto_hep/hep.h"

#define NR_KEYS 14
#define SIPTRACE_TABLE_VERSION 5
#define HEP_PREFIX_LEN (sizeof("hep:") - 1)
#define SIP_TRACE_TYPE_STR "sip"

#define GET_SIPTRACE_CONTEXT \
	context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, sl_ctx_idx)

#define SET_SIPTRACE_CONTEXT(st_ctx) \
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, sl_ctx_idx, st_ctx)

enum trace_flags {TRACE_MESSAGE=(1<<0), TRACE_TRANSACTION=(1<<1),
			TRACE_SL_TRANSACTION=(1<<2), /* transaction aware in stateless mode */
			TRACE_DIALOG=(1<<3)};


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
	unsigned int hash; /* hash over the uri*/
	unsigned char *traceable; /* whether or not this idd is traceable */

	union {
		st_db_struct_t  *db;
		st_hep_struct_t hep;
		struct sip_uri  uri;
	} el;


	struct tlist_elem *next;
} tlist_elem_t, *tlist_elem_p;

enum tid_types {TYPE_LIST=0, TYPE_PVAR};
typedef struct tid_param {
	enum tid_types type;
	union {
		tlist_elem_p lst;
		pv_elem_p el;
	} u;
} tid_param_t, *tid_param_p;


typedef struct trace_info {
	str *trace_attrs;
	int trace_types;
	tlist_elem_p trace_list;
} trace_info_t, *trace_info_p;



/* SIPTRACE API */

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

/* SIPTRACE API data types */
typedef int trace_proto_id_t;
typedef int siptrace_id_hash_t;
typedef void * siptrace_dest_t;

/* SIPTRACE API function defintions */
typedef trace_proto_id_t(register_traced_type_f)(char* name);
typedef siptrace_id_hash_t(is_id_traced_f)(int id);
typedef trace_dest(get_next_trace_dest_f)(trace_dest last_dest,
								siptrace_id_hash_t hash);

typedef struct {
	trace_proto_t*          trace_api;
	register_traced_type_f* register_type;
	is_id_traced_f*         is_id_traced;
	get_next_trace_dest_f*  get_next_destination;
} siptrace_api_t;

typedef int (*load_siptrace_api_f)(siptrace_api_t* api);

int bind_siptrace_proto(siptrace_api_t* api);
trace_proto_id_t register_traced_type(char* name);
siptrace_id_hash_t is_id_traced(int id);
trace_dest get_next_trace_dest(trace_dest last_dest, siptrace_id_hash_t hash);

static inline int load_siptrace_api(siptrace_api_t* api)
{
	load_siptrace_api_f load_siptrace;

	if ( !(load_siptrace = (load_siptrace_api_f)find_export("load_siptrace", 0, 0))) {
		LM_ERR("failed to import load_siptrace function!\n");
		return -1;
	}

	if (load_siptrace( api ) == -1)
		return -1;

	return 0;
}



#endif

