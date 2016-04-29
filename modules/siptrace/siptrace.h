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

#define NR_KEYS 14
#define SIPTRACE_TABLE_VERSION 5

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
	struct sip_uri uri;
	char version;
	int transport;
} st_hep_struct_t;


enum types { TYPE_HEP=0, TYPE_SIP, TYPE_DB, TYPE_END };
typedef struct tlist_elem {
	str name;          /* name of the partition */
	enum types type;   /* SIP-DB-HEP */
	unsigned int hash; /* hash over the uri*/
	unsigned char *traceable; /* whether or not this idd is traceable */

	union {
		st_db_struct_t  *db;
		st_hep_struct_t *hep;
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
	tlist_elem_p trace_list;
} trace_info_t, *trace_info_p;

static int sip_trace_fixup(void **param, int param_no);
static int sip_trace_w(struct sip_msg*, char*, char*, char*);
static int sip_trace(struct sip_msg*, trace_info_p);

static int trace_dialog(struct sip_msg*, trace_info_p);
static int trace_transaction(struct sip_msg* msg, trace_info_p info,
								char dlg_tran);


static void trace_onreq_out(struct cell* t, int type, struct tmcb_params *ps);
static void trace_onreply_in(struct cell* t, int type, struct tmcb_params *ps);
static void trace_onreply_out(struct cell* t, int type, struct tmcb_params *ps);
static void trace_msg_out(struct sip_msg* req, str  *buffer,
			struct socket_info* send_sock, int proto, union sockaddr_union *to,
			trace_info_p info);
static void siptrace_dlg_cancel(struct cell* t, int type, struct tmcb_params *param);

/*
 * callback used for statelessly forwarded requests; also catches the ACK in
 * stateful transaction
 */
static void trace_slreq_out(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *to, struct socket_info *sock, int proto);
static void trace_slreply_out(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *dst, struct socket_info *sock, int proto);

#if 0
static void trace_slack_in(struct sip_msg* req, str *buffer,int rpl_code,
				union sockaddr_union *dst, struct socket_info *sock, int proto);
#endif

static struct mi_root* sip_trace_mi(struct mi_root* cmd, void* param );

static int trace_send_duplicate(char *buf, int len, struct sip_uri *uri);
static int trace_send_hep_duplicate(str *body, str *fromproto, str *fromip,
		unsigned short fromport, str *toproto, str *toip,
		unsigned short toport, st_hep_struct_t* hep);



static int pipport2su (str *sproto, str *ip, unsigned short port,
			union sockaddr_union *tmp_su, unsigned int *proto);

static int parse_trace_id(unsigned int type, void *val);

void free_trace_info_pkg(void *param);
void free_trace_info_shm(void *param);
#endif

