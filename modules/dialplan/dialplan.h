/*
 * Copyright (C)  2007-2008 Voice Sistem SRL
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
 *  2007-08-01 initial version (ancuta onofrei)
 */

#ifndef _DP_DIALPLAN_H
#define _DP_DIALPLAN_H

#include "../../parser/msg_parser.h"
#include "../../rw_locking.h"
#include "../../time_rec.h"

#include "../../db/db.h"
#include "../../re.h"
#include <pcre.h>

#define REGEX_OP	1
#define EQUAL_OP	0

#define DEFAULT_PARTITION  "default"

#define DP_CASE_INSENSITIVE		1
#define DP_INDEX_HASH_SIZE		16

typedef struct dpl_node{
	int dpid;
	int table_id; /*choose between matching regexp/strings with same priority*/
	int pr;
	int matchop;
	int match_flags;
	str match_exp, subst_exp, repl_exp; /*keeping the original strings*/
	pcre * match_comp, * subst_comp; /*compiled patterns*/
	struct subst_expr * repl_comp;
	str attrs;
	str timerec;
	tmrec_t *parsed_timerec;

	struct dpl_node * next; /*next rule*/
}dpl_node_t, *dpl_node_p;

/* HASH_SIZE	buckets of matching strings (lowercase hashing)
   1			bucket of regexps (index: HASH_SIZE) */
typedef struct dpl_index{
	dpl_node_t * first_rule;
	dpl_node_t * last_rule;

}dpl_index_t, *dpl_index_p;

/*For every DPID*/
typedef struct dpl_id{
	int dp_id;
	dpl_index_t* rule_hash;/*fast access :string rules are hashed*/
	struct dpl_id * next;
}dpl_id_t,*dpl_id_p;

typedef struct dp_connection_list {

	dpl_id_t *hash[2];
	str table_name;
	str partition;
	str db_url;
	int crt_index, next_index;

	db_con_t** dp_db_handle;
	db_func_t dp_dbf;

	rw_lock_t *ref_lock;

	struct dp_connection_list * next;
} dp_connection_list_t, *dp_connection_list_p;

#define DP_VAL_INT		0
#define DP_VAL_SPEC		1
#define DP_VAL_STR		2
#define DP_VAL_STR_SPEC		3

typedef struct dp_pv_int {
	int id;
	pv_spec_t partition;
} dp_pv_int_t;

typedef struct dp_param{
	int type;
	union {
		int id;
		pv_spec_t sp[2];
		dp_pv_int_t pv_id;
	} v;

	dp_connection_list_p hash;
}dp_param_t, *dp_param_p;

int init_data();
void destroy_data();
int dp_load_db(dp_connection_list_p dp_table);
int dp_load_all_db(void);
void dp_disconnect_all_db(void);

dpl_id_p select_dpid(dp_connection_list_p table, int id, int index);

struct subst_expr* repl_exp_parse(str subst);
void repl_expr_free(struct subst_expr *se);
int translate(struct sip_msg *msg, str user_name, str* repl_user, dpl_id_p idp, str *);
int rule_translate(struct sip_msg *msg, str , dpl_node_t * rule,  str *);
int test_match(str string, pcre * exp, int * out, int out_max);


typedef void * (*func_malloc)(size_t );
typedef void  (*func_free)(void * );

void * wrap_shm_malloc(size_t size);
void  wrap_shm_free(void *);


pcre * wrap_pcre_compile(char *  pattern, int flags);
void wrap_pcre_free( pcre*);


extern rw_lock_t *ref_lock;
extern str dp_df_part;

#endif
