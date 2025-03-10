/*
 * Copyright (C) 2005-2008 Voice Sistem SRL
 * Copyright (C) 2020 OpenSIPS Solutions
 *
 * This file is part of Open SIP Server (OpenSIPS).
 *
 * DROUTING OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * DROUTING OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */


#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>


#include "../../dprint.h"
#include "../../route.h"
#include "../../db/db.h"
#include "../../mem/shm_mem.h"
#include "../../mem/rpm_mem.h"
#include "../../time_rec.h"
#include "../../socket_info.h"
#include "../../status_report.h"

#include "dr_load.h"
#include "routing.h"
#include "prefix_tree.h"
#include "parse.h"
#include "dr_db_def.h"


extern void *dr_srg;

enum dr_gw_socket_filter_mode {
	DR_GW_SOCK_FILTER_MODE_NONE=0,
	DR_GW_SOCK_FILTER_MODE_IGNORE,
	DR_GW_SOCK_FILTER_MODE_MATCH
};

enum dr_gw_socket_filter_mode gw_sock_filter = DR_GW_SOCK_FILTER_MODE_NONE;


#define check_val2( _col, _val, _type1, _type2, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=(_type1) && (_val)->type!=(_type2)) { \
			LM_ERR("column %.*s has a bad type [%d], accepting only [%d,%d]\n",\
				_col.len, _col.s, (_val)->type, _type1, _type2); \
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %.*s is null\n", _col.len, _col.s); \
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %.*s (str) is empty\n", _col.len, _col.s); \
			goto error;\
		} \
	}while(0)

#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=(_type)) { \
			LM_ERR("column %.*s has a bad type [%d], accepting only [%d]\n",\
				_col.len, _col.s, (_val)->type, _type); \
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %.*s is null\n", _col.len, _col.s); \
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %.*s (str) is empty\n", _col.len, _col.s); \
			goto error;\
		} \
	}while(0)


int dr_set_gw_sock_filter_mode(char *mode)
{
	if ( strcasecmp( mode, "none")==0 ) {
		gw_sock_filter = DR_GW_SOCK_FILTER_MODE_NONE;
		return 0;
	}
	if ( strcasecmp( mode, "ignore")==0 ) {
		gw_sock_filter = DR_GW_SOCK_FILTER_MODE_IGNORE;
		return 0;
	}
	if ( strcasecmp( mode, "matched-only")==0 ) {
		gw_sock_filter = DR_GW_SOCK_FILTER_MODE_MATCH;
		return 0;
	}
	return -1;
}

void hash_rule(char* grplst, str* prefix, rt_info_t* rule, MD5_CTX* hash_ctx)
{
	int i;

	if (hash_ctx == NULL)
		return;

	MD5Update(hash_ctx, grplst, strlen(grplst));
	if (prefix->s && prefix->len)
		MD5Update(hash_ctx, prefix->s, prefix->len);

	MD5Update(hash_ctx, (char *)&rule->priority, sizeof(rule->priority));
	if (rule->attrs.s && rule->attrs.len)
		MD5Update(hash_ctx, rule->attrs.s, rule->attrs.len);
	MD5Update(hash_ctx, (char *)rule->sort_alg, sizeof(rule->sort_alg));

	for (i=0;i<rule->pgwa_len;i++) {
		if (rule->pgwl[i].is_carrier == 1)
			hash_carrier(rule->pgwl[i].dst.carrier,hash_ctx);
		else
			hash_dst(rule->pgwl[i].dst.gw,hash_ctx);
	}
}

static int add_rule(rt_data_t *rdata, char *grplst, str *prefix,
		rt_info_t *rule, osips_malloc_f malloc_f, osips_free_f free_f,MD5_CTX* hash_ctx)
{
	long int t;
	char *tmp;
	char *ep;
	int n;

	tmp=grplst;
	n=0;
	/* parse the grplst */
	while(tmp && (*tmp!=0)) {
		errno = 0;
		t = strtol(tmp, &ep, 10);
		if (ep == tmp) {
			LM_ERR("bad grp id '%c' (%d)[%s]\n",
					*ep, (int)(ep-grplst), grplst);
			goto error;
		}
		if ((!IS_SPACE(*ep)) && (*ep != SEP) && (*ep != SEP1) && (*ep!=0)) {
			LM_ERR("bad char %c (%d) [%s]\n",
					*ep, (int)(ep-grplst), grplst);
			goto error;
		}
		if (errno == ERANGE && (t== LONG_MAX || t== LONG_MIN)) {
			LM_ERR("out of bounds\n");
			goto error;
		}
		n++;
		/* add rule -> has prefix? */
		if (prefix->len) {
			/* add the routing rule */
			if ( add_prefix(rdata->pt, prefix, rule, (unsigned int)t,
					malloc_f, free_f)!=0 ) {
				LM_ERR("failed to add prefix route\n");
				goto error;
			}
		} else {
			if ( add_rt_info( &rdata->noprefix, rule, (unsigned int)t,
					malloc_f, free_f)!=0 ) {
				LM_ERR("failed to add prefixless route\n");
				goto error;
			}
		}
		/* keep parsing */
		if(IS_SPACE(*ep))
			EAT_SPACE(ep);
		if(ep && (*ep == SEP || *ep == SEP1))
			ep++;
		tmp = ep;
	}

	if(n==0) {
		LM_ERR("no id in grp list [%s]\n",
				grplst);
		goto error;
	}

	hash_rule(grplst,prefix,rule,hash_ctx);

	return 0;
error:
	return -1;
}

static struct head_cache_socket *get_cache_sock_info(struct head_cache *cache,
		const struct socket_info *old_sock)
{
	struct head_cache_socket *hsock;
	for (hsock = cache->sockets; hsock; hsock = hsock->next)
		if (hsock->old_sock == old_sock)
			return hsock;
	return NULL;
}


static int add_cache_sock_info(struct head_cache *cache, const struct socket_info *sock,
		str *host, int port, int proto)
{
	struct head_cache_socket *hsock;

	/* don't add the socket twice */
	if (get_cache_sock_info(cache, sock))
		return -2;

	hsock = rpm_malloc(sizeof *hsock + host->len);
	if (!hsock) {
		LM_ERR("could not allocate peristent memory for socket!\n");
		return -1;
	}
	hsock->host.s = (char *)(hsock + 1);
	memcpy(hsock->host.s, host->s, host->len);
	hsock->host.len = host->len;
	hsock->port = port;
	hsock->proto = proto;
	hsock->old_sock = hsock->new_sock = sock;
	hsock->next = cache->sockets;
	cache->sockets = hsock;

	LM_DBG("added persistent socket info to %.*s:%d (%d) -> %p\n",
			host->len, host->s, port, proto, sock);

	return 0;
}

int dr_cache_update_sock(void *param, str key, void *value)
{
	pgw_t *gw = (pgw_t *)value;
	struct head_cache_socket *sock;
	struct head_cache *cache = (struct head_cache *)param;

	if (!gw->sock)
		return -1;

	sock = get_cache_sock_info(cache, gw->sock);
	if (!sock) {
		LM_WARN("could not find socket for gateway %.*s\n",
				gw->id.len, gw->id.s);
		return -1;
	} else {
		/* got the socket - update the gateway! */
		gw->sock = sock->new_sock;
		return 0;
	}
}

void dr_update_head_cache(struct head_db *head)
{
	struct head_cache_socket *sock;

	head->rdata = head->cache->rdata;
	map_for_each(head->rdata->pgw_tree, dr_cache_update_sock, head->cache);

	for (sock = head->cache->sockets; sock; sock = sock->next)
		sock->old_sock = sock->new_sock;
}


/* dr_gateways table */
#define INT_VALS_STRIP_DRD_COL    0
#define INT_VALS_TYPE_DRD_COL     1
#define INT_VALS_PROBE_DRD_COL    2
#define INT_VALS_STATE_DRD_COL    3
#define STR_VALS_ADDRESS_DRD_COL  0
#define STR_VALS_PREFIX_DRD_COL   1
#define STR_VALS_ATTRS_DRD_COL    2
#define STR_VALS_GWID_DRD_COL     3
#define STR_VALS_ID_DRD_COL       4

/* dr_carriers table */
#define INT_VALS_STATE_DRC_COL    0
#define INT_VALS_FLAGS_DRC_COL    1
#define STR_VALS_CID_DRC_COL      0
#define STR_VALS_GWLIST_DRC_COL   1
#define STR_VALS_ATTRS_DRC_COL    2
#define STR_VALS_ID_DRC_COL       3
#define STR_VALS_SORT_ALG_DRC_COL 4

/* dr_rules table */
#define INT_VALS_RULE_ID_DRR_COL  0
#define INT_VALS_BLANK_1          1
#define INT_VALS_PRIORITY_DRR_COL 2
#define INT_VALS_SCRIPT_ROUTE_ID  3
#define INT_VALS_QR_PROFILE_DRR_COL 4
#define STR_VALS_GROUP_DRR_COL    0
#define STR_VALS_PREFIX_DRR_COL   1
#define STR_VALS_TIME_DRR_COL     2
#define STR_VALS_ROUTEID_DRR_COL  3
#define STR_VALS_DSTLIST_DRR_COL  4
#define STR_VALS_ATTRS_DRR_COL    5
#define STR_VALS_SORT_ALG_DRR_COL 6

/* loads routing info for given partition; if partition_name is NULL
 * loads all partitions
 */

extern struct custom_rule_table *custom_rule_tables;

rt_data_t* dr_load_routing_info(struct head_db *part,
                  int persistent_state, str *rules_tables, int rules_tables_no,MD5_CTX* hash_ctx)
{
	int    int_vals[5];
	char * str_vals[7];
	str tmp;
	db_func_t *dr_dbf = &part->db_funcs;
	db_con_t* db_hdl = *part->db_con;
	str *drd_table = &part->drd_table;
	str *drc_table = &part->drc_table;
	db_key_t columns[10];
	db_res_t* res;
	db_row_t* row;
	rt_info_t *ri;
	rt_data_t *rdata;
	tmrec_expr *time_rec;
	int i, j, n;
	int loaded_gw = 0, loaded_cr = 0, loaded_rl = 0;
	int discarded_gw = 0, discarded_cr = 0, discarded_rl = 0;
	int no_rows = 10;
	int db_cols;
	const struct socket_info *sock;
	str s_sock, host;
	int proto, port;
	char id_buf[INT2STR_MAX_LEN];

	res = 0;
	ri = 0;
	rdata = 0;

	sr_add_report( dr_srg, STR2CI(part->partition),
		CHAR_INT("starting DB data loading"), 0 /*is_public*/);

	/* init new data structure */
	if ( (rdata=build_rt_data(part))==0 ) {
		LM_ERR("failed to build rdata\n");
		goto error;
	}

	/* read the destinations */
	if (dr_dbf->use_table( db_hdl, drd_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", drd_table->len,drd_table->s);
		goto error;
	}

	columns[0] = &id_drd_col;
	columns[1] = &gwid_drd_col;
	columns[2] = &address_drd_col;
	columns[3] = &strip_drd_col;
	columns[4] = &prefix_drd_col;
	columns[5] = &type_drd_col;
	columns[6] = &attrs_drd_col;
	columns[7] = &probe_drd_col;
	columns[8] = &sock_drd_col;
	if (persistent_state) {
		columns[9] = &state_drd_col;
		db_cols = 10;
	} else {
		db_cols = 9;
	}

	if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
		if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, db_cols, 0, 0 ) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
		no_rows = estimate_available_rows( 4+32+15+4+32+4+128+4+32+4, db_cols);
		if (no_rows==0) no_rows = 10;
		if(dr_dbf->fetch_result(db_hdl, &res, no_rows )<0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if ( dr_dbf->query(db_hdl,0,0,0,columns,0,db_cols,0,&res) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
	}

	LM_DBG("%d records found in %.*s\n",
			RES_ROW_N(res), drd_table->len,drd_table->s);

	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			/* DB ID column */
			if ( VAL_TYPE( ROW_VALUES(row) ) == DB_INT ) {
				/* if INT type, convert it to string */
				check_val( id_drd_col, ROW_VALUES(row), DB_INT, 1, 0);
				/* int2bstr returns a null terminated string */
				str_vals[STR_VALS_ID_DRD_COL] =
					int2bstr((unsigned long)VAL_INT(ROW_VALUES(row)),
							id_buf, &int_vals[0]/*useless*/);
			} else {
				/* if not INT, accept only STRING type */
				check_val( id_drd_col, ROW_VALUES(row), DB_STRING, 1, 0);
				str_vals[STR_VALS_ID_DRD_COL] = (char*)VAL_STRING(ROW_VALUES(row));
			}
			/* GW ID column */
			check_val( gwid_drd_col, ROW_VALUES(row)+1, DB_STRING, 1, 1);
			str_vals[STR_VALS_GWID_DRD_COL] = (char*)VAL_STRING(ROW_VALUES(row)+1);
			/* ADDRESS column */
			check_val( address_drd_col, ROW_VALUES(row)+2, DB_STRING, 1, 1);
			str_vals[STR_VALS_ADDRESS_DRD_COL] = (char*)VAL_STRING(ROW_VALUES(row)+2);
			/* STRIP column */
			check_val2( strip_drd_col, ROW_VALUES(row)+3, DB_INT, DB_BIGINT, 1, 0);
			int_vals[INT_VALS_STRIP_DRD_COL] = VAL_INT   (ROW_VALUES(row)+3);
			/* PREFIX column */
			check_val( prefix_drd_col, ROW_VALUES(row)+4, DB_STRING, 0, 0);
			str_vals[STR_VALS_PREFIX_DRD_COL] = (char*)VAL_STRING(ROW_VALUES(row)+4);
			/* TYPE column */
			check_val2( type_drd_col, ROW_VALUES(row)+5, DB_INT, DB_BIGINT, 1, 0);
			int_vals[INT_VALS_TYPE_DRD_COL] = VAL_INT(ROW_VALUES(row)+5);
			/* ATTRS column */
			check_val( attrs_drd_col, ROW_VALUES(row)+6, DB_STRING, 0, 0);
			str_vals[STR_VALS_ATTRS_DRD_COL] = (char*)VAL_STRING(ROW_VALUES(row)+6);
			/* PROBE_MODE column */
			check_val2( probe_drd_col, ROW_VALUES(row)+7, DB_INT, DB_BIGINT, 1, 0);
			int_vals[INT_VALS_PROBE_DRD_COL] = VAL_INT(ROW_VALUES(row)+7);
			/* SOCKET column */
			check_val( sock_drd_col, ROW_VALUES(row)+8, DB_STRING, 0, 0);
			if ( gw_sock_filter!=DR_GW_SOCK_FILTER_MODE_IGNORE &&
					!VAL_NULL(ROW_VALUES(row)+8) &&
					(s_sock.s=(char*)VAL_STRING(ROW_VALUES(row)+8))[0]!=0 ) {
				s_sock.len = strlen(s_sock.s);
				if (parse_phostport( s_sock.s, s_sock.len, &host.s, &host.len,
							&port, &proto)!=0){
					LM_ERR("GW <%s>(%s): socket description <%.*s> "
							"is not valid -> ignoring socket\n",
							str_vals[STR_VALS_GWID_DRD_COL],
							str_vals[STR_VALS_ID_DRD_COL], s_sock.len,s_sock.s);
					sock = NULL;
				} else {
					sock = grep_internal_sock_info( &host, port, proto);
					if (sock == NULL) {
						if (gw_sock_filter==DR_GW_SOCK_FILTER_MODE_MATCH)
							continue;
						LM_ERR("GW <%s>(%s): socket <%.*s> is not local to "
								"OpenSIPS (we must listen on it) -> ignoring socket\n",
								str_vals[STR_VALS_GWID_DRD_COL],
								str_vals[STR_VALS_ID_DRD_COL], s_sock.len,s_sock.s);
					} else if (part->cache) {
						/* if we have cache, we need to cache the socket
						 * information */
						add_cache_sock_info(part->cache,
								sock, &host, port, proto);
					}
				}
			} else {
				sock = NULL;
			}
			/*STATE column */
			if (persistent_state) {
				check_val2( state_drd_col, ROW_VALUES(row)+9, DB_INT,
					DB_BIGINT, 1, 0);
				int_vals[INT_VALS_STATE_DRD_COL] = VAL_INT(ROW_VALUES(row)+9);
			} else {
				int_vals[INT_VALS_STATE_DRD_COL] = 0; /* by default enabled */
			}

			/* add the destinaton definition in */
			if ( add_dst( rdata, str_vals[STR_VALS_GWID_DRD_COL],
						str_vals[STR_VALS_ADDRESS_DRD_COL],
						int_vals[INT_VALS_STRIP_DRD_COL],
						str_vals[STR_VALS_PREFIX_DRD_COL],
						int_vals[INT_VALS_TYPE_DRD_COL],
						str_vals[STR_VALS_ATTRS_DRD_COL],
						int_vals[INT_VALS_PROBE_DRD_COL],
						sock,
						int_vals[INT_VALS_STATE_DRD_COL],
						part->malloc,
						part->free,
				   		hash_ctx )<0 ) {
				LM_ERR("failed to add destination <%s>(%s) -> skipping\n",
						str_vals[STR_VALS_GWID_DRD_COL],
						str_vals[STR_VALS_ID_DRD_COL]);
				discarded_gw++;
				continue;
			}
			loaded_gw++;
		}
		if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
			if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
				LM_ERR("fetching rows\n");
				goto error;
			}
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	dr_dbf->free_result(db_hdl, res);
	res = 0;


	/* read the carriers, if any */
	if (dr_dbf->use_table( db_hdl, drc_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", drc_table->len,drc_table->s);
		goto error;
	}

	columns[0] = &id_drc_col;
	columns[1] = &cid_drc_col;
	columns[2] = &flags_drc_col;
	columns[3] = &sort_alg_drc_col;
	columns[4] = &gwlist_drc_col;
	columns[5] = &attrs_drc_col;
	if (persistent_state) {
		columns[6] = &state_drc_col;
		db_cols = 7;
	} else {
		db_cols = 6;
	}

	if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
		if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, db_cols, 0, 0 ) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
		no_rows = estimate_available_rows( 4+4+32+64+64+1, db_cols);
		if (no_rows==0) no_rows = 10;
		if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
			LM_ERR("Error fetching rows (1)\n");
			goto error;
		}
	} else {
		if ( dr_dbf->query(db_hdl,0,0,0,columns,0,db_cols,0,&res) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
	}

	if (RES_ROW_N(res) == 0) {
		LM_DBG("table \"%.*s\" empty\n", drc_table->len,drc_table->s );
	} else {
		LM_DBG("%d records found in %.*s\n",
				RES_ROW_N(res), drc_table->len,drc_table->s);
		do {
			for(i=0; i < RES_ROW_N(res); i++) {
				row = RES_ROWS(res) + i;
				/* DB ID column */
				if ( VAL_TYPE( ROW_VALUES(row) ) == DB_INT ) {
					/* if INT type, convert it to string */
					check_val( id_drc_col, ROW_VALUES(row), DB_INT, 1, 0);
					/* int2bstr returns a null terminated string */
					str_vals[STR_VALS_ID_DRC_COL] =
						int2bstr((unsigned long)VAL_INT(ROW_VALUES(row)),
								id_buf, &int_vals[0]/*useless*/);
				} else {
					/* if not INT, accept only STRING type */
					check_val( id_drd_col, ROW_VALUES(row), DB_STRING, 1, 0);
					str_vals[STR_VALS_ID_DRC_COL] = (char*)VAL_STRING(ROW_VALUES(row));
				}
				/* CARRIER_ID column */
				check_val( cid_drc_col, ROW_VALUES(row)+1, DB_STRING, 1, 1);
				str_vals[STR_VALS_CID_DRC_COL] = (char*)VAL_STRING(ROW_VALUES(row)+1);
				/* flags column */
				check_val2( flags_drc_col, ROW_VALUES(row)+2, DB_INT, DB_BIGINT, 1, 0);
				int_vals[INT_VALS_FLAGS_DRC_COL] = VAL_INT(ROW_VALUES(row)+2);
				/* sort_alg column */
				if( VAL_TYPE(ROW_VALUES(row)+3) == DB_INT ) {
					check_val(sort_alg_drc_col, ROW_VALUES(row)+3, DB_INT, 1, 0);
					str_vals[STR_VALS_SORT_ALG_DRC_COL] = int2bstr((unsigned long)
							VAL_INT(ROW_VALUES(row)+3), id_buf, &int_vals[0]);
				} else {
					check_val(sort_alg_drc_col, ROW_VALUES(row)+3, DB_STRING, 1, 0);
					str_vals[STR_VALS_SORT_ALG_DRC_COL] = (char*)VAL_STRING(
							ROW_VALUES(row)+3);
				}
				/* GWLIST column */
				check_val( gwlist_drc_col, ROW_VALUES(row)+4,
					ROW_VALUES(row)[4].type == DB_BLOB ? DB_BLOB : DB_STRING, 1, 1);
				str_vals[STR_VALS_GWLIST_DRC_COL] = (char*)VAL_STRING(ROW_VALUES(row)+4);
				/* ATTRS column */
				check_val( attrs_drc_col, ROW_VALUES(row)+5,
					ROW_VALUES(row)[5].type == DB_BLOB ? DB_BLOB : DB_STRING, 0, 0);
				str_vals[STR_VALS_ATTRS_DRC_COL] = (char*)VAL_STRING(ROW_VALUES(row)+5);
				/* STATE column */
				if (persistent_state) {
					check_val( state_drc_col, ROW_VALUES(row)+6, DB_INT, 1, 0);
					int_vals[INT_VALS_STATE_DRC_COL] = VAL_INT(ROW_VALUES(row)+6);
				} else {
					/* by default enabled */
					int_vals[INT_VALS_STATE_DRC_COL] = 0;
				}

				/* add the new carrier */
				if ( add_carrier( str_vals[STR_VALS_CID_DRC_COL],
							int_vals[INT_VALS_FLAGS_DRC_COL],
							str_vals[STR_VALS_SORT_ALG_DRC_COL],
							str_vals[STR_VALS_GWLIST_DRC_COL],
							str_vals[STR_VALS_ATTRS_DRC_COL],
							int_vals[INT_VALS_STATE_DRC_COL], rdata,
							part->malloc,
							part->free,
							hash_ctx) != 0 ) {
					LM_ERR("failed to add carrier db_id <%s> -> skipping\n",
							str_vals[STR_VALS_ID_DRC_COL]);
					discarded_cr++;
					continue;
				}
				loaded_cr++;
			}
			if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
				if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
					LM_ERR("fetching rows (1)\n");
					goto error;
				}
			} else {
				break;
			}
		} while(RES_ROW_N(res)>0);
	}
	dr_dbf->free_result(db_hdl, res);
	res = 0;

	for (j = 0; j < rules_tables_no; j++) {
		/* read the routing rules */
		if (dr_dbf->use_table(db_hdl, rules_tables + j) < 0) {
			LM_ERR("cannot select table \"%.*s\"\n",
			       rules_tables[j].len, rules_tables[j].s);
			goto error;
		}

		columns[0] = &rule_id_drr_col;
		columns[1] = &group_drr_col;
		columns[2] = &prefix_drr_col;
		columns[3] = &time_drr_col;
		columns[4] = &priority_drr_col;
		columns[5] = &routeid_drr_col;
		columns[6] = &dstlist_drr_col;
		columns[7] = &sort_alg_drr_col;
		columns[8] = &sort_profile_drr_col;
		columns[9] = &attrs_drr_col;

		if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
			if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, 10, 0, 0) < 0) {
				LM_ERR("DB query failed\n");
				goto error;
			}
			no_rows = estimate_available_rows( 4+32+32+128+32+64+128+4+1, 10/*cols*/);
			if (no_rows==0) no_rows = 10;
			if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
				LM_ERR("Error fetching rows (2)\n");
				goto error;
			}
		} else {
			if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, 10, 0, &res) < 0) {
				LM_ERR("DB query failed\n");
				goto error;
			}
		}

		LM_DBG("initial %d records found in %.*s\n", RES_ROW_N(res),
		       rules_tables[j].len, rules_tables[j].s);

		n = 0;
		do {
			for(i=0; i < RES_ROW_N(res); i++) {
				row = RES_ROWS(res) + i;
				/* RULE_ID column */
				check_val( rule_id_drr_col, ROW_VALUES(row), DB_INT, 1, 0);
				int_vals[INT_VALS_RULE_ID_DRR_COL] = VAL_INT (ROW_VALUES(row));
				/* GROUP column */
				check_val( group_drr_col, ROW_VALUES(row)+1, DB_STRING, 1, 1);
				str_vals[STR_VALS_GROUP_DRR_COL] =
					(char*)VAL_STRING(ROW_VALUES(row)+1);
				/* PREFIX column - it may be null or empty */
				check_val( prefix_drr_col, ROW_VALUES(row)+2, DB_STRING, 0, 0);
				if ((ROW_VALUES(row)+2)->nul || VAL_STRING(ROW_VALUES(row)+2)==0){
					tmp.s = NULL;
					tmp.len = 0;
				} else {
					str_vals[STR_VALS_PREFIX_DRR_COL] =
						(char*)VAL_STRING(ROW_VALUES(row)+2);
					tmp.s = str_vals[STR_VALS_PREFIX_DRR_COL];
					tmp.len = strlen(str_vals[STR_VALS_PREFIX_DRR_COL]);
				}
				/* TIME column */
				check_val( time_drr_col, ROW_VALUES(row)+3,
					ROW_VALUES(row)[3].type == DB_BLOB ? DB_BLOB : DB_STRING, 0, 0);
				/* PRIORITY column */
				check_val2( priority_drr_col, ROW_VALUES(row)+4, DB_INT, DB_BIGINT, 1, 0);
				int_vals[INT_VALS_PRIORITY_DRR_COL] = VAL_INT(ROW_VALUES(row)+4);
				/* ROUTE_ID column */
				check_val( routeid_drr_col, ROW_VALUES(row)+5, DB_STRING, 0, 0);
				/* DSTLIST column */
				check_val2( dstlist_drr_col, ROW_VALUES(row)+6, DB_STRING, DB_BLOB, 0, 1);
				str_vals[STR_VALS_DSTLIST_DRR_COL] = ROW_VALUES(row)[6].type == DB_STRING ?
					(char*)VAL_STRING(ROW_VALUES(row)+6) : VAL_BLOB(ROW_VALUES(row)+6).s;
				/* SORT_ALG column */
				if( VAL_TYPE(ROW_VALUES(row)+7) == DB_INT ) {
					check_val(sort_alg_drr_col, ROW_VALUES(row)+7, DB_INT, 1, 0);
					str_vals[STR_VALS_SORT_ALG_DRR_COL] = int2bstr((unsigned long)
							VAL_INT(ROW_VALUES(row)+7), id_buf, &int_vals[0]);
				} else {
					check_val(sort_alg_drr_col, ROW_VALUES(row)+7, DB_STRING, 1, 0);
					str_vals[STR_VALS_SORT_ALG_DRR_COL] = (char*)VAL_STRING(
							ROW_VALUES(row)+7);
				}
				/* SORT_PROFILE column */
				check_val2(sort_profile_drr_col, ROW_VALUES(row)+8, DB_INT, DB_BIGINT, 0, 0);
				int_vals[INT_VALS_QR_PROFILE_DRR_COL] = VAL_INT(ROW_VALUES(row)+8);
				/* ATTRS column */
				check_val2( attrs_drr_col, ROW_VALUES(row)+9, DB_STRING, DB_BLOB, 0, 0);
				str_vals[STR_VALS_ATTRS_DRR_COL] = ROW_VALUES(row)[9].type == DB_STRING ?
					(char*)VAL_STRING(ROW_VALUES(row)+9) : VAL_BLOB(ROW_VALUES(row)+9).s;
				/* parse the time definition */
				if ( VAL_NULL(ROW_VALUES(row)+3) ||
				((str_vals[STR_VALS_TIME_DRR_COL]=
					(char*)VAL_STRING(ROW_VALUES(row)+3))==NULL ) ||
				*(str_vals[STR_VALS_TIME_DRR_COL]) == 0)
					time_rec = NULL;
				else if ((time_rec = tmrec_expr_parse(
				              str_vals[STR_VALS_TIME_DRR_COL], SHM_ALLOC))==0) {
					LM_ERR("bad time definition <%s> for rule id %d -> skipping\n",
						str_vals[STR_VALS_TIME_DRR_COL],
						int_vals[INT_VALS_RULE_ID_DRR_COL]);
					continue;
				}
				/* set the script route name */
				if ( VAL_NULL(ROW_VALUES(row)+5) ||
				((str_vals[STR_VALS_ROUTEID_DRR_COL]=
					(char*)VAL_STRING(ROW_VALUES(row)+5))==NULL ) ||
				str_vals[STR_VALS_ROUTEID_DRR_COL][0]==0 ) {
					str_vals[STR_VALS_ROUTEID_DRR_COL] = NULL;
				}
				/* build the routing rule */
				if ((ri = build_rt_info( int_vals[INT_VALS_RULE_ID_DRR_COL],
								int_vals[INT_VALS_PRIORITY_DRR_COL], time_rec,
								str_vals[STR_VALS_ROUTEID_DRR_COL],
								str_vals[STR_VALS_DSTLIST_DRR_COL],
								str_vals[STR_VALS_SORT_ALG_DRR_COL],
								int_vals[INT_VALS_QR_PROFILE_DRR_COL],
								str_vals[STR_VALS_ATTRS_DRR_COL], rdata,
								part->malloc,
								part->free))== 0 ) {
					LM_ERR("failed to add routing info for rule id %d -> "
							"skipping\n", int_vals[INT_VALS_RULE_ID_DRR_COL]);
					tmrec_expr_free( time_rec );
					continue;
				}
				/* add the rule */
				if (add_rule(rdata, str_vals[STR_VALS_GROUP_DRR_COL], &tmp, ri,
						part->malloc, part->free,hash_ctx)!=0) {
					LM_ERR("failed to add rule id %d -> skipping\n",
							int_vals[INT_VALS_RULE_ID_DRR_COL]);
					free_rt_info(ri, part->free);
					discarded_rl++;
					continue;
				}
				n++;
			}

			if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
				if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
					LM_ERR("fetching rows (2)\n");
					goto error;
				}
				LM_DBG("additional %d records found in %.*s\n", RES_ROW_N(res),
				       rules_tables[j].len, rules_tables[j].s);
			} else {
				break;
			}
		} while(RES_ROW_N(res)>0);

		dr_dbf->free_result(db_hdl, res);
		res = NULL;

		if (custom_rule_tables)
			LM_NOTICE("loaded %d rules from table '%.*s'\n", n,
			          rules_tables[j].len, rules_tables[j].s);
		loaded_rl += n;
	}

	LM_INFO("loaded %d (discarded %d) gateways in partition '%.*s'\n",
		loaded_gw, discarded_gw,
		part->partition.len, part->partition.s);

	LM_INFO("loaded %d (discarded %d) carriers in partition '%.*s'\n",
		loaded_cr, discarded_cr,
		part->partition.len, part->partition.s);

	if (custom_rule_tables)
		LM_INFO("loaded %d (discarded %d) rules from %d table%s in "
			"partition '%.*s'\n", loaded_rl, discarded_rl, rules_tables_no,
			rules_tables_no != 1 ? "s":"",
			part->partition.len, part->partition.s);
	else
		LM_NOTICE("loaded %d (discarded %d) rules in partition '%.*s'\n",
			loaded_rl, discarded_rl,
			 part->partition.len, part->partition.s);

	/* do the reporting */
	sr_add_report( dr_srg, STR2CI(part->partition),
		CHAR_INT("DB data loading successfully completed"), 0 /*is_public*/);
	sr_add_report_fmt( dr_srg, STR2CI(part->partition), 0 /*is_public*/,
			"%d gateways loaded (%d discarded), "
			"%d carriers loaded (%d discarded), "
			"%d rules loaded (%d discarded)",
		loaded_gw, discarded_gw,
		loaded_cr, discarded_cr,
		loaded_rl, discarded_rl);

	return rdata;
error:
	sr_add_report( dr_srg, STR2CI(part->partition),
		CHAR_INT("DB data loading failed, discarding"), 0 /*is_public*/);
	if (res)
		dr_dbf->free_result(db_hdl, res);
	if (rdata)
		free_rt_data(rdata, part->free);
	rdata = NULL;
	return 0;
}
