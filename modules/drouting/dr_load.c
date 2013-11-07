/*
 * $Id$
 *
 * Copyright (C) 2005-2008 Voice Sistem SRL
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * For any questions about this software and its license, please contact
 * Voice Sistem at following e-mail address:
 *         office@voice-system.ro
 *
 * History:
 * ---------
 *  2005-02-20  first version (cristian)
 *  2005-02-27  ported to 0.9.0 (bogdan)
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
#include "../../time_rec.h"
#include "../../socket_info.h"

#include "dr_load.h"
#include "routing.h"
#include "prefix_tree.h"
#include "parse.h"


#define ID_DRD_COL       "id"
#define GWID_DRD_COL     "gwid"
#define ADDRESS_DRD_COL  "address"
#define STRIP_DRD_COL    "strip"
#define PREFIX_DRD_COL   "pri_prefix"
#define TYPE_DRD_COL     "type"
#define ATTRS_DRD_COL    "attrs"
#define PROBE_DRD_COL    "probe_mode"
#define SOCKET_DRD_COL   "socket"
#define STATE_DRD_COL    "state"
static str id_drd_col = str_init(ID_DRD_COL);
static str gwid_drd_col = str_init(GWID_DRD_COL);
static str address_drd_col = str_init(ADDRESS_DRD_COL);
static str strip_drd_col = str_init(STRIP_DRD_COL);
static str prefix_drd_col = str_init(PREFIX_DRD_COL);
static str type_drd_col = str_init(TYPE_DRD_COL);
static str attrs_drd_col = str_init(ATTRS_DRD_COL);
static str probe_drd_col = str_init(PROBE_DRD_COL);
static str sock_drd_col = str_init(SOCKET_DRD_COL);
static str state_drd_col = str_init(STATE_DRD_COL);

#define RULE_ID_DRR_COL   "ruleid"
#define GROUP_DRR_COL     "groupid"
#define PREFIX_DRR_COL    "prefix"
#define TIME_DRR_COL      "timerec"
#define PRIORITY_DRR_COL  "priority"
#define ROUTEID_DRR_COL   "routeid"
#define DSTLIST_DRR_COL   "gwlist"
static str rule_id_drr_col = str_init(RULE_ID_DRR_COL);
static str group_drr_col = str_init(GROUP_DRR_COL);
static str prefix_drr_col = str_init(PREFIX_DRR_COL);
static str time_drr_col = str_init(TIME_DRR_COL);
static str priority_drr_col = str_init(PRIORITY_DRR_COL);
static str routeid_drr_col = str_init(ROUTEID_DRR_COL);
static str dstlist_drr_col = str_init(DSTLIST_DRR_COL);

#define ID_DRC_COL     "id"
#define CID_DRC_COL    "carrierid"
#define FLAGS_DRC_COL  "flags"
#define GWLIST_DRC_COL "gwlist"
#define ATTRS_DRC_COL  "attrs"
#define STATE_DRC_COL  "attrs"
static str id_drc_col = str_init(ID_DRC_COL);
static str cid_drc_col = str_init(CID_DRC_COL);
static str flags_drc_col = str_init(FLAGS_DRC_COL);
static str gwlist_drc_col = str_init(GWLIST_DRC_COL);
static str attrs_drc_col = str_init(ATTRS_DRC_COL);
static str state_drc_col = str_init(STATE_DRC_COL);

#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("column %s has a bad type\n", _col); \
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %s is null\n", _col); \
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %s (str) is empty\n", _col); \
			goto error;\
		} \
	}while(0)



static inline tmrec_t* parse_time_def(char *time_str)
{
	tmrec_p time_rec;
	char *p,*s;

	p = time_str;
	time_rec = 0;

/*	time_rec = (tmrec_t*)shm_malloc(sizeof(tmrec_t)); */
	time_rec = tmrec_new(SHM_ALLOC);
	if (time_rec==0) {
		LM_ERR("no more shm mem\n");
		goto error;
	}
/*	memset( time_rec, 0, sizeof(tmrec_t)); */

	/* empty definition? */
	if ( time_str==0 || *time_str==0 )
		goto done;

	load_TR_value( p, s, time_rec, tr_parse_dtstart, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_duration, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_freq, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_until, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_interval, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_bymday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byyday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byweekno, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_bymonth, parse_error, done);

	/* success */
done:
	return time_rec;
parse_error:
	LM_ERR("parse error in <%s> around position %i\n",
		time_str, (int)(long)(p-time_str));
error:
	if (time_rec)
		tmrec_free( time_rec );
	return 0;
}


static int add_rule(rt_data_t *rdata, char *grplst, str *prefix, rt_info_t *rule)
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
			if ( add_prefix(rdata->pt, prefix, rule, (unsigned int)t)!=0 ) {
				LM_ERR("failed to add prefix route\n");
					goto error;
			}
		} else {
			if ( add_rt_info( &rdata->noprefix, rule, (unsigned int)t)!=0 ) {
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

	return 0;
error:
	return -1;
}


rt_data_t* dr_load_routing_info( db_func_t *dr_dbf, db_con_t* db_hdl,
		str *drd_table, str *drc_table, str* drr_table, int persistent_state)
{
	int    int_vals[5];
	char * str_vals[6];
	str tmp;
	db_key_t columns[10];
	db_res_t* res;
	db_row_t* row;
	rt_info_t *ri;
	rt_data_t *rdata;
	tmrec_t   *time_rec;
	int i,n;
	int no_rows = 10;
	int db_cols;
	struct socket_info *sock;
	str s_sock, host;
	int proto, port;

	res = 0;
	ri = 0;
	rdata = 0;

	/* init new data structure */
	if ( (rdata=build_rt_data())==0 ) {
		LM_ERR("failed to build rdata\n");
		goto error;
	}

	if (db_check_table_version(dr_dbf, db_hdl, drd_table, 6/*version*/ )!= 0)
		goto error;

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
		if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, db_cols, 0, &res) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
	}

	LM_DBG("%d records found in %.*s\n",
		RES_ROW_N(res), drd_table->len,drd_table->s);

	n = 0;
	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			/* DB ID column */
			check_val(ID_DRD_COL, ROW_VALUES(row), DB_INT, 1, 0);
			int_vals[0] = VAL_INT(ROW_VALUES(row));
			/* GW ID column */
			check_val(GWID_DRD_COL, ROW_VALUES(row)+1, DB_STRING, 1, 1);
			str_vals[3] = (char*)VAL_STRING(ROW_VALUES(row)+1);
			/* ADDRESS column */
			check_val(ADDRESS_DRD_COL, ROW_VALUES(row)+2, DB_STRING, 1, 1);
			str_vals[0] = (char*)VAL_STRING(ROW_VALUES(row)+2);
			/* STRIP column */
			check_val(STRIP_DRD_COL, ROW_VALUES(row)+3, DB_INT, 1, 0);
			int_vals[1] = VAL_INT   (ROW_VALUES(row)+3);
			/* PREFIX column */
			check_val(PREFIX_DRD_COL, ROW_VALUES(row)+4, DB_STRING, 0, 0);
			str_vals[1] = (char*)VAL_STRING(ROW_VALUES(row)+4);
			/* TYPE column */
			check_val(TYPE_DRD_COL, ROW_VALUES(row)+5, DB_INT, 1, 0);
			int_vals[2] = VAL_INT(ROW_VALUES(row)+5);
			/* ATTRS column */
			check_val(ATTRS_DRD_COL, ROW_VALUES(row)+6, DB_STRING, 0, 0);
			str_vals[2] = (char*)VAL_STRING(ROW_VALUES(row)+6);
			/*PROBE_MODE column */
			check_val(PROBE_DRD_COL, ROW_VALUES(row)+7, DB_INT, 1, 0);
			int_vals[3] = VAL_INT(ROW_VALUES(row)+7);
			/*SOCKET column */
			check_val(SOCKET_DRD_COL, ROW_VALUES(row)+8, DB_STRING, 0, 0);
			if ( !VAL_NULL(ROW_VALUES(row)+8) &&
			(s_sock.s=(char*)VAL_STRING(ROW_VALUES(row)+8))[0]!=0 ) {
				s_sock.len = strlen(s_sock.s);
				if (parse_phostport( s_sock.s, s_sock.len, &host.s, &host.len,
				&port, &proto)!=0){
					LM_ERR("GW <%s>(%d): socket description <%.*s> "
						"is not valid -> ignoring socket\n", str_vals[3],
						int_vals[0], s_sock.len,s_sock.s);
					sock = NULL;
				} else {
					sock = grep_sock_info( &host, port, proto);
					if (sock == NULL) {
						LM_ERR("GW <%s>(%d): socket <%.*s> is not local to"
						" OpenSIPS (we must listen on it) -> ignoring socket\n",
						str_vals[3], int_vals[0], s_sock.len,s_sock.s);
					}
				}
			} else {
				sock = NULL;
			}
			/*STATE column */
			if (persistent_state) {
				check_val(STATE_DRD_COL, ROW_VALUES(row)+9, DB_INT, 1, 0);
				int_vals[4] = VAL_INT(ROW_VALUES(row)+9);
			} else {
				int_vals[4] = 0; /* by default enabled */
			}

			/* add the destinaton definition in */
			if ( add_dst( rdata, str_vals[3], str_vals[0], int_vals[1],
			str_vals[1], int_vals[2], str_vals[2], int_vals[3],
			sock, int_vals[4] )<0 ) {
				LM_ERR("failed to add destination <%s>(%d) -> skipping\n",
					str_vals[3],int_vals[0]);
				continue;
			}
			n++;
		}
		if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
			if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
				LM_ERR( "fetching rows (1)\n");
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
	columns[3] = &gwlist_drc_col;
	columns[4] = &attrs_drc_col;
	if (persistent_state) {
		columns[5] = &state_drc_col;
		db_cols = 6;
	} else {
		db_cols = 5;
	}

	if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
		if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, db_cols, 0, 0 ) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
		no_rows = estimate_available_rows( 4+4+32+64+64, db_cols);
		if (no_rows==0) no_rows = 10;
		if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, db_cols, 0, &res) < 0) {
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
				/* ID column */
				check_val(ID_DRC_COL, ROW_VALUES(row), DB_INT, 1, 0);
				int_vals[0] = VAL_INT(ROW_VALUES(row));
				/* CARRIER_ID column */
				check_val(CID_DRC_COL, ROW_VALUES(row)+1, DB_STRING, 1, 1);
				str_vals[0] = (char*)VAL_STRING(ROW_VALUES(row)+1);
				/* flags column */
				check_val(ID_DRC_COL, ROW_VALUES(row)+2, DB_INT, 1, 0);
				int_vals[1] = VAL_INT(ROW_VALUES(row)+2);
				/* GWLIST column */
				check_val(GWLIST_DRC_COL, ROW_VALUES(row)+3, DB_STRING, 1, 1);
				str_vals[1] = (char*)VAL_STRING(ROW_VALUES(row)+3);
				/* ATTRS column */
				check_val(ATTRS_DRC_COL, ROW_VALUES(row)+4, DB_STRING, 0, 0);
				str_vals[2] = (char*)VAL_STRING(ROW_VALUES(row)+4);
				/* STATE column */
				if (persistent_state) {
					check_val(STATE_DRC_COL, ROW_VALUES(row)+5, DB_INT, 1, 0);
					int_vals[2] = VAL_INT(ROW_VALUES(row)+5);
				} else {
					int_vals[2] = 0; /* by default enabled */
				}

				/* add the new carrier */
				if ( add_carrier( int_vals[0], str_vals[0], int_vals[1],
				str_vals[1], str_vals[2], int_vals[2], rdata) != 0 ) {
					LM_ERR("failed to add carrier db_id %d -> skipping\n",
						int_vals[0]);
					continue;
				}
			}
			if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
				if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
					LM_ERR( "fetching rows (1)\n");
					goto error;
				}
			} else {
				break;
			}
		} while(RES_ROW_N(res)>0);
	}
	dr_dbf->free_result(db_hdl, res);
	res = 0;


	/* read the routing rules */
	if (dr_dbf->use_table( db_hdl, drr_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", drr_table->len, drr_table->s);
		goto error;
	}

	columns[0] = &rule_id_drr_col;
	columns[1] = &group_drr_col;
	columns[2] = &prefix_drr_col;
	columns[3] = &time_drr_col;
	columns[4] = &priority_drr_col;
	columns[5] = &routeid_drr_col;
	columns[6] = &dstlist_drr_col;
	columns[7] = &attrs_drd_col;

	if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
		if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, 8, 0, 0) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
		no_rows = estimate_available_rows( 4+32+32+128+32+64+128, 8/*cols*/);
		if (no_rows==0) no_rows = 10;
		if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if ( dr_dbf->query( db_hdl, 0, 0, 0, columns, 0, 8, 0, &res) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
	}

	if (RES_ROW_N(res) == 0) {
		LM_WARN("table \"%.*s\" is empty\n", drr_table->len, drr_table->s);
	}

	LM_DBG("initial %d records found in %.*s\n", RES_ROW_N(res),
		drr_table->len, drr_table->s);

	n = 0;
	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			/* RULE_ID column */
			check_val(RULE_ID_DRR_COL, ROW_VALUES(row), DB_INT, 1, 0);
			int_vals[0] = VAL_INT (ROW_VALUES(row));
			/* GROUP column */
			check_val(GROUP_DRR_COL, ROW_VALUES(row)+1, DB_STRING, 1, 1);
			str_vals[0] = (char*)VAL_STRING(ROW_VALUES(row)+1);
			/* PREFIX column - it may be null or empty */
			check_val(PREFIX_DRR_COL, ROW_VALUES(row)+2, DB_STRING, 0, 0);
			if ((ROW_VALUES(row)+2)->nul || VAL_STRING(ROW_VALUES(row)+2)==0){
				tmp.s = NULL;
				tmp.len = 0;
			} else {
				str_vals[1] = (char*)VAL_STRING(ROW_VALUES(row)+2);
				tmp.s = str_vals[1];
				tmp.len = strlen(str_vals[1]);
			}
			/* TIME column */
			check_val(TIME_DRR_COL, ROW_VALUES(row)+3, DB_STRING, 0, 0);
			str_vals[2] = (char*)VAL_STRING(ROW_VALUES(row)+3);
			/* PRIORITY column */
			check_val(PRIORITY_DRR_COL, ROW_VALUES(row)+4, DB_INT, 1, 0);
			int_vals[2] = VAL_INT   (ROW_VALUES(row)+4);
			/* ROUTE_ID column */
			check_val(ROUTEID_DRR_COL, ROW_VALUES(row)+5, DB_STRING, 0, 0);
			str_vals[3] = (char*)VAL_STRING(ROW_VALUES(row)+5);
			/* DSTLIST column */
			check_val(DSTLIST_DRR_COL, ROW_VALUES(row)+6, DB_STRING, 1, 1);
			str_vals[4] = (char*)VAL_STRING(ROW_VALUES(row)+6);
			/* ATTRS column */
			check_val(ATTRS_DRD_COL, ROW_VALUES(row)+7, DB_STRING, 0, 0);
			str_vals[5] = (char*)VAL_STRING(ROW_VALUES(row)+7);
			/* parse the time definition */
			if (str_vals[2] == NULL || *(str_vals[2]) == 0)
				time_rec = NULL;
			else if ((time_rec=parse_time_def(str_vals[2]))==0) {
				LM_ERR("bad time definition <%s> for rule id %d -> skipping\n",
					str_vals[2], int_vals[0]);
				continue;
			}
			/* lookup for the script route ID */
			if (str_vals[3] && str_vals[3][0]) {
				int_vals[3] =  get_script_route_ID_by_name( str_vals[3],
						rlist, RT_NO);
				if (int_vals[3]==-1) {
					LM_WARN("route <%s> does not exist\n",str_vals[3]);
					int_vals[3] = 0;
				}
			} else {
				int_vals[3] = 0;
			}
			/* build the routing rule */
			if ((ri = build_rt_info( int_vals[0], int_vals[2], time_rec,
			int_vals[3], str_vals[4], str_vals[5], rdata))== 0 ) {
				LM_ERR("failed to add routing info for rule id %d -> "
					"skipping\n", int_vals[0]);
				tmrec_free( time_rec );
				continue;
			}
			/* add the rule */
			if (add_rule( rdata, str_vals[0], &tmp, ri)!=0) {
				LM_ERR("failed to add rule id %d -> skipping\n", int_vals[0]);
				free_rt_info( ri );
				continue;
			}
			n++;
		}
		if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
			if(dr_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
				LM_ERR( "fetching rows (1)\n");
				goto error;
			}
			LM_DBG("additional %d records found in %.*s\n", RES_ROW_N(res),
				drr_table->len, drr_table->s);
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	dr_dbf->free_result(db_hdl, res);
	res = 0;

	LM_DBG("%d total records loaded from table %.*s\n", n,
		drr_table->len, drr_table->s);

	return rdata;
error:
	if (res)
		dr_dbf->free_result(db_hdl, res);
	if (rdata)
		free_rt_data( rdata, 1 );
	rdata = NULL;
	return 0;
}
