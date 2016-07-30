/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
#include "dr_db_def.h"


#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("column %.*s has a bad type\n", _col.len, _col.s); \
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
#define INT_VALS_FLAGS_DRC_COL    0
#define INT_VALS_STATE_DRC_COL    1
#define STR_VALS_CID_DRC_COL      0
#define STR_VALS_GWLIST_DRC_COL   1
#define STR_VALS_ATTRS_DRC_COL    2
#define STR_VALS_ID_DRC_COL       3

/* dr_rules table */
#define INT_VALS_RULE_ID_DRR_COL  0
#define INT_VALS_BLANK_1          1
#define INT_VALS_PRIORITY_DRR_COL 2
#define INT_VALS_SCRIPT_ROUTE_ID  3
#define STR_VALS_GROUP_DRR_COL    0
#define STR_VALS_PREFIX_DRR_COL   1
#define STR_VALS_TIME_DRR_COL     2
#define STR_VALS_ROUTEID_DRR_COL  3
#define STR_VALS_DSTLIST_DRR_COL  4
#define STR_VALS_ATTRS_DRR_COL    5

/* loads routing info for given partition; if partition_name is NULL
 * loads all partitions
 */

rt_data_t* dr_load_routing_info(struct head_db *current_partition
		, int persistent_state)
{
	int    int_vals[5];
	char * str_vals[6];
	str tmp;
	db_func_t *dr_dbf = &current_partition->db_funcs;
	db_con_t* db_hdl = *current_partition->db_con;
	str *drd_table = &current_partition->drd_table;
	str *drc_table = &current_partition->drc_table;
	str *drr_table = &current_partition->drr_table;
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
	char id_buf[INT2STR_MAX_LEN];

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
		if ( dr_dbf->query(db_hdl,0,0,0,columns,0,db_cols,0,&res) < 0) {
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
			check_val( strip_drd_col, ROW_VALUES(row)+3, DB_INT, 1, 0);
			int_vals[INT_VALS_STRIP_DRD_COL] = VAL_INT   (ROW_VALUES(row)+3);
			/* PREFIX column */
			check_val( prefix_drd_col, ROW_VALUES(row)+4, DB_STRING, 0, 0);
			str_vals[STR_VALS_PREFIX_DRD_COL] = (char*)VAL_STRING(ROW_VALUES(row)+4);
			/* TYPE column */
			check_val( type_drd_col, ROW_VALUES(row)+5, DB_INT, 1, 0);
			int_vals[INT_VALS_TYPE_DRD_COL] = VAL_INT(ROW_VALUES(row)+5);
			/* ATTRS column */
			check_val( attrs_drd_col, ROW_VALUES(row)+6, DB_STRING, 0, 0);
			str_vals[STR_VALS_ATTRS_DRD_COL] = (char*)VAL_STRING(ROW_VALUES(row)+6);
			/*PROBE_MODE column */
			check_val( probe_drd_col, ROW_VALUES(row)+7, DB_INT, 1, 0);
			int_vals[INT_VALS_PROBE_DRD_COL] = VAL_INT(ROW_VALUES(row)+7);
			/*SOCKET column */
			check_val( sock_drd_col, ROW_VALUES(row)+8, DB_STRING, 0, 0);
			if ( !VAL_NULL(ROW_VALUES(row)+8) &&
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
					sock = grep_sock_info( &host, port, proto);
					if (sock == NULL) {
						LM_ERR("GW <%s>(%s): socket <%.*s> is not local to "
								"OpenSIPS (we must listen on it) -> ignoring socket\n",
								str_vals[STR_VALS_GWID_DRD_COL],
								str_vals[STR_VALS_ID_DRD_COL], s_sock.len,s_sock.s);
					}
				}
			} else {
				sock = NULL;
			}
			/*STATE column */
			if (persistent_state) {
				check_val( state_drd_col, ROW_VALUES(row)+9, DB_INT, 1, 0);
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
						int_vals[INT_VALS_STATE_DRD_COL] )<0 ) {
				LM_ERR("failed to add destination <%s>(%s) -> skipping\n",
						str_vals[STR_VALS_GWID_DRD_COL],
						str_vals[STR_VALS_ID_DRD_COL]);
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
				check_val( flags_drc_col, ROW_VALUES(row)+2, DB_INT, 1, 0);
				int_vals[INT_VALS_FLAGS_DRC_COL] = VAL_INT(ROW_VALUES(row)+2);
				/* GWLIST column */
				check_val( gwlist_drc_col, ROW_VALUES(row)+3, DB_STRING, 1, 1);
				str_vals[STR_VALS_GWLIST_DRC_COL] = (char*)VAL_STRING(ROW_VALUES(row)+3);
				/* ATTRS column */
				check_val( attrs_drc_col, ROW_VALUES(row)+4, DB_STRING, 0, 0);
				str_vals[STR_VALS_ATTRS_DRC_COL] = (char*)VAL_STRING(ROW_VALUES(row)+4);
				/* STATE column */
				if (persistent_state) {
					check_val( state_drc_col, ROW_VALUES(row)+5, DB_INT, 1, 0);
					int_vals[INT_VALS_STATE_DRC_COL] = VAL_INT(ROW_VALUES(row)+5);
				} else {
					/* by default enabled */
					int_vals[INT_VALS_STATE_DRC_COL] = 0;
				}

				/* add the new carrier */
				if ( add_carrier( str_vals[STR_VALS_CID_DRC_COL],
							int_vals[INT_VALS_FLAGS_DRC_COL],
							str_vals[STR_VALS_GWLIST_DRC_COL],
							str_vals[STR_VALS_ATTRS_DRC_COL],
							int_vals[INT_VALS_STATE_DRC_COL], rdata) != 0 ) {
					LM_ERR("failed to add carrier db_id <%s> -> skipping\n",
							str_vals[STR_VALS_ID_DRC_COL]);
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
	columns[7] = &attrs_drr_col;

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
			check_val( rule_id_drr_col, ROW_VALUES(row), DB_INT, 1, 0);
			int_vals[INT_VALS_RULE_ID_DRR_COL] = VAL_INT (ROW_VALUES(row));
			/* GROUP column */
			check_val( group_drr_col, ROW_VALUES(row)+1, DB_STRING, 1, 1);
			str_vals[STR_VALS_GROUP_DRR_COL] = (char*)VAL_STRING(ROW_VALUES(row)+1);
			/* PREFIX column - it may be null or empty */
			check_val( prefix_drr_col, ROW_VALUES(row)+2, DB_STRING, 0, 0);
			if ((ROW_VALUES(row)+2)->nul || VAL_STRING(ROW_VALUES(row)+2)==0){
				tmp.s = NULL;
				tmp.len = 0;
			} else {
				str_vals[STR_VALS_PREFIX_DRR_COL] = (char*)VAL_STRING(ROW_VALUES(row)+2);
				tmp.s = str_vals[STR_VALS_PREFIX_DRR_COL];
				tmp.len = strlen(str_vals[STR_VALS_PREFIX_DRR_COL]);
			}
			/* TIME column */
			check_val( time_drr_col, ROW_VALUES(row)+3, DB_STRING, 0, 0);
			str_vals[STR_VALS_TIME_DRR_COL] = (char*)VAL_STRING(ROW_VALUES(row)+3);
			/* PRIORITY column */
			check_val( priority_drr_col, ROW_VALUES(row)+4, DB_INT, 1, 0);
			int_vals[INT_VALS_PRIORITY_DRR_COL] = VAL_INT   (ROW_VALUES(row)+4);
			/* ROUTE_ID column */
			check_val( routeid_drr_col, ROW_VALUES(row)+5, DB_STRING, 0, 0);
			str_vals[STR_VALS_ROUTEID_DRR_COL] = (char*)VAL_STRING(ROW_VALUES(row)+5);
			/* DSTLIST column */
			check_val( dstlist_drr_col, ROW_VALUES(row)+6, DB_STRING, 1, 1);
			str_vals[STR_VALS_DSTLIST_DRR_COL] = (char*)VAL_STRING(ROW_VALUES(row)+6);
			/* ATTRS column */
			check_val( attrs_drr_col, ROW_VALUES(row)+7, DB_STRING, 0, 0);
			str_vals[STR_VALS_ATTRS_DRR_COL] = (char*)VAL_STRING(ROW_VALUES(row)+7);
			/* parse the time definition */
			if (str_vals[STR_VALS_TIME_DRR_COL] == NULL || *(str_vals[STR_VALS_TIME_DRR_COL]) == 0)
				time_rec = NULL;
			else if ((time_rec=parse_time_def(str_vals[STR_VALS_TIME_DRR_COL]))==0) {
				LM_ERR("bad time definition <%s> for rule id %d -> skipping\n",
						str_vals[STR_VALS_TIME_DRR_COL], int_vals[INT_VALS_RULE_ID_DRR_COL]);
				continue;
			}
			/* lookup for the script route ID */
			if (str_vals[STR_VALS_ROUTEID_DRR_COL] && str_vals[STR_VALS_ROUTEID_DRR_COL][0]) {
				int_vals[INT_VALS_SCRIPT_ROUTE_ID] =
					get_script_route_ID_by_name( str_vals[STR_VALS_ROUTEID_DRR_COL], rlist, RT_NO);
				if (int_vals[INT_VALS_SCRIPT_ROUTE_ID]==-1) {
					LM_WARN("route <%s> does not exist\n",
							str_vals[STR_VALS_ROUTEID_DRR_COL]);
					int_vals[INT_VALS_SCRIPT_ROUTE_ID] = 0;
				}
			} else {
				int_vals[INT_VALS_SCRIPT_ROUTE_ID] = 0;
			}
			/* build the routing rule */
			if ((ri = build_rt_info( int_vals[INT_VALS_RULE_ID_DRR_COL],
							int_vals[INT_VALS_PRIORITY_DRR_COL], time_rec,
							int_vals[INT_VALS_SCRIPT_ROUTE_ID],
							str_vals[STR_VALS_DSTLIST_DRR_COL],
							str_vals[STR_VALS_ATTRS_DRR_COL], rdata))== 0 ) {
				LM_ERR("failed to add routing info for rule id %d -> "
						"skipping\n", int_vals[INT_VALS_RULE_ID_DRR_COL]);
				tmrec_free( time_rec );
				continue;
			}
			/* add the rule */
			if (add_rule( rdata, str_vals[STR_VALS_GROUP_DRR_COL], &tmp, ri)!=0) {
				LM_ERR("failed to add rule id %d -> skipping\n",
						int_vals[INT_VALS_RULE_ID_DRR_COL]);
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
