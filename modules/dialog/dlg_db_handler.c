/*
 * $Id$
 *
 * Copyright (C) 2007-2009 Voice System SRL
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 * 2007-05-10  initial version (ancuta)
 * 2007-07-06 additional information saved in the database: cseq, contact, 
 *            route set and socket_info for both caller and callee (ancuta)
 * 2009-09-09 support for early dialogs added; proper handling of cseq
 *            while PRACK is used (bogdan)
 */

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../timer.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../../str.h"
#include "../../socket_info.h"
#include "dlg_hash.h"
#include "dlg_db_handler.h"
#include "dlg_cb.h"
#include "dlg_profile.h"


str call_id_column			=	str_init(CALL_ID_COL);
str from_uri_column			=	str_init(FROM_URI_COL);
str from_tag_column			=	str_init(FROM_TAG_COL);
str to_uri_column			=	str_init(TO_URI_COL);
str to_tag_column			=	str_init(TO_TAG_COL);
str h_id_column				=	str_init(HASH_ID_COL);
str h_entry_column			=	str_init(HASH_ENTRY_COL);
str state_column			=	str_init(STATE_COL);
str user_flags_column		=	str_init(USER_FLAGS_COL); /* FIXME - is this used anywhere ? no reference to it */
str start_time_column		=	str_init(START_TIME_COL);
str timeout_column			=	str_init(TIMEOUT_COL);
str to_cseq_column			=	str_init(TO_CSEQ_COL);
str from_cseq_column		=	str_init(FROM_CSEQ_COL);
str to_ping_cseq_column		=	str_init(TO_PING_CSEQ_COL);
str from_ping_cseq_column	=	str_init(FROM_PING_CSEQ_COL);
str to_route_column			=	str_init(TO_ROUTE_COL);
str from_route_column		=	str_init(FROM_ROUTE_COL);
str to_contact_column		=	str_init(TO_CONTACT_COL);
str from_contact_column		=	str_init(FROM_CONTACT_COL);
str to_sock_column			=	str_init(TO_SOCK_COL);
str from_sock_column		=	str_init(FROM_SOCK_COL);
str mangled_fu_column		=	str_init(MANGLED_FU_COL);
str mangled_tu_column		=	str_init(MANGLED_TU_COL);
str vars_column				=	str_init(VARS_COL);
str profiles_column			=	str_init(PROFILES_COL);
str sflags_column			=	str_init(SFLAGS_COL);
str flags_column			=	str_init(FLAGS_COL);
str dialog_table_name		=	str_init(DIALOG_TABLE_NAME);
int dlg_db_mode				=	DB_MODE_NONE;

static db_con_t* dialog_db_handle    = 0; /* database connection handle */
static db_func_t dialog_dbf;

extern int dlg_enable_stats;
extern int active_dlgs_cnt;
extern int early_dlgs_cnt;

#define SET_INT_VALUE(_val, _int)\
	do{\
		VAL_INT(_val)   = _int;\
		VAL_NULL(_val) = 0;\
	}while(0);

#define SET_STR_VALUE(_val, _str)\
	do{\
		if ( (_str).len != 0) { \
			VAL_STR((_val)).s 		= (_str).s;\
			VAL_STR((_val)).len 	= (_str).len;\
			VAL_NULL(_val) = 0;\
		} else { \
			VAL_STR((_val)).s 		= NULL;\
			VAL_STR((_val)).len 	= 0;\
			VAL_NULL(_val) = 1;\
		}\
	}while(0);

#define GET_STR_VALUE(_res, _values, _index, _not_null, _unref)\
	do{\
		if (VAL_NULL((_values)+ (_index))) { \
			if (_not_null) {\
				if (_unref) unref_dlg(dlg,1);\
				goto next_dialog; \
			} else { \
				(_res).s = 0; \
				(_res).len = 0; \
			}\
		} else { \
			(_res).s = VAL_STR((_values)+ (_index)).s;\
			(_res).len = strlen(VAL_STR((_values)+ (_index)).s);\
		} \
	}while(0);


static int load_dialog_info_from_db(int dlg_hash_size);


int dlg_connect_db(const str *db_url)
{
	if (dialog_db_handle) {
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}
	if ((dialog_db_handle = dialog_dbf.init(db_url)) == 0)
		return -1;
	return 0;
}


static int use_dialog_table(void)
{
	if(!dialog_db_handle){
		LM_ERR("invalid database handle\n");
		return -1;
	}

	dialog_dbf.use_table(dialog_db_handle, &dialog_table_name);

	return 0;
}


static int remove_all_dialogs_from_db(void)
{
	if (use_dialog_table()!=0)
		return -1;

	if(dialog_dbf.delete(dialog_db_handle, NULL, NULL, NULL, 0) < 0) {
		LM_ERR("failed to delete database information\n");
		return -1;
	}

	return 0;
}


int init_dlg_db(const str *db_url, int dlg_hash_size , int db_update_period)
{
	/* Find a database module */
	if (db_bind_mod(db_url, &dialog_dbf) < 0){
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}

	if (dlg_connect_db(db_url)!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	if(db_check_table_version(&dialog_dbf, dialog_db_handle,
	&dialog_table_name, DLG_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		return -1;
	}

	if( (dlg_db_mode==DB_MODE_DELAYED) &&
	(register_timer( dialog_update_db, 0, db_update_period)<0 )) {
		LM_ERR("failed to register update db\n");
		return -1;
	}

	if( (load_dialog_info_from_db(dlg_hash_size) ) !=0 ){
		LM_ERR("unable to load the dialog data\n");
		return -1;
	}

	if (dlg_db_mode==DB_MODE_SHUTDOWN && remove_all_dialogs_from_db()!=0) {
		LM_WARN("failed to properly remove all the dialogs form DB\n");
	}

	dialog_dbf.close(dialog_db_handle);
	dialog_db_handle = 0;

	return 0;
}



void destroy_dlg_db(void)
{
	/* close the DB connection */
	if (dialog_db_handle) {
		dialog_dbf.close(dialog_db_handle);
		dialog_db_handle = 0;
	}
}



static int select_entire_dialog_table(db_res_t ** res, int *no_rows)
{
	db_key_t query_cols[DIALOG_TABLE_TOTAL_COL_NO] = {	&h_entry_column,
			&h_id_column,		&call_id_column,	&from_uri_column,
			&from_tag_column,	&to_uri_column,		&to_tag_column,
			&start_time_column,	&state_column,		&timeout_column,
			&from_cseq_column,	&to_cseq_column,	&from_route_column,
			&to_route_column, 	&from_contact_column, &to_contact_column,
			&from_sock_column,	&to_sock_column,	&vars_column,
			&profiles_column,	&sflags_column,		&from_ping_cseq_column,
			&to_ping_cseq_column,&flags_column, &mangled_fu_column,&mangled_tu_column};

	if(use_dialog_table() != 0){
		return -1;
	}

	/* select the whole tabel and all the columns */
	if (DB_CAPABILITY(dialog_dbf, DB_CAP_FETCH)) {
		if(dialog_dbf.query(dialog_db_handle,0,0,0,query_cols, 0,
		DIALOG_TABLE_TOTAL_COL_NO, 0, 0) < 0) {
			LM_ERR("Error while querying (fetch) database\n");
			return -1;
		}
		*no_rows = estimate_available_rows( 4+4+128+64+32+54+32+4+4+4+16+16
			+256+256+64+64+32+32+256+256+4+4+4+4,DIALOG_TABLE_TOTAL_COL_NO );
		if (*no_rows==0) *no_rows = 10;
		if(dialog_dbf.fetch_result(dialog_db_handle,res,*no_rows)<0){
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	} else {
		if(dialog_dbf.query(dialog_db_handle,0,0,0,query_cols, 0,
		DIALOG_TABLE_TOTAL_COL_NO, 0, res) < 0) {
			LM_ERR("Error while querying database\n");
			return -1;
		}
	}

	return 0;
}



struct socket_info * create_socket_info(db_val_t * vals, int n){

	struct socket_info * sock;
	str host, p;
	int port, proto;

	/* socket name */
	p.s  = (VAL_STR(vals+n)).s;
	p.len = strlen(p.s);

	if (VAL_NULL(vals+n) || p.s==0 || p.s[0]==0){
		sock = 0;
	} else {
		if (parse_phostport( p.s, p.len, &host.s, &host.len, 
		&port, &proto)!=0) {
			LM_ERR("bad socket <%.*s>\n", p.len, p.s);
			return 0;
		}
		sock = grep_sock_info( &host, (unsigned short)port, proto);
		if (sock==0) {
			LM_WARN("non-local socket <%.*s>...ignoring\n", p.len, p.s);
			}
	}

	return sock;
}


static inline void strip_esc(str *s)
{
	char *c = s->s;
	int len = s->len;

	for ( ; len > 0; len--, c++) {
		if (*c == '\\' && len > 0 &&
				(*(c+1)=='\\' || *(c+1)=='#' || *(c+1)=='|')) {
			memmove(c, c + 1, len - 1);
			s->len--;
			len--;
		}
	}
}


static inline char* read_pair(char *b, char *end, str *name, str *val)
{
	/* read name */
	name->s = b;
	while( b<end && !( (*b=='|'|| *b=='#') &&
				(*(b-1)!='\\' || *(b-2)=='\\')) )
		b++;
	if (b==end) return NULL;
	if (*b=='|') goto skip;
	name->len = b - name->s;
	if (name->len==0) goto skip;
	strip_esc(name);
	/*LM_DBG("-----read name <%.*s>(%d)\n",name->len,name->s,name->len);*/

	/* read # */
	b++;

	/* read value */
	val->s = b;
	while( b<end && !( (*b=='|'|| *b=='#') &&
				(*(b-1)!='\\' || *(b-2)=='\\')) )
		b++;
	if (b==end) return NULL;
	if (*b=='#') goto skip;
	val->len = b - val->s;
	if (val->len==0) val->s = 0;
	strip_esc(val);
	/*LM_DBG("-----read value <%.*s>(%d)\n",val->len,val->s,val->len);*/

	/* read | */
	b++;
	return b;

skip:
	while(b<end && *b=='|' && *(b-1)!='\\') b++;
	if (b!=end) b++;
	return (b==end)?NULL:b;
}


static void read_dialog_vars(char *b, int l, struct dlg_cell *dlg)
{
	str name, val;
	char *end;
	char *p;

	end = b + l;
	p = b;
	do {
		/* read a new pair from input string */
		p = read_pair( p, end, &name, &val);
		if (p==NULL) break;

		if (val.len==0) continue;

		LM_DBG("new var found  <%.*s>=<%.*s>\n",name.len,name.s,val.len,val.s);

		/* add the variable */
		if (store_dlg_value( dlg, &name, &val)!=0)
			LM_ERR("failed to add val, skipping...\n");
	} while(p!=end);

}


static void read_dialog_profiles(char *b, int l, struct dlg_cell *dlg)
{
	struct dlg_profile_table *profile;
	str name, val;
	char *end;
	char *p;

	end = b + l;
	p = b;
	current_dlg_pointer = dlg;

	do {
		/* read a new pair from input string */
		p = read_pair( p, end, &name, &val);
		if (p==NULL) break;

		LM_DBG("new profile found  <%.*s>=<%.*s>\n",name.len,name.s,val.len,val.s);

		/* add to the profile */
		profile = search_dlg_profile( &name );
		if (profile==NULL) {
			LM_ERR("profile <%.*s> does not exist anymore\n",name.len,name.s);
			continue;
		}
		if (set_dlg_profile( NULL, profile->has_value?&val:NULL, profile) < 0 )
			LM_ERR("failed to add to profile, skipping....\n");

	} while(p!=end);

	current_dlg_pointer = NULL;
}


static int load_dialog_info_from_db(int dlg_hash_size)
{
	db_res_t * res;
	db_val_t * values;
	db_row_t * rows;
	int i, nr_rows;
	struct dlg_cell *dlg;
	str callid, from_uri, to_uri, from_tag, to_tag;
	str cseq1,cseq2,contact1,contact2,rroute1,rroute2,mangled_fu,mangled_tu;
	unsigned int next_id;
	int no_rows = 10;

	res = 0;
	if((nr_rows = select_entire_dialog_table(&res,&no_rows)) < 0)
		goto end;

	nr_rows = RES_ROW_N(res);

	do {
		LM_DBG("loading information from database for %i dialogs\n", nr_rows);

		rows = RES_ROWS(res);

		/* for every row---dialog */
		for(i=0; i<nr_rows; i++){

			values = ROW_VALUES(rows + i);

			if (VAL_NULL(values) || VAL_NULL(values+1)) {
				LM_ERR("columns %.*s or/and %.*s cannot be null -> skipping\n",
					h_entry_column.len, h_entry_column.s,
					h_id_column.len, h_id_column.s);
				continue;
			}

			if (VAL_NULL(values+7) || VAL_NULL(values+8)) {
				LM_ERR("columns %.*s or/and %.*s cannot be null -> skipping\n",
					start_time_column.len, start_time_column.s,
					state_column.len, state_column.s);
				continue;
			}

			if ( VAL_INT(values+8) == DLG_STATE_DELETED ) {
				LM_DBG("dialog already terminated -> skipping\n");
				continue;
			}

			/*restore the dialog info*/
			GET_STR_VALUE(callid, values, 2, 1, 0);
			GET_STR_VALUE(from_uri, values, 3, 1, 0);
			GET_STR_VALUE(from_tag, values, 4, 1, 0);
			GET_STR_VALUE(to_uri, values, 5, 1, 0);

			if((dlg=build_new_dlg(&callid, &from_uri, &to_uri, &from_tag))==0){
				LM_ERR("failed to build new dialog\n");
				goto error;
			}

			if(dlg->h_entry != VAL_INT(values)){
				LM_ERR("inconsistent hash data in the dialog database: "
					"you may have restarted opensips using a different "
					"hash_size: please erase %.*s database and restart\n", 
					dialog_table_name.len, dialog_table_name.s);
				shm_free(dlg);
				goto error;
			}

			/*link the dialog*/
			link_dlg(dlg, 0);

			dlg->h_id = VAL_INT(values+1);
			next_id = d_table->entries[dlg->h_entry].next_id;

			d_table->entries[dlg->h_entry].next_id =
				(next_id < dlg->h_id) ? (dlg->h_id+1) : next_id;

			GET_STR_VALUE(to_tag, values, 6, 1, 1);

			dlg->start_ts	= VAL_INT(values+7);

			dlg->state 		= VAL_INT(values+8);
			if (dlg->state==DLG_STATE_CONFIRMED_NA ||
			dlg->state==DLG_STATE_CONFIRMED) {
				active_dlgs_cnt++;
			} else if (dlg->state==DLG_STATE_EARLY) {
				early_dlgs_cnt++;
			}

			GET_STR_VALUE(cseq1, values, 10 , 1, 1);
			GET_STR_VALUE(cseq2, values, 11 , 1, 1);
			GET_STR_VALUE(rroute1, values, 12, 0, 0);
			GET_STR_VALUE(rroute2, values, 13, 0, 0);
			GET_STR_VALUE(contact1, values, 14, 0, 1);
			GET_STR_VALUE(contact2, values, 15, 0, 1);

			GET_STR_VALUE(mangled_fu, values, 24,0,1);
			GET_STR_VALUE(mangled_tu, values, 25,0,1);

			/* add the 2 legs */
			if ( (dlg_add_leg_info( dlg, &from_tag, &rroute1, &contact1,
			&cseq1, create_socket_info(values, 16),0,0)!=0) ||
			(dlg_add_leg_info( dlg, &to_tag, &rroute2, &contact2,
			&cseq2, create_socket_info(values, 17),&mangled_fu,&mangled_tu)!=0) ) {
				LM_ERR("dlg_set_leg_info failed\n");
				/* destroy the dialog */
				unref_dlg(dlg,1);
				continue;
			}
			dlg->legs_no[DLG_LEG_200OK] = DLG_FIRST_CALLEE_LEG;

			/* script variables */
			if (!VAL_NULL(values+18))
				read_dialog_vars( VAL_STR(values+18).s,
					VAL_STR(values+18).len, dlg);

			/* profiles */
			if (!VAL_NULL(values+19))
				read_dialog_profiles( VAL_STR(values+19).s,
					strlen(VAL_STR(values+19).s), dlg);


			/* script flags */
			if (!VAL_NULL(values+20)) {
				dlg->user_flags = VAL_INT(values+20);
			}

			/* top hiding */
			dlg->flags = VAL_INT(values+23);
			if (dlg_db_mode==DB_MODE_SHUTDOWN)
				dlg->flags |= DLG_FLAG_NEW;

			/* calculcate timeout */
			dlg->tl.timeout = (unsigned int)(VAL_INT(values+9)) + get_ticks();
			if (dlg->tl.timeout<=(unsigned int)time(0))
				dlg->tl.timeout = 0;
			else
				dlg->tl.timeout -= (unsigned int)time(0);

			/* restore the timer values */
			if (0 != insert_dlg_timer( &(dlg->tl), (int)dlg->tl.timeout )) {
				LM_CRIT("Unable to insert dlg %p [%u:%u] "
					"with clid '%.*s' and tags '%.*s' '%.*s'\n",
					dlg, dlg->h_entry, dlg->h_id,
					dlg->callid.len, dlg->callid.s,
					dlg->legs[DLG_CALLER_LEG].tag.len,
					dlg->legs[DLG_CALLER_LEG].tag.s,
					dlg->legs[callee_idx(dlg)].tag.len,
					ZSW(dlg->legs[callee_idx(dlg)].tag.s));
				/* destroy the dialog */
				unref_dlg(dlg,1);
				continue;
			}

			/* reference the dialog as kept in the timer list */
			ref_dlg(dlg,1);
			LM_DBG("current dialog timeout is %u\n", dlg->tl.timeout);

			dlg->lifetime = 0;

			dlg->legs[DLG_CALLER_LEG].last_gen_cseq = 
				(unsigned int)(VAL_INT(values+21));
			dlg->legs[callee_idx(dlg)].last_gen_cseq = 
				(unsigned int)(VAL_INT(values+22));

			if (dlg->flags & DLG_FLAG_PING_CALLER || dlg->flags & DLG_FLAG_PING_CALLEE) {
				if (0 != insert_ping_timer(dlg)) 
					LM_CRIT("Unable to insert dlg %p into ping timer\n",dlg); 
				else {
					/* reference dialog as kept in ping timer list */
					ref_dlg(dlg,1);
				}
			}

			next_dialog:
			;
		}

		/* any more data to be fetched ?*/
		if (DB_CAPABILITY(dialog_dbf, DB_CAP_FETCH)) {
			if (dialog_dbf.fetch_result( dialog_db_handle, &res,no_rows) < 0) {
				LM_ERR("fetching more rows failed\n");
				goto error;
			}
			nr_rows = RES_ROW_N(res);
		} else {
			nr_rows = 0;
		}

	}while (nr_rows>0);

end:
	dialog_dbf.free_result(dialog_db_handle, res);
	return 0;
error:
	dialog_dbf.free_result(dialog_db_handle, res);
	return -1;
}



/* this is only called from destroy_dlg, where the cell's entry 
 * lock is acquired
 */
int remove_dialog_from_db(struct dlg_cell * cell)
{
	static db_ps_t my_ps = NULL;
	db_val_t values[2];
	db_key_t match_keys[2] = { &h_entry_column, &h_id_column};

	/*if the dialog hasn 't been yet inserted in the database*/
	LM_DBG("trying to remove a dialog, update_flag is %i\n", cell->flags);
	if (cell->flags & DLG_FLAG_NEW) 
		return 0;

	if (use_dialog_table()!=0)
		return -1;

	VAL_TYPE(values) = VAL_TYPE(values+1) = DB_INT;
	VAL_NULL(values) = VAL_NULL(values+1) = 0;

	VAL_INT(values) 	= cell->h_entry;
	VAL_INT(values+1) 	= cell->h_id;

	CON_PS_REFERENCE(dialog_db_handle) = &my_ps;

	if(dialog_dbf.delete(dialog_db_handle, match_keys, 0, values, 2) < 0) {
		LM_ERR("failed to delete database information\n");
		return -1;
	}

	LM_DBG("callid was %.*s\n", cell->callid.len, cell->callid.s );

	/* dialog saved */
	run_dlg_callbacks( DLGCB_SAVED, cell, 0, DLG_DIR_NONE, 0);

	return 0;
}



int update_dialog_dbinfo(struct dlg_cell * cell)
{
	static db_ps_t my_ps_insert = NULL;
	static db_ps_t my_ps_update = NULL;
	struct dlg_entry entry;
	db_val_t values[DIALOG_TABLE_FIX_COL_NO];
	int callee_leg;

	db_key_t insert_keys[DIALOG_TABLE_FIX_COL_NO] = { &h_entry_column,
			&h_id_column,        &call_id_column,     &from_uri_column,
			&from_tag_column,    &to_uri_column,      &to_tag_column,
			&from_sock_column,   &to_sock_column,
			&start_time_column,  &mangled_fu_column,  &mangled_tu_column,
			
			&state_column,       &timeout_column,
			&from_cseq_column,   &to_cseq_column,     &from_ping_cseq_column,
			&to_ping_cseq_column,&flags_column,          &from_route_column,
			&to_route_column,    &from_contact_column,&to_contact_column};

	if(use_dialog_table()!=0)
		return -1;

	callee_leg= callee_idx(cell);

	if((cell->flags & DLG_FLAG_NEW) != 0){
		/* save all the current dialogs information*/
		VAL_TYPE(values) = VAL_TYPE(values+1) = VAL_TYPE(values+9) = 
		VAL_TYPE(values+12) = VAL_TYPE(values+13) = VAL_TYPE(values+16) =
		VAL_TYPE(values+17) = VAL_TYPE(values+18) = DB_INT;

		VAL_TYPE(values+2) = VAL_TYPE(values+3) = VAL_TYPE(values+4) = 
		VAL_TYPE(values+5) = VAL_TYPE(values+6) = VAL_TYPE(values+7) = 
		VAL_TYPE(values+8) = VAL_TYPE(values+10) = VAL_TYPE(values+11) =
		VAL_TYPE(values+14) = VAL_TYPE(values+15) = 
		VAL_TYPE(values+19) = VAL_TYPE(values+20) = VAL_TYPE(values+21)=
		VAL_TYPE(values+22) = DB_STR;

		/* lock the entry */
		entry = (d_table->entries)[cell->h_entry];
		dlg_lock( d_table, &entry);

		SET_INT_VALUE(values, cell->h_entry);
		SET_INT_VALUE(values+1, cell->h_id);
		SET_STR_VALUE(values+2, cell->callid);

		SET_STR_VALUE(values+3, cell->from_uri);
		SET_STR_VALUE(values+4, cell->legs[DLG_CALLER_LEG].tag);
		SET_STR_VALUE(values+5, cell->to_uri);
		SET_STR_VALUE(values+6, cell->legs[callee_leg].tag);

		SET_STR_VALUE(values+7, cell->legs[DLG_CALLER_LEG].bind_addr->sock_str);
		if (cell->legs[callee_leg].bind_addr) {
			SET_STR_VALUE(values+8, 
				cell->legs[callee_leg].bind_addr->sock_str);
		} else {
			VAL_NULL(values+8) = 1;
		}

		SET_INT_VALUE(values+9, cell->start_ts);

		SET_STR_VALUE(values+10,cell->legs[callee_leg].from_uri);
		SET_STR_VALUE(values+11,cell->legs[callee_leg].to_uri);

		SET_INT_VALUE(values+12, cell->state);
		SET_INT_VALUE(values+13, (unsigned int)( (unsigned int)time(0) +
			 cell->tl.timeout - get_ticks()) );

		SET_STR_VALUE(values+14, cell->legs[DLG_CALLER_LEG].r_cseq);
		SET_STR_VALUE(values+15, cell->legs[callee_leg].r_cseq);
		SET_INT_VALUE(values+16,cell->legs[DLG_CALLER_LEG].last_gen_cseq);
		SET_INT_VALUE(values+17,cell->legs[callee_leg].last_gen_cseq);
		SET_INT_VALUE(values+18, cell->flags);
		SET_STR_VALUE(values+19, cell->legs[DLG_CALLER_LEG].route_set);
		SET_STR_VALUE(values+20, cell->legs[callee_leg].route_set);
		SET_STR_VALUE(values+21, cell->legs[DLG_CALLER_LEG].contact);
		SET_STR_VALUE(values+22, cell->legs[callee_leg].contact);

		CON_PS_REFERENCE(dialog_db_handle) = &my_ps_insert;

		if((dialog_dbf.insert(dialog_db_handle, insert_keys, values, 
								DIALOG_TABLE_FIX_COL_NO)) !=0){
			LM_ERR("could not add another dialog to db\n");
			goto error;
		}

		/* dialog saved */
		run_dlg_callbacks( DLGCB_SAVED, cell, 0, DLG_DIR_NONE, 0);

		cell->flags &= ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED);

	} else if((cell->flags & DLG_FLAG_CHANGED) != 0) {
		/* save only dialog's state and timeout */
		VAL_TYPE(values) = VAL_TYPE(values+1) = 
		VAL_TYPE(values+12) = VAL_TYPE(values+13) = VAL_TYPE(values+16) =
		VAL_TYPE(values+17) = VAL_TYPE(values+18) = DB_INT;

		VAL_TYPE(values+14) = VAL_TYPE(values+15) =DB_STR;

		/* lock the entry */
		entry = (d_table->entries)[cell->h_entry];
		dlg_lock( d_table, &entry);

		SET_INT_VALUE(values, cell->h_entry);
		SET_INT_VALUE(values+1, cell->h_id);
		SET_INT_VALUE(values+12, cell->state);
		SET_INT_VALUE(values+13, (unsigned int)( (unsigned int)time(0) +
				 cell->tl.timeout - get_ticks()) );

		SET_STR_VALUE(values+14, cell->legs[DLG_CALLER_LEG].r_cseq);
		SET_STR_VALUE(values+15, cell->legs[callee_leg].r_cseq);
		SET_INT_VALUE(values+16,cell->legs[DLG_CALLER_LEG].last_gen_cseq);
		SET_INT_VALUE(values+17,cell->legs[callee_leg].last_gen_cseq);
		SET_INT_VALUE(values+18, cell->flags);

		CON_PS_REFERENCE(dialog_db_handle) = &my_ps_update;

		if((dialog_dbf.update(dialog_db_handle, (insert_keys), 0, 
						(values), (insert_keys+12), (values+12), 2, 7)) !=0){
			LM_ERR("could not update database info\n");
			goto error;
		}

		/* dialog saved */
		run_dlg_callbacks( DLGCB_SAVED, cell, 0, DLG_DIR_NONE, 0);

		cell->flags &= ~(DLG_FLAG_CHANGED);
	} else {
		return 0;
	}

	dlg_unlock( d_table, &entry);
	return 0;

error:
	dlg_unlock( d_table, &entry);
	return -1;
}


static inline unsigned int write_pair( char *b, str *name, str *val)
{
	int i,j;

	for( i=0,j=0 ; i<name->len ; i++) {
		if (name->s[i]=='|' || name->s[i]=='#' || name->s[i]=='\\')
			b[j++] = '\\';
		b[j++] = name->s[i];
	}
	b[j++] = '#';
	for( i=0 ; val && i<val->len ; i++) {
		if (val->s[i]=='|' || val->s[i]=='#' || val->s[i]=='\\')
			b[j++] = '\\';
		b[j++] = val->s[i];
	}
	b[j++] = '|';

	return j;
}


static str* write_dialog_vars( struct dlg_val *vars)
{
	static str o = {NULL,0};
	static int o_l;
	struct dlg_val *v;
	unsigned int l,i;
	char *p;

	/* compute the required len */
	for ( v=vars,l=0 ; v ; v=v->next) {
		l += v->name.len + 1 + v->val.len + 1;
		for( i=0 ; i<v->name.len ; i++ )
			if (v->name.s[i]=='|' || v->name.s[i]=='#' || v->name.s[i]=='\\') l++;
		for( i=0 ; i<v->val.len ; i++ )
			if (v->val.s[i]=='|' || v->val.s[i]=='#' || v->val.s[i]=='\\') l++;
	}

	/* allocate the string to be stored */
	if ( o.s==NULL && o_l<l) {
		if (o.s) pkg_free(o.s);
		o.s = (char*)malloc(l);
		if (o.s==NULL) {
			LM_ERR("not enough pkg mem (req=%d)\n",l);
			return NULL;
		}
		o_l = l;
	}

	/* write the stuff into it */
	o.len = l;
	p = o.s;
	for ( v=vars ; v ; v=v->next) {
		p += write_pair( p, &v->name, &v->val);
	}
	if (o.len!=p-o.s) {
		LM_CRIT("BUG - buffer overflow allocated %d, written %d\n",
			o.len,(int)(p-o.s));
		return NULL;
	}
	LM_DBG("var string is <%.*s>(%d)\n", l,o.s,l);

	return &o;
}


static str* write_dialog_profiles( struct dlg_profile_link *links)
{
	static str o = {NULL,0};
	static int o_l;
	struct dlg_profile_link *link;
	unsigned int l,i;
	char *p;

	/* compute the required len */
	for ( link=links,l=0 ; link ; link=link->next) {
		l += link->profile->name.len + 1 + link->value.len + 1;
		for( i=0 ; i<link->profile->name.len ; i++ )
			if (link->profile->name.s[i]=='|' || link->profile->name.s[i]=='#') l++;
		for( i=0 ; i<link->value.len ; i++ )
			if (link->value.s[i]=='|' ||
			link->value.s[i]=='#') l++;
	}

	/* allocate the string to be stored */
	if ( o.s==NULL && o_l<l) {
		if (o.s) pkg_free(o.s);
		o.s = (char*)malloc(l);
		if (o.s==NULL) {
			LM_ERR("not enough pkg mem (req=%d)\n",l);
			return NULL;
		}
		o_l = l;
	}

	/* write the stuff into it */
	o.len = l;
	p = o.s;
	for ( link=links; link ; link=link->next) {
		p += write_pair( p, &link->profile->name, &link->value);
	}
	if (o.len!=p-o.s) {
		LM_CRIT("BUG - buffer overflow allocated %d, written %d\n",
			o.len,(int)(p-o.s));
		return NULL;
	}
	LM_DBG("profile string is <%.*s>(%d)\n", l,o.s,l);

	return &o;
}


static inline void set_final_update_cols(db_val_t *vals, struct dlg_cell *cell,
																	int on_shutdown)
{
	str *s;

	if (on_shutdown) {
		if (cell->vals==NULL) {
			VAL_NULL(vals) = 1;
		} else {
			s = write_dialog_vars( cell->vals );
			if (s==NULL) {
				VAL_NULL(vals) = 1;
			} else {
				SET_STR_VALUE(vals, *s);
			}
		}
		if (cell->profile_links==NULL) {
			VAL_NULL(vals+1) = 1;
		} else {
			s = write_dialog_profiles( cell->profile_links );
			if (s==NULL) {
				VAL_NULL(vals+1) = 1;
			} else {
				SET_STR_VALUE(vals+1, *s);
			}
		}
		SET_INT_VALUE(vals+2,  cell->user_flags);
	} else {
		VAL_NULL(vals) = 1;
		VAL_NULL(vals+1) = 1;
		SET_INT_VALUE(vals+2,  0);
	}
}



void dialog_update_db(unsigned int ticks, void * param)
{
	static db_ps_t my_ps_update = NULL;
	static db_ps_t my_ps_insert = NULL;
	int index;
	db_val_t values[DIALOG_TABLE_TOTAL_COL_NO];
	struct dlg_entry entry;
	struct dlg_cell  * cell; 
	unsigned char on_shutdown;
	int callee_leg,ins_done=0;
	static query_list_t *ins_list = NULL;

	db_key_t insert_keys[DIALOG_TABLE_TOTAL_COL_NO] = {	&h_entry_column,
			&h_id_column,		&call_id_column,		&from_uri_column,
			&from_tag_column,	&to_uri_column,			&to_tag_column,
			&from_sock_column,	&to_sock_column,		&start_time_column,
			&from_route_column,	&to_route_column, 	&from_contact_column,
			&to_contact_column, &mangled_fu_column, &mangled_tu_column,
			/*update chunk */
			&state_column,		&timeout_column,		&from_cseq_column,
			&to_cseq_column,	&from_ping_cseq_column, &to_ping_cseq_column,
			&vars_column,		&profiles_column,		&sflags_column, &flags_column};

	if (dialog_db_handle==0 || use_dialog_table()!=0)
		return;

	on_shutdown = (ticks==0);

	/*save the current dialogs information*/
	VAL_TYPE(values) = VAL_TYPE(values+1) = VAL_TYPE(values+9) = 
	VAL_TYPE(values+16) = VAL_TYPE(values+17) = VAL_TYPE(values+20) =
	VAL_TYPE(values+21) = VAL_TYPE(values+24) = VAL_TYPE(values+25)= DB_INT;

	VAL_TYPE(values+2) = VAL_TYPE(values+3) = VAL_TYPE(values+4) = 
	VAL_TYPE(values+5) = VAL_TYPE(values+6) = VAL_TYPE(values+7) = 
	VAL_TYPE(values+8) = VAL_TYPE(values+10) = VAL_TYPE(values+11) = 
	VAL_TYPE(values+12) = VAL_TYPE(values+13) = VAL_TYPE(values+14) =
	VAL_TYPE(values+15) = VAL_TYPE(values+18) = VAL_TYPE(values+19) = 
	VAL_TYPE(values+22) = VAL_TYPE(values+23) = DB_STR;

	for(index = 0; index< d_table->size; index++){

		/* lock the whole entry */
		entry = (d_table->entries)[index];
		dlg_lock( d_table, &entry);

		for(cell = entry.first; cell != NULL; cell = cell->next){

			callee_leg = callee_idx(cell);

			if( (cell->flags & DLG_FLAG_NEW) != 0 ) {

				if ( cell->state == DLG_STATE_DELETED ) {
					/* don't need to insert dialogs already terminated */
					continue;
				}
				LM_DBG("inserting new dialog %p\n",cell);

				SET_INT_VALUE(values, cell->h_entry);
				SET_INT_VALUE(values+1, cell->h_id);
				SET_STR_VALUE(values+2, cell->callid);
				SET_STR_VALUE(values+3, cell->from_uri);

				SET_STR_VALUE(values+4, cell->legs[DLG_CALLER_LEG].tag);
				SET_STR_VALUE(values+5, cell->to_uri);
				SET_STR_VALUE(values+6, cell->legs[callee_leg].tag);

				SET_STR_VALUE(values+7,
					cell->legs[DLG_CALLER_LEG].bind_addr->sock_str);
				if (cell->legs[callee_leg].bind_addr) {
					SET_STR_VALUE(values+8, 
						cell->legs[callee_leg].bind_addr->sock_str);
				} else {
					VAL_NULL(values+8) = 1;
				}

				SET_INT_VALUE(values+9,  cell->start_ts);

				SET_STR_VALUE(values+10, cell->legs[DLG_CALLER_LEG].route_set);
				SET_STR_VALUE(values+11,
					cell->legs[callee_leg].route_set);
				SET_STR_VALUE(values+12, cell->legs[DLG_CALLER_LEG].contact);
				SET_STR_VALUE(values+13,
					cell->legs[callee_leg].contact);


				SET_STR_VALUE(values+14,cell->legs[callee_leg].from_uri);
				SET_STR_VALUE(values+15,cell->legs[callee_leg].to_uri);

				SET_INT_VALUE(values+16, cell->state);
				SET_INT_VALUE(values+17, (unsigned int)((unsigned int)time(0)
					+ cell->tl.timeout - get_ticks()) );

				SET_STR_VALUE(values+18, cell->legs[DLG_CALLER_LEG].r_cseq);
				SET_STR_VALUE(values+19, cell->legs[callee_leg].r_cseq);

				SET_INT_VALUE(values+20, cell->legs[DLG_CALLER_LEG].last_gen_cseq);
				SET_INT_VALUE(values+21, cell->legs[callee_leg].last_gen_cseq);

				set_final_update_cols(values+22, cell, on_shutdown);
				SET_INT_VALUE(values+25, cell->flags);

				CON_PS_REFERENCE(dialog_db_handle) = &my_ps_insert;
				if (con_set_inslist(&dialog_dbf,dialog_db_handle,
				&ins_list,insert_keys,DIALOG_TABLE_TOTAL_COL_NO) < 0 )
					CON_RESET_INSLIST(dialog_db_handle);

				if((dialog_dbf.insert(dialog_db_handle, insert_keys, 
				values, DIALOG_TABLE_TOTAL_COL_NO)) !=0){
					LM_ERR("could not add another dialog to db\n");
					goto error;
				}

				if (ins_done==0)
					ins_done=1;

				/* dialog saved */
				run_dlg_callbacks( DLGCB_SAVED, cell, 0, DLG_DIR_NONE, 0);

				cell->flags &= ~(DLG_FLAG_NEW |DLG_FLAG_CHANGED);

			} else if ( (cell->flags & DLG_FLAG_CHANGED)!=0 || on_shutdown ){

				LM_DBG("updating existing dialog %p\n",cell);

				SET_INT_VALUE(values, cell->h_entry);
				SET_INT_VALUE(values+1, cell->h_id);

				SET_INT_VALUE(values+16, cell->state);
				SET_INT_VALUE(values+17, (unsigned int)((unsigned int)time(0)
					 + cell->tl.timeout - get_ticks()) );
				SET_STR_VALUE(values+18, cell->legs[DLG_CALLER_LEG].r_cseq);
				SET_STR_VALUE(values+19, cell->legs[callee_leg].r_cseq);
				SET_INT_VALUE(values+20, cell->legs[DLG_CALLER_LEG].last_gen_cseq);
				SET_INT_VALUE(values+21, cell->legs[callee_leg].last_gen_cseq);

				set_final_update_cols(values+22, cell, on_shutdown);
				SET_INT_VALUE(values+25, cell->flags);

				CON_PS_REFERENCE(dialog_db_handle) = &my_ps_update;

				if((dialog_dbf.update(dialog_db_handle, (insert_keys), 0, 
				(values), (insert_keys+16), (values+16), 2, 10)) !=0) {
					LM_ERR("could not update database info\n");
					goto error;
				}

				/* dialog saved */
				run_dlg_callbacks( DLGCB_SAVED, cell, 0, DLG_DIR_NONE, 0);

				cell->flags &= ~DLG_FLAG_CHANGED;
			}

		}
		dlg_unlock( d_table, &entry);

	}

	if (ins_done) {
		LM_DBG("dlg timer attempting to flush rows to DB\n");
		/* flush everything to DB
		 * so that next-time timer fires
		 * we are sure that DB updates will be succesful */
		if (ql_flush_rows(&dialog_dbf,dialog_db_handle,ins_list) < 0)
			LM_ERR("failed to flush rows to DB\n");
	}

	return;

error:
	dlg_unlock( d_table, &entry);
}

