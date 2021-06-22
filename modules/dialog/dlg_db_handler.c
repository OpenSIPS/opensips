/*
 * Copyright (C) 2009-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "../../pt.h"
#include "dlg_hash.h"
#include "dlg_db_handler.h"
#include "dlg_cb.h"
#include "dlg_profile.h"
#include "dlg_replication.h"

str dlg_id_column			=	str_init(DLG_ID_COL);
str call_id_column			=	str_init(CALL_ID_COL);
str from_uri_column			=	str_init(FROM_URI_COL);
str from_tag_column			=	str_init(FROM_TAG_COL);
str to_uri_column			=	str_init(TO_URI_COL);
str to_tag_column			=	str_init(TO_TAG_COL);
str state_column			=	str_init(STATE_COL);
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
str mflags_column			=	str_init(MFLAGS_COL);
str flags_column			=	str_init(FLAGS_COL);
str rt_on_answer_column		=	str_init(RT_ON_ANSWER_COL);
str rt_on_timeout_column	=	str_init(RT_ON_TIMEOUT_COL);
str rt_on_hangup_column		=	str_init(RT_ON_HANGUP_COL);
str dialog_table_name		=	str_init(DIALOG_TABLE_NAME);
int dlg_db_mode				=	DB_MODE_NONE;

static db_con_t* dialog_db_handle    = 0; /* database connection handle */
static db_func_t dialog_dbf;

extern int active_dlgs_cnt;
extern int early_dlgs_cnt;
extern int dlg_bulk_del_no;

static inline void set_final_update_cols(db_val_t *, struct dlg_cell *, int);

#define SET_BIGINT_VALUE(_val, _bigint)\
	do{\
		VAL_BIGINT(_val)   = _bigint;\
		VAL_NULL(_val) = 0;\
	}while(0);

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

#define SET_ROUTE_VALUE(_val, _idx) \
	do {\
		if (_idx) { \
			VAL_STRING((_val)) = sroutes->request[_idx].name;\
			VAL_NULL((_val)) = 0;\
		} else {\
			VAL_STRING((_val)) = NULL;\
			VAL_NULL((_val)) = 1;\
		}\
	}while(0)

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

#define GET_ROUTE_VALUE(_res, _values, _index) \
	do { \
		if (VAL_NULL((_values)+ (_index))) { \
			(_res) = 0; \
		} else { \
			str __s;\
			__s.s = VAL_STR((_values)+ (_index)).s;\
			__s.len = strlen(VAL_STR((_values)+ (_index)).s);\
			(_res) =  get_script_route_ID_by_name_str( &__s, \
				sroutes->request, RT_NO);\
			if ((_res)==-1) { \
				LM_WARN("loaded <%.*s> route not found " \
				"in the script\n", __s.len, __s.s); \
				(_res) = 0; \
			}\
		}\
	} while(0)


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

	if (dlg_db_mode == DB_MODE_DELAYED) {
		if (register_timer("dlg-dbupdate",dialog_update_db,
		(void*)(unsigned long)1 /*do locking*/,
		db_update_period, TIMER_FLAG_SKIP_ON_DELAY)<0 ) {
			LM_ERR("failed to register update db\n");
			return -1;
		}
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
	db_key_t query_cols[DIALOG_TABLE_TOTAL_COL_NO] = {
			&dlg_id_column,		&call_id_column,	&from_uri_column,
			&from_tag_column,	&to_uri_column,		&to_tag_column,
			&start_time_column,	&state_column,		&timeout_column,
			&from_cseq_column,	&to_cseq_column,	&from_route_column,
			&to_route_column,	&from_contact_column,&to_contact_column,
			&from_sock_column,	&to_sock_column,	&vars_column,
			&profiles_column,	&sflags_column,		&from_ping_cseq_column,
			&to_ping_cseq_column,&flags_column,		&mangled_fu_column,
			&mangled_tu_column,	&mflags_column,		&rt_on_answer_column,
			&rt_on_timeout_column,&rt_on_hangup_column};

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
		*no_rows = estimate_available_rows( 4+255+128+64+128+64+64+64+11+11+4+4
				+512+512+128+128+64+64+4+4+4+4096+512+4+4+4+16+16+16,
				DIALOG_TABLE_TOTAL_COL_NO );

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
	while (b<end) {
		if (*b=='|' || *b=='#')
			break;
		else if (*b == '\\')
			b++;
		b++;
	}
	if (b>=end) return NULL;
	if (*b=='|') goto skip;
	name->len = b - name->s;
	if (name->len==0) goto skip;
	strip_esc(name);
	/*LM_DBG("-----read name <%.*s>(%d)\n",name->len,name->s,name->len);*/

	/* read # */
	b++;

	/* read value */
	val->s = b;
	while (b<end) {
		if (*b=='|' || *b=='#')
			break;
		else if (*b == '\\')
			b++;
		b++;
	}
	if (b>=end) return NULL;
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

/* The function is always considered to be lock-less ( safe )
 * it's either called when dialog is not linked yes, or is under the dialog lock */
void read_dialog_vars(char *b, int l, struct dlg_cell *dlg)
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
		if (store_dlg_value_unsafe( dlg, &name, &val)!=0)
			LM_ERR("failed to add val, skipping...\n");
	} while(p!=end);

}


void read_dialog_profiles(char *b, int l, struct dlg_cell *dlg,int double_check,
															char is_replicated)
{
	struct dlg_profile_table *profile;
	struct dlg_profile_link *it;
	str name, val,double_check_name;
	char *end;
	char *p,*s,*e;
	char bk;
	unsigned repl_type;

	end = b + l;
	p = b;

	do {
		/* read a new pair from input string */
		p = read_pair( p, end, &name, &val);
		if (p==NULL) break;

		LM_DBG("new profile found  <%.*s>=<%.*s>\n",name.len,name.s,val.len,val.s);

		if (double_check) {
			LM_DBG("Double checking profile - if it exists we'll skip it \n");
			repl_type = REPL_NONE;

			/* check if this is a shared profile, and remove /s for manual
			 * matching */
			double_check_name = name;
			s = memchr(name.s, '/', name.len);

			if (s) {
				e = double_check_name.s + double_check_name.len;
				double_check_name.len = s - double_check_name.s;
				trim_spaces_lr( double_check_name );
				/* skip spaces after p */
				for (++s; *s == ' ' && s < e; s++);
				if ( s < e && *s == 's')
				repl_type = REPL_CACHEDB;
				else if (s < e && *s == 'b')
				repl_type = REPL_PROTOBIN;
			}

			if (dlg->locked_by != process_no)
				dlg_lock_dlg(dlg);

			for (it=dlg->profile_links;it;it=it->next) {
				if (it->profile->repl_type == repl_type &&
					it->profile->name.len == double_check_name.len &&
					memcmp(it->profile->name.s,double_check_name.s,
						   double_check_name.len) == 0) {
					if (dlg->locked_by != process_no)
						dlg_unlock_dlg(dlg);
					LM_DBG("Profile is already linked into the dlg\n");
					goto next;
				}
			}

			if (dlg->locked_by != process_no)
				dlg_unlock_dlg(dlg);
		}

		/* add to the profile */
		profile = search_dlg_profile( &name );
		if (profile==NULL) {
			LM_DBG("profile <%.*s> does not exist now, creating it\n",name.len,name.s);
			/* create a new one */
			bk = name.s[name.len];
			name.s[name.len] = 0;
			if (add_profile_definitions(name.s, (val.len && val.s)?1:0 ) != 0) {
				LM_ERR("failed to add dialog profile <%.*s>\n", name.len, name.s);
				name.s[name.len] = bk;
				continue;
			}
			name.s[name.len] = bk;
			/* double check the created profile */
			profile = search_dlg_profile(&name);
			if (profile == NULL) {
				LM_CRIT("BUG - cannot find just added dialog profile <%.*s>\n", name.len, name.s);
				continue;
			}
		}
		if (set_dlg_profile( dlg, profile->has_value ? &val : NULL, profile,
		    is_replicated) < 0 )
			LM_ERR("failed to add to profile, skipping....\n");
		next:
			;
	} while(p!=end);

	return;
}


int remove_ended_dlgs_from_db(void)
{
	static db_ps_t my_ps = NULL;
	db_val_t values[1];
	db_key_t match_keys[1] = { &state_column};

	if (use_dialog_table()!=0)
		return -1;

	VAL_TYPE(values) = DB_INT;
	VAL_NULL(values) = 0;

	VAL_INT(values) = DLG_STATE_DELETED ;

	CON_PS_REFERENCE(dialog_db_handle) = &my_ps;

	if(dialog_dbf.delete(dialog_db_handle, match_keys, 0, values, 1) < 0) {
		LM_ERR("failed to delete database information\n");
		return -1;
	}

	return 0;
}

static int load_dialog_info_from_db(int dlg_hash_size)
{
	db_res_t * res;
	db_val_t * values;
	db_row_t * rows;
	int i, nr_rows;
	struct dlg_cell *dlg;
	struct dlg_entry *d_entry;
	str callid, from_uri, to_uri, from_tag, to_tag;
	str cseq1,cseq2,contact1,contact2,rroute1,rroute2,mangled_fu,mangled_tu;
	int no_rows = 10;
	struct socket_info *caller_sock,*callee_sock;
	int found_ended_dlgs=0;
	unsigned int hash_entry,hash_id;
	str tag_name;
	int rc;

	res = 0;
	if((nr_rows = select_entire_dialog_table(&res,&no_rows)) < 0)
		goto error;

	nr_rows = RES_ROW_N(res);

	do {
		LM_DBG("loading information from database for %i dialogs\n", nr_rows);

		rows = RES_ROWS(res);

		/* for every row---dialog */
		for(i=0; i<nr_rows; i++){

			values = ROW_VALUES(rows + i);

			if (VAL_NULL(values) || VAL_TYPE(values) != DB_BIGINT) {
				LM_ERR("column %.*s cannot be null/has wrong type %d -> skipping\n",
					dlg_id_column.len,dlg_id_column.s,VAL_TYPE(values));
				continue;
			}

			dlg_parse_db_id(VAL_BIGINT(values), hash_entry, hash_id);

			if (VAL_NULL(values+6) || VAL_NULL(values+7)) {
				LM_ERR("columns %.*s or/and %.*s cannot be null -> skipping\n",
					start_time_column.len, start_time_column.s,
					state_column.len, state_column.s);
				continue;
			}

			if ( VAL_INT(values+7) == DLG_STATE_DELETED ) {
				LM_INFO("dialog already terminated -> skipping\n");
				found_ended_dlgs=1;
				continue;
			}

			caller_sock = create_socket_info(values, 15);
			callee_sock = create_socket_info(values, 16);
			if (caller_sock == NULL || callee_sock == NULL) {
				LM_ERR("Dialog in DB doesn't match any listening sockets\n");
				continue;
			}

			/*restore the dialog info*/
			GET_STR_VALUE(callid, values, 1, 1, 0);
			GET_STR_VALUE(from_tag, values, 3, 1, 0);
			GET_STR_VALUE(to_tag, values, 5, 1, 0);

			d_entry = &d_table->entries[hash_entry];
			dlg_lock(d_table, d_entry);

			if (get_dlg_unsafe(d_entry, &callid, &from_tag, &to_tag,
			                   &dlg) == 0) {
				/*
				 * there are two cases that could lead here:
				 * 1) a race condition between the loading from DB and events
				 *    received over a replicated channel - in this case we
				 *    double check if the dialog has the same callid, and if
				 *    we do, we drop the loaded dialog, as it has already been
				 *    learned through replication
				 * 2) a call looping scenario - a call that passes more than
				 *    once through the same OpenSIPS instance, basically
				 *    creating different dialogs with different hash IDs - in
				 *    this case we shall learn the new dialog (Ticket #2311)
				 */
				if (dlg->h_id == hash_id) {
					dlg_unlock(d_table, d_entry);
					LM_DBG("dialog already exists, skipping (ci: %.*s, did: %u.%u)\n",
							callid.len, callid.s, hash_entry, hash_id);
					continue;
				}
			}

			GET_STR_VALUE(from_uri, values, 2, 1, 0);
			GET_STR_VALUE(to_uri, values, 4, 1, 0);

			if((dlg=build_new_dlg(&callid, &from_uri, &to_uri, &from_tag))==0){
				LM_ERR("failed to build new dialog\n");
				goto error_unlock;
			}

			if(dlg->h_entry != hash_entry){
				LM_ERR("inconsistent hash data in the dialog database: "
					"you may have restarted opensips using a different "
					"hash_size: please erase %.*s database and restart\n"
					"dlg : %u, db : %u\n",
					dialog_table_name.len, dialog_table_name.s,
					dlg->h_entry,hash_entry);
				shm_free(dlg);
				continue;
			}

			/* link the dialog */
			link_dlg_unsafe(d_entry, dlg);

			dlg->h_id = hash_id;

			/* next_id follows the max value of all loaded ids */
			if (d_table->entries[dlg->h_entry].next_id <= dlg->h_id)
				d_table->entries[dlg->h_entry].next_id = dlg->h_id + 1;

			GET_STR_VALUE(to_tag, values, 5, 1, 1);

			dlg->start_ts	= VAL_INT(values+6);

			dlg->state 		= VAL_INT(values+7);

			GET_STR_VALUE(cseq1, values, 9 , 1, 1);
			GET_STR_VALUE(cseq2, values, 10 , 1, 1);
			GET_STR_VALUE(rroute1, values, 11, 0, 0);
			GET_STR_VALUE(rroute2, values, 12, 0, 0);
			GET_STR_VALUE(contact1, values, 13, 0, 1);
			GET_STR_VALUE(contact2, values, 14, 0, 1);

			GET_STR_VALUE(mangled_fu, values, 23,0,1);
			GET_STR_VALUE(mangled_tu, values, 24,0,1);

			/* add the 2 legs */
			if ( (dlg_update_leg_info(0, dlg, &from_tag, &rroute1, &contact1,
			NULL, &cseq1, caller_sock,0,0,0,0)!=0) ||
			(dlg_update_leg_info(1, dlg, &to_tag, &rroute2, &contact2,
			NULL, &cseq2, callee_sock,&mangled_fu,&mangled_tu,0,0)!=0) ) {
				LM_ERR("dlg_set_leg_info failed\n");
				/* destroy the dialog */
				unref_dlg_unsafe(dlg, 1, d_entry);
				continue;
			}
			dlg->legs_no[DLG_LEG_200OK] = DLG_FIRST_CALLEE_LEG;

			/* script variables */
			if (!VAL_NULL(values+17)) {
				if (VAL_TYPE(values+17) == DB_BLOB) {
					read_dialog_vars( VAL_BLOB(values+17).s,
							VAL_BLOB(values+17).len, dlg);
				} else {
					LM_ERR("non-blob variables column - cannot store dialog variables\n");
				}
			}

			/* script flags */
			if (!VAL_NULL(values+19)) {
				dlg->user_flags = VAL_INT(values+19);
			}

			/* module flags */
			if (!VAL_NULL(values+25)) {
				dlg->mod_flags = VAL_INT(values+25);
			}

			/* the script routes */
			GET_ROUTE_VALUE( dlg->rt_on_answer, values, 26);
			GET_ROUTE_VALUE( dlg->rt_on_timeout, values, 27);
			GET_ROUTE_VALUE( dlg->rt_on_hangup, values, 28);

			/* dialog flags */
			dlg->flags = VAL_INT(values+22);
			if (dlg_db_mode==DB_MODE_SHUTDOWN)
				dlg->flags |= DLG_FLAG_NEW;

			/* mark this dialog as loaded from DB in order to drop it when
			 * syncing from cluster is finished */
			dlg->flags |= DLG_FLAG_FROM_DB;

			/* calculate timeout */
			dlg->tl.timeout = (unsigned int)(VAL_INT(values+8));
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
				unref_dlg_unsafe(dlg, 1, d_entry);
				continue;
			}

			/* reference the dialog as kept in the timer list + this ref */
			ref_dlg_unsafe(dlg, 2);
			LM_DBG("current dialog timeout is %u\n", dlg->tl.timeout);

			dlg->lifetime = 0;

			dlg->legs[DLG_CALLER_LEG].last_gen_cseq =
				(unsigned int)(VAL_INT(values+20));
			dlg->legs[callee_idx(dlg)].last_gen_cseq =
				(unsigned int)(VAL_INT(values+21));

			dlg_unlock(d_table, d_entry);

			/* profiles */
			if (!VAL_NULL(values+18))
				read_dialog_profiles( VAL_STR(values+18).s,
					strlen(VAL_STR(values+18).s), dlg, 0, 0);

			if (dlg->flags & DLG_FLAG_PING_CALLER || dlg->flags & DLG_FLAG_PING_CALLEE) {
				if (0 != insert_ping_timer(dlg))
					LM_CRIT("Unable to insert dlg %p into ping timer\n",dlg);
				else {
					/* reference dialog as kept in ping timer list */
					ref_dlg(dlg, 1);
				}
			}


			if (restore_reinvite_pinging(dlg) != 0)
				LM_ERR("failed to fetch some Re-INVITE pinging data\n");
			if (dlg_has_reinvite_pinging(dlg)) {
				/* re-populate Re-INVITE pinging fields */
				if (0 != insert_reinvite_ping_timer(dlg))
					LM_CRIT("Unable to insert dlg %p into reinvite"
					        "ping timer\n", dlg);
				else
					/* reference dialog as kept in reinvite ping timer list */
					ref_dlg(dlg, 1);
			}

			if ((rc = fetch_dlg_value(dlg, &shtag_dlg_val, &tag_name, 0)) == 0) {
				if (shm_str_dup(&dlg->shtag, &tag_name) < 0)
					LM_ERR("No more shm memory\n");
			} else if (rc == -1)
				LM_ERR("Failed to get dlg value for sharing tag\n");

			if (dlg_db_mode == DB_MODE_DELAYED) {
				/* to be later removed by timer */
				ref_dlg(dlg, 1);
			}

			if (dlg->state==DLG_STATE_CONFIRMED_NA ||
			dlg->state==DLG_STATE_CONFIRMED) {
				active_dlgs_cnt++;
			} else if (dlg->state==DLG_STATE_EARLY) {
				early_dlgs_cnt++;
			}
			run_load_callback_per_dlg(dlg);
			unref_dlg(dlg, 1);

			next_dialog:;
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

	dialog_dbf.free_result(dialog_db_handle, res);
	if (found_ended_dlgs)
		remove_ended_dlgs_from_db();
	return 0;

error_unlock:
	dlg_unlock(d_table, d_entry);
error:
	dialog_dbf.free_result(dialog_db_handle, res);
	if (found_ended_dlgs)
		remove_ended_dlgs_from_db();
	return -1;
}

static struct dlg_cell **dlg_del_holder=NULL;
static int dlg_del_curr_no=0;
static db_val_t *dlg_del_values=NULL;
static db_key_t *dlg_del_keys=NULL;

int dlg_timer_remove_from_db(struct dlg_cell *cell)
{
	static db_ps_t my_ps = NULL;
	int i;

	/* here we are in the context of the dlg timer
	 * dialog d_entry is locked and we also have an extra ref
	 * that must be released when we attempt the delete */

	if (dlg_del_holder == NULL) {
		LM_DBG("First time dialog del is attempted\n");

		/* allocate all needed structures */
		dlg_del_holder = pkg_malloc(dlg_bulk_del_no *
						sizeof(struct dlg_cell *));
		if (!dlg_del_holder) {
			LM_ERR("No more pkg for dlg delete holders\n");
			return -1;
		}
		memset(dlg_del_holder,0,dlg_bulk_del_no*sizeof(struct dlg_cell *));

		dlg_del_values = pkg_malloc(dlg_bulk_del_no *
						sizeof(db_val_t));
		if (!dlg_del_values) {
			LM_ERR("No more pkg for dlg delete values\n");
			pkg_free(dlg_del_holder);
			return -1;
		}

		for (i=0;i<dlg_bulk_del_no;i++) {
			VAL_TYPE(dlg_del_values+i) = DB_BIGINT;
			VAL_NULL(dlg_del_values+i) = 0;
		}

		dlg_del_keys = pkg_malloc(dlg_bulk_del_no *
						sizeof(db_key_t));
		if (!dlg_del_keys) {
			LM_ERR("No more pkg for dlg_delete keys\n");
			pkg_free(dlg_del_holder);
			pkg_free(dlg_del_values);
			return -1;
		}

		for (i=0;i<dlg_bulk_del_no;i++)
			dlg_del_keys[i] = &dlg_id_column;
	}

	/* store info in del holders */
	VAL_BIGINT(dlg_del_values+dlg_del_curr_no) = dlg_get_db_id(cell);
	dlg_del_holder[dlg_del_curr_no]=cell;
	/* mark is as deleted so we don't care about it later
	 * in the timer */
	cell->flags |= DLG_FLAG_DB_DELETED;
	dlg_del_curr_no++;

	if (dlg_del_curr_no == dlg_bulk_del_no) {
		LM_DBG("triggering delete for %d dialogs\n",dlg_del_curr_no);

		CON_PS_REFERENCE(dialog_db_handle) = &my_ps;
		CON_USE_OR_OP(dialog_db_handle);
		if(dialog_dbf.delete(dialog_db_handle, dlg_del_keys,
					0, dlg_del_values, dlg_bulk_del_no) < 0)
			LM_ERR("failed to delete bulk database information !!!\n");

		/* from timer point of view, we are done with the dialogs */
		for (i=0;i<dlg_bulk_del_no;i++) {
			cell = dlg_del_holder[i];
			unref_dlg_unsafe(cell,1,&(d_table->entries[cell->h_entry]));
		}

		dlg_del_curr_no = 0;
	}

	/* still not enough piled up dialogs - wait for more */
	return 0;
}

int dlg_timer_flush_del(void)
{
	struct dlg_cell *cell;
	int i;

	/* here we are in the context of the dlg timer
	 * we also have an extra ref
	 * that must be released when we attempt the delete */

	if (dlg_del_curr_no > 0) {
		CON_USE_OR_OP(dialog_db_handle);
		if(dialog_dbf.delete(dialog_db_handle, dlg_del_keys,
					0, dlg_del_values, dlg_del_curr_no) < 0)
			LM_ERR("failed to delete bulk database information !!!\n");

		/* from timer point of view, we are done with the dialogs */
		for (i=0;i<dlg_del_curr_no;i++) {
			cell = dlg_del_holder[i];
			unref_dlg(cell,1);
		}

		dlg_del_curr_no = 0;
	}

	return 0;
}

int remove_dialog_from_db(struct dlg_cell * cell)
{
	static db_ps_t my_ps = NULL;
	db_val_t values[1];
	db_key_t match_keys[1] = { &dlg_id_column };

	/*if the dialog hasn 't been yet inserted in the database*/
	LM_DBG("trying to remove a dialog, flags are %u\n", cell->flags);
	if (cell->flags & DLG_FLAG_NEW)
		return 0;

	if (use_dialog_table()!=0)
		return -1;

	VAL_TYPE(values) = DB_BIGINT;
	VAL_NULL(values) = 0;

	VAL_BIGINT(values) = dlg_get_db_id(cell);

	CON_PS_REFERENCE(dialog_db_handle) = &my_ps;

	if(dialog_dbf.delete(dialog_db_handle, match_keys, 0, values, 1) < 0) {
		LM_ERR("failed to delete database information\n");
		return -1;
	}

	LM_DBG("callid was %.*s\n", cell->callid.len, cell->callid.s );

	/* dialog saved */
	run_dlg_callbacks(DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL, 1, 1);

	return 0;
}

int update_dialog_timeout_info(struct dlg_cell * cell)
{
	static db_ps_t my_ps_update = NULL;
	struct dlg_entry entry;
	db_val_t values[2];

	db_key_t insert_keys[DIALOG_TABLE_TOTAL_COL_NO] = {
			&dlg_id_column,      &timeout_column};

	if(use_dialog_table()!=0)
		return -1;

	if (!(cell->flags & DLG_FLAG_CHANGED))
		return 0;

	/* save only dialog's state and timeout */
	VAL_TYPE(values) = DB_BIGINT;
	VAL_TYPE(values+1) = DB_INT;

	/* lock the entry */
	entry = (d_table->entries)[cell->h_entry];
	dlg_lock( d_table, &entry);

	SET_BIGINT_VALUE(values, dlg_get_db_id(cell));
	SET_INT_VALUE(values+1, (unsigned int)( (unsigned int)time(0) +
			 cell->tl.timeout - get_ticks()) );

	CON_PS_REFERENCE(dialog_db_handle) = &my_ps_update;

	if((dialog_dbf.update(dialog_db_handle, (insert_keys), 0,
					(values), (insert_keys+1), (values+1), 1, 1)) !=0){
		LM_ERR("could not update database timeout info\n");
		goto error;
	}

	/* dialog saved */
	run_dlg_callbacks( DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL, 1, 1);

	cell->flags &= ~(DLG_FLAG_CHANGED);

	dlg_unlock( d_table, &entry);
	return 0;

error:
	dlg_unlock( d_table, &entry);
	return -1;
}

int update_dialog_dbinfo(struct dlg_cell * cell)
{
	static db_ps_t my_ps_insert = NULL;
	static db_ps_t my_ps_update = NULL;
	static db_ps_t my_ps_update_vp = NULL;
	struct dlg_entry entry;
	db_val_t values[DIALOG_TABLE_TOTAL_COL_NO];
	int callee_leg;

	db_key_t insert_keys[DIALOG_TABLE_TOTAL_COL_NO] = {
			&dlg_id_column,      &call_id_column,      &from_uri_column,
			&from_tag_column,    &to_uri_column,       &to_tag_column,
			&from_sock_column,   &to_sock_column,
			&start_time_column,  &mangled_fu_column,   &mangled_tu_column,

			&state_column,       &timeout_column,
			&from_cseq_column,   &to_cseq_column,      &from_ping_cseq_column,
			&to_ping_cseq_column,&flags_column,
			&vars_column,        &profiles_column,     &sflags_column,
			&mflags_column,      &from_contact_column,
			&to_contact_column,  &from_route_column,   &to_route_column,
			&rt_on_answer_column,&rt_on_timeout_column,&rt_on_hangup_column};

	if(use_dialog_table()!=0)
		return -1;

	callee_leg= callee_idx(cell);

	if((cell->flags & DLG_FLAG_NEW) != 0){
		/* save all the current dialogs information*/
		VAL_TYPE(values) = DB_BIGINT;

		VAL_TYPE(values+8) = VAL_TYPE(values+11) = VAL_TYPE(values+12) =
		VAL_TYPE(values+15) =VAL_TYPE(values+16) = VAL_TYPE(values+17) =
		VAL_TYPE(values+20) = VAL_TYPE(values+21) = DB_INT;

		VAL_TYPE(values+1) = VAL_TYPE(values+2) = VAL_TYPE(values+3) =
		VAL_TYPE(values+4) = VAL_TYPE(values+5) = VAL_TYPE(values+6) =
		VAL_TYPE(values+7) = VAL_TYPE(values+9) = VAL_TYPE(values+10) =
		VAL_TYPE(values+13) = VAL_TYPE(values+14) = VAL_TYPE(values+19) =
		VAL_TYPE(values+22) = VAL_TYPE(values+23) = VAL_TYPE(values+24) =
		VAL_TYPE(values+25) = DB_STR;
		VAL_TYPE(values+26) = VAL_TYPE(values+27) = VAL_TYPE(values+28) =
		DB_STRING;
		VAL_TYPE(values+18) = DB_BLOB;

		/* lock the entry */
		entry = (d_table->entries)[cell->h_entry];
		dlg_lock( d_table, &entry);

		SET_BIGINT_VALUE(values, dlg_get_db_id(cell));
		/* to be later removed by timer */SET_STR_VALUE(values+1, cell->callid);

		SET_STR_VALUE(values+2, cell->from_uri);
		SET_STR_VALUE(values+3, cell->legs[DLG_CALLER_LEG].tag);
		SET_STR_VALUE(values+4, cell->to_uri);
		SET_STR_VALUE(values+5, cell->legs[callee_leg].tag);

		SET_STR_VALUE(values+6, cell->legs[DLG_CALLER_LEG].bind_addr->sock_str);
		if (cell->legs[callee_leg].bind_addr) {
			SET_STR_VALUE(values+7,
				cell->legs[callee_leg].bind_addr->sock_str);
		} else {
			VAL_NULL(values+7) = 1;
		}

		SET_INT_VALUE(values+8, cell->start_ts);

		SET_STR_VALUE(values+9,cell->legs[callee_leg].from_uri);
		SET_STR_VALUE(values+10,cell->legs[callee_leg].to_uri);

		SET_INT_VALUE(values+11, cell->state);
		SET_INT_VALUE(values+12, (unsigned int)( (unsigned int)time(0) +
			 cell->tl.timeout - get_ticks()) );

		SET_STR_VALUE(values+13, cell->legs[DLG_CALLER_LEG].r_cseq);
		SET_STR_VALUE(values+14, cell->legs[callee_leg].r_cseq);
		SET_INT_VALUE(values+15,cell->legs[DLG_CALLER_LEG].last_gen_cseq);
		SET_INT_VALUE(values+16,cell->legs[callee_leg].last_gen_cseq);
		SET_INT_VALUE(values+17, cell->flags &
				~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED|DLG_FLAG_DB_DELETED));
		set_final_update_cols(values+18, cell, 0);
		SET_STR_VALUE(values+22, cell->legs[DLG_CALLER_LEG].contact);
		SET_STR_VALUE(values+23, cell->legs[callee_leg].contact);
		SET_STR_VALUE(values+24, cell->legs[DLG_CALLER_LEG].route_set);
		SET_STR_VALUE(values+25, cell->legs[callee_leg].route_set);

		SET_ROUTE_VALUE(values+26, cell->rt_on_answer);
		SET_ROUTE_VALUE(values+27, cell->rt_on_timeout);
		SET_ROUTE_VALUE(values+28, cell->rt_on_hangup);

		CON_PS_REFERENCE(dialog_db_handle) = &my_ps_insert;

		if((dialog_dbf.insert(dialog_db_handle, insert_keys, values,
								DIALOG_TABLE_TOTAL_COL_NO)) !=0){
			LM_ERR("could not add another dialog to db - state=%d callid=%.*s\n",
					cell->state, cell->callid.len, cell->callid.s);
			goto error;
		}

		/* dialog saved */
		run_dlg_callbacks(DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL, 1, 1);

		cell->flags &= ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED);

	} else if((cell->flags & DLG_FLAG_CHANGED) != 0) {
		/* save only dialog's state and timeout */
		VAL_TYPE(values) = DB_BIGINT;
		VAL_TYPE(values+11) = VAL_TYPE(values+12) = VAL_TYPE(values+15) =
		VAL_TYPE(values+16) = VAL_TYPE(values+17) = VAL_TYPE(values+20) =
		VAL_TYPE(values+21) = DB_INT;

		VAL_TYPE(values+13) = VAL_TYPE(values+14) = VAL_TYPE(values+19) =
		VAL_TYPE(values+22) = VAL_TYPE(values+23) = DB_STR;
		VAL_TYPE(values+18) = DB_BLOB;

		/* lock the entry */
		entry = (d_table->entries)[cell->h_entry];
		dlg_lock( d_table, &entry);

		SET_BIGINT_VALUE(values, dlg_get_db_id(cell));
		SET_INT_VALUE(values+11, cell->state);
		SET_INT_VALUE(values+12, (unsigned int)( (unsigned int)time(0) +
				 cell->tl.timeout - get_ticks()) );

		SET_STR_VALUE(values+13, cell->legs[DLG_CALLER_LEG].r_cseq);
		SET_STR_VALUE(values+14, cell->legs[callee_leg].r_cseq);
		SET_INT_VALUE(values+15,cell->legs[DLG_CALLER_LEG].last_gen_cseq);
		SET_INT_VALUE(values+16,cell->legs[callee_leg].last_gen_cseq);
		SET_INT_VALUE(values+17, cell->flags &
				~(DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED|DLG_FLAG_DB_DELETED));
		set_final_update_cols(values+18, cell, 0);
		SET_STR_VALUE(values+22, cell->legs[DLG_CALLER_LEG].contact);
		SET_STR_VALUE(values+23, cell->legs[callee_leg].contact);

		CON_PS_REFERENCE(dialog_db_handle) = &my_ps_update;

		if((dialog_dbf.update(dialog_db_handle, (insert_keys), 0,
						(values), (insert_keys+11), (values+11), 1, 13)) !=0){
			LM_ERR("could not update database info\n");
			goto error;
		}

		/* dialog saved */
		run_dlg_callbacks(DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL, 1, 1);

		cell->flags &= ~(DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED);
	} else if (cell->flags & DLG_FLAG_VP_CHANGED) {
		VAL_TYPE(values) = DB_BIGINT;
		VAL_TYPE(values+18) = DB_BLOB;
		VAL_TYPE(values+19) = DB_STR;
		VAL_TYPE(values+20) = DB_INT;
		VAL_TYPE(values+21) = DB_INT;

		/* lock the entry */
		entry = (d_table->entries)[cell->h_entry];
		dlg_lock( d_table, &entry);

		SET_BIGINT_VALUE(values, dlg_get_db_id(cell));

		set_final_update_cols(values+18, cell, 0);

		CON_PS_REFERENCE(dialog_db_handle) = &my_ps_update_vp;

		if((dialog_dbf.update(dialog_db_handle, (insert_keys), 0,
						(values), (insert_keys+18), (values+18), 1, 4)) !=0){
			LM_ERR("could not update database info\n");
			goto error;
		}

		run_dlg_callbacks(DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL, 1, 1);

		cell->flags &= ~DLG_FLAG_VP_CHANGED;
	} else {
		return 0;
	}

	dlg_unlock( d_table, &entry);
	return 0;

error:
	dlg_unlock( d_table, &entry);
	return -1;
}


static inline unsigned int write_pair( char *b, str *name, str *name_suffix,
				str *val)
{
	int i,j;

	for( i=0,j=0 ; i<name->len ; i++) {
		if (name->s[i]=='|' || name->s[i]=='#' || name->s[i]=='\\')
			b[j++] = '\\';
		b[j++] = name->s[i];
	}
	if (name_suffix) {
		memcpy(b+j,name_suffix->s,name_suffix->len);
		j+=name_suffix->len;
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


str* write_dialog_vars( struct dlg_val *vars)
{
	static str o = {NULL,0};
	static int o_l=0;
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
	if ( o.s==NULL || o_l<l) {
		if (o.s) pkg_free(o.s);
		o.s = (char*)pkg_malloc(l);
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
		p += write_pair( p, &v->name,NULL, &v->val);
	}
	if (o.len!=p-o.s) {
		LM_CRIT("BUG - buffer overflow allocated %d, written %d\n",
			o.len,(int)(p-o.s));
		return NULL;
	}
	LM_DBG("var string is <%.*s>(%d)\n", l,o.s,l);

	return &o;
}

/* needs to be run under the dialog lock , since it iterates on the profile links, which might get
 * deallocated if the dialog ends */
str* write_dialog_profiles( struct dlg_profile_link *links)
{
	static str o = {NULL,0},cached_marker={"/s",2}, bin_marker={"/b", 2};
	static int o_l = 0;
	struct dlg_profile_link *link;
	unsigned int l,i;
	char *p;

	/* compute the required len */
	for ( link=links,l=0 ; link ; link=link->next) {
		l += link->profile->name.len + 1 + link->value.len + 1;
		for( i=0 ; i<link->profile->name.len ; i++ )
			if (link->profile->name.s[i]=='|' || link->profile->name.s[i]=='#'
					|| link->profile->name.s[i]=='\\') l++;
		for( i=0 ; i<link->value.len ; i++ )
			if (link->value.s[i]=='|' || link->value.s[i]=='#'
					|| link->value.s[i]=='\\') l++;
		if (link->profile->repl_type!=REPL_NONE/*==(CACHEDB||PROTOBIN)*/)
			l+=cached_marker.len; /* same length for both */
	}

	/* allocate the string to be stored */
	if ( o.s==NULL || o_l<l) {
		if (o.s) pkg_free(o.s);
		o.s = (char*)pkg_malloc(l);
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
		if (link->profile->repl_type == REPL_CACHEDB)
			p += write_pair( p, &link->profile->name, &cached_marker,
							&link->value);
		else if (link->profile->repl_type == REPL_PROTOBIN)
			p += write_pair( p, &link->profile->name, &bin_marker,
							&link->value);
		else
			p += write_pair( p, &link->profile->name, NULL, &link->value);
	}
	if (o.len!=p-o.s) {
		LM_CRIT("BUG - buffer overflow allocated %d, written %d\n",
			o.len,(int)(p-o.s));
		return NULL;
	}
	LM_DBG("profile string is <%.*s>(%d)\n", l,o.s,l);

	return &o;
}

/* duplicate the SDPs/Contacts of caller/callee(s) into dlg val storage */
int persist_reinvite_pinging(struct dlg_cell *dlg)
{
	str caller_in_sdp = str_init("uCSDP"), callee_in_sdp = str_init("ucSDP");
	str caller_out_sdp = str_init("aCSDP"), callee_out_sdp = str_init("acSDP");
	str caller_adv_ct = str_init("Cct"), callee_adv_ct = str_init("cct");

	if (dlg->legs_no[DLG_LEG_200OK] == 0) {
		LM_DBG("non-confirmed dialogs are not DB persistent!\n");
		return 0;
	}

	if (dlg->legs[DLG_CALLER_LEG].in_sdp.len &&
			store_dlg_value_unsafe(dlg, &caller_in_sdp,
				&dlg->legs[DLG_CALLER_LEG].in_sdp) != 0) {
		LM_ERR("failed to persist caller UAC SDP\n");
		return -1;
	}

	if (dlg->legs[DLG_CALLER_LEG].out_sdp.len &&
			store_dlg_value_unsafe(dlg, &caller_out_sdp,
				&dlg->legs[DLG_CALLER_LEG].out_sdp) != 0) {
		LM_ERR("failed to persist caller advertised SDP\n");
		return -1;
	}

	if (store_dlg_value_unsafe(dlg, &caller_adv_ct,
	                    &dlg->legs[DLG_CALLER_LEG].adv_contact) != 0) {
		LM_ERR("failed to persist caller advertised Contact\n");
		return -1;
	}

	if (dlg->legs[dlg->legs_no[DLG_LEG_200OK]].in_sdp.len &&
			store_dlg_value_unsafe(dlg, &callee_in_sdp,
				&dlg->legs[dlg->legs_no[DLG_LEG_200OK]].in_sdp) != 0) {
		LM_ERR("failed to persist callee UAC SDP\n");
		return -1;
	}

	if (dlg->legs[dlg->legs_no[DLG_LEG_200OK]].out_sdp.len &&
			store_dlg_value_unsafe(dlg, &callee_out_sdp,
				&dlg->legs[dlg->legs_no[DLG_LEG_200OK]].out_sdp) != 0) {
		LM_ERR("failed to persist callee advertised SDP\n");
		return -1;
	}

	if (store_dlg_value_unsafe(dlg, &callee_adv_ct,
	           &dlg->legs[dlg->legs_no[DLG_LEG_200OK]].adv_contact) != 0) {
		LM_ERR("failed to persist callee advertised Contact\n");
		return -1;
	}

	return 0;
}

/* re-populate the SDPs/Contacts of caller/callee(s) from dlg val storage */
int restore_reinvite_pinging(struct dlg_cell *dlg)
{
	str caller_in_sdp = str_init("uCSDP"), callee_in_sdp = str_init("ucSDP");
	str caller_out_sdp = str_init("aCSDP"), callee_out_sdp = str_init("acSDP");
	str caller_adv_ct = str_init("Cct"), callee_adv_ct = str_init("cct");
	str out_buf;
	int ret = 0;

	if (fetch_dlg_value(dlg, &caller_in_sdp, &out_buf, 0) != 0) {
		dlg->legs[DLG_CALLER_LEG].in_sdp.len = 0;
		dlg->legs[DLG_CALLER_LEG].in_sdp.s = 0;
	} else {
		if (shm_str_dup(&dlg->legs[DLG_CALLER_LEG].in_sdp, &out_buf) != 0) {
			LM_ERR("oom\n");
			ret = -1;
		}
	}

	if (fetch_dlg_value(dlg, &caller_out_sdp, &out_buf, 0) != 0) {
		dlg->legs[DLG_CALLER_LEG].out_sdp.len = 0;
		dlg->legs[DLG_CALLER_LEG].out_sdp.s = 0;
	} else {
		if (shm_str_dup(&dlg->legs[DLG_CALLER_LEG].out_sdp, &out_buf) != 0) {
			LM_ERR("oom\n");
			ret = -1;
		}
	}

	if (fetch_dlg_value(dlg, &caller_adv_ct, &out_buf, 0) != 0) {
		LM_ERR("failed to fetch caller advertised Contact\n");
		ret = -1;
	} else {
		if (shm_str_dup(&dlg->legs[DLG_CALLER_LEG].adv_contact,
		                &out_buf) != 0) {
			LM_ERR("oom\n");
			ret = -1;
		}
	}

	if (fetch_dlg_value(dlg, &callee_in_sdp, &out_buf, 0) != 0) {
		dlg->legs[DLG_FIRST_CALLEE_LEG].in_sdp.len = 0;
		dlg->legs[DLG_FIRST_CALLEE_LEG].in_sdp.s = 0;
	} else {
		if (shm_str_dup(&dlg->legs[DLG_FIRST_CALLEE_LEG].in_sdp, &out_buf) != 0) {
			LM_ERR("oom\n");
			ret = -1;
		}
	}


	if (fetch_dlg_value(dlg, &callee_out_sdp, &out_buf, 0) != 0) {
		dlg->legs[DLG_FIRST_CALLEE_LEG].out_sdp.len = 0;
		dlg->legs[DLG_FIRST_CALLEE_LEG].out_sdp.s = 0;
	} else {
		if (shm_str_dup(&dlg->legs[DLG_FIRST_CALLEE_LEG].out_sdp, &out_buf) != 0) {
			LM_ERR("oom\n");
			ret = -1;
		}
	}

	if (fetch_dlg_value(dlg, &callee_adv_ct, &out_buf, 0) != 0) {
		LM_ERR("failed to fetch callee advertised Contact\n");
		ret = -1;
	} else {
		if (shm_str_dup(&dlg->legs[DLG_FIRST_CALLEE_LEG].adv_contact,
		                &out_buf) != 0) {
			LM_ERR("oom\n");
			ret = -1;
		}
	}

	return ret;
}

static inline void set_final_update_cols(db_val_t *vals, struct dlg_cell *cell,
		int on_shutdown)
{
	str *s;

	LM_DBG("DLG vals and profiles should %s[%x:%d]\n",
			(db_flush_vp && (cell->flags & DLG_FLAG_VP_CHANGED)) ?
			"be saved" : "not be saved", cell->flags, db_flush_vp);

	if (on_shutdown || db_flush_vp) {
		/* it is very likely to flush the vals/profiles to DB, so trigger the
		 * callback to see if other modules may want to add more vals/profiles
		 before the actual writting */
		run_dlg_callbacks(DLGCB_WRITE_VP, cell, 0, DLG_DIR_NONE, NULL, 1, 1);
	}

	if (persist_reinvite_pinging(cell) != 0)
		LM_ERR("failed to persist some Re-INVITE pinging info\n");

	/* save sharing tag name as dlg val */
	if (cell->shtag.s && store_dlg_value_unsafe(cell, &shtag_dlg_val,
		&cell->shtag) < 0)
		LM_ERR("Failed to store sharing tag name as dlg val\n");

	if (on_shutdown || (db_flush_vp && (cell->flags & DLG_FLAG_VP_CHANGED))) {
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
		SET_INT_VALUE(vals+3,  cell->mod_flags);
	} else {
		VAL_NULL(vals) = 1;
		VAL_NULL(vals+1) = 1;
		SET_INT_VALUE(vals+2,  0);
		SET_INT_VALUE(vals+3,  0);
	}

}



void dialog_update_db(unsigned int ticks, void *do_lock)
{
	static db_ps_t my_ps_update = NULL;
	static db_ps_t my_ps_insert = NULL;
	static db_ps_t my_ps_update_vp = NULL;
	int index;
	db_val_t values[DIALOG_TABLE_TOTAL_COL_NO];
	struct dlg_entry *entry;
	struct dlg_cell  * cell,*next_cell;
	unsigned char on_shutdown;
	int callee_leg,ins_done=0;
	static query_list_t *ins_list = NULL;

	db_key_t insert_keys[DIALOG_TABLE_TOTAL_COL_NO] = {
			&dlg_id_column,		&call_id_column,		&from_uri_column,
			&from_tag_column,	&to_uri_column,			&to_tag_column,
			&from_sock_column,	&to_sock_column,		&start_time_column,
			&from_route_column,	&to_route_column, 	&mangled_fu_column,
			&mangled_tu_column, &from_contact_column, &to_contact_column,
			/*update chunk */
			&state_column,		&timeout_column,		&from_cseq_column,
			&to_cseq_column,	&from_ping_cseq_column, &to_ping_cseq_column,
			&vars_column,		&profiles_column,		&sflags_column,
			&mflags_column,		&flags_column,			&rt_on_answer_column,
			&rt_on_timeout_column,&rt_on_hangup_column};

	if (dialog_db_handle==0 || use_dialog_table()!=0)
		return;

	on_shutdown = (ticks==0);

	/*save the current dialogs information*/
	VAL_TYPE(values) = DB_BIGINT;
	VAL_TYPE(values+8) =
	VAL_TYPE(values+15) = VAL_TYPE(values+16) = VAL_TYPE(values+19) =
	VAL_TYPE(values+20) = VAL_TYPE(values+23) = VAL_TYPE(values+24)=
	VAL_TYPE(values+25) = DB_INT;

	VAL_TYPE(values+1) = VAL_TYPE(values+2) = VAL_TYPE(values+3) =
	VAL_TYPE(values+4) = VAL_TYPE(values+5) = VAL_TYPE(values+6) =
	VAL_TYPE(values+7) = VAL_TYPE(values+9) = VAL_TYPE(values+10) =
	VAL_TYPE(values+11) = VAL_TYPE(values+12) = VAL_TYPE(values+13) =
	VAL_TYPE(values+14) = VAL_TYPE(values+17) = VAL_TYPE(values+18) =
	VAL_TYPE(values+22) = DB_STR;

	VAL_TYPE(values+26) = VAL_TYPE(values+27) = VAL_TYPE(values+28) =
	DB_STRING;

	VAL_TYPE(values+21) = DB_BLOB;

	for(index = 0; index< d_table->size; index++){

		/* lock the whole entry */
		entry = &((d_table->entries)[index]);
		if (do_lock)
			dlg_lock( d_table, entry);

		for (cell = entry->first; cell != NULL; ) {
			callee_leg = callee_idx(cell);

			if( (cell->flags & DLG_FLAG_NEW) != 0 ) {
				if ( cell->state == DLG_STATE_DELETED ) {
					if (!(cell->flags & DLG_FLAG_DB_DELETED)) {
						/* first time we see this dialog */
						/* save pointer to next dialog */
						next_cell=cell->next;
						/* mark it as deleted so as we don't deal with it later */
						cell->flags |= DLG_FLAG_DB_DELETED;
						/* timer is done with this dialog */
						cell->locked_by = process_no;
						unref_dlg_unsafe(cell,1,entry);
						cell->locked_by = 0;
						cell=next_cell;
						continue;
					}
					/* timer was done with the dialog but somebody else
					 * is still holding the ref, just skip over it */
					cell=cell->next;
					continue;
				}
				LM_DBG("inserting new dialog %p\n",cell);

				SET_BIGINT_VALUE(values, dlg_get_db_id(cell));
				SET_STR_VALUE(values+1, cell->callid);
				SET_STR_VALUE(values+2, cell->from_uri);

				SET_STR_VALUE(values+3, cell->legs[DLG_CALLER_LEG].tag);
				SET_STR_VALUE(values+4, cell->to_uri);
				SET_STR_VALUE(values+5, cell->legs[callee_leg].tag);

				SET_STR_VALUE(values+6,
					cell->legs[DLG_CALLER_LEG].bind_addr->sock_str);
				if (cell->legs[callee_leg].bind_addr) {
					SET_STR_VALUE(values+7,
						cell->legs[callee_leg].bind_addr->sock_str);
				} else {
					VAL_NULL(values+7) = 1;
				}

				SET_INT_VALUE(values+8,  cell->start_ts);

				SET_STR_VALUE(values+9, cell->legs[DLG_CALLER_LEG].route_set);
				SET_STR_VALUE(values+10,
					cell->legs[callee_leg].route_set);

				SET_STR_VALUE(values+11,cell->legs[callee_leg].from_uri);
				SET_STR_VALUE(values+12,cell->legs[callee_leg].to_uri);

				SET_STR_VALUE(values+13, cell->legs[DLG_CALLER_LEG].contact);
				SET_STR_VALUE(values+14,
					cell->legs[callee_leg].contact);

				SET_INT_VALUE(values+15, cell->state);
				SET_INT_VALUE(values+16, (unsigned int)((unsigned int)time(0)
					+ cell->tl.timeout - get_ticks()) );

				SET_STR_VALUE(values+17, cell->legs[DLG_CALLER_LEG].r_cseq);
				SET_STR_VALUE(values+18, cell->legs[callee_leg].r_cseq);

				SET_INT_VALUE(values+19, cell->legs[DLG_CALLER_LEG].last_gen_cseq);
				SET_INT_VALUE(values+20, cell->legs[callee_leg].last_gen_cseq);

				set_final_update_cols(values+21, cell, on_shutdown);
				SET_INT_VALUE(values+25, cell->flags &
					~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED|DLG_FLAG_DB_DELETED));

				SET_ROUTE_VALUE(values+26, cell->rt_on_answer);
				SET_ROUTE_VALUE(values+27, cell->rt_on_timeout);
				SET_ROUTE_VALUE(values+28, cell->rt_on_hangup);

				CON_PS_REFERENCE(dialog_db_handle) = &my_ps_insert;
				if (con_set_inslist(&dialog_dbf,dialog_db_handle,
				&ins_list,insert_keys,DIALOG_TABLE_TOTAL_COL_NO) < 0 )
					CON_RESET_INSLIST(dialog_db_handle);

				if((dialog_dbf.insert(dialog_db_handle, insert_keys,
				values, DIALOG_TABLE_TOTAL_COL_NO)) !=0){
					LM_ERR("could not add another dialog to db - state=%d callid=%.*s\n",
							cell->state, cell->callid.len, cell->callid.s);
					cell = cell->next;
					continue;
				}

				if (ins_done==0)
					ins_done=1;

				/* dialog saved */
				cell->locked_by = process_no;
				run_dlg_callbacks(DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL, 1, 1);
				cell->locked_by = 0;

				cell->flags &= ~(DLG_FLAG_NEW |DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED);

			} else if (cell->state == DLG_STATE_DELETED &&
					   !(cell->flags & DLG_FLAG_DB_DELETED)) {
				/* save pointer to next dialog
				 * delete might swipe cell from under our feet */
				next_cell=cell->next;
				dlg_timer_remove_from_db(cell);
				cell=next_cell;
				continue;
			} else if ( (cell->flags & DLG_FLAG_CHANGED)!=0 || on_shutdown ){
				LM_DBG("updating existing dialog %p\n",cell);

				SET_BIGINT_VALUE(values, dlg_get_db_id(cell));

				SET_STR_VALUE(values+13, cell->legs[DLG_CALLER_LEG].contact);
				SET_STR_VALUE(values+14,
					cell->legs[callee_leg].contact);
				SET_INT_VALUE(values+15, cell->state);
				SET_INT_VALUE(values+16, (unsigned int)((unsigned int)time(0)
					 + cell->tl.timeout - get_ticks()) );
				SET_STR_VALUE(values+17, cell->legs[DLG_CALLER_LEG].r_cseq);
				SET_STR_VALUE(values+18, cell->legs[callee_leg].r_cseq);
				SET_INT_VALUE(values+19, cell->legs[DLG_CALLER_LEG].last_gen_cseq);
				SET_INT_VALUE(values+20, cell->legs[callee_leg].last_gen_cseq);

				set_final_update_cols(values+21, cell, on_shutdown);
				SET_INT_VALUE(values+25, cell->flags);

				CON_PS_REFERENCE(dialog_db_handle) = &my_ps_update;

				if((dialog_dbf.update(dialog_db_handle, (insert_keys), 0,
				(values), (insert_keys+13), (values+13), 1, 13)) !=0) {
					LM_ERR("could not update database info\n");
					cell = cell->next;
					continue;
				}

				/* dialog saved */
				cell->locked_by = process_no;
				run_dlg_callbacks(DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL, 1, 1);
				cell->locked_by = 0;

				cell->flags &= ~(DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED);
			} else if (db_flush_vp && (cell->flags & DLG_FLAG_VP_CHANGED)) {

				SET_BIGINT_VALUE(values, dlg_get_db_id(cell));

				set_final_update_cols(values+21, cell, on_shutdown);

				CON_PS_REFERENCE(dialog_db_handle) = &my_ps_update_vp;

				if((dialog_dbf.update(dialog_db_handle, (insert_keys), 0,
				(values), (insert_keys+21), (values+21), 1, 4)) !=0) {
					LM_ERR("could not update database info\n");
					cell = cell->next;
					continue;
				}

				cell->locked_by = process_no;
				run_dlg_callbacks(DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL,1, 1);
				cell->locked_by = 0;

				cell->flags &= ~DLG_FLAG_VP_CHANGED;
			}
			cell = cell->next;
		}
		if (do_lock)
			dlg_unlock( d_table, entry);
	}

	if (ins_done) {
		LM_DBG("dlg timer attempting to flush rows to DB\n");
		/* flush everything to DB
		 * so that next-time timer fires
		 * we are sure that DB updates will be successful */
		if (ql_flush_rows(&dialog_dbf,dialog_db_handle,ins_list) < 0)
			LM_ERR("failed to flush rows to DB\n");
	}

	dlg_timer_flush_del();
	return;
}

static int sync_dlg_db_mem(void)
{
	db_res_t * res;
	db_val_t * values;
	db_row_t * rows;
	struct dlg_entry *d_entry;
	struct dlg_cell *known_dlg, *dlg = NULL;
	int i, nr_rows,callee_leg_idx,db_timeout;
	int no_rows = 10;
	unsigned int db_caller_cseq = 0, db_callee_cseq = 0;
	unsigned int dlg_caller_cseq = 0, dlg_callee_cseq = 0;
	struct socket_info *caller_sock,*callee_sock;
	str callid, from_uri, to_uri, from_tag, to_tag;
	str cseq1,cseq2,contact1,contact2,rroute1,rroute2,mangled_fu,mangled_tu;
	unsigned int hash_entry, hash_id;
	str tag_name;
	int rc;

	res = 0;
	if((nr_rows = select_entire_dialog_table(&res,&no_rows)) < 0)
		goto error;

	nr_rows = RES_ROW_N(res);

	do {
		LM_DBG("loading information from database for %i dialogs\n", nr_rows);

		rows = RES_ROWS(res);

		/* for every row---dialog */
		for(i=0; i<nr_rows; i++){

			values = ROW_VALUES(rows + i);

			if (VAL_NULL(values) || VAL_TYPE(values) != DB_BIGINT) {
				LM_ERR("column %.*s cannot be null -> skipping\n",
					dlg_id_column.len, dlg_id_column.s);
				continue;
			}

			dlg_parse_db_id(VAL_BIGINT(values), hash_entry, hash_id);

			if (VAL_NULL(values+6) || VAL_NULL(values+7)) {
				LM_ERR("columns %.*s or/and %.*s cannot be null -> skipping\n",
					start_time_column.len, start_time_column.s,
					state_column.len, state_column.s);
				continue;
			}

			if ( VAL_INT(values+7) == DLG_STATE_DELETED ) {
				LM_DBG("dialog already terminated -> skipping\n");
				continue;
			}

			/*restore the dialog info*/
			GET_STR_VALUE(callid, values, 1, 1, 0);
			GET_STR_VALUE(from_tag, values, 3, 1, 0);
			GET_STR_VALUE(to_tag, values, 5, 1, 0);

			/* TODO - check about hash resize ? maybe hash was lowered & we overflow the hash */
			known_dlg = 0;
			d_entry = &(d_table->entries[hash_entry]);

			/* lock the whole entry */
			dlg_lock( d_table, d_entry);

			if (get_dlg_unsafe(d_entry, &callid, &from_tag, &to_tag, &known_dlg) != 0) {
				/* we can safely unlock here */
				dlg_unlock( d_table, d_entry);
				LM_DBG("First seen dialog - load all stuff - callid = [%.*s]\n",callid.len,callid.s);
				GET_STR_VALUE(from_uri, values, 2, 1, 0);
				GET_STR_VALUE(to_uri, values, 4, 1, 0);

				caller_sock = create_socket_info(values, 15);
				callee_sock = create_socket_info(values, 16);
				if (caller_sock == NULL || callee_sock == NULL) {
					LM_ERR("Dialog in DB doesn't match any listening sockets\n");
					continue;
				}

				/* first time we see this dialog - build it from scratch */
				if((dlg=build_new_dlg(&callid, &from_uri, &to_uri, &from_tag))==0){
					LM_ERR("failed to build new dialog\n");
					goto error;
				}

				if(dlg->h_entry != hash_entry){
					LM_ERR("inconsistent hash data in the dialog database: "
						"you may have restarted opensips using a different "
						"hash_size: please erase %.*s database and restart\n",
						dialog_table_name.len, dialog_table_name.s);
					shm_free(dlg);
					continue;
				}

				/*link the dialog*/
				link_dlg(dlg, 0);

				dlg->h_id = hash_id;

				/* next_id follows the max value of all loaded ids */
				if (d_table->entries[dlg->h_entry].next_id <= dlg->h_id)
					d_table->entries[dlg->h_entry].next_id = dlg->h_id + 1;

				dlg->start_ts	= VAL_INT(values+6);

				dlg->state 		= VAL_INT(values+7);

				GET_STR_VALUE(cseq1, values, 9 , 1, 1);
				GET_STR_VALUE(cseq2, values, 10 , 1, 1);
				GET_STR_VALUE(rroute1, values, 11, 0, 0);
				GET_STR_VALUE(rroute2, values, 12, 0, 0);
				GET_STR_VALUE(contact1, values, 13, 0, 1);
				GET_STR_VALUE(contact2, values, 14, 0, 1);

				GET_STR_VALUE(mangled_fu, values, 23,0,1);
				GET_STR_VALUE(mangled_tu, values, 24,0,1);

				/* add the 2 legs */
				if ((dlg_update_leg_info(0, dlg, &from_tag, &rroute1,&contact1,
				NULL, &cseq1, caller_sock,0,0,0,0)!=0) ||
				(dlg_update_leg_info(1, dlg, &to_tag, &rroute2, &contact2,
				NULL, &cseq2, callee_sock,&mangled_fu,&mangled_tu,0,0)!=0) ) {
					LM_ERR("dlg_set_leg_info failed\n");
					/* destroy the dialog */
					unref_dlg(dlg,1);
					continue;
				}
				dlg->legs_no[DLG_LEG_200OK] = DLG_FIRST_CALLEE_LEG;

				/* script variables */
				if (!VAL_NULL(values+17)) {
					if (VAL_TYPE(values+17) == DB_BLOB) {
						read_dialog_vars( VAL_BLOB(values+17).s,
								VAL_BLOB(values+17).len, dlg);
					} else {
						LM_ERR("non-blob variables column - cannot store dialog variables\n");
					}
				}

				/* profiles */
				if (!VAL_NULL(values+18))
					read_dialog_profiles( VAL_STR(values+18).s,
						strlen(VAL_STR(values+18).s), dlg, 0, 0);


				/* script flags */
				if (!VAL_NULL(values+19)) {
					dlg->user_flags = VAL_INT(values+19);
				}

				/* module flags */
				if (!VAL_NULL(values+25)) {
					dlg->mod_flags = VAL_INT(values+25);
				}

				GET_ROUTE_VALUE( dlg->rt_on_answer, values, 26);
				GET_ROUTE_VALUE( dlg->rt_on_timeout, values, 27);
				GET_ROUTE_VALUE( dlg->rt_on_hangup, values, 28);

				/* top hiding */
				dlg->flags = VAL_INT(values+22);
				if (dlg_db_mode==DB_MODE_SHUTDOWN)
					dlg->flags |= DLG_FLAG_NEW;

				/* calculate timeout */
				dlg->tl.timeout = (unsigned int)(VAL_INT(values+8));
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
					(unsigned int)(VAL_INT(values+20));
				dlg->legs[callee_idx(dlg)].last_gen_cseq =
					(unsigned int)(VAL_INT(values+21));

				if (dlg->flags & DLG_FLAG_PING_CALLER || dlg->flags & DLG_FLAG_PING_CALLEE) {
					if (0 != insert_ping_timer(dlg))
						LM_CRIT("Unable to insert dlg %p into ping timer\n",dlg);
					else {
						/* reference dialog as kept in ping timer list */
						ref_dlg(dlg,1);
					}
				}

				if (restore_reinvite_pinging(dlg) != 0)
					LM_ERR("failed to fetch some Re-INVITE pinging data\n");
				else if (dlg_has_reinvite_pinging(dlg)) {
					/* re-populate Re-INVITE pinging fields */
					if (0 != insert_reinvite_ping_timer(dlg))
						LM_CRIT("Unable to insert dlg %p into reinvite"
						        "ping timer\n", dlg);
					else {
						/* reference dialog as kept in reinvite ping timer list */
						ref_dlg(dlg,1);
					}
				}

				if ((rc = fetch_dlg_value(dlg, &shtag_dlg_val, &tag_name, 0)) == 0) {
					if (shm_str_dup(&dlg->shtag, &tag_name) < 0)
						LM_ERR("No more shm memory\n");
				} else if (rc == -1)
					LM_ERR("Failed to get dlg value for sharing tag\n");

				if (dlg_db_mode == DB_MODE_DELAYED) {
					/* to be later removed by timer */
					ref_dlg(dlg,1);
				}

				update_dlg_stats(dlg, +1);

				run_load_callback_per_dlg(dlg);

				if (dlg->state==DLG_STATE_CONFIRMED_NA ||
				dlg->state==DLG_STATE_CONFIRMED) {
					if_update_stat(dlg_enable_stats, active_dlgs, 1);
				} else if (dlg->state==DLG_STATE_EARLY) {
					if_update_stat(dlg_enable_stats, early_dlgs, 1);
				}
			} else {
				/* we already saw this dialog before
				 * check which is the newer version */

				if (known_dlg->state > VAL_INT(values+7)) {
					LM_DBG("mem has a newer state - ignore \n");
					/* we know a newer version compared to the DB
					 * ignore it */
					dlg_unlock( d_table, d_entry);
					goto next_dialog;
				} else if (known_dlg->state == VAL_INT(values+7)) {
					LM_DBG("mem has same state as DB \n");
					/* same state :-( no way to tell which is newer */

					/* play nice and store longest timeout, although not always correct*/
					db_timeout = (unsigned int)(VAL_INT(values+8));
					if (db_timeout<=(unsigned int)time(0))
						db_timeout = 0;
					else
						db_timeout -= (unsigned int)time(0);
					db_timeout += get_ticks();

					if (known_dlg->tl.timeout < db_timeout)
						known_dlg->tl.timeout = db_timeout;

					/* check with is newer cseq for caller leg */
					if (!VAL_NULL(values+9)) {
						cseq1.s = VAL_STR(values+9).s;
						cseq1.len = strlen(cseq1.s);

						if (str2int(&cseq1,&db_caller_cseq) < 0)
							LM_ERR("Caller CSEQ not numeric!\n");
						if (str2int(&known_dlg->legs[DLG_CALLER_LEG].r_cseq,&dlg_caller_cseq) < 0)
							LM_ERR("dlg Caller CSEQ not numeric!\n");

						/* Is DB cseq newer ? */
						if (db_caller_cseq > dlg_caller_cseq) {
							if (known_dlg->legs[DLG_CALLER_LEG].r_cseq.len < cseq1.len) {
								known_dlg->legs[DLG_CALLER_LEG].r_cseq.s =
									shm_realloc(known_dlg->legs[DLG_CALLER_LEG].r_cseq.s,cseq1.len);
								if (!known_dlg->legs[DLG_CALLER_LEG].r_cseq.s) {
									LM_ERR("no more shm\n");
									dlg_unlock( d_table, d_entry);
									goto next_dialog;
								}
							}
							memcpy(known_dlg->legs[DLG_CALLER_LEG].r_cseq.s,cseq1.s,cseq1.len);
							known_dlg->legs[DLG_CALLER_LEG].r_cseq.len = cseq1.len;
						}
					} else {
						/* DB has a null cseq - just keep
						 * what we have so far */
						;
					}

					/* check with is newer cseq for caller leg */
					if (!VAL_NULL(values+10)) {
						cseq2.s = VAL_STR(values+10).s;
						cseq2.len = strlen(cseq2.s);

						callee_leg_idx = callee_idx(known_dlg);
						if (str2int(&cseq2,&db_callee_cseq) < 0)
							LM_ERR("Callee CSEQ not numeric!\n");
						if (str2int(&known_dlg->legs[callee_leg_idx].r_cseq,&dlg_callee_cseq) < 0)
							LM_ERR("dlg Callee CSEQ not numeric!\n");

						/* Is DB cseq newer ? */
						if (db_callee_cseq > dlg_callee_cseq) {
							if (known_dlg->legs[callee_leg_idx].r_cseq.len < cseq2.len) {
								known_dlg->legs[callee_leg_idx].r_cseq.s =
									shm_realloc(known_dlg->legs[callee_leg_idx].r_cseq.s,cseq2.len);
								if (!known_dlg->legs[callee_leg_idx].r_cseq.s) {
									LM_ERR("no more shm\n");
									dlg_unlock( d_table, d_entry);
									goto next_dialog;
								}
							}
							memcpy(known_dlg->legs[callee_leg_idx].r_cseq.s,cseq2.s,cseq2.len);
							known_dlg->legs[callee_leg_idx].r_cseq.len = cseq2.len;
						}
					} else {
						/* DB has a null cseq - just keep
						 * what we have so far */
						;
					}

					/* update ping cseqs, whichever is newer */
					if (known_dlg->legs[DLG_CALLER_LEG].last_gen_cseq <
						(unsigned int)(VAL_INT(values+20)))
						known_dlg->legs[DLG_CALLER_LEG].last_gen_cseq =
							(unsigned int)(VAL_INT(values+20));
					if (known_dlg->legs[callee_idx(known_dlg)].last_gen_cseq <
						(unsigned int)(VAL_INT(values+21)))
						known_dlg->legs[callee_idx(known_dlg)].last_gen_cseq =
							(unsigned int)(VAL_INT(values+21));

					/* update script variables
					 * if already found, delete the old ones
					 * and replace with new one */
					if (!VAL_NULL(values+17)) {
						if (VAL_TYPE(values+17) == DB_BLOB) {
							read_dialog_vars( VAL_BLOB(values+17).s,
									VAL_BLOB(values+17).len, known_dlg);
						} else {
							LM_ERR("non-blob variables column - cannot store dialog variables\n");
						}
					}

					/* skip flags - keep what we have - anyway can't tell which is new */

					known_dlg->locked_by = process_no;

					/* profiles - do not insert into a profile
					 * is dlg is already in that profile*/
					if (!VAL_NULL(values+18))
						read_dialog_profiles( VAL_STR(values+18).s,
							strlen(VAL_STR(values+18).s), known_dlg, 1, 0);

					known_dlg->locked_by = 0;
					dlg_unlock( d_table, d_entry);
				} else {
					/* DB has newer state, just update fields from DB */
					LM_DBG("DB has newer state \n");

					/* set new state */
					known_dlg->state = VAL_INT(values+7);

					/* update timeout */
					known_dlg->tl.timeout = (unsigned int)(VAL_INT(values+8));
					if (known_dlg->tl.timeout<=(unsigned int)time(0))
						known_dlg->tl.timeout = 0;
					else
						known_dlg->tl.timeout -= (unsigned int)time(0);
					known_dlg->tl.timeout += get_ticks();

					/* update cseqs */
					if (!VAL_NULL(values+9)) {
						cseq1.s = VAL_STR(values+9).s;
						cseq1.len = strlen(cseq1.s);

						if (known_dlg->legs[DLG_CALLER_LEG].r_cseq.len < cseq1.len) {
							known_dlg->legs[DLG_CALLER_LEG].r_cseq.s =
								shm_realloc(known_dlg->legs[DLG_CALLER_LEG].r_cseq.s,cseq1.len);
							if (!known_dlg->legs[DLG_CALLER_LEG].r_cseq.s) {
								LM_ERR("no more shm\n");
								dlg_unlock( d_table, d_entry);
								goto next_dialog;
							}
						}
						memcpy(known_dlg->legs[DLG_CALLER_LEG].r_cseq.s,cseq1.s,cseq1.len);
						known_dlg->legs[DLG_CALLER_LEG].r_cseq.len = cseq1.len;
					}

					if (!VAL_NULL(values+10)) {
						cseq2.s = VAL_STR(values+10).s;
						cseq2.len = strlen(cseq1.s);
						callee_leg_idx = callee_idx(known_dlg);

						if (known_dlg->legs[callee_leg_idx].r_cseq.len < cseq2.len) {
							known_dlg->legs[callee_leg_idx].r_cseq.s =
								shm_realloc(known_dlg->legs[callee_leg_idx].r_cseq.s,cseq2.len);
							if (!known_dlg->legs[callee_leg_idx].r_cseq.s) {
								LM_ERR("no more shm\n");
								dlg_unlock( d_table, d_entry);
								goto next_dialog;
							}
						}

						memcpy(known_dlg->legs[callee_leg_idx].r_cseq.s,cseq2.s,cseq2.len);
						known_dlg->legs[callee_leg_idx].r_cseq.len = cseq2.len;
					}

					/* update ping cseqs */
					known_dlg->legs[DLG_CALLER_LEG].last_gen_cseq =
						(unsigned int)(VAL_INT(values+20));
					known_dlg->legs[callee_idx(known_dlg)].last_gen_cseq =
						(unsigned int)(VAL_INT(values+21));

					/* update flags */
					known_dlg->flags = VAL_INT(values+22);
					if (dlg_db_mode==DB_MODE_SHUTDOWN)
						known_dlg->flags |= DLG_FLAG_NEW;

					/* update the routes too */
					GET_ROUTE_VALUE( known_dlg->rt_on_answer, values, 26);
					GET_ROUTE_VALUE( known_dlg->rt_on_timeout, values, 27);
					GET_ROUTE_VALUE( known_dlg->rt_on_hangup, values, 28);

					/* update script variables
					 * if already found, delete the old one
					 * and replace with new one */
					if (!VAL_NULL(values+17)) {
						if (VAL_TYPE(values+17) == DB_BLOB) {
							read_dialog_vars( VAL_BLOB(values+17).s,
									VAL_BLOB(values+17).len, known_dlg);
						} else {
							LM_ERR("non-blob variables column - cannot store dialog variables\n");
						}
					}

					known_dlg->locked_by = process_no;

					/* profiles - do not insert into a profile
					 * is dlg is already in that profile*/
					if (!VAL_NULL(values+18))
						read_dialog_profiles( VAL_STR(values+18).s,
							strlen(VAL_STR(values+18).s), known_dlg, 1, 0);

					known_dlg->locked_by = 0;
					dlg_unlock( d_table, d_entry);
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

	dialog_dbf.free_result(dialog_db_handle, res);
	return 0;
error:
	dialog_dbf.free_result(dialog_db_handle, res);
	return -1;
}

/*
 * truncates and restores the dialog table with CONFIRMED dialogs from memory
 */
static int restore_dlg_db(void)
{
	int i, callee_leg, ins_done = 0;
	struct dlg_entry *e;
	struct dlg_cell *cell;
	static query_list_t *ins_list = NULL;
	static db_ps_t my_ps_insert = NULL;

	db_val_t values[DIALOG_TABLE_TOTAL_COL_NO];

	db_key_t insert_keys[DIALOG_TABLE_TOTAL_COL_NO] = {
			&dlg_id_column,		&call_id_column,		&from_uri_column,
			&from_tag_column,	&to_uri_column,			&to_tag_column,
			&from_sock_column,	&to_sock_column,		&start_time_column,
			&from_route_column,	&to_route_column,		&from_contact_column,
			&to_contact_column, &mangled_fu_column,		&mangled_tu_column,
			&state_column,		&timeout_column,		&from_cseq_column,
			&to_cseq_column,	&from_ping_cseq_column, &to_ping_cseq_column,
			&vars_column,		&profiles_column,		&sflags_column,
			&mflags_column,		&flags_column,			&rt_on_answer_column,
			&rt_on_timeout_column,&rt_on_hangup_column};

	VAL_TYPE(values) = DB_BIGINT;
	VAL_TYPE(values+8) =
	VAL_TYPE(values+15) = VAL_TYPE(values+16) = VAL_TYPE(values+19) =
	VAL_TYPE(values+20) = VAL_TYPE(values+23) = VAL_TYPE(values+24)=
	VAL_TYPE(values+25) = DB_INT;

	VAL_TYPE(values+1) = VAL_TYPE(values+2) = VAL_TYPE(values+3) =
	VAL_TYPE(values+4) = VAL_TYPE(values+5) = VAL_TYPE(values+6) =
	VAL_TYPE(values+7) = VAL_TYPE(values+9) = VAL_TYPE(values+10) =
	VAL_TYPE(values+11) = VAL_TYPE(values+12) = VAL_TYPE(values+13) =
	VAL_TYPE(values+14) = VAL_TYPE(values+17) = VAL_TYPE(values+18) =
	VAL_TYPE(values+22) = DB_STR;

	VAL_TYPE(values+26) = VAL_TYPE(values+27) = VAL_TYPE(values+28) =
	DB_STRING;

	VAL_TYPE(values+21) = DB_BLOB;

	if (remove_all_dialogs_from_db() != 0) {
		LM_ERR("Failed to truncate dialog table!\n");
		return -1;
	}

	for (i = 0; i < d_table->size; i++) {
		e = d_table->entries + i;

		dlg_lock(d_table, e);

		for (cell = e->first; cell; cell = cell->next) {

			if (cell->state != DLG_STATE_CONFIRMED &&
				cell->state != DLG_STATE_CONFIRMED_NA)
				continue;

			callee_leg = callee_idx(cell);

			SET_BIGINT_VALUE(values, dlg_get_db_id(cell));
			SET_STR_VALUE(values+1, cell->callid);
			SET_STR_VALUE(values+2, cell->from_uri);

			SET_STR_VALUE(values+3, cell->legs[DLG_CALLER_LEG].tag);
			SET_STR_VALUE(values+4, cell->to_uri);
			SET_STR_VALUE(values+5, cell->legs[callee_leg].tag);

			SET_STR_VALUE(values+6,
				cell->legs[DLG_CALLER_LEG].bind_addr->sock_str);
			if (cell->legs[callee_leg].bind_addr) {
				SET_STR_VALUE(values+7,
					cell->legs[callee_leg].bind_addr->sock_str);
			} else {
				VAL_NULL(values+7) = 1;
			}

			SET_INT_VALUE(values+8,  cell->start_ts);

			SET_STR_VALUE(values+9, cell->legs[DLG_CALLER_LEG].route_set);
			SET_STR_VALUE(values+10,
				cell->legs[callee_leg].route_set);
			SET_STR_VALUE(values+11, cell->legs[DLG_CALLER_LEG].contact);
			SET_STR_VALUE(values+12,
				cell->legs[callee_leg].contact);


			SET_STR_VALUE(values+13,cell->legs[callee_leg].from_uri);
			SET_STR_VALUE(values+14,cell->legs[callee_leg].to_uri);

			SET_INT_VALUE(values+15, cell->state);
			SET_INT_VALUE(values+16, (unsigned int)((unsigned int)time(0)
				+ cell->tl.timeout - get_ticks()) );

			SET_STR_VALUE(values+17, cell->legs[DLG_CALLER_LEG].r_cseq);
			SET_STR_VALUE(values+18, cell->legs[callee_leg].r_cseq);

			SET_INT_VALUE(values+19, cell->legs[DLG_CALLER_LEG].last_gen_cseq);
			SET_INT_VALUE(values+20, cell->legs[callee_leg].last_gen_cseq);

			set_final_update_cols(values+21, cell, 1);
			SET_INT_VALUE(values+25, cell->flags & ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|
													 DLG_FLAG_VP_CHANGED));

			SET_ROUTE_VALUE(values+26, cell->rt_on_answer);
			SET_ROUTE_VALUE(values+27, cell->rt_on_timeout);
			SET_ROUTE_VALUE(values+28, cell->rt_on_hangup);

			CON_PS_REFERENCE(dialog_db_handle) = &my_ps_insert;
			if (con_set_inslist(&dialog_dbf,dialog_db_handle,
			&ins_list,insert_keys,DIALOG_TABLE_TOTAL_COL_NO) < 0 )
				CON_RESET_INSLIST(dialog_db_handle);

			if((dialog_dbf.insert(dialog_db_handle, insert_keys,
			values, DIALOG_TABLE_TOTAL_COL_NO)) !=0){
				LM_ERR("could not add another dialog to db - state=%d callid=%.*s\n",
						cell->state, cell->callid.len, cell->callid.s);
				continue;
			}

			if (ins_done == 0)
				ins_done = 1;

			/* dialog saved */
			run_dlg_callbacks(DLGCB_DB_SAVED, cell, 0, DLG_DIR_NONE, NULL, 1, 1);

			cell->flags &= ~(DLG_FLAG_NEW |DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED);
		}

		dlg_unlock(d_table, e);
	}

	if (ins_done) {
		LM_DBG("attempting to flush rows to DB\n");
		/* flush everything to DB
		 * so that next-time timer fires
		 * we are sure that DB updates will be successful */
		if (ql_flush_rows(&dialog_dbf,dialog_db_handle,ins_list) < 0)
			LM_ERR("failed to flush rows to DB\n");
	}

	return 0;
}

mi_response_t *mi_sync_db_dlg(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (dlg_db_mode == 0)
		return init_mi_error(400, MI_SSTR("Cannot sync in no-db mode"));
	if (sync_dlg_db_mem() < 0)
		return init_mi_error(400, MI_SSTR("Sync mem with DB failed"));
	else
		return init_mi_result_ok();
}

mi_response_t *mi_restore_dlg_db(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (dlg_db_mode == 0)
		return init_mi_error(400, MI_SSTR("Cannot restore db in no-db mode!"));
	if (restore_dlg_db() < 0)
		return init_mi_error(400, MI_SSTR("Restore dlg DB failed!"));
	else
		return init_mi_result_ok();
}

