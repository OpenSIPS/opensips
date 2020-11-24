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

#include <stdlib.h>
#include <string.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../time_rec.h"

#include "dp_db.h"

dp_head_p dp_hlist;
dp_head_p dp_df_head;

str default_dp_db_url;
str default_dp_table     =   str_init(DP_TABLE_NAME);

str dpid_column          =   str_init(DPID_COL);
str pr_column            =   str_init(PR_COL);
str match_op_column      =   str_init(MATCH_OP_COL);
str match_exp_column     =   str_init(MATCH_EXP_COL);
str match_flags_column   =   str_init(MATCH_FLAGS_COL);
str subst_exp_column     =   str_init(SUBST_EXP_COL);
str repl_exp_column      =   str_init(REPL_EXP_COL);
str disabled_column      =   str_init(DISABLED_COL);
str attrs_column         =   str_init(ATTRS_COL);
str timerec_column       =   str_init(TIMEREC_COL);


#define GET_STR_VALUE(_res, _values, _index, _null)\
	do{\
		if ( VAL_NULL((_values)+ (_index))) { \
			if ( !_null) { \
				LM_ERR(" values %d is NULL - not allowed\n",_index);\
				goto err;\
			} else { \
				(_res).s = NULL; \
				(_res).len = 0; \
			} \
		} else  { \
			(_res).s = VAL_STR((_values)+ (_index)).s;\
			(_res).len = strlen(VAL_STR((_values)+ (_index)).s);\
		}\
	}while(0);

void destroy_rule(dpl_node_t * rule);
void destroy_hash(dpl_id_t **rules_hash);

dpl_node_t * build_rule(db_val_t * values);
int add_rule2hash(dpl_node_t * rule, dp_connection_list_t *table, int index);

void list_rule(dpl_node_t * );
void list_hash(dpl_id_t * , rw_lock_t *);


dp_connection_list_p dp_conns;

int test_db(dp_connection_list_p dp_connection)
{
	if (!dp_connection->partition.s) {
		LM_ERR("NULL partition name\n");
		return -1;
	}

	if (db_bind_mod(&dp_connection->db_url, &dp_connection->dp_dbf) < 0) {
		LM_ERR("failed to find a client driver for DB URL: '%.*s'\n",
		       dp_connection->db_url.len, dp_connection->db_url.s);
		return -1;
	}

	if (dp_connect_db(dp_connection) != 0)
		return -1;

	if (db_check_table_version(&dp_connection->dp_dbf,
		 *dp_connection->dp_db_handle, &dp_connection->table_name,
			 DP_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		goto error;
	}

	dp_disconnect_db(dp_connection);
	return 0;

error:
	dp_disconnect_db(dp_connection);
	return -1;
}


int init_db_data(dp_connection_list_p dp_connection)
{
	if (dp_connection->partition.s == 0) {
		LM_ERR("invalid partition name\n");
		return -1;
	}

	if (dp_connect_db(dp_connection) !=0)
		return -1;


	if (db_check_table_version(&dp_connection->dp_dbf,
		*dp_connection->dp_db_handle, &dp_connection->table_name,
			DP_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		goto error;
	}


	if(dp_load_db(dp_connection) != 0){
		LM_ERR("failed to load database data\n");
		goto error;
	}

	return 0;
error:

	dp_disconnect_db(dp_connection);
	return -1;
}


int dp_connect_db(dp_connection_list_p conn)
{
	if (*conn->dp_db_handle) {
		LM_CRIT("BUG: connection to DB already open\n");
		return -1;
	}

	if ((*conn->dp_db_handle = conn->dp_dbf.init(&conn->db_url)) == 0) {
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	return 0;
}


void dp_disconnect_db(dp_connection_list_p dp_conn)
{
	if (*dp_conn->dp_db_handle) {
		dp_conn->dp_dbf.close(*dp_conn->dp_db_handle);
		*dp_conn->dp_db_handle = NULL;
	}
}


int init_data(void)
{
	dp_head_p start, tmp;

	if (!dp_hlist) {
		LM_ERR("no partition defined, not even the default one!\n");
		return -1;
	}

	/* was the default partition re-pointed? */
	if (!str_match(&dp_df_part, _str(DEFAULT_PARTITION))) {
		int found = 0;

		for (start = dp_hlist; start; start = start->next) {
			if (str_match(&dp_df_part, &start->partition)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			LM_ERR("partition not found: '%.*s'\n",
			       dp_df_part.len, dp_df_part.s);
			return -1;
		}
	}

	if (!dp_df_head) {
		if (pkg_str_dup(&dp_df_part, &dp_hlist->partition) < 0) {
			LM_ERR("oom\n");
			return -1;
		}

		LM_INFO("no 'default' partition set, assuming '%.*s'\n",
		        dp_df_part.len, dp_df_part.s);
	}

	start = dp_hlist;
	while (start) {
		LM_DBG("Adding partition with name [%.*s]\n",
				start->partition.len, start->partition.s);

		if (!dp_add_connection(start)) {
			LM_ERR("failed to initialize partition '%.*s'\n",
					start->partition.len, start->partition.s);
			return -1;
		}

		tmp   = start;
		start = start->next;
		pkg_free(tmp);
	}

	dp_hlist = NULL;
	dp_df_head = NULL;
	return 0;
}


void destroy_data(void)
{
	dp_connection_list_t *el, *next;

	LM_DBG("Destroying data\n");
	for (el = dp_conns; el && (next = el->next, 1); el = next) {
		destroy_hash(&el->hash[0]);
		destroy_hash(&el->hash[1]);
		lock_destroy_rw(el->ref_lock);

		shm_free(el->table_name.s);
		shm_free(el->partition.s);
		shm_free(el->db_url.s);
		shm_free(el);
	}
}

int dp_load_all_db(void)
{
	dp_connection_list_t *el;

	for (el = dp_conns; el; el = el->next) {
			if (dp_load_db(el) < 0) {
					LM_ERR("unable to load %.*s table\n",
							el->table_name.len, el->table_name.s);
					return -1;
			}
	}
	return 0;
}

void dp_disconnect_all_db(void)
{
	dp_connection_list_t *el;

	for (el = dp_conns; el; el = el->next)
		dp_disconnect_db(el);
}

/*load rules from DB*/
int dp_load_db(dp_connection_list_p dp_conn)
{
	int i, nr_rows;
	db_res_t * res = 0;
	db_val_t * values;
	db_row_t * rows;
	db_key_t query_cols[DP_TABLE_COL_NO] = {
		&dpid_column,		&pr_column,
		&match_op_column,	&match_exp_column,	&match_flags_column,
		&subst_exp_column,	&repl_exp_column,	&attrs_column,	&timerec_column };
	db_key_t order = &pr_column;
	/* disabled condition */
	db_key_t cond_cols[1] = { &disabled_column };
	db_val_t cond_val[1];

	dpl_node_t *rule;
	int no_rows = 10;


	lock_start_write( dp_conn->ref_lock );

	if( dp_conn->crt_index != dp_conn->next_index){
		LM_WARN("a load command already generated, aborting reload...\n");
		lock_stop_write( dp_conn->ref_lock );
		return 0;
	}

	dp_conn->next_index = dp_conn->crt_index == 0 ? 1 : 0;

	lock_stop_write( dp_conn->ref_lock );

	if (dp_conn->dp_dbf.use_table(*dp_conn->dp_db_handle, &dp_conn->table_name) < 0){
		LM_ERR("error in use_table\n");
		goto err1;
	}

	VAL_TYPE(cond_val) = DB_INT;
	VAL_NULL(cond_val) = 0;
	VAL_INT(cond_val) = 0;

	if (DB_CAPABILITY(dp_conn->dp_dbf, DB_CAP_FETCH)) {
		if(dp_conn->dp_dbf.query(*dp_conn->dp_db_handle,cond_cols,
				0,cond_val,query_cols,1,
					DP_TABLE_COL_NO, order, 0) < 0){
			LM_ERR("failed to query database!\n");

			goto err1;
		}
		no_rows = estimate_available_rows( 4+4+4+64+4+64+64+128,
			DP_TABLE_COL_NO);
		if (no_rows==0) no_rows = 10;
		if(dp_conn->dp_dbf.fetch_result(*dp_conn->dp_db_handle,
						&res, no_rows)<0) {
			LM_ERR("failed to fetch\n");
			if (res)
				dp_conn->dp_dbf.free_result(*dp_conn->dp_db_handle, res);

			goto err1;
		}
	} else {
		/*select the whole table and all the columns*/
		if(dp_conn->dp_dbf.query(*dp_conn->dp_db_handle,
				cond_cols,0,cond_val,query_cols,1,
			DP_TABLE_COL_NO, order, &res) < 0){
				LM_ERR("failed to query database\n");

			goto err1;
		}
	}

	nr_rows = RES_ROW_N(res);



	if(nr_rows == 0){
		LM_WARN("no data in the db\n");
		goto end;
	}

	do {
		for(i=0; i<RES_ROW_N(res); i++){
			rows = RES_ROWS(res);
			values = ROW_VALUES(rows+i);

			if ((rule = build_rule(values)) == NULL) {
				LM_WARN(" failed to build rule -> skipping\n");
				continue;
			}

			rule->table_id = i;

			if(add_rule2hash(rule , dp_conn, dp_conn->next_index) != 0) {
				LM_ERR("add_rule2hash failed\n");
				goto err2;
			}
		}


		if (DB_CAPABILITY(dp_conn->dp_dbf, DB_CAP_FETCH)) {
			if(dp_conn->dp_dbf.fetch_result(*dp_conn->dp_db_handle,
							&res, no_rows)<0) {
				LM_ERR("failure while fetching!\n");
				if (res)
					dp_conn->dp_dbf.free_result(*dp_conn->dp_db_handle, res);
				goto err1;
			}
		} else {
			break;
		}
	}  while(RES_ROW_N(res)>0);


end:


	/*update data*/
	lock_start_write( dp_conn->ref_lock );

	destroy_hash(&dp_conn->hash[dp_conn->crt_index]);

	dp_conn->crt_index = dp_conn->next_index;

	lock_stop_write( dp_conn->ref_lock );

	list_hash(dp_conn->hash[dp_conn->crt_index], dp_conn->ref_lock);

	dp_conn->dp_dbf.free_result(*dp_conn->dp_db_handle, res);
	return 0;

err1:

	lock_start_write( dp_conn->ref_lock );

	dp_conn->next_index = dp_conn->crt_index;

	lock_stop_write( dp_conn->ref_lock );

	return -1;

err2:
	if(rule)	destroy_rule(rule);
	destroy_hash(&dp_conn->hash[dp_conn->next_index]);
	dp_conn->dp_dbf.free_result(*dp_conn->dp_db_handle, res);

	lock_start_write( dp_conn->ref_lock );

	dp_conn->next_index = dp_conn->crt_index;
	/* if lock defined - release the exclusive writing access */

	lock_stop_write( dp_conn->ref_lock );
	return -1;
}


int str_to_shm(str src, str * dest)
{
	if (src.len ==0 || src.s ==0)
		return 0;

	dest->s = (char*)shm_malloc((src.len+1) * sizeof(char));
	if (!dest->s) {
		LM_ERR("out of shm memory\n");
		return -1;
	}

	memcpy(dest->s, src.s, src.len);
	dest->s[src.len] = '\0';
	dest->len = src.len;

	return 0;
}

static inline tmrec_t* parse_time_def(char *time_str) {

	tmrec_p time_rec;
	char *p,*s;

	p = time_str;
	time_rec = 0;

	time_rec = tmrec_new(SHM_ALLOC);
	if (time_rec==0) {
		LM_ERR("no more shm mem\n");
		goto error;
	}

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

/*compile the expressions, and if ok, build the rule */
dpl_node_t * build_rule(db_val_t * values)
{
	tmrec_t *parsed_timerec;
	pcre * match_comp, *subst_comp;
	struct subst_expr * repl_comp;
	dpl_node_t * new_rule;
	str match_exp, subst_exp, repl_exp, attrs, timerec;
	int matchop;
	int namecount;

	matchop = VAL_INT(values+2);

	if((matchop != REGEX_OP) && (matchop!=EQUAL_OP)){
		LM_ERR("invalid value for match operator\n");
		return NULL;
	}

	parsed_timerec = 0;
	match_comp = subst_comp = 0;
	repl_comp = 0;
	new_rule = 0;

	GET_STR_VALUE(match_exp, values, 3, 0);
	if(matchop == REGEX_OP){

		LM_DBG("Compiling %.*s expression with flag: %d\n",
				match_exp.len, match_exp.s, VAL_INT(values+4));

		match_comp = wrap_pcre_compile(match_exp.s, VAL_INT(values+4));

		if(!match_comp){
			LM_ERR("failed to compile match expression \"%.*s\"\n",
				match_exp.len, match_exp.s);
			goto err;
		}
	}

	LM_DBG("building subst rule\n");
	GET_STR_VALUE(subst_exp, values, 5, 1);
	if(!VAL_NULL(values+5) && subst_exp.s && subst_exp.len){
		/* subst regexp */
		subst_comp = wrap_pcre_compile(subst_exp.s, VAL_INT(values+4));
		if(subst_comp == NULL){
			LM_ERR("failed to compile subst expression \"%.*s\"\n",
					subst_exp.len, subst_exp.s);
			goto err;
		}
	}

	/* replace exp */
	GET_STR_VALUE(repl_exp, values, 6, 1);
	if(!VAL_NULL(values+6) && repl_exp.len && repl_exp.s){
		repl_comp = repl_exp_parse(repl_exp);
		if(!repl_comp){
			LM_ERR("failed to compile replacing expression \"%.*s\"\n",
				repl_exp.len, repl_exp.s);
			goto err;
		}
	}

	pcre_fullinfo(
		subst_comp, /* the compiled pattern */
		NULL, /* no extra data - we didn't study the pattern */
		PCRE_INFO_CAPTURECOUNT, /* number of named substrings */
		&namecount); /* where to put the answer */

	LM_DBG("references:%d , max:%d\n",namecount,
		repl_comp?repl_comp->max_pmatch:0);

	if ( (repl_comp!=NULL) && (namecount<repl_comp->max_pmatch) &&
	(repl_comp->max_pmatch!=0) ){
		LM_ERR("repl_exp uses a non existing subexpression\n");
			goto err;
	}

	new_rule = (dpl_node_t *)shm_malloc(sizeof(dpl_node_t));
	if(!new_rule){
		LM_ERR("out of shm memory(new_rule)\n");
		goto err;
	}
	memset(new_rule, 0, sizeof(dpl_node_t));

	if(str_to_shm(match_exp, &new_rule->match_exp)!=0)
		goto err;

	if (subst_comp)
		if(str_to_shm(subst_exp, &new_rule->subst_exp)!=0)
			goto err;
	if (repl_comp)
		if(str_to_shm(repl_exp, &new_rule->repl_exp)!=0)
			goto err;

	/*set the rest of the rule fields*/
	new_rule->dpid          =	VAL_INT(values);
	new_rule->pr            =	VAL_INT(values+1);
	new_rule->match_flags   =	VAL_INT(values+4);
	new_rule->matchop       =	matchop;

	/* attributes */
	GET_STR_VALUE(attrs, values, 7, 1);
	if( !VAL_NULL(values+7) && attrs.len && attrs.s) {
		if(str_to_shm(attrs, &new_rule->attrs)!=0)
			goto err;
		LM_DBG("attrs are %.*s\n",
			new_rule->attrs.len, new_rule->attrs.s);
	}

	/* Retrieve and Parse Timerec Matching Pattern */
	GET_STR_VALUE(timerec, values, 8, 1);
	if( !VAL_NULL(values+8) && timerec.len && timerec.s) {
		parsed_timerec = parse_time_def(timerec.s);
		if(!parsed_timerec) {
			LM_ERR("failed to parse timerec pattern %.*s\n",
				timerec.len, timerec.s);
			goto err;
		}

		if(str_to_shm(timerec, &new_rule->timerec) != 0)
			goto err;

		new_rule->parsed_timerec = parsed_timerec;

		LM_DBG("timerecs are %.*s\n",
			new_rule->timerec.len, new_rule->timerec.s);
	}

	if (match_comp)
		new_rule->match_comp = match_comp;

	if (subst_comp)
		new_rule->subst_comp = subst_comp;

	if (repl_comp)
		new_rule->repl_comp  = repl_comp;

	return new_rule;

err:
	if(parsed_timerec)	shm_free(parsed_timerec);
	if(match_comp)		wrap_pcre_free(match_comp);
	if(subst_comp)		wrap_pcre_free(subst_comp);
	if(repl_comp)		repl_expr_free(repl_comp);
	if(new_rule)		destroy_rule(new_rule);
	return NULL;
}


int add_rule2hash(dpl_node_t * rule, dp_connection_list_t *conn, int index)
{
	dpl_id_p crt_idp;
	dpl_index_p indexp;
	int new_id, bucket = 0;

	if(!conn){
		LM_ERR("data not allocated\n");
		return -1;
	}

	new_id = 0;

	crt_idp = select_dpid(conn, rule->dpid, index);
	/*didn't find a dpl_id*/
	if(!crt_idp){
		crt_idp = shm_malloc(sizeof(dpl_id_t) + (DP_INDEX_HASH_SIZE+1) * sizeof(dpl_index_t));
		if(!crt_idp){
			LM_ERR("out of shm memory (crt_idp)\n");
			return -1;
		}
		memset(crt_idp, 0, sizeof(dpl_id_t) + (DP_INDEX_HASH_SIZE+1) * sizeof(dpl_index_t));
		crt_idp->dp_id = rule->dpid;
		crt_idp->rule_hash = (dpl_index_t*)(crt_idp + 1);
		new_id = 1;
		LM_DBG("new dpl_id %i\n", rule->dpid);
	}

	switch (rule->matchop) {
		case REGEX_OP:
			indexp = &crt_idp->rule_hash[DP_INDEX_HASH_SIZE];
			break;

		case EQUAL_OP:
			if (rule->match_exp.s == NULL || rule->match_exp.len == 0) {
				LM_ERR("NULL matching expressions in database not accepted!!!\n");
				return -1;
			}
			bucket = core_case_hash(&rule->match_exp, NULL, DP_INDEX_HASH_SIZE);

			indexp = &crt_idp->rule_hash[bucket];
			break;

		default:
			LM_ERR("SKIPPED RULE. Unsupported match operator (%d).\n",
					rule->matchop);
			goto err;
	}

/* Add the new rule to the corresponding bucket */

	rule->next = 0;
	if(!indexp->first_rule)
		indexp->first_rule = rule;

	if(indexp->last_rule)
		indexp->last_rule->next = rule;

	indexp->last_rule = rule;

	if(new_id){
		crt_idp->next = conn->hash[conn->next_index];
		conn->hash[conn->next_index] = crt_idp;
	}
	LM_DBG("added the rule id %i pr %i next %p to the "
		" %i bucket\n", rule->dpid,
		rule->pr, rule->next, rule->matchop == REGEX_OP ? DP_INDEX_HASH_SIZE : bucket);

	return 0;

err:
	if(new_id)
		shm_free(crt_idp);
	return -1;
}


void destroy_hash(dpl_id_t **rules_hash)
{
	dpl_id_p crt_idp;
	dpl_index_p indexp;
	dpl_node_p rulep;
	int i;

	if(!rules_hash || !*rules_hash)
		return;

	for(crt_idp = *rules_hash; crt_idp; crt_idp = *rules_hash) {

		for (i = 0, indexp = &crt_idp->rule_hash[i];
			 i <= DP_INDEX_HASH_SIZE;
			 i++, indexp = &crt_idp->rule_hash[i]) {

			for (rulep = indexp->first_rule; rulep; rulep=indexp->first_rule) {

				destroy_rule(rulep);
				indexp->first_rule = rulep->next;

				shm_free(rulep);
				rulep = NULL;
			}
		}
		*rules_hash = crt_idp->next;

		shm_free(crt_idp);
		crt_idp = NULL;
	}

	*rules_hash = NULL;
}


void destroy_rule(dpl_node_t * rule){

	if(!rule)
		return;

	LM_DBG("destroying rule with priority %i\n",
		rule->pr);

	if(rule->match_comp)
		wrap_pcre_free(rule->match_comp);

	if(rule->subst_comp)
		wrap_pcre_free(rule->subst_comp);

	/*destroy repl_exp*/
	if(rule->repl_comp)
		repl_expr_free(rule->repl_comp);

	if(rule->match_exp.s)
		shm_free(rule->match_exp.s);

	if(rule->subst_exp.s)
		shm_free(rule->subst_exp.s);

	if(rule->repl_exp.s)
		shm_free(rule->repl_exp.s);

	if(rule->attrs.s)
		shm_free(rule->attrs.s);

	if(rule->timerec.s)
		shm_free(rule->timerec.s);

	if(rule->parsed_timerec)
		shm_free(rule->parsed_timerec);
}


dpl_id_p select_dpid(dp_connection_list_p conn, int id, int index)
{
	dpl_id_p idp;

	if(!conn || !conn->hash[index])
		return NULL;

	for(idp = conn->hash[index]; idp!=NULL; idp = idp->next)
		if(idp->dp_id == id)
			return idp;

	return NULL;
}


/* FOR DEBUG PURPOSES */
void list_hash(dpl_id_t * hash, rw_lock_t * ref_lock)
{
	dpl_id_p crt_idp;
	dpl_node_p rulep;
	int i;

	if(!hash)
		return;

	/* lock the data for reading */
	lock_start_read( ref_lock );

	for(crt_idp = hash; crt_idp; crt_idp = crt_idp->next) {
		LM_DBG("DPID: %i, pointer %p\n", crt_idp->dp_id, crt_idp);

		for (i = 0; i <= DP_INDEX_HASH_SIZE; i++) {
			LM_DBG("BUCKET %d rules:\n", i);

			for(rulep = crt_idp->rule_hash[i].first_rule; rulep;
				rulep = rulep->next) {

				list_rule(rulep);
			}
		}
	}

	/* we are done reading -> unref the data */
	lock_stop_read( ref_lock );
}


void list_rule(dpl_node_t * rule)
{
	LM_DBG("RULE %p: pr %i next %p match_exp %.*s match_flags %d, "
		"subst_exp %.*s, repl_exp %.*s and attrs %.*s and timerec %.*s\n", rule,
		rule->pr, rule->next,
		rule->match_exp.len,	rule->match_exp.s,
		rule->match_flags,
		rule->subst_exp.len,	rule->subst_exp.s,
		rule->repl_exp.len,	rule->repl_exp.s,
		rule->attrs.len,	rule->attrs.s,
		rule->timerec.len,	rule->timerec.s);
}

/* Retrieves the corresponding entry of the given partition name */
dp_connection_list_p dp_get_connection(str *partition)
{
	dp_connection_list_t *el;

	el = dp_conns;
	while (el && str_strcmp(partition, &el->partition))
		el = el->next;

	return el;
}

dp_connection_list_p dp_get_connections(void)
{
	return dp_conns;
}

/* Adds a new separate partition and loads all rules from database in shm */
dp_connection_list_p dp_add_connection(dp_head_p head)
{
	dp_connection_list_t *el;

	if ((el = dp_get_connection(&head->partition)) != NULL){
		return el;
	}

	el = shm_malloc(sizeof(dp_connection_list_t));

	if (!el) {
		LM_ERR("No more shm mem\n");
		return NULL;
	}

	memset(el, 0, sizeof(dp_connection_list_t));

	/* create & init lock */
	if((el->ref_lock = lock_init_rw()) == NULL) {
		LM_ERR("Failed to init lock\n");
		shm_free(el);
		return NULL;
	}

	if (shm_str_dup(&el->table_name, &head->dp_table_name) != 0 ||
	        shm_str_dup(&el->partition, &head->partition) != 0 ||
	        shm_str_dup(&el->db_url, &head->dp_db_url) != 0) {
		LM_ERR("oom\n");
		return NULL;
	}

	el->dp_db_handle = pkg_malloc(sizeof(db_con_t*));
	if (!el->dp_db_handle) {
		LM_ERR("No more shm mem\n");
		return NULL;
	}

	*el->dp_db_handle = 0;

	/* *el->dp_db_handle is set to null at the end of test_db;
	 * no need to do it again here */
	if (test_db(el) != 0) {
		LM_ERR("Unable to test db\n");
		shm_free(el);
		return NULL;
	}

	el->next = dp_conns;
	dp_conns = el;

	LM_DBG("Added dialplan partition [%.*s] table [%.*s].\n",
		 head->partition.len, head->partition.s,
				head->dp_table_name.len, head->dp_table_name.s);
	return el;
}
