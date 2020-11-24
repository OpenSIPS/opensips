 /*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice System SRL
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
 * 2003-04-04  grand acc cleanup (jiri)
 * 2003-11-04  multidomain support for mysql introduced (jiri)
 * 2004-06-06  updated to the new DB api, cleanup: acc_db_{bind, init,close)
 *              added (andrei)
 * 2005-05-30  acc_extra patch commited (ramona)
 * 2005-06-28  multi leg call support added (bogdan)
 * 2006-01-13  detect_direction (for sequential requests) added (bogdan)
 * 2006-09-08  flexible multi leg accounting support added,
 *             code cleanup for low level functions (bogdan)
 * 2006-09-19  final stage of a masive re-structuring and cleanup (bogdan)
 */


#include <stdio.h>
#include <time.h>

#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"      /* q_memchr */
#include "../../mem/mem.h"
#include "../../usr_avp.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../../parser/hf.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../parser/digest/digest.h"
#include "../tm/t_funcs.h"
#include "../../aaa/aaa.h"

#include "acc.h"
#include "acc_mod.h"
#include "acc_extra.h"
#include "acc_logic.h"
#include "acc_vars.h"

#define TABLE_VERSION 7

#define GET_LEN(p)     (*(unsigned short *)(p))
#define MAX_LEN_VALUE  USHRT_MAX
#define SET_LEN(p, n)  (*(unsigned short *)(p) = (unsigned short)(n))

#define LEG_VALUE( leg, extra, ctx) (ctx->leg_values[leg][extra->tag_idx].value)

str created_str = str_init("accX_created");
str core_str = str_init("accX_core");
str leg_str = str_init("accX_leg");
str flags_str = str_init("accX_flags");
str table_str = str_init("accX_table");
str extra_str = str_init("accX_extra");

extern struct acc_extra *log_extra_tags;
extern struct acc_extra *db_extra_tags;
extern struct acc_extra *aaa_extra_tags;
extern struct acc_extra *evi_extra_tags;

extern tag_t* extra_tags;
extern int extra_tgs_len;

extern struct acc_extra *log_leg_tags;
extern struct acc_extra *db_leg_tags;
extern struct acc_extra *aaa_leg_tags;
extern struct acc_extra *evi_leg_tags;

extern tag_t* leg_tags;
extern int leg_tgs_len;

extern struct acc_enviroment acc_env;

extern int acc_flags_ctx_idx;


event_id_t acc_cdr_event = EVI_ERROR;
event_id_t acc_event = EVI_ERROR;
event_id_t acc_missed_event = EVI_ERROR;

static db_func_t acc_dbf;
static db_con_t* db_handle=0;
extern int acc_log_facility;


/* call created avp id */
extern int acc_created_avp_id;

static int build_core_dlg_values(struct dlg_cell *dlg,struct sip_msg *req);
static int build_extra_dlg_values(extra_value_t* values);
static int build_leg_dlg_values(acc_ctx_t* ctx);
static void complete_dlg_values(str *stored_values,str *val_arr,short nr_vals);
/* prebuild functions */
static int prebuild_core_arr(struct dlg_cell *dlg, str *buffer, struct timeval *start);

/* array used to collect the values before being
 * pushed to the storage backend (whatever used) */
static str val_arr[ACC_CORE_LEN+ACC_CDR_LEN+MAX_ACC_EXTRA+MAX_ACC_LEG];


/********************************************
 *        acc CORE function
 ********************************************/
#define get_ft_body( _ft_hdr) \
	((struct to_body*)_ft_hdr->parsed)

#define SET_EMPTY_VAL(_i) \
	do { \
		c_vals[_i].s = 0; \
		c_vals[_i].len = 0; \
	} while(0)

/* returns:
 * 		method name
 * 		from TAG
 * 		to TAG
 * 		callid
 * 		sip_code
 * 		sip_status
 * 		*/
static inline int core2strar( struct sip_msg *req, str *c_vals)
{
	struct to_body *ft_body;
	struct hdr_field *from;
	struct hdr_field *to;

	/* method */
	c_vals[0] = req->first_line.u.request.method;

	/* from/to URI and TAG */
	if (req->msg_flags&FL_REQ_UPSTREAM) {
		LM_DBG("the flag UPSTREAM is set -> swap F/T\n"); \
		from = acc_env.to;
		to = req->from;
	} else {
		from = req->from;
		to = acc_env.to;
	}

	if (from && (ft_body=get_ft_body(from)) && ft_body->tag_value.len) {
		c_vals[1] = ft_body->tag_value;
	} else {
		SET_EMPTY_VAL(1);
	}

	if (to && (ft_body=get_ft_body(to)) && ft_body->tag_value.len) {
		c_vals[2] = ft_body->tag_value;
	} else {
		SET_EMPTY_VAL(2);
	}

	/* Callid */
	if (req->callid && req->callid->body.len)
		c_vals[3] = req->callid->body;
	else
		SET_EMPTY_VAL(3);

	/* SIP code */
	c_vals[4] = acc_env.code_s;

	c_vals[5] = acc_env.reason;

	gettimeofday(&acc_env.ts, NULL);

	return ACC_CORE_LEN;
}


/********************************************
 *        LOG  ACCOUNTING
 ********************************************/
static str log_attrs[ACC_CORE_LEN + ACC_CDR_LEN + MAX_ACC_EXTRA + MAX_ACC_LEG];
void acc_log_init(void)
{
	struct acc_extra *extra;
	int n;

	n = 0;

	/* fixed core attributes */
	init_str(&log_attrs[n++], A_METHOD);
	init_str(&log_attrs[n++], A_FROMTAG);
	init_str(&log_attrs[n++], A_TOTAG);
	init_str(&log_attrs[n++], A_CALLID);
	init_str(&log_attrs[n++], A_CODE);
	init_str(&log_attrs[n++], A_STATUS);

	/* init the extra db keys */
	for (extra = log_extra_tags; extra; extra = extra->next)
		log_attrs[n++] = extra->name;

	/* multi leg call columns */
	for (extra = log_leg_tags; extra; extra = extra->next)
		log_attrs[n++] = extra->name;

	/* cdrs columns */
	init_str(&log_attrs[n++], A_DURATION);
	init_str(&log_attrs[n++], A_SETUPTIME);
	init_str(&log_attrs[n++], A_CREATED);
}

int acc_log_cdrs(struct dlg_cell *dlg, struct sip_msg *msg, acc_ctx_t* ctx)
{
	static char log_msg[MAX_SYSLOG_SIZE];
	static char *log_msg_end=log_msg+MAX_SYSLOG_SIZE-2;
	char *p;
	int i, j, ret, res = -1, n;
	struct timeval start_time;
	str core_s, leg_s, extra_s;

	struct acc_extra* extra;

	core_s.s = extra_s.s = leg_s.s = 0;

	ret = prebuild_core_arr(dlg, &core_s, &start_time);
	if (ret < 0) {
		LM_ERR("cannot copy core arguments\n");
		goto end;
	}


	/* prevent acces for setting variable */
	accX_lock(&ctx->lock);
	for (extra=log_extra_tags, i=ACC_CORE_LEN; extra; extra=extra->next, ++i, ++ret)
		val_arr[i] = ctx->extra_values[extra->tag_idx].value;

	for ( i = 0,p = log_msg ; i<ret ; i++ ) {
		if (p + 1 + log_attrs[i].len + 1 + val_arr[i].len >= log_msg_end) {
			LM_WARN("acc message too long, truncating..\n");
			p = log_msg_end;
			break;
		}

		*(p++) = A_SEPARATOR_CHR;
		memcpy(p, log_attrs[i].s, log_attrs[i].len);
		p += log_attrs[i].len;
		*(p++) = A_EQ_CHR;
		memcpy(p, val_arr[i].s, val_arr[i].len);
		p += val_arr[i].len;
	}

	if (ctx->leg_values) {
		leg_s.len = 4;
		for (j=0; j<ctx->legs_no; j++) {
			for (extra=log_leg_tags, n=ret; extra; extra=extra->next, n++) {
				if (p+1+log_attrs[i].len+1+
						LEG_VALUE(j, extra, ctx).len >= log_msg_end) {
					LM_WARN("acc message too long, truncating..\n");
					p = log_msg_end;
					break;
				}
				*(p++) = A_SEPARATOR_CHR;
				memcpy(p, log_attrs[n].s, log_attrs[n].len);
				p += log_attrs[n].len;
				*(p++) = A_EQ_CHR;
				memcpy(p, LEG_VALUE(j, extra, ctx).s, LEG_VALUE(j, extra, ctx).len);
				p += LEG_VALUE(j, extra, ctx).len;
			}
		}
	} else {
		LM_DBG("no legs\n");
	}
	accX_unlock(&ctx->lock);

	/* terminating line */
	*(p++) = '\n';
	*(p++) = 0;

	LM_GEN2(acc_log_facility, acc_log_level,
		"%.*screated=%lu;call_start_time=%lu;duration=%lu;ms_duration=%lu;setuptime=%lu%s",
		acc_env.text.len, acc_env.text.s,(unsigned long)ctx->created,
		(unsigned long)start_time.tv_sec,
		(unsigned long)(ctx->bye_time.tv_sec-start_time.tv_sec),
		(unsigned long)TIMEVAL_MS_DIFF(start_time, ctx->bye_time),
		(unsigned long)(start_time.tv_sec - ctx->created), log_msg);

	res = 1;
end:
	if (core_s.s)
		pkg_free(core_s.s);
	if (extra_s.s)
		pkg_free(extra_s.s);
	if (leg_s.s)
		pkg_free(leg_s.s);
	return res;
}


int acc_log_request( struct sip_msg *rq, struct sip_msg *rpl, int cdr_flag)
{
	static char log_msg[MAX_SYSLOG_SIZE];
	static char *log_msg_end=log_msg+MAX_SYSLOG_SIZE-2;
	char *p;
	int m;
	int i, j;
	unsigned int _created=0;
	unsigned int _setup_time=0;

	struct acc_extra* extra;
	acc_ctx_t* ctx = try_fetch_ctx();

	if (ctx && cdr_flag) {
		/* get created value from context */
		_created = ctx->created;
		_setup_time = time(NULL) - _created;
	}

	/* get default values */
	m = core2strar( rq, val_arr);

	/* get extra values */
	if (ctx) {
		/* prevent acces for setting variable */
		accX_lock(&ctx->lock);
		for (extra=log_extra_tags; extra; extra=extra->next, ++m)
			val_arr[m] = ctx->extra_values[extra->tag_idx].value;
	}

	for ( i = 0,p = log_msg ; i<m ; i++ ) {
		if (p + 1 + log_attrs[i].len + 1 + val_arr[i].len >= log_msg_end) {
			LM_WARN("acc message too long, truncating..\n");
			p = log_msg_end;
			break;
		}
		*(p++) = A_SEPARATOR_CHR;
		memcpy(p, log_attrs[i].s, log_attrs[i].len);
		p += log_attrs[i].len;
		*(p++) = A_EQ_CHR;
		memcpy(p, val_arr[i].s, val_arr[i].len);
		p += val_arr[i].len;
	}

	/* get per leg attributes */
	if (ctx) {
		/* we are still under lock here */
		if (ctx->leg_values) {
			for (j=0; j<ctx->legs_no; j++) {
				for (extra=log_leg_tags, i=m; extra; extra=extra->next, i++) {
					if (p+1+log_attrs[i].len+1+
							LEG_VALUE(j, extra, ctx).len >= log_msg_end) {
						LM_WARN("acc message too long, truncating..\n");
						p = log_msg_end;
						break;
					}
					*(p++) = A_SEPARATOR_CHR;
					memcpy(p, log_attrs[i].s, log_attrs[i].len);
					p += log_attrs[i].len;
					*(p++) = A_EQ_CHR;
					memcpy(p, LEG_VALUE(j, extra, ctx).s, LEG_VALUE(j, extra,ctx).len);
					p += LEG_VALUE(j, extra, ctx).len;
				}
			}
		} else {
			LM_DBG("no legs\n");
		}
		accX_unlock(&ctx->lock);
	}

	/* terminating line */
	*(p++) = '\n';
	*(p++) = 0;


	if (ctx && cdr_flag) {
		LM_GEN2(acc_log_facility, acc_log_level, "%.*stimestamp=%lu;created=%lu;setuptime=%lu%s",
			acc_env.text.len, acc_env.text.s,
			(unsigned long) acc_env.ts.tv_sec,
			(unsigned long) _created,
			(unsigned long) _setup_time, log_msg);
		return 1;
	}

	LM_GEN2(acc_log_facility, acc_log_level, "%.*stimestamp=%lu%s",
		acc_env.text.len, acc_env.text.s,(unsigned long) acc_env.ts.tv_sec, log_msg);

	return 1;
}

/********************************************
 *        SQL  ACCOUNTING
 ********************************************/

/* caution: keys need to be aligned to core format */
static db_key_t db_keys[ACC_CORE_LEN+1+ACC_CDR_LEN+MAX_ACC_EXTRA+MAX_ACC_LEG];
static db_val_t db_vals[ACC_CORE_LEN+1+ACC_CDR_LEN+MAX_ACC_EXTRA+MAX_ACC_LEG];


static void acc_db_init_keys(void)
{
	struct acc_extra *extra;
	int time_idx;
	int i;
	int n;

	/* init the static db keys */
	n = 0;
	/* caution: keys need to be aligned to core format */
	db_keys[n++] = &acc_method_col;
	db_keys[n++] = &acc_fromtag_col;
	db_keys[n++] = &acc_totag_col;
	db_keys[n++] = &acc_callid_col;
	db_keys[n++] = &acc_sipcode_col;
	db_keys[n++] = &acc_sipreason_col;
	db_keys[n++] = &acc_time_col;
	time_idx = n-1;

	/* init the extra db keys */
	for(extra=db_extra_tags; extra ; extra=extra->next)
		db_keys[n++] = &extra->name;

	/* multi leg call columns */
	for( extra=db_leg_tags; extra ; extra=extra->next)
		db_keys[n++] = &extra->name;

	/* init the values */
	for(i = 0; i < n; i++) {
		VAL_TYPE(db_vals + i)=DB_STR;
		VAL_NULL(db_vals + i)=0;
	}

	VAL_TYPE(db_vals+time_idx)=DB_DATETIME;

	db_keys[n++] = &acc_setuptime_col;
	db_keys[n++] = &acc_created_col;
	db_keys[n++] = &acc_duration_col;
	db_keys[n++] = &acc_ms_duration_col;
	VAL_TYPE(db_vals + n-1) = DB_INT;
	VAL_TYPE(db_vals + n-2) = DB_INT;
	VAL_TYPE(db_vals + n-3) = DB_DATETIME;
	VAL_TYPE(db_vals + n-4) = DB_INT;
}


/* binds to the corresponding database module
 * returns 0 on success, -1 on error */
int acc_db_init(const str* db_url)
{
	if (db_bind_mod(db_url, &acc_dbf)<0){
		LM_ERR("bind_db failed\n");
		return -1;
	}

	/* Check database capabilities */
	if (!DB_CAPABILITY(acc_dbf, DB_CAP_INSERT)) {
		LM_ERR("database module does not implement insert function\n");
		return -1;
	}

	db_handle=acc_dbf.init(db_url);

	if (db_handle==0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	if (db_check_table_version(&acc_dbf, db_handle, &db_table_acc,
				TABLE_VERSION) < 0) {
		LM_ERR("error during table version check\n");
		return -1;
	}

	acc_db_close();

	acc_db_init_keys();

	return 0;
}


/* initialize the database connection
 * returns 0 on success, -1 on error */
int acc_db_init_child(const str *db_url)
{
	db_handle=acc_dbf.init(db_url);
	if (db_handle==0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	return 0;
}


/* close a db connection */
void acc_db_close(void)
{
	if (db_handle && acc_dbf.close)
		acc_dbf.close(db_handle);
	db_handle = NULL;
}


int acc_db_request( struct sip_msg *rq, struct sip_msg *rpl,
		query_list_t **ins_list, int cdr_flag, int missed)
{
	/**
	 * The list of people which have bugfixed these PS:
	 *		d837ed865d - 2016, Bogdan.  Fix crash.
	 *		a250191728 - 2017, Razvan.  Fix crash.
	 *		    latest - 2020, Liviu.  Fix crash.
	 */
	static db_ps_t my_ps_ins = NULL;
	static db_ps_t my_ps_ins2 = NULL;
	static db_ps_t my_ps_ins3 = NULL;
	static db_ps_t my_ps_ins4 = NULL;
	static db_ps_t my_ps = NULL;
	static db_ps_t my_ps2 = NULL;
	static db_ps_t my_ps3 = NULL;
	static db_ps_t my_ps4 = NULL;
	db_ps_t *ps;
	int m;
	int n = 0;
	int i, j;
	unsigned int  _setup_time=0;
	unsigned int extra_start;

	struct acc_extra* extra;
	acc_ctx_t* ctx = try_fetch_ctx();

	if (!acc_dbf.use_table || !acc_dbf.insert) {
		LM_ERR("database not loaded! Probably database url not defined!\n");
		return -1;
	}

	if (ctx && cdr_flag) {
		/* get created value from context */
		_setup_time = time(NULL) - ctx->created;
	}

	/* formatted database columns */
	m = core2strar( rq, val_arr );

	for(i = 0; i < m; i++)
		VAL_STR(db_vals+i) = val_arr[i];

	/* time value */
	VAL_TIME(db_vals+(m++)) = acc_env.ts.tv_sec;

	/* just count the values to do other ops inside lock */
	if (ctx) {
		extra_start=m;
		for (extra=db_extra_tags; extra; extra=extra->next, ++m);
		for( extra=db_leg_tags, n=m; extra; extra=extra->next, n++);

		VAL_INT(db_vals+n) = _setup_time;

		if (cdr_flag) {
			VAL_NULL(db_vals+n+1) = 0;
			VAL_TIME(db_vals+n+1) = ctx->created;
		}
		else
			VAL_NULL(db_vals+n+1) = 1;

		n+=2;

		if (!missed) {
			/* duration and ms_duration */
			VAL_INT(db_vals+n) = 0;
			VAL_INT(db_vals+n+1) = 0;
			n+=2;
		}
	}

	acc_dbf.use_table(db_handle, &acc_env.text/*table*/);
	if (ctx && cdr_flag) {
		if (ins_list)
			ps = &my_ps_ins2; /* CDR to known table */
		else
			ps = &my_ps2; /* CDR to custom table */
	} else if (ctx) {
		if (missed) {
			if (ins_list)
				ps = &my_ps_ins; /* normal acc to known missed table */
			else
				ps = &my_ps; /* normal acc to custom missed table */
		} else {
			if (ins_list)
				ps = &my_ps_ins4; /* normal acc to known table */
			else
				ps = &my_ps4; /* normal acc to custom table */
		}
	} else {
		/* no ctx - no extra */
		if (ins_list)
			ps = &my_ps_ins3;
		else
			ps = &my_ps3;
	}

	CON_PS_REFERENCE(db_handle) = ps;


	/* multi-leg columns */
	if (ctx) {
		/* prevent acces for setting variable */
		accX_lock(&ctx->lock);

		/* extra columns */
		if (ctx->extra_values) {
			for (extra=db_extra_tags, i=extra_start; extra; extra=extra->next, ++i) {
				VAL_STR(db_vals+i) = ctx->extra_values[extra->tag_idx].value;
			}
		}

		if ( !ctx->leg_values ) {
			accX_unlock(&ctx->lock);
			if (con_set_inslist(&acc_dbf,db_handle,ins_list,db_keys,n) < 0 )
				CON_RESET_INSLIST(db_handle);
			if (acc_dbf.insert(db_handle, db_keys, db_vals, n) < 0) {
				LM_ERR("failed to insert into %.*s table\n", acc_env.text.len, acc_env.text.s);
				return -1;
			}
		} else {
			for (j=0; j < ctx->legs_no; j++) {
				for (extra=db_leg_tags, i=m; extra; extra=extra->next, i++) {
					VAL_STR(db_vals+i)=LEG_VALUE( j, extra, ctx);
				}
				if (con_set_inslist(&acc_dbf,db_handle,ins_list,db_keys,n) < 0 )
					CON_RESET_INSLIST(db_handle);
				if (acc_dbf.insert(db_handle, db_keys, db_vals, n) < 0) {
					LM_ERR("failed to insert into %.*s table\n", acc_env.text.len, acc_env.text.s);
					accX_unlock(&ctx->lock);
					return -1;
				}
			}
			accX_unlock(&ctx->lock);
		}
	} else {
		if (con_set_inslist(&acc_dbf,db_handle,ins_list,db_keys,m) < 0 )
				CON_RESET_INSLIST(db_handle);
		if (acc_dbf.insert(db_handle, db_keys, db_vals, m) < 0) {
			LM_ERR("failed to insert into %.*s table\n", acc_env.text.len, acc_env.text.s);
			return -1;
		}
	}

	return 1;
}

int acc_db_cdrs(struct dlg_cell *dlg, struct sip_msg *msg, acc_ctx_t* ctx)
{
	int total, i, ret, res = -1, j;
	int nr_leg_vals=0;
	struct timeval start_time;
	str core_s, leg_s, extra_s, table;
	static db_ps_t my_ps = NULL;
	static query_list_t *ins_list = NULL;

	struct acc_extra* extra;

	if (!acc_dbf.use_table || !acc_dbf.insert) {
		LM_ERR("database not loaded! Probably database url not defined!\n");
		return -1;
	}

	core_s.s = extra_s.s = leg_s.s = 0;

	ret = prebuild_core_arr(dlg, &core_s, &start_time);
	if (ret < 0) {
		LM_ERR("cannot copy core arguments\n");
		goto end;
	}

	/* count the number of extra values*/
	for (extra=db_extra_tags; extra; extra=extra->next, ++ret);
	/* count the number of leg values*/
	for (extra=db_leg_tags, nr_leg_vals=0; extra; extra=extra->next, nr_leg_vals++);

	table = ctx->acc_table;

	for (i=0;i<ACC_CORE_LEN;i++)
		VAL_STR(db_vals+i) = val_arr[i];

	VAL_TIME(db_vals+ACC_CORE_LEN) = start_time.tv_sec;
	VAL_INT(db_vals+ret+nr_leg_vals+1) =
		start_time.tv_sec - ctx->created;
	VAL_NULL(db_vals+ret+nr_leg_vals+2) = 0;
	VAL_TIME(db_vals+ret+nr_leg_vals+2) = ctx->created;
	VAL_INT(db_vals+ret+nr_leg_vals+3) =
		ctx->bye_time.tv_sec - start_time.tv_sec;
	VAL_INT(db_vals+ret+nr_leg_vals+4) =
		TIMEVAL_MS_DIFF(start_time, ctx->bye_time);

	total = ret + 5;
	acc_dbf.use_table(db_handle, &table);
	CON_PS_REFERENCE(db_handle) = &my_ps;


	/* prevent acces for setting variable */
	accX_lock(&ctx->lock);

	for (extra=db_extra_tags,i=ACC_CORE_LEN+1; extra; extra=extra->next, ++i)
		VAL_STR(db_vals+i) = ctx->extra_values[extra->tag_idx].value;

	if (!ctx->leg_values) {
		if (con_set_inslist(&acc_dbf,db_handle,&ins_list,db_keys,total) < 0 )
			CON_RESET_INSLIST(db_handle);
		if (acc_dbf.insert(db_handle, db_keys, db_vals, total) < 0) {
			LM_ERR("failed to insert into database\n");
			accX_unlock(&ctx->lock);
			goto end;
		}
		accX_unlock(&ctx->lock);
	} else {
		total += nr_leg_vals;
		leg_s.len = 4;
		for (i=0; i < ctx->legs_no; i++) {
			for (extra=db_leg_tags, j=0; extra; extra=extra->next, j++) {
				VAL_STR(db_vals+ret+j+1) = LEG_VALUE( i, extra, ctx);
			}

			if (con_set_inslist(&acc_dbf,db_handle,&ins_list,db_keys,total) < 0 )
				CON_RESET_INSLIST(db_handle);
			if (acc_dbf.insert(db_handle,db_keys,db_vals,total) < 0) {
				LM_ERR("failed inserting into database\n");
				accX_unlock(&ctx->lock);
				goto end;
			}
		}
		accX_unlock(&ctx->lock);
	}

	res = 1;
end:
	if (core_s.s)
		pkg_free(core_s.s);
	if (extra_s.s)
		pkg_free(extra_s.s);
	if (leg_s.s)
		pkg_free(leg_s.s);
	return res;
}


/********************************************
 *        AAA PROTOCOL  ACCOUNTING
 ********************************************/
enum { RA_ACCT_STATUS_TYPE=0, RA_SERVICE_TYPE, RA_SIP_RESPONSE_CODE,
	RA_SIP_METHOD, RA_TIME_STAMP, RA_STATIC_MAX};
enum {RV_STATUS_START=0, RV_STATUS_STOP, RV_STATUS_ALIVE, RV_STATUS_FAILED,
	RV_SIP_SESSION, RV_STATIC_MAX};
static aaa_map
	rd_attrs[RA_STATIC_MAX+ACC_CORE_LEN+ACC_CDR_LEN-2+MAX_ACC_EXTRA+MAX_ACC_LEG];
static aaa_map rd_vals[RV_STATIC_MAX];

int init_acc_aaa(char* aaa_proto_url, int srv_type)
{
	int n;
	str prot_url;

	memset(rd_attrs, 0, sizeof(rd_attrs));
	memset(rd_vals, 0, sizeof(rd_vals));

	rd_attrs[RA_ACCT_STATUS_TYPE].name  = "Acct-Status-Type";
	rd_attrs[RA_SERVICE_TYPE].name      = "Service-Type";
	rd_attrs[RA_SIP_RESPONSE_CODE].name	= "Sip-Response-Code";
	rd_attrs[RA_SIP_METHOD].name        = "Sip-Method";
	rd_attrs[RA_TIME_STAMP].name        = "Event-Timestamp";
	n = RA_STATIC_MAX;
	/* caution: keep these aligned to core acc output */
	rd_attrs[n++].name                  = "Sip-From-Tag";
	rd_attrs[n++].name                  = "Sip-To-Tag";
	rd_attrs[n++].name                  = "Acct-Session-Id";

	rd_vals[RV_STATUS_START].name        = "Start";
	rd_vals[RV_STATUS_STOP].name         = "Stop";
	rd_vals[RV_STATUS_ALIVE].name        = "Alive";
	rd_vals[RV_STATUS_FAILED].name       = "Failed";
	rd_vals[RV_SIP_SESSION].name         = "Sip-Session";

	/* add and count the extras as attributes */
	n += extra2attrs( aaa_extra_tags, rd_attrs, n);

	/* add and count the legs as attributes */
	n += extra2attrs( aaa_leg_tags, rd_attrs, n);

	rd_attrs[n++].name = "Sip-Call-Duration";
	rd_attrs[n++].name = "Sip-Call-MSDuration";
	rd_attrs[n++].name = "Sip-Call-Setuptime";
	rd_attrs[n++].name = "Sip-Call-Created";

	prot_url.s = aaa_proto_url;
	prot_url.len = strlen(aaa_proto_url);

	if(aaa_prot_bind(&prot_url, &proto)) {
		LM_ERR("AAA protocol bind failure\n");
		return -1;
	}

	conn = proto.init_prot(&prot_url);
	if (!conn) {
		LM_ERR("AAA protocol initialization failure\n");
		return -1;
	}

	INIT_AV(proto, conn, rd_attrs, n, rd_vals, RV_STATIC_MAX, "acc", -1, -1);

	if (srv_type != -1)
		rd_vals[RV_SIP_SESSION].value = srv_type;


	LM_DBG("init_acc_aaa success!\n");
	return 0;
}

static inline aaa_map *aaa_status( struct sip_msg *req, int code )
{
	if (req->REQ_METHOD == METHOD_INVITE && get_to(req)->tag_value.len == 0
				&& code>=200 && code<300)
		return &rd_vals[RV_STATUS_START];
	if ((req->REQ_METHOD==METHOD_BYE || req->REQ_METHOD==METHOD_CANCEL))
		return &rd_vals[RV_STATUS_STOP];
	if (get_to(req)->tag_value.len)
		return &rd_vals[RV_STATUS_ALIVE];
	return &rd_vals[RV_STATUS_FAILED];
}

#define ADD_AAA_AVPAIR(_attr,_val,_len) \
	do { \
		if ( (_len)!=0 && \
		proto.avp_add(conn, send, &rd_attrs[_attr], _val, _len, 0)) { \
			LM_ERR("failed to add %s, %d\n", rd_attrs[_attr].name,_attr); \
			goto error; \
		} \
	}while(0)

int acc_aaa_request( struct sip_msg *req, struct sip_msg *rpl, int cdr_flag)
{
	int attr_cnt, extra_len = 0;
	aaa_message *send;
	int offset, i, av_type;
	aaa_map *r_stat;
	int locked = 0;

	unsigned int _created=0;
	unsigned int _setup_time=0;

	struct acc_extra* extra;
	acc_ctx_t* ctx = try_fetch_ctx();

	if ((send = proto.create_aaa_message(conn, AAA_ACCT)) == NULL) {
		LM_ERR("failed to create new aaa message for acct\n");
		return -1;
	}

	if (ctx &&cdr_flag) {
		_created = ctx->created;
		_setup_time = time(NULL) - _created;
	}

	attr_cnt = core2strar( req, val_arr);
	/* not interested in the last 2 values */
	attr_cnt -= 2;

	r_stat = aaa_status( req, acc_env.code); /* AAA PROTOCOL status */
	ADD_AAA_AVPAIR( RA_ACCT_STATUS_TYPE, &(r_stat->value), -1);

	av_type = rd_vals[RV_SIP_SESSION].value; /* session*/
	ADD_AAA_AVPAIR( RA_SERVICE_TYPE, &av_type, -1);

	av_type = (uint32_t)acc_env.code; /* status=integer */
	ADD_AAA_AVPAIR( RA_SIP_RESPONSE_CODE, &av_type, -1);

	av_type = req->REQ_METHOD; /* method */
	ADD_AAA_AVPAIR( RA_SIP_METHOD, &av_type, -1);

	/* unix time */
	av_type = (uint32_t)acc_env.ts.tv_sec;
	ADD_AAA_AVPAIR( RA_TIME_STAMP, &av_type, -1);

	if (ctx)
		for (extra=aaa_extra_tags; extra; extra=extra->next, extra_len++);

	/* add the values for the vector - start from 1 instead of
	 * 0 to skip the first value which is the METHOD as string */
	offset = RA_STATIC_MAX-1;
	for (i = 1; i < attr_cnt; i++)
		ADD_AAA_AVPAIR( offset + i, val_arr[i].s, val_arr[i].len );

	if (cdr_flag) {
		av_type = (uint32_t)_setup_time;
		ADD_AAA_AVPAIR( offset + attr_cnt + extra_len + 1, &av_type, -1);
		av_type = (uint32_t)_created;
		ADD_AAA_AVPAIR( offset + attr_cnt + extra_len + 2, &av_type, -1);
	}

	/* call-legs attributes also get inserted */
	if (ctx) {
		/* prevent acces for setting variable */
		accX_lock(&ctx->lock);
		locked = 1;

		for (extra = aaa_extra_tags, i=attr_cnt; extra; i++, extra=extra->next) {
			ADD_AAA_AVPAIR(offset+i, ctx->extra_values[extra->tag_idx].value.s,
										ctx->extra_values[extra->tag_idx].value.len);
		}

		if (ctx->leg_values) {
			offset += attr_cnt;
			for (i=0; i<ctx->legs_no; i++) {
				for (extra=aaa_leg_tags; extra; extra=extra->next) {
					ADD_AAA_AVPAIR( offset+i,
						LEG_VALUE(i, extra, ctx).s, LEG_VALUE(i, extra, ctx).len);
				}
			}
		}
		accX_unlock(&ctx->lock);
		locked = 0;
	}

	if (proto.send_aaa_request(conn, send, NULL)) {
		LM_ERR("Radius accounting request failed for status: '%s' "
			"Call-Id: '%.*s' \n",r_stat->name,
			req->callid->body.len, req->callid->body.s);
		goto error;
	}

	proto.destroy_aaa_message(conn, send);
	return 1;

error:
	if (locked)
		accX_unlock(&ctx->lock);
	proto.destroy_aaa_message(conn, send);
	return -1;
}

int acc_aaa_cdrs(struct dlg_cell *dlg, struct sip_msg *msg, acc_ctx_t* ctx)
{
	int i, j, ret, res = -1;
	int nr_leg_vals=0;
	struct timeval start_time;
	str core_s, leg_s, extra_s;
	aaa_message *send = NULL;
	int offset, av_type;
	aaa_map *r_stat;
	int locked = 0;

	struct acc_extra* extra;

	core_s.s = extra_s.s = leg_s.s = 0;

	ret = prebuild_core_arr(dlg, &core_s, &start_time);
	if (ret < 0) {
		LM_ERR("cannot copy core arguments\n");
		goto error;
	}

	/* count the number of extra values */
	for (extra=aaa_extra_tags; extra; extra=extra->next, ++ret);
	/* count the number of values in one leg */
	for (extra=aaa_leg_tags, nr_leg_vals=0; extra; extra=extra->next, nr_leg_vals++);

	if ((send = proto.create_aaa_message(conn, AAA_ACCT)) == NULL) {
		LM_ERR("failed to create new aaa message for acct\n");
		goto error;
	}

	r_stat = &rd_vals[RV_STATUS_STOP]; /* AAA PROTOCOL status */
	ADD_AAA_AVPAIR(RA_ACCT_STATUS_TYPE,&(r_stat->value),-1);

	av_type = rd_vals[RV_SIP_SESSION].value; /* session*/
	ADD_AAA_AVPAIR( RA_SERVICE_TYPE, &av_type, -1);

	av_type =  (uint32_t)acc_env.code; /* status=integer */
	ADD_AAA_AVPAIR( RA_SIP_RESPONSE_CODE, &av_type, -1);

	av_type = METHOD_INVITE; /* method */
	ADD_AAA_AVPAIR( RA_SIP_METHOD, &av_type, -1);

	av_type = (uint32_t)start_time.tv_sec; /* call start time */
	ADD_AAA_AVPAIR( RA_TIME_STAMP, &av_type, -1);

	/* add the values for the vector - start from 1 instead of
	 * 0 to skip the first value which is the METHOD as string */
	offset = RA_STATIC_MAX-1;
	for (i = 1; i < ACC_CORE_LEN-2; i++)
		ADD_AAA_AVPAIR( offset + i, val_arr[i].s, val_arr[i].len );
	offset = ret + 2;

	/* add duration and setup values */
	av_type = (uint32_t)(ctx->bye_time.tv_sec - start_time.tv_sec);
	ADD_AAA_AVPAIR( offset + nr_leg_vals, &av_type, -1);
	av_type = (uint32_t)TIMEVAL_MS_DIFF(start_time, ctx->bye_time);
	ADD_AAA_AVPAIR( offset + nr_leg_vals + 1, &av_type, -1);
	av_type = (uint32_t)(start_time.tv_sec - ctx->created);
	ADD_AAA_AVPAIR( offset + nr_leg_vals + 2, &av_type, -1);

	/* prevent acces for setting variable */
	accX_lock(&ctx->lock);
	locked = 1;

	/* call-legs attributes also get inserted */
	/**
	 * there are RA_STATIC_MAX values in that enum
	 * and there are three more values defined in rd_attrs:
	 * Sip-From-Tag, Sip-ToTag, Acct-Session-Id
	 * so the total number of values we willhave to jump over is
	 * RA_STATIC_MAX+3
	 */
	for (extra=aaa_extra_tags, i=RA_STATIC_MAX+3; extra; extra=extra->next, ++i) {
		ADD_AAA_AVPAIR( i, ctx->extra_values[extra->tag_idx].value.s ,
							ctx->extra_values[extra->tag_idx].value.len );
	}

	if (ctx->leg_values) {
		leg_s.len = 4;
		for (i=0; i<ctx->legs_no; i++) {
			for (extra=aaa_leg_tags,j=0; extra; extra=extra->next, j++) {
				ADD_AAA_AVPAIR( offset+j,
					LEG_VALUE(i, extra, ctx).s, LEG_VALUE(i, extra, ctx).len);
			}
		}
	}
	accX_unlock(&ctx->lock);
	locked =  0;

	if (proto.send_aaa_request(conn, send, NULL)) {
		LM_ERR("Radius accounting request failed for status: '%s' "
			"Call-Id: '%.*s' \n",r_stat->name,
			val_arr[3].len, val_arr[3].s);
		goto error;
	}


	res = 1;
error:
	if (locked)
		accX_unlock(&ctx->lock);
	if (core_s.s)
		pkg_free(core_s.s);
	if (extra_s.s)
		pkg_free(extra_s.s);
	if (leg_s.s)
		pkg_free(leg_s.s);
	return res;
}


/********************************************
 *        EVENT INTERFACE  ACCOUNTING
 ********************************************/
/* names of the parameters of the event */
static str acc_method_evi     = str_init("method");
static str acc_fromtag_evi    = str_init("from_tag");
static str acc_totag_evi      = str_init("to_tag");
static str acc_callid_evi     = str_init("callid");
static str acc_sipcode_evi    = str_init("sip_code");
static str acc_sipreason_evi  = str_init("sip_reason");
static str acc_time_evi       = str_init("time");
static str acc_duration_evi   = str_init("duration");
static str acc_ms_duration_evi= str_init("ms_duration");
static str acc_setuptime_evi  = str_init("setuptime");
static str acc_created_evi    = str_init("created");

static str evi_acc_name = str_init("E_ACC_CDR");
static str evi_acc_event_name = str_init("E_ACC_EVENT");
static str evi_acc_missed_name = str_init("E_ACC_MISSED_EVENT");

/* static event's list */
evi_params_p acc_event_params;
evi_param_p evi_params[ACC_CORE_LEN+1+MAX_ACC_EXTRA+MAX_ACC_LEG];

evi_params_p acc_cdr_event_params;
evi_param_p evi_cdr_params[ACC_CORE_LEN+1+ACC_CDR_LEN+
	MAX_ACC_EXTRA+MAX_ACC_LEG];

evi_params_p acc_missed_event_params;
evi_param_p evi_missed_params[ACC_CORE_LEN+1+ACC_DLG_LEN+
	MAX_ACC_EXTRA+MAX_ACC_LEG];

#define EVI_CREATE_PARAM(_name, _list, _arr, _n) \
	do { \
		if (!(_arr[_n++] = \
				evi_param_create(_list, &(_name)))) \
			goto error; \
	} while (0)

#define EVI_CREATE_PARAMS(_name) \
	do { \
		if (!(evi_params[n++] = \
				evi_param_create(acc_event_params, &(_name)))) \
			goto error; \
		if (!(evi_cdr_params[nc++] = \
				evi_param_create(acc_cdr_event_params, &(_name)))) \
			goto error; \
		if (!(evi_missed_params[nm++] = \
				evi_param_create(acc_missed_event_params, &(_name)))) \
			goto error; \
	} while (0)


int  init_acc_evi(void)
{
	struct acc_extra *extra;
	int n = 0, nm = 0, nc = 0;

	acc_event = evi_publish_event(evi_acc_event_name);
	if (acc_event == EVI_ERROR) {
		LM_ERR("cannot register ACC event\n");
		return -1;
	}

	acc_cdr_event = evi_publish_event(evi_acc_name);
	if (acc_cdr_event == EVI_ERROR) {
		LM_ERR("cannot register ACC CDR event\n");
		return -1;
	}

	acc_missed_event = evi_publish_event(evi_acc_missed_name);
	if (acc_missed_event == EVI_ERROR) {
		LM_ERR("cannot register missed CDR event\n");
		return -1;
	}

	/* we handle the parameters list by ourselves */
	acc_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!acc_event_params) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(acc_event_params, 0, sizeof(evi_params_t));

	acc_cdr_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!acc_cdr_event_params) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(acc_cdr_event_params, 0, sizeof(evi_params_t));

	acc_missed_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!acc_missed_event_params) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(acc_missed_event_params, 0, sizeof(evi_params_t));

	EVI_CREATE_PARAMS(acc_method_evi);
	EVI_CREATE_PARAMS(acc_fromtag_evi);
	EVI_CREATE_PARAMS(acc_totag_evi);
	EVI_CREATE_PARAMS(acc_callid_evi);
	EVI_CREATE_PARAMS(acc_sipcode_evi);
	EVI_CREATE_PARAMS(acc_sipreason_evi);
	EVI_CREATE_PARAMS(acc_time_evi);

	/* init the extra db keys */
	for(extra=evi_extra_tags; extra ; extra=extra->next)
		EVI_CREATE_PARAMS(extra->name);

	/* multi leg call columns */
	for( extra=evi_leg_tags; extra ; extra=extra->next)
		EVI_CREATE_PARAMS(extra->name);

	EVI_CREATE_PARAM(acc_duration_evi, acc_cdr_event_params, evi_cdr_params, nc);
	EVI_CREATE_PARAM(acc_ms_duration_evi, acc_cdr_event_params,
		evi_cdr_params, nc);

	EVI_CREATE_PARAM(acc_setuptime_evi, acc_cdr_event_params, evi_cdr_params, nc);
	EVI_CREATE_PARAM(acc_setuptime_evi, acc_missed_event_params,
		evi_missed_params, nm);

	EVI_CREATE_PARAM(acc_created_evi, acc_cdr_event_params, evi_cdr_params, nc);
	EVI_CREATE_PARAM(acc_created_evi, acc_missed_event_params,
		evi_missed_params, nm);

	return 0;

error:
	LM_ERR("error while creating parameter %d\n", n-1);
	return -1;
}
#undef EVI_CREATE_PARAM


int acc_evi_request( struct sip_msg *rq, struct sip_msg *rpl, int cdr_flag,
	int missed_flag)
{
	int m;
	int n;
	int i;
	int ret = -1;
	int nr_leg_vals;

	unsigned int _created=0;
	unsigned int _setup_time=0;

	struct acc_extra* extra;
	acc_ctx_t* ctx = try_fetch_ctx();

	/*
	 * if the code is not set, choose the missed calls event
	 * otherwise, check if the code is negative
	 */
	if (acc_env.event == EVI_ERROR) {
		LM_ERR("event not registered %d\n", acc_event);
		return -1;
	}

	/* check if someone is interested in this event */
	if (!evi_probe_event(acc_env.event))
		return 1;

	if (ctx && cdr_flag) {
		_created = ctx->created;
		_setup_time = time(NULL) - _created;
	}

	m = core2strar( rq, val_arr );

	for(i = 0; i < m; i++)
		if(evi_param_set_str(acc_env.ev_params[i], &val_arr[i]) < 0) {
			LM_ERR("cannot set acc parameter\n");
			return -1;
		}
	/* time value */
	if (evi_param_set_int(acc_env.ev_params[m++], &acc_env.ts) < 0) {
		LM_ERR("cannot set timestamp parameter\n");
		return -1;
	}

	for (extra=evi_extra_tags; extra; extra=extra->next, ++m);

	for (extra=evi_leg_tags, nr_leg_vals=0; extra; extra=extra->next, nr_leg_vals++);

	if (missed_flag && evi_param_set_int(acc_env.ev_params[m+nr_leg_vals],
		&_setup_time) < 0) {
		LM_ERR("cannot set setuptime parameter\n");
		goto end;
	}

	if (missed_flag && evi_param_set_int(acc_env.ev_params[m+nr_leg_vals+1],
		&_created) < 0) {
		LM_ERR("cannot set created parameter\n");
		goto end;
	}


	/* multi-leg columns */
	if (ctx) {
		/* prevent acces for setting variable */
		accX_lock(&ctx->lock);

		/* extra columns */
		/* i will now indicate at the first position after the core values, where
		 * we have to put the extras*/
		for( extra=evi_extra_tags, i++; extra; extra=extra->next, i++)
			if(evi_param_set_str(acc_env.ev_params[i],
						&ctx->extra_values[extra->tag_idx].value) < 0) {
				LM_ERR("cannot set acc extra parameter\n");
				accX_unlock(&ctx->lock);
				return -1;
			}

		if ( !ctx->leg_values) {
			accX_unlock(&ctx->lock);
			if (evi_raise_event(acc_env.event, acc_env.ev_params_list) < 0) {
				LM_ERR("cannot raise ACC event\n");
				goto end;
			}
		} else {
			for (i=0; i<ctx->legs_no; i++) {
				for (extra=evi_leg_tags, n=m; extra; extra=extra->next,n++) {
					if (evi_param_set_str(acc_env.ev_params[n],
								&LEG_VALUE(i, extra, ctx)) < 0) {
						LM_ERR("cannot set acc extra parameter\n");
						accX_unlock(&ctx->lock);
						goto end;
					}
				}

				if (evi_raise_event(acc_env.event, acc_env.ev_params_list) < 0) {
					LM_ERR("cannot raise ACC event\n");
					accX_unlock(&ctx->lock);
					goto end;
				}
			}
			accX_unlock(&ctx->lock);
		}
	} else {
		if (evi_raise_event(acc_env.event, acc_env.ev_params_list) < 0) {
			LM_ERR("cannot raise ACC event\n");
			goto end;
		}
	}



	ret = 1;
end:
	return ret;
}

int acc_evi_cdrs(struct dlg_cell *dlg, struct sip_msg *msg, acc_ctx_t* ctx)
{
	int  i, ret, res = -1, j;
	int nr_leg_vals;
	int aux_time;
	struct timeval start_time;
	str core_s, leg_s, extra_s;

	struct acc_extra* extra;

	if (acc_cdr_event == EVI_ERROR) {
		LM_ERR("event not registered %d\n", acc_cdr_event);
		return -1;
	}

	/* check if someone is interested in this event */
	if (!evi_probe_event(acc_cdr_event))
		return 1;

	core_s.s = extra_s.s = leg_s.s = 0;

	ret = prebuild_core_arr(dlg, &core_s, &start_time);
	if (ret < 0) {
		LM_ERR("cannot copy core arguments\n");
		goto end;
	}

	/* count extras just to avoid doing all operations below  under lock */
	for (extra=evi_extra_tags; extra; extra=extra->next, ++ret);

	/* count the number of leg values */
	for (extra=evi_leg_tags, nr_leg_vals=0; extra; extra=extra->next, nr_leg_vals++);

	for (i=0;i<ACC_CORE_LEN;i++)
		if(evi_param_set_str(evi_cdr_params[i], &val_arr[i]) < 0) {
			LM_ERR("cannot set acc parameter\n");
			goto end;
		}

	if (evi_param_set_int(evi_cdr_params[ACC_CORE_LEN], &start_time.tv_sec) < 0) {
		LM_ERR("cannot set start_time parameter\n");
		goto end;
	}

	aux_time = ctx->bye_time.tv_sec - start_time.tv_sec;
	if (evi_param_set_int(evi_cdr_params[ret+nr_leg_vals+1], &aux_time) < 0) {
		LM_ERR("cannot set duration parameter\n");
		goto end;
	}

	aux_time = TIMEVAL_MS_DIFF(start_time, ctx->bye_time);
	if (evi_param_set_int(evi_cdr_params[ret+nr_leg_vals+2], &aux_time) < 0) {
		LM_ERR("cannot set duration parameter\n");
		goto end;
	}
	aux_time = start_time.tv_sec - ctx->created;
	if (evi_param_set_int(evi_cdr_params[ret+nr_leg_vals+3], &aux_time) < 0) {
		LM_ERR("cannot set setuptime parameter\n");
		goto end;
	}
	if (evi_param_set_int(evi_cdr_params[ret+nr_leg_vals+4], &ctx->created) < 0) {
		LM_ERR("cannot set created parameter\n");
		goto end;
	}

	/* prevent acces for setting variable */
	accX_lock(&ctx->lock);

	for (extra=evi_extra_tags, i=ACC_CORE_LEN+1; extra; extra=extra->next, i++)
		if(evi_param_set_str(evi_cdr_params[i], &ctx->extra_values[extra->tag_idx].value) < 0) {
			LM_ERR("cannot set acc parameter\n");
			accX_unlock(&ctx->lock);
			goto end;
		}


	if (!ctx->leg_values) {
		accX_unlock(&ctx->lock);
		/* make sure the parameters list is built */
		if (evi_raise_event(acc_cdr_event, acc_cdr_event_params) < 0) {
			LM_ERR("cannot raise acc CDR event\n");
			goto end;
		}
	} else {
		leg_s.len = 4;
		for (i=0;i<ctx->legs_no;i++) {
			for (extra=evi_leg_tags, j=0; extra; extra=extra->next, j++) {
				if(evi_param_set_str(evi_cdr_params[ret+j+1], &LEG_VALUE(i, extra, ctx)) < 0) {
					LM_ERR("cannot set acc parameter\n");
					accX_unlock(&ctx->lock);
					goto end;
				}
			}

			if (evi_raise_event(acc_cdr_event, acc_cdr_event_params) < 0) {
				LM_ERR("cannot raise acc CDR event\n");
				accX_unlock(&ctx->lock);
				goto end;
			}
		}
		accX_unlock(&ctx->lock);
	}

	res = 1;
end:
	if (core_s.s)
		pkg_free(core_s.s);
	if (extra_s.s)
		pkg_free(extra_s.s);
	if (leg_s.s)
		pkg_free(leg_s.s);
	return res;
}

/* Functions used to store values into dlg */

static str cdr_buf;
int cdr_data_len;

int set_dlg_value(str *value)
{
	if (value->s == NULL)
		value->len = 0;

	if (value->len > MAX_LEN_VALUE) {
		LM_WARN("value too long, truncating! (%.*s..., len: %d)\n",
		        64, value->s, value->len);
		value->len = MAX_LEN_VALUE;
	}

	if (pkg_str_extend(&cdr_buf, cdr_data_len + value->len + 2) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	SET_LEN(cdr_buf.s + cdr_data_len, value->len);

	memcpy(cdr_buf.s + cdr_data_len + 2, value->s, value->len);
	cdr_data_len += value->len + 2;

	return 1;
}

static void complete_dlg_values(str *stored_values,str *val_arr,short nr_vals)
{
	short i;
	char *p = stored_values->s;
	short len;

	for (i=0;i<nr_vals;i++)
	{
		len = GET_LEN(p);
		val_arr[i].len = len;
		val_arr[i].s = p+2;
		p = p + len + 2;
	}
}

/* stores core values and leg values into dlg */
int store_core_leg_values(struct dlg_cell *dlg, struct sip_msg *req)
{
	str bytes;

	if ( build_core_dlg_values(dlg, req) < 0) {
		LM_ERR("cannot build core value string\n");
		return -1;
	}

	bytes.s = cdr_buf.s;
	bytes.len = cdr_data_len;
	if ( dlg_api.store_dlg_value(dlg, &core_str, &bytes) < 0) {
		LM_ERR("cannot store core values into dialog\n");
		return -1;
	}

	return 1;
}


/* stores extra values into dlg */
int store_extra_values(extra_value_t* values, str *values_str,
		struct dlg_cell *dlg)
{
	str bytes;

	if ( build_extra_dlg_values(values) < 0) {
		LM_ERR("cannot build core value string\n");
		return -1;
	}

	bytes.s = cdr_buf.s;
	bytes.len = cdr_data_len;
	if ( dlg_api.store_dlg_value(dlg, values_str, &bytes) < 0) {
		LM_ERR("cannot store core values into dialog\n");
		return -1;
	}

	return 1;
}

int store_leg_values(acc_ctx_t* ctx, str* values_str, struct dlg_cell *dlg)
{
	str bytes;

	if (ctx == NULL || values_str == NULL) {
		LM_ERR("bad usage!\n");
		return -1;
	}

	if ( build_leg_dlg_values(ctx) < 0) {
		LM_ERR("cannot build legs value string\n");
		return -1;
	}

	bytes.s = cdr_buf.s;
	bytes.len = cdr_data_len;
	if (dlg_api.store_dlg_value(dlg, values_str, &bytes) < 0) {
		LM_ERR("cannot store dialog string\n");
		return -1;
	}

	return 0;
}

/* builds core string */
static int build_core_dlg_values(struct dlg_cell *dlg,struct sip_msg *req)
{
	str value;
	int i, count;

	cdr_data_len = 0;
	count = core2strar( req, val_arr);
	for (i=0; i<count; i++)
		if (set_dlg_value(&val_arr[i]) < 0)
			return -1;

	value.s = (char*)&acc_env.ts;
	value.len = sizeof(struct timeval);
	if (set_dlg_value(&value) < 0)
		return -1;

	return 1;
}

/* builds extra values string */
static int build_extra_dlg_values(extra_value_t* values)
{
	str val_arr[MAX_ACC_EXTRA];
	int nr, i;

	/* init cdr buf before doing SET_LEN on it */
	if (pkg_str_extend(&cdr_buf, STRING_INIT_SIZE) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	cdr_data_len = 2;
	nr = extra2strar(values, val_arr, 0);

	for (i=0; i<nr; i++)
		if (set_dlg_value(&val_arr[i]) < 0)
			return -1;
	SET_LEN(cdr_buf.s, nr);

	return nr;
}

/* builds leg values string */
static int build_leg_dlg_values(acc_ctx_t* ctx)
{
	int i, j;

	/* init cdr buf before doing SET_LEN on it */
	if (pkg_str_extend(&cdr_buf, STRING_INIT_SIZE) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	cdr_data_len = 4;
	if (!ctx->leg_values)
		SET_LEN(cdr_buf.s,0);
	else {
		SET_LEN(cdr_buf.s, leg_tgs_len);
		for (i=0; i < ctx->legs_no; i++) {
			for (j=0; j < leg_tgs_len; j++) {
				if (set_dlg_value(&ctx->leg_values[i][j].value) < 0) {
					return -1;
				}
			}
		}
	}

	SET_LEN(cdr_buf.s+2,ctx->legs_no);
	return 0;
}

/* create accounting dialog */
struct dlg_cell *create_acc_dlg(struct sip_msg* req)
{
	struct dlg_cell *dlg;

	if (!dlg_api.get_dlg) {
		LM_ERR("dialog not loaded!\n");
		return NULL;
	}

	dlg = dlg_api.get_dlg();
	if (!dlg) {
		/* if the dialog doesn't exist we try to create it */
		if ( dlg_api.create_dlg(req,0) < 0) {
			LM_ERR("error creating new dialog\n");
			return NULL;
		}
		dlg = dlg_api.get_dlg();
		if (!dlg) {
			LM_ERR("error getting new dialog\n");
			return NULL;
		}
	}

	return dlg;
}


/* gets core values from dlg and stores them into val_arr array */
static int prebuild_core_arr(struct dlg_cell *dlg, str *buffer, struct timeval *start)
{
	if (!start || !buffer) {
		LM_ERR("invalid parameters\n");
		return -1;
	}
	buffer->len = 0;
	buffer->s = 0;

	/* fetching core string values */
	if (dlg_api.fetch_dlg_value(dlg, &core_str, buffer, 1) < 0) {
		LM_ERR("cannot fetch core string value\n");
		return -1;
	}

	complete_dlg_values(buffer, val_arr, ACC_CORE_LEN+1);
	memcpy(start, val_arr[ACC_CORE_LEN].s, val_arr[ACC_CORE_LEN].len);

	return ACC_CORE_LEN;
}


/*
 * @param list of tag names and their indexes
 *
 *
 */
static int restore_extra_from_str(extra_value_t *values,
											 str* extra_s, int extra_len)
{
	int i;

	pv_value_t value;

	value.flags = PV_VAL_STR;
	for (i=0; i<extra_len; i++) {
		value.rs.len = GET_LEN(extra_s->s);
		value.rs.s =  extra_s->s + 2;
		value.flags = value.rs.len == 0 ? PV_VAL_NULL : PV_VAL_STR;

		if (set_value_shm(&value, &values[i])< 0) {
			LM_ERR("failed to set shm value!\n");
			return -1;
		}

		extra_s->s += 2 + value.rs.len;
		extra_s->len -= 2 + value.rs.len;
	}

	return 0;
}

static int restore_extra(struct dlg_cell* dlg,
			str *type_str, acc_ctx_t* ctx)
{
	int extra_len;
	str buffer;

	if (ctx == NULL) {
		LM_ERR("bad call!\n");
		return -1;
	}

	if (dlg_api.fetch_dlg_value(dlg, type_str, &buffer, 0) < 0) {
		LM_ERR("cannot fetch <%.*s> value from dialog!\n",
				type_str->len, type_str->s);
		return -1;
	}

	/* jump over the total length */
	extra_len = GET_LEN(buffer.s);
	buffer.s += 2;
	buffer.len -= 2;

	if (extra_len != extra_tgs_len) {
		LM_WARN("extra tags were added/removed since last run!"
				"won't restore values!\n");
		return 0;
	}

	if (!ctx->extra_values &&
			build_acc_extra_array(extra_len, &ctx->extra_values) < 0) {
		LM_ERR("failed to build extra pvar list!\n");
		return -1;
	}

	if (restore_extra_from_str(ctx->extra_values, &buffer, extra_len) < 0) {
		LM_ERR("failed to restore extra values!\n");
		free_extra_array(ctx->extra_values, extra_len);
		return -1;
	}

	return 0;
}

static int restore_legs(struct dlg_cell* dlg,
			str *type_str, acc_ctx_t* ctx)
{
	short extra_len, i;
	str buffer;

	if (ctx == NULL) {
		LM_ERR("bad call!\n");
		return -1;
	}

	if (dlg_api.fetch_dlg_value(dlg, type_str, &buffer, 0) < 0) {
		LM_ERR("cannot fetch <%.*s> value from dialog!\n",
				type_str->len, type_str->s);
		return -1;
	}

	ctx->legs_no = GET_LEN(buffer.s+2);
	extra_len = GET_LEN(buffer.s);

	if (extra_len != leg_tgs_len) {
		LM_WARN("tags were added/removed since last run! won't restore values!\n");
		return 0;
	}

	if (!ctx->leg_values) {
		ctx->leg_values = shm_malloc(ctx->legs_no * sizeof(leg_value_p));
		if (ctx->leg_values == NULL) {
			LM_ERR("no more shm!\n");
			return -1;
		}
		for (i=0; i<ctx->legs_no; i++) {
			if (build_acc_extra_array(extra_len, &ctx->leg_values[i]) < 0) {
				LM_ERR("could not build extra leg %d\n", i);
				goto error;
			}
		}
	}

	buffer.s += 4;
	buffer.len -=4;

	for (i=0; i<ctx->legs_no; i++) {
		if (restore_extra_from_str(ctx->leg_values[i], &buffer, extra_len) < 0) {
			LM_ERR("failed to restore leg values!\n");
			goto error;
		}
	}

	return 0;
error:
	for (i--; i >= 0; i--)
		free_extra_array(ctx->leg_values[i], extra_len);
	shm_free(ctx->leg_values);
	return -1;
}

int restore_dlg_extra_ctx(struct dlg_cell* dlg, acc_ctx_t *ctx)
{
	if (extra_tags &&
			restore_extra(dlg, &extra_str, ctx)) {
		LM_ERR("failed to restore extra!\n");
		return -1;
	}

	if (leg_tags &&
			restore_legs(dlg, &leg_str, ctx)) {
		LM_ERR("failed to restore legs!\n");
		if (extra_tgs_len && ctx->extra_values)
			free_extra_array(ctx->extra_values, extra_tgs_len);
		return -1;
	}
	return 0;
}


/*
 * restore extras that are held in dlg vals
 */
int restore_dlg_extra(struct dlg_cell* dlg, acc_ctx_t** ctx_p)
{

	acc_ctx_t* ctx;

	if (ctx_p == NULL) {
		LM_ERR("bad usage! null context!\n");
		return -1;
	}

	ctx = shm_malloc(sizeof(acc_ctx_t));
	if (ctx == NULL) {
		LM_ERR("no more shm!\n");
		return -1;
	}

	memset(ctx, 0, sizeof(acc_ctx_t));

	if (restore_dlg_extra_ctx(dlg, ctx) < 0) {
		shm_free(ctx);
		return -1;
	}

	*ctx_p = ctx;

	return 0;

}
