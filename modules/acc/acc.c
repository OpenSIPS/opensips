 /* $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#ifdef DIAM_ACC
#include "diam_dict.h"
#include "diam_message.h"
#include "diam_tcp.h"
#endif

#include "acc.h"
#include "acc_mod.h"
#include "acc_extra.h"
#include "acc_logic.h"

#define TABLE_VERSION 6

#define GET_LEN(p)	(*((unsigned char*)p) | *((unsigned char*)p+1) << 8)
#define MAX_LEN_VALUE 65535
#define SET_LEN(p,n) \
	do { \
		*(p) = (n) & 0x00FF; \
		*(p+1) = (n) >> 8; \
	} while(0)

str created_str = str_init("accX_created");
str core_str = str_init("accX_core");
str leg_str = str_init("accX_leg");
str flags_str = str_init("accX_flags");
str db_extra_str = str_init("accX_db");
str log_extra_str = str_init("accX_log");
str aaa_extra_str = str_init("accX_aaa");

extern struct acc_extra *log_extra;
extern struct acc_extra *leg_info;
extern struct acc_enviroment acc_env;

extern struct acc_extra *aaa_extra;

#ifdef DIAM_ACC
extern char *diameter_client_host;
extern int diameter_client_port;
extern struct acc_extra *dia_extra;
#endif

static db_func_t acc_dbf;
static db_con_t* db_handle=0;
extern struct acc_extra *db_extra;
extern int acc_log_facility;

static int build_core_dlg_values(struct dlg_cell *dlg,struct sip_msg *req);
static int build_extra_dlg_values(struct acc_extra* extra, 
		struct dlg_cell *dlg,struct sip_msg *req, struct sip_msg *reply);
static int build_leg_dlg_values(struct dlg_cell *dlg,struct sip_msg *req);
static void complete_dlg_values(str *stored_values,str *val_arr,short nr_vals);
static int prebuild_string(str *value_str, struct dlg_cell *dlg, str *core_s,
		str *extra_s,str *leg_s, short *leg_idx, short *leg_values,
		short *nr_legs, time_t *created, time_t *start);

static int store_extra_values(struct acc_extra* extra, str *values_str,
		struct dlg_cell *dlg, struct sip_msg *req, struct sip_msg *reply);

/* array used to collect the values before being
 * pushed to the storage backend (whatever used) */
static str val_arr[ACC_CORE_LEN+ACC_DLG_LEN+MAX_ACC_EXTRA+MAX_ACC_LEG];


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

	acc_env.ts = time(NULL);
	return ACC_CORE_LEN;
}


/********************************************
 *        LOG  ACCOUNTING
 ********************************************/
static str log_attrs[ACC_CORE_LEN+ACC_DLG_LEN+MAX_ACC_EXTRA+MAX_ACC_LEG];

#define SET_LOG_ATTR(_n,_atr)  \
	do { \
		log_attrs[_n].s=A_##_atr; \
		log_attrs[_n].len=A_##_atr##_LEN; \
		n++; \
	} while(0)


void acc_log_init(void)
{
	struct acc_extra *extra;
	int n;

	n = 0;

	/* fixed core attributes */
	SET_LOG_ATTR(n,METHOD);
	SET_LOG_ATTR(n,FROMTAG);
	SET_LOG_ATTR(n,TOTAG);
	SET_LOG_ATTR(n,CALLID);
	SET_LOG_ATTR(n,CODE);
	SET_LOG_ATTR(n,STATUS);

	/* init the extra db keys */
	for(extra=log_extra; extra ; extra=extra->next)
		log_attrs[n++] = extra->name;

	/* multi leg call columns */
	for( extra=leg_info ; extra ; extra=extra->next)
		log_attrs[n++] = extra->name;

	/* cdrs columns */
	SET_LOG_ATTR(n,DURATION);
	SET_LOG_ATTR(n,SETUPTIME);
	SET_LOG_ATTR(n,CREATED);
}

int acc_log_cdrs_request(struct dlg_cell *dlg)
{
	static char log_msg[MAX_SYSLOG_SIZE];
	static char *log_msg_end=log_msg+MAX_SYSLOG_SIZE-2;
	char *p;
	int i,j, cdrs_pos, result = -1;
	time_t created, start_time;
	str core_s, leg_s, extra_s;
	short nr_legs, leg_values, nr;

	core_s.s = leg_s.s = extra_s.s = NULL;
	core_s.len = leg_s.len = extra_s.len = 0;

	if (prebuild_string(&log_extra_str, dlg, &core_s, &extra_s, &leg_s, &nr,
				&leg_values, &nr_legs, &created, &start_time) < 0) {
		LM_ERR("cannot store values\n");
		goto end;
	}
	cdrs_pos = leg_values + nr;

	for ( i = 0,p = log_msg ; i<nr ; i++ ) {
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

	if ( leg_info ) {
		leg_s.len = 4;
		for (j=0; j<nr_legs; j++) {
			complete_dlg_values(&leg_s,val_arr+nr,leg_values);
			for (i=nr; i<nr+leg_values; i++) {
				if (p+1+log_attrs[i].len+1+val_arr[i].len >= log_msg_end) {
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
		}
	}

	/* terminating line */
	*(p++) = '\n';
	*(p++) = 0;

	LM_GEN2(acc_log_facility, log_level,
		"%.*screated=%lu;call_start_time=%lu;duration=%d;setuptime=%d%s",
		acc_env.text.len, acc_env.text.s,(unsigned long)created,
		(unsigned long)start_time,val_arr[cdrs_pos].len,
		val_arr[cdrs_pos+1].len, log_msg);

	result = 1;

end:
	if (core_s.s)
		pkg_free(core_s.s);
	if (extra_s.s)
		pkg_free(extra_s.s);
	if (leg_s.s)
		pkg_free(leg_s.s);

	return result;
}


int acc_log_request( struct sip_msg *rq, struct sip_msg *rpl)
{
	static char log_msg[MAX_SYSLOG_SIZE];
	static char *log_msg_end=log_msg+MAX_SYSLOG_SIZE-2;
	char *p;
	int n;
	int m;
	int i;

	/* get default values */
	m = core2strar( rq, val_arr);

	/* get extra values */
	m += extra2strar( log_extra, rq, rpl, val_arr+m);

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
	if ( leg_info ) {
		n = legs2strar(leg_info,rq,val_arr+m,1);
		do {
			for (i=m; i<m+n; i++) {
				if (p+1+log_attrs[i].len+1+val_arr[i].len >= log_msg_end) {
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
		}while (p!=log_msg_end && (n=legs2strar(leg_info,rq,val_arr+m,0))!=0);
	}

	/* terminating line */
	*(p++) = '\n';
	*(p++) = 0;

	LM_GEN2(acc_log_facility, log_level, "%.*stimestamp=%lu%s",
		acc_env.text.len, acc_env.text.s,(unsigned long) acc_env.ts, log_msg);

	return 1;
}

int store_log_extra_values(struct dlg_cell *dlg, struct sip_msg *req,
		struct sip_msg *reply)
{
	return store_extra_values(log_extra, &log_extra_str, dlg, req, reply);
}


/********************************************
 *        SQL  ACCOUNTING
 ********************************************/

/* caution: keys need to be aligned to core format */
static db_key_t db_keys[ACC_CORE_LEN+1+ACC_DLG_LEN+MAX_ACC_EXTRA+MAX_ACC_LEG];
static db_val_t db_vals[ACC_CORE_LEN+1+ACC_DLG_LEN+MAX_ACC_EXTRA+MAX_ACC_LEG];


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
	for(extra=db_extra; extra ; extra=extra->next)
		db_keys[n++] = &extra->name;

	/* multi leg call columns */
	for( extra=leg_info ; extra ; extra=extra->next)
		db_keys[n++] = &extra->name;

	/* init the values */
	for(i = 0; i < n; i++) {
		VAL_TYPE(db_vals + i)=DB_STR;
		VAL_NULL(db_vals + i)=0;
	}
	VAL_TYPE(db_vals+time_idx)=DB_DATETIME;
	
	if (dlg_api.get_dlg) {
		db_keys[n++] = &acc_duration_col;
		db_keys[n++] = &acc_setuptime_col;
		db_keys[n++] = &acc_created_col;
	}


	if (dlg_api.get_dlg) {
		VAL_TYPE(db_vals + n-3) = DB_INT;
		VAL_TYPE(db_vals + n-2) = DB_INT;
		VAL_TYPE(db_vals + n-1) = DB_DATETIME;
	}

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
		query_list_t **ins_list)
{
	static db_ps_t my_ps_ins = NULL;
	static db_ps_t my_ps = NULL;
	int m;
	int n;
	int i;

	/* formated database columns */
	m = core2strar( rq, val_arr );

	for(i = 0; i < m; i++)
		VAL_STR(db_vals+i) = val_arr[i];
	/* time value */
	VAL_TIME(db_vals+(m++)) = acc_env.ts;

	/* extra columns */
	m += extra2strar( db_extra, rq, rpl, val_arr+m);

	for( i++; i < m; i++)
		VAL_STR(db_vals+i) = val_arr[i];

	acc_dbf.use_table(db_handle, &acc_env.text/*table*/);
	CON_PS_REFERENCE(db_handle) = ins_list? &my_ps_ins : &my_ps;

	/* multi-leg columns */
	if ( !leg_info ) {
		if (con_set_inslist(&acc_dbf,db_handle,ins_list,db_keys,m) < 0 )
			CON_RESET_INSLIST(db_handle);
		if (acc_dbf.insert(db_handle, db_keys, db_vals, m) < 0) {
			LM_ERR("failed to insert into database\n");
			return -1;
		}
	} else {
		n = legs2strar(leg_info,rq,val_arr+m,1);
		do {
			for ( i = m; i < m + n; i++)
				VAL_STR(db_vals+i)=val_arr[i];
			if (con_set_inslist(&acc_dbf,db_handle,ins_list,db_keys,m+n) < 0 )
				CON_RESET_INSLIST(db_handle);
			if (acc_dbf.insert(db_handle, db_keys, db_vals, m+n) < 0) {
				LM_ERR("failed to insert into database\n");
				return -1;
			}
		}while ( (n = legs2strar(leg_info,rq,val_arr+m,0))!=0 );
	}

	return 1;
}

int acc_db_cdrs_request(struct dlg_cell *dlg)
{
	int total,i,j, cdrs_pos;
	int time_idx, result = -1;
	static db_ps_t my_ps = NULL;
	time_t created, start_time;
	str core_s, leg_s, extra_s;
	short nr_legs, leg_values, nr;
	static query_list_t *ins_list = NULL;

	core_s.s = leg_s.s = extra_s.s = NULL;
	core_s.len = leg_s.len = extra_s.len = 0;

	if (prebuild_string(&db_extra_str, dlg, &core_s, &extra_s, &leg_s, &nr,
				&leg_values, &nr_legs, &created, &start_time) < 0) {
		LM_ERR("cannot store values\n");
		goto end;
	}
	time_idx = ACC_CORE_LEN;

	for (i=0;i<ACC_CORE_LEN;i++)
		VAL_STR(db_vals+i) = val_arr[i];
	for (i=ACC_CORE_LEN; i<nr; i++)
		VAL_STR(db_vals+i+1) = val_arr[i];

	VAL_TIME(db_vals+time_idx) = start_time;
	cdrs_pos = leg_values + nr;
	VAL_INT(db_vals+cdrs_pos+1) = val_arr[cdrs_pos].len;
	VAL_INT(db_vals+cdrs_pos+2) = val_arr[cdrs_pos+1].len;
	VAL_TIME(db_vals+cdrs_pos+3) = created;

	total = nr+4;
	acc_dbf.use_table(db_handle, &acc_env.text);
	CON_PS_REFERENCE(db_handle) = &my_ps;

	if (!leg_info) {
		if (con_set_inslist(&acc_dbf,db_handle,&ins_list,db_keys,total) < 0 )
			CON_RESET_INSLIST(db_handle);
		if (acc_dbf.insert(db_handle, db_keys, db_vals, total) < 0) {
			LM_ERR("failed to insert into database\n");
			goto end;
		}
	} else {
		total += leg_values;
		leg_s.len = 4;
		for (i=0;i<nr_legs;i++) {
			complete_dlg_values(&leg_s,val_arr+nr,leg_values);
			for (j = 0; j<leg_values; j++)
				VAL_STR(db_vals+nr+j+1) = val_arr[nr+j];
			if (con_set_inslist(&acc_dbf,db_handle,&ins_list,db_keys,total) < 0 )
				CON_RESET_INSLIST(db_handle);
			if (acc_dbf.insert(db_handle,db_keys,db_vals,total) < 0) {
				LM_ERR("failed inserting into database\n");
				goto end;
			}
		}
	}

	result = 1;
end:
	if (core_s.s)
		pkg_free(core_s.s);
	if (extra_s.s)
		pkg_free(extra_s.s);
	if (leg_s.s)
		pkg_free(leg_s.s);

	return result;
}

int store_db_extra_values(struct dlg_cell *dlg, struct sip_msg *req,
		struct sip_msg *reply)
{
	return store_extra_values(db_extra, &db_extra_str, dlg, req, reply);
}

/************ AAA PROTOCOLS helper functions **************/
inline static uint32_t phrase2code(str *phrase)
{
	uint32_t code;
	int i;

	if (phrase->len<3) return 0;
	code=0;
	for (i=0;i<3;i++) {
		if (!(phrase->s[i]>='0' && phrase->s[i]<'9'))
				return 0;
		code=code*10+phrase->s[i]-'0';
	}
	return code;
}


/********************************************
 *        AAA PROTOCOL  ACCOUNTING
 ********************************************/
enum { RA_ACCT_STATUS_TYPE=0, RA_SERVICE_TYPE, RA_SIP_RESPONSE_CODE,
	RA_SIP_METHOD, RA_TIME_STAMP, RA_STATIC_MAX};
enum {RV_STATUS_START=0, RV_STATUS_STOP, RV_STATUS_ALIVE, RV_STATUS_FAILED,
	RV_SIP_SESSION, RV_STATIC_MAX};
static aaa_map
	rd_attrs[RA_STATIC_MAX+ACC_CORE_LEN+ACC_DLG_LEN-2+MAX_ACC_EXTRA+MAX_ACC_LEG];
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
	n += extra2attrs( aaa_extra, rd_attrs, n);
	/* add and count the legs as attributes */
	n += extra2attrs( leg_info, rd_attrs, n);

	if (dlg_api.get_dlg) {
		rd_attrs[n++].name = "Sip-Call-Duration";
		rd_attrs[n++].name = "Sip-Call-Setuptime";
	}

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

int acc_aaa_request( struct sip_msg *req, struct sip_msg *rpl)
{
	int attr_cnt;
	aaa_message *send;
	int offset, i, av_type;
	aaa_map *r_stat;

	if ((send = proto.create_aaa_message(conn, AAA_ACCT)) == NULL) {
		LM_ERR("failed to create new aaa message for acct\n");
		return -1;
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
	av_type = (uint32_t)acc_env.ts;
	ADD_AAA_AVPAIR( RA_TIME_STAMP, &av_type, -1);

	/* add extra also */
	attr_cnt += extra2strar( aaa_extra, req, rpl, val_arr+attr_cnt);

	/* add the values for the vector - start from 1 instead of
	 * 0 to skip the first value which is the METHOD as string */
	offset = RA_STATIC_MAX-1;
	for (i = 1; i < attr_cnt; i++)
		ADD_AAA_AVPAIR( offset + i, val_arr[i].s, val_arr[i].len );

	/* call-legs attributes also get inserted */
	if (leg_info) {
		offset += attr_cnt;
		attr_cnt = legs2strar(leg_info,req,val_arr,1);
		do {
			for (i = 0; i < attr_cnt; i++)
				ADD_AAA_AVPAIR( offset+i, val_arr[i].s, val_arr[i].len );
		} while ((attr_cnt = legs2strar(leg_info,req,val_arr,0)) != 0);
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
	proto.destroy_aaa_message(conn, send);
	return -1;
}

int acc_aaa_cdrs_request( struct dlg_cell *dlg)
{
	aaa_message *send = NULL;
	int offset, i, j, av_type;
	aaa_map *r_stat;
	str core_s, leg_s, extra_s;
	short nr_legs, leg_values, attr_cnt;
	time_t created, start_time;
	int result = -1;

	core_s.s = leg_s.s = extra_s.s = NULL;
	core_s.len = leg_s.len = extra_s.len = 0;

	if (prebuild_string(&aaa_extra_str, dlg, &core_s, &extra_s, &leg_s,
				&attr_cnt,&leg_values, &nr_legs, &created, &start_time) < 0) {
		LM_ERR("cannot store values\n");
		goto error;
	}

	if ((send = proto.create_aaa_message(conn, AAA_ACCT)) == NULL) {
		LM_ERR("failed to create new aaa message for acct\n");
		goto error;
	}

	r_stat = &rd_vals[RV_STATUS_STOP]; /* AAA PROTOCOL status */
	ADD_AAA_AVPAIR(RA_ACCT_STATUS_TYPE,&(r_stat->value),-1);

	av_type = rd_vals[RV_SIP_SESSION].value; /* session*/
	ADD_AAA_AVPAIR( RA_SERVICE_TYPE, &av_type, -1);

	av_type = (uint32_t)acc_env.code; /* status=integer */
	ADD_AAA_AVPAIR( RA_SIP_RESPONSE_CODE, &av_type, -1);

	av_type = METHOD_INVITE; /* method */
	ADD_AAA_AVPAIR( RA_SIP_METHOD, &av_type, -1);

	av_type = (uint32_t)start_time; /* call start time */
	ADD_AAA_AVPAIR( RA_TIME_STAMP, &av_type, -1);

	/* add the values for the vector - start from 1 instead of
	 * 0 to skip the first value which is the METHOD as string */
	offset = RA_STATIC_MAX-1;
	for (i = 1; i < ACC_CORE_LEN-2; i++)
		ADD_AAA_AVPAIR( offset + i, val_arr[i].s, val_arr[i].len );
	for (i = ACC_CORE_LEN - 2; i<attr_cnt - 2; i++)
		ADD_AAA_AVPAIR( offset + i, val_arr[i+2].s,
				val_arr[i+2].len );
	offset = attr_cnt + 2;

	/* add duration and setup values */
	av_type = (uint32_t)val_arr[attr_cnt + leg_values].len;
	ADD_AAA_AVPAIR( offset + leg_values, &av_type, -1);
	av_type = (uint32_t)val_arr[attr_cnt + leg_values + 1].len;
	ADD_AAA_AVPAIR( offset + leg_values + 1, &av_type, -1);

	/* call-legs attributes also get inserted */
	if (leg_info) {
		leg_s.len = 4;
		for (i=0; i<nr_legs; i++) {
			complete_dlg_values(&leg_s, val_arr, leg_values);
			for (j=0; j<leg_values; j++)
				ADD_AAA_AVPAIR( offset+j, val_arr[j].s,
						val_arr[j].len );
		}
	}

	if (proto.send_aaa_request(conn, send, NULL)) {
		LM_ERR("Radius accounting request failed for status: '%s' "
			"Call-Id: '%.*s' \n",r_stat->name,
			val_arr[3].len, val_arr[3].s);
		goto error;
	}

	result = 1;
error:
	proto.destroy_aaa_message(conn, send);
	if (core_s.s)
		pkg_free(core_s.s);
	if (extra_s.s)
		pkg_free(extra_s.s);
	if (leg_s.s)
		pkg_free(leg_s.s);

	return result;
}

int store_aaa_extra_values(struct dlg_cell *dlg, struct sip_msg *req,
		struct sip_msg *reply)
{
	return store_extra_values(aaa_extra, &aaa_extra_str, dlg, req, reply);
}

/********************************************
 *        DIAMETER  ACCOUNTING
 ********************************************/
#ifdef DIAM_ACC

#define AA_REQUEST 265
#define AA_ANSWER  265

#define ACCOUNTING_REQUEST 271
#define ACCOUNTING_ANSWER  271

static int diam_attrs[ACC_CORE_LEN+MAX_ACC_EXTRA+MAX_ACC_LEG];

int acc_diam_init()
{
	int n;
	int m;

	n = 0;
	/* caution: keep these aligned to core acc output */
	diam_attrs[n++] = AVP_SIP_METHOD;
	diam_attrs[n++] = AVP_SIP_FROM_TAG;
	diam_attrs[n++] = AVP_SIP_TO_TAG;
	diam_attrs[n++] = AVP_SIP_CALLID;
	diam_attrs[n++] = AVP_SIP_STATUS;

	m = extra2int( dia_extra, diam_attrs+n);
	if (m<0) {
		LM_ERR("extra names for DIAMETER must be integer AVP codes\n");
		return -1;
	}
	n += m;

	m = extra2int( leg_info, diam_attrs+n);
	if (m<0) {
		LM_ERR("leg info names for DIAMTER must be integer AVP codes\n");
		return -1;
	}
	n += m;

	return 0;
}


inline unsigned long diam_status(struct sip_msg *rq, int code)
{
	if ((rq->REQ_METHOD==METHOD_INVITE || rq->REQ_METHOD==METHOD_ACK)
				&& code>=200 && code<300) 
		return AAA_ACCT_START;

	if ((rq->REQ_METHOD==METHOD_BYE || rq->REQ_METHOD==METHOD_CANCEL))
		return AAA_ACCT_STOP;

	if (code>=200 && code <=300)  
		return AAA_ACCT_EVENT;

	return -1;
}


int acc_diam_request( struct sip_msg *req, struct sip_msg *rpl)
{
	int attr_cnt;
	int cnt;
	AAAMessage *send = NULL;
	AAA_AVP *avp;
	struct sip_uri puri;
	str *uri;
	int ret;
	int i;
	int status;
	char tmp[2];
	unsigned int mid;

	attr_cnt = core2strar( req, val_arr);
	/* last value is not used */
	attr_cnt--;

	if ( (send=AAAInMessage(ACCOUNTING_REQUEST, AAA_APP_NASREQ))==NULL) {
		LM_ERR("failed to create new AAA request\n");
		return -1;
	}

	/* AVP_ACCOUNTIG_RECORD_TYPE */
	if( (status = diam_status(req, acc_env.code))<0) {
		LM_ERR("status unknown\n");
		goto error;
	}
	tmp[0] = status+'0';
	tmp[1] = 0;
	if( (avp=AAACreateAVP(AVP_Accounting_Record_Type, 0, 0, tmp,
	1, AVP_DUPLICATE_DATA)) == 0) {
		LM_ERR("failed to create AVP:no more free memory!\n");
		goto error;
	}
	if( AAAAddAVPToMessage(send, avp, 0)!= AAA_ERR_SUCCESS) {
		LM_ERR("avp not added \n");
		AAAFreeAVP(&avp);
		goto error;
	}
	/* SIP_MSGID AVP */
	mid = req->id;
	if( (avp=AAACreateAVP(AVP_SIP_MSGID, 0, 0, (char*)(&mid), 
	sizeof(mid), AVP_DUPLICATE_DATA)) == 0) {
		LM_ERR("failed to create AVP:no more free memory!\n");
		goto error;
	}
	if( AAAAddAVPToMessage(send, avp, 0)!= AAA_ERR_SUCCESS) {
		LM_ERR("avp not added \n");
		AAAFreeAVP(&avp);
		goto error;
	}

	/* SIP Service AVP */
	if( (avp=AAACreateAVP(AVP_Service_Type, 0, 0, SIP_ACCOUNTING, 
	SERVICE_LEN, AVP_DUPLICATE_DATA)) == 0) {
		LM_ERR("failed to create AVP:no more free memory!\n");
		goto error;
	}
	if( AAAAddAVPToMessage(send, avp, 0)!= AAA_ERR_SUCCESS) {
		LM_ERR("avp not added \n");
		AAAFreeAVP(&avp);
		goto error;
	}

	/* also the extra attributes */
	attr_cnt += extra2strar( dia_extra, rpl, req, val_arr);

	/* add attributes */
	for(i=0; i<attr_cnt; i++) {
		if((avp=AAACreateAVP(diam_attrs[i], 0,0, val_arr[i].s, val_arr[i].len,
		AVP_DUPLICATE_DATA)) == 0) {
			LM_ERR("failed to create AVP: no more free memory!\n");
			goto error;
		}
		if( AAAAddAVPToMessage(send, avp, 0)!= AAA_ERR_SUCCESS) {
			LM_ERR("avp not added \n");
			AAAFreeAVP(&avp);
			goto error;
		}
	}

	/* and the leg attributes */
	if ( leg_info ) {
		cnt = legs2strar(leg_info,req,val_arr,1);
		do {
			for (i=0; i<cnt; i++) {
				if((avp=AAACreateAVP(diam_attrs[attr_cnt+i], 0, 0,
				val_arr[i].s, val_arr[i].len, AVP_DUPLICATE_DATA)) == 0) {
					LM_ERR("failed to create AVP: no more free memory!\n");
					goto error;
				}
				if( AAAAddAVPToMessage(send, avp, 0)!= AAA_ERR_SUCCESS) {
					LM_ERR("avp not added \n");
					AAAFreeAVP(&avp);
					goto error;
				}
			}
		} while ( (cnt=legs2strar(leg_info,req,val_arr,0))!=0 );
	}

	if (get_uri(req, &uri) < 0) {
		LM_ERR("failed to get uri, From/To URI not found\n");
		goto error;
	}

	if (parse_uri(uri->s, uri->len, &puri) < 0) {
		LM_ERR("failed to parse From/To URI\n");
		goto error;
	}

	/* Destination-Realm AVP */
	if( (avp=AAACreateAVP(AVP_Destination_Realm, 0, 0, puri.host.s,
	puri.host.len, AVP_DUPLICATE_DATA)) == 0) {
		LM_ERR("failed to create AVP:no more free memory!\n");
		goto error;
	}

	if( AAAAddAVPToMessage(send, avp, 0)!= AAA_ERR_SUCCESS) {
		LM_ERR("avp not added \n");
		AAAFreeAVP(&avp);
		goto error;
	}

	/* prepare the message to be sent over the network */
	if(AAABuildMsgBuffer(send) != AAA_ERR_SUCCESS) {
		LM_ERR("message buffer not created\n");
		goto error;
	}

	if(sockfd==AAA_NO_CONNECTION) {
		sockfd = init_mytcp(diameter_client_host, diameter_client_port);
		if(sockfd==AAA_NO_CONNECTION) {
			LM_ERR("failed to reconnect to Diameter client\n");
			goto error;
		}
	}

	/* send the message to the DIAMETER client */
	ret = tcp_send_recv(sockfd, send->buf.s, send->buf.len, rb, req->id);
	if(ret == AAA_CONN_CLOSED) {
		LM_NOTICE("connection to Diameter client closed.It will be "
				"reopened by the next request\n");
		close(sockfd);
		sockfd = AAA_NO_CONNECTION;
		goto error;
	}

	if(ret != ACC_SUCCESS) {
		/* a transmission error occurred */
		LM_ERR("message sending to the DIAMETER backend authorization "
				"server failed\n");
		goto error;
	}

	AAAFreeMessage(&send);
	return 1;

error:
	AAAFreeMessage(&send);
	return -1;
}

#endif


/* Functions used to store values into dlg */

static str cdr_buf = {NULL, 0};
int cdr_len = 0;

int set_dlg_value(str *value)
{
	if (value->s == NULL)
		value->len = 0;

	if (cdr_buf.len + value->len + 2 > cdr_len) {
		if (cdr_len == 0) {
			cdr_len = STRING_INIT_SIZE;
			cdr_buf.s = (char*)pkg_malloc(cdr_len);
			if (!cdr_buf.s) {
				LM_ERR("No more memory\n");
				return -1;
			}
		} else {
			do {
				/* realloc until memory is large enough  */
				cdr_len *= 2;
			} while (cdr_len < cdr_buf.len + value->len + 2);
			cdr_buf.s = pkg_realloc(cdr_buf.s, cdr_len);
			if (cdr_buf.s == NULL) {
				LM_ERR("No more memory\n");
				return -1;
			}
		}
	}

	if (value->len > MAX_LEN_VALUE) {
		value->len = MAX_LEN_VALUE;
		LM_WARN("Value too log, truncating..\n");
	}
	SET_LEN(cdr_buf.s + cdr_buf.len, value->len);

	memcpy(cdr_buf.s + cdr_buf.len + 2, value->s, value->len);
	cdr_buf.len += value->len + 2;
	
	return 1;
}

static void complete_dlg_values(str *stored_values,str *val_arr,short nr_vals)
{
	short i;
	char *p = stored_values->s + stored_values->len;
	short len;

	for (i=0;i<nr_vals;i++)
	{
		len = GET_LEN(p);
		val_arr[i].len = len;
		val_arr[i].s = p+2;
		p = p + len + 2;
	}

	stored_values->len = p - stored_values->s;
}

/* stores core values and leg values into dlg */
int store_core_leg_values(struct dlg_cell *dlg, struct sip_msg *req)
{
	if ( build_core_dlg_values(dlg, req) < 0) {
		LM_ERR("cannot build core value string\n");
		return -1;
	}

	if ( dlg_api.store_dlg_value(dlg, &core_str, &cdr_buf) < 0) {
		LM_ERR("cannot store core values into dialog\n");
		return -1;
	}

	if ( build_leg_dlg_values(dlg, req) < 0) {
		LM_ERR("cannot build legs value string\n");
		return -1;
	}
	
	if (dlg_api.store_dlg_value(dlg,&leg_str,&cdr_buf) < 0) {
		LM_ERR("cannot store dialog string\n");
		return -1;
	}

	return 1;
}


/* stores extra values into dlg */
static int store_extra_values(struct acc_extra* extra, str *values_str,
		struct dlg_cell *dlg, struct sip_msg *req, struct sip_msg *reply)
{
	if ( build_extra_dlg_values(extra, dlg, req, reply) < 0) {
		LM_ERR("cannot build core value string\n");
		return -1;
	}

	if ( dlg_api.store_dlg_value(dlg, values_str, &cdr_buf) < 0) {
		LM_ERR("cannot store core values into dialog\n");
		return -1;
	}

	return 1;
}

/* builds core string */
static int build_core_dlg_values(struct dlg_cell *dlg,struct sip_msg *req)
{
	str value;
	int i, count;

	cdr_buf.len = 0;
	count = core2strar( req, val_arr);
	for (i=0; i<count; i++)
		if (set_dlg_value(&val_arr[i]) < 0)
			return -1;
	
	value.s = (char*)&acc_env.ts;
	value.len = sizeof(time_t);
	if (set_dlg_value(&value) < 0)
		return -1;

	return 1;
}

/* builds extra values string */
static int build_extra_dlg_values(struct acc_extra *extra,
		struct dlg_cell *dlg,struct sip_msg *req, struct sip_msg *reply)
{
	str val_arr[MAX_ACC_EXTRA];
	int nr, i;

	cdr_buf.len = 2;
	nr = extra2strar(extra, req, reply, val_arr);

	for (i=0; i<nr; i++)
		if (set_dlg_value(&val_arr[i]) < 0)
			return -1;
	SET_LEN(cdr_buf.s, nr);
	return nr;
}

/* builds leg values string */
static int build_leg_dlg_values(struct dlg_cell *dlg,struct sip_msg *req)
{
	str val_arr[MAX_ACC_LEG];
	int nr_values, i,nr_legs=0;

	cdr_buf.len = 4;
	if (!leg_info)
		SET_LEN(cdr_buf.s,0);
	else {
		nr_values = legs2strar(leg_info,req,val_arr,1);
		SET_LEN(cdr_buf.s,nr_values);
		do {
			for (i=0;i<nr_values;i++)
				if (set_dlg_value(&val_arr[i]) < 0)
					return -1;
			nr_legs++;
		} while ( (nr_values = legs2strar(leg_info,req,val_arr,0)) != 0);
	}
	SET_LEN(cdr_buf.s+2,nr_legs);
	return 1;
}

/* gets values from dlg and stores them into val_arr array */
static int prebuild_string(str *value_str, struct dlg_cell *dlg, str *core_s,
		str *extra_s,str *leg_s, short *leg_idx, short *leg_values,
		short *nr_legs, time_t *created, time_t *start)
{
	int cdrs_pos;
	short extra_len, nr;

	if (!leg_idx) {
		LM_ERR("null pointer to leg index\n");
		return -1;
	}

	/* fetching core, extra and leg string values */
	if (dlg_api.fetch_dlg_value(dlg, &core_str, core_s, 1) < 0) {
		LM_ERR("cannot fetch core string value\n");
		return -1;
	}
	if (dlg_api.fetch_dlg_value(dlg, value_str, extra_s, 1) < 0) {
		LM_ERR("cannot fetch extra string value\n");
		return -1;
	}
	if (dlg_api.fetch_dlg_value(dlg, &leg_str, leg_s, 1) < 0) {
		LM_ERR("cannot fetch leg string value\n");
		return -1;
	}

	/* getting legs number, and extra number */
	*leg_values = GET_LEN(leg_s->s);
	*nr_legs = GET_LEN(leg_s->s+2);
	extra_len = GET_LEN(extra_s->s);

	core_s->len = 0;
	complete_dlg_values(core_s, val_arr, ACC_CORE_LEN+1);

	/* get the time value then overwrite it */
	memcpy(start, val_arr[ACC_CORE_LEN].s, val_arr[ACC_CORE_LEN].len);
	nr = ACC_CORE_LEN;

	extra_s->len = 2;
	complete_dlg_values(extra_s, val_arr+nr, extra_len);
	nr += extra_len;
	*leg_idx = nr;
	cdrs_pos = *leg_values + nr;

	if (dlg_api.fetch_dlg_value(dlg,&created_str, val_arr+cdrs_pos+2,0) < 0) {
		LM_ERR("error fetching base dlg value\n");
		return -1;
	}
	memcpy(created, val_arr[cdrs_pos+2].s, val_arr[cdrs_pos+2].len);

	/* calculate duration and setup time */
	val_arr[cdrs_pos].len = time(NULL) - *start;
	val_arr[cdrs_pos+1].len = *start - *created;

	return 1;
}

/* create accounting dialog */
int create_acc_dlg(struct sip_msg* req)
{
	struct dlg_cell *dlg;
	str current_time;
	time_t curr_time;

	dlg = dlg_api.get_dlg();
	if (!dlg) {
		/* if the dialog doesn't exist we try to create it */
		if ( dlg_api.create_dlg(req) < 0) {
			LM_ERR("error creating new dialog\n");
			return -1;
		}
		dlg = dlg_api.get_dlg();
		if (!dlg) {
			LM_ERR("error getting new dialog\n");
			return -1;
		}
	}

	/* store the created time into dlg */
	curr_time = time(NULL);
	current_time.s = (char*)&curr_time;
	current_time.len = sizeof(time_t);
	
	if ( dlg_api.store_dlg_value(dlg,&created_str,&current_time) < 0)
		return -1;

	return 1;
}
