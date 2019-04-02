/*
 * Copyright (C) 2017 Răzvan Crainea <razvan@opensips.org>
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

#ifndef _CGRATES_COMMON_H_
#define _CGRATES_COMMON_H_

#include "../../lib/json/opensips_json_c_helper.h"

#include "../../lib/list.h"
#include "../../str.h"
#include "../../usr_avp.h"
#include "../../context.h"

#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"

extern struct dlg_binds cgr_dlgb;
extern struct tm_binds cgr_tmb;

#define CGR_KVF_TYPE_INT	0x1
#define CGR_KVF_TYPE_STR	0x2
#define CGR_KVF_TYPE_NULL	0x4


struct cgr_kv {
	unsigned char flags;
	str key; /* must be null terminated */
	int_str value;
	struct list_head list;
};

struct cgr_acc_ctx;
struct cgr_acc_sess;

struct cgr_session {
	str tag;
	struct list_head list;
	struct list_head req_kvs;
	struct list_head event_kvs;
	struct cgr_acc_sess *acc_info;
};

struct cgr_ctx {

	unsigned flags;

	/* acc context holder */
	struct cgr_acc_ctx *acc;

	/* variables */
	struct list_head *sessions;
};

struct cgr_local_ctx {
	/* reply status */
	unsigned reply_flags;
	struct list_head kvs;
	int_str *reply;
};

enum cgrc_state {
	CGRC_FREE, CGRC_USED, CGRC_CLOSED
};

struct cgr_conn {
	int fd;
	char flags;
	enum cgrc_state state;
	time_t disable_time;
	struct cgr_engine *engine;
	struct json_tokener *jtok;
	struct list_head list;
};

struct cgr_msg {
	json_object *msg;
	json_object *opts;
	json_object *params;
};

/* init common variables */
extern int cgre_compat_mode;
int cgr_init_common(void);

/* message builder */
struct cgr_msg *cgr_get_generic_msg(str *method, struct cgr_session *sess);
int cgr_obj_push_str(json_object *msg, const char *key, str *value);
int cgr_obj_push_int(json_object *msg, const char *key, unsigned int value);
int cgr_obj_push_bool(json_object *msg, const char *key, int value);

/* handle local ctx */
extern int cgr_ctx_local_idx;
void cgr_free_local_ctx(void *param);
int cgrates_set_reply(int type, int_str *value);
int cgrates_set_reply_with_values(json_object *msg);
struct cgr_kv *cgr_get_local(str key);

/* key-value manipulation */
struct cgr_kv *cgr_new_kv(str key);
struct cgr_kv *cgr_new_const_kv(const char *key);
struct cgr_kv *cgr_new_real_kv(char *key, int klen, int dup);
void cgr_free_kv(struct cgr_kv *kv);
void cgr_free_kv_val(struct cgr_kv *kv);
void cgr_free_sess(struct cgr_session *sess);
struct cgr_kv *cgr_get_kv(struct list_head *list, str name);
struct cgr_kv *cgr_get_const_kv(struct list_head *list, const char *name);
struct cgr_session *cgr_get_sess(struct cgr_ctx *ctx, str *name);
struct cgr_session *cgr_new_sess(str *tag);
struct cgr_session *cgr_get_sess_new(struct cgr_ctx *ctx, str *name);

/* context manipulation */
extern int cgr_ctx_idx;
extern int cgr_tm_ctx_idx;
struct cgr_ctx *cgr_get_ctx_new(void);
struct cgr_ctx *cgr_get_ctx(void);
struct cgr_ctx *cgr_try_get_ctx(void);
void cgr_free_ctx(void *param);
void cgr_move_ctx( struct cell* t, int type, struct tmcb_params *ps);

#define CGR_GET_CTX() ((struct cgr_ctx *)context_get_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, cgr_ctx_idx))
#define CGR_PUT_CTX(_p) context_put_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, cgr_ctx_idx, (_p))
#define CGR_GET_LOCAL_CTX() \
	((struct cgr_local_ctx *)context_get_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, cgr_ctx_local_idx))
#define CGR_PUT_LOCAL_CTX(_p) \
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, \
		cgr_ctx_local_idx, (_p))
#define CGR_GET_TM_CTX(_t) \
	(cgr_tmb.t_ctx_get_ptr(_t, cgr_tm_ctx_idx))
#define CGR_PUT_TM_CTX(_t, _p) \
	cgr_tmb.t_ctx_put_ptr(_t, cgr_tm_ctx_idx, _p)


/* CGR logic */
typedef  int (*cgr_proc_reply_f)(struct cgr_conn *, json_object *,
		void *, char *error);

/* Returns:
 *   2 - if cgrates already engaged by a different call
 *   1 - if cgrates successfully engaged
 *  -1 - cgrates returned error
 *  -2 - internal error
 *  -3 - no suitable cgrates server found
 *  -4 - cgrates engaged on invalid message
 */
int cgr_handle_cmd(struct sip_msg *msg, json_object *jmsg,
		cgr_proc_reply_f f, void *p);
int cgr_handle_async_cmd(struct sip_msg *msg, json_object *jmsg,
		cgr_proc_reply_f f, void *p, async_ctx *ctx);
int cgrates_async_resume_req(int fd, void *param);
int cgrc_async_read(struct cgr_conn *c,
		cgr_proc_reply_f f, void *p);
int cgrates_process(json_object *jobj,
		struct cgr_conn *c, cgr_proc_reply_f proc_reply, void *p);

/* parameters manipulation */
str *cgr_get_acc(struct sip_msg *msg, str *acc_p);
str *cgr_get_dst(struct sip_msg *msg, str *acc_p);

#endif /* _CGRATES_COMMON_H_ */
