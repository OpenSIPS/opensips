/*
 * Copyright (C) 2016 Razvan Crainea <razvan@opensips.org>
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

#include <json.h>
#include "../../lib/list.h"
#include "../../str.h"
#include "../../usr_avp.h"
#include "../../context.h"
#include "../../parser/parse_uri.h"

#define CGR_KVF_TYPE_SHM	0x1
#define CGR_KVF_TYPE_INT	0x2
#define CGR_KVF_TYPE_STR	0x4
#define CGR_KVF_TYPE_NULL	0x8


struct cgr_kv {
	int flags;
	str key; /* must be null terminated */
	int_str value;
	struct list_head list;
};

struct cgr_acc_ctx;

struct cgr_ctx {

	unsigned flags;

	/* reply status */
	unsigned reply_flags;
	int_str *reply;

	/* acc info */
	struct cgr_acc_ctx *acc;

	/* variables */
	struct list_head kv_store;
};


enum cgrc_state {
	CGRC_FREE, CGRC_USED, CGRC_CLOSED
};

struct cgr_conn {
	int fd;
	char flags;
	enum cgrc_state state;
	struct cgr_engine *engine;
	struct json_tokener *jtok;
	struct list_head list;
};


/* message builder */
int cgrates_set_reply(int type, int_str *value);
json_object *cgr_get_generic_msg(char *method, struct list_head *list,
		struct list_head *prio_list);

/* key-value manipulation */
struct cgr_kv *cgr_new_kv(str key, int dup);
void cgr_free_kv(struct cgr_kv *kv);
void cgr_free_kv_val(struct cgr_kv *kv);
struct cgr_kv *cgr_get_kv(struct list_head *ctx, str name);;
int cgr_push_kv_str(struct list_head *list, const char *key,
		str *value);
int cgr_push_kv_int(struct list_head *list, const char *key,
		int value);
int cgr_dup_kvlist_shm(struct list_head *from, struct list_head *to);


/* context manipulation */
extern int cgr_ctx_idx;
struct cgr_ctx *cgr_get_ctx_new(void);

#define CGR_GET_CTX() ((struct cgr_ctx *)context_get_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, cgr_ctx_idx))
#define CGR_PUT_CTX(_p) context_put_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, cgr_ctx_idx, (_p))

#define CGR_RESET_REPLY_CTX() \
	do { \
		struct cgr_ctx *_c = CGR_GET_CTX(); \
		if (_c->reply) \
			pkg_free(_c->reply); \
		_c->reply = 0; \
	} while (0)


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
int cgrates_async_resume_req(int fd, void *param);
int cgrc_async_read(struct cgr_conn *c,
		cgr_proc_reply_f f, void *p);
int cgrates_process(json_object *jobj,
		struct cgr_conn *c, cgr_proc_reply_f proc_reply, void *p);

/* sip-msg manipulation */
static inline str *get_request_user(struct sip_msg *msg)
{
	if(msg->parsed_uri_ok == 0 && parse_sip_msg_uri(msg)<0) {
		LM_ERR("cannot parse Requst URI!\n");
		return NULL;
	}
	return &msg->parsed_uri.user;
}


#endif /* _CGRATES_COMMON_H_ */
