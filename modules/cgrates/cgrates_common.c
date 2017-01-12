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

#include <string.h>
#include "../../dprint.h"
#include "../../str.h"
#include "../../async.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "cgrates.h"
#include "cgrates_acc.h"
#include "cgrates_common.h"
#include "cgrates_engine.h"

enum cgrm_type {
	CGRM_UNSPEC, CGRM_REQ, CGRM_REPL
};


/* key-value manipulation */
struct cgr_kv *cgr_get_kv(struct list_head *ctx, str name)
{
	struct list_head *l;
	struct cgr_kv *kv;

	if (!ctx)
		return NULL;
	list_for_each(l, ctx) {
		kv = list_entry(l, struct cgr_kv, list);
		if (kv->key.len == name.len && !memcmp(kv->key.s, name.s, name.len))
			return kv;
	}
	return NULL;
}

struct cgr_kv *cgr_get_const_kv(struct list_head *ctx, const char *name)
{
	str sname;
	sname.s = (char *)name;
	sname.len = strlen(name);
	return cgr_get_kv(ctx, sname);
}

struct cgr_kv *cgr_new_real_kv(char *key, int klen, int dup)
{
	struct cgr_kv *kv;
	int len = sizeof *kv + (dup? (klen + 1) : 0);
	kv = shm_malloc(len);
	if (!kv) {
		LM_ERR("out of shm mem\n");
		return NULL;
	}
	memset(kv, 0, sizeof *kv);
	if (dup) {
		kv->key.s = (char *)(kv + 1);
		memcpy(kv->key.s, key, klen);
		kv->key.len = klen;
		kv->key.s[kv->key.len] = '\0';
	} else {
		kv->key.s = key;
		kv->key.len = klen;
	}
	return kv;
}

struct cgr_kv *cgr_new_kv(str key)
{
	return cgr_new_real_kv(key.s, key.len, 1);
}

struct cgr_kv *cgr_new_const_kv(const char *key)
{
	return cgr_new_real_kv((char *)key, strlen(key), 0);
}

/* TODO: delete me! */
int cgr_push_kv_str(struct list_head *list, const char *key,
		str *value)
{
	str skey;
	
	skey.s = (char *)key;
	skey.len = strlen(key);
	/* XXX: note that for now we do not need to duplicate the key's value */
	//struct cgr_kv *kv = cgr_new_kv(skey, 0);
	struct cgr_kv *kv = cgr_new_kv(skey);
	if (!kv)
		return -1;
	kv->value.s.s = pkg_malloc(value->len);
	if (!kv->value.s.s) {
		LM_ERR("cannot allocate memory for %s value\n", key);
		return -1;
	}
	kv->flags |= CGR_KVF_TYPE_STR;
	kv->value.s.len = value->len;
	memcpy(kv->value.s.s, value->s, value->len);
	list_add(&kv->list, list);
	return 0;
}

/* TODO: delete me! */
int cgr_push_kv_int(struct list_head *list, const char *key,
		int value)
{
	str skey;
	
	skey.s = (char *)key;
	skey.len = strlen(key);
	/* XXX: note that for now we do not need to duplicate the key's value */
	//struct cgr_kv *kv = cgr_new_kv(skey, 0);
	struct cgr_kv *kv = cgr_new_kv(skey);
	if (!kv)
		return -1;
	kv->flags |= CGR_KVF_TYPE_INT;
	kv->value.n = value;
	list_add(&kv->list, list);
	return 0;
}

void cgr_free_kv_val(struct cgr_kv *kv)
{
	if ((kv->flags & CGR_KVF_TYPE_STR) && kv->value.s.s) {
		shm_free(kv->value.s.s);
		kv->value.s.s = 0;
		kv->value.s.len = 0;
	}
	kv->flags &= ~(CGR_KVF_TYPE_INT|CGR_KVF_TYPE_STR|CGR_KVF_TYPE_NULL);

}

void cgr_free_kv(struct cgr_kv *kv)
{
	list_del(&kv->list);
	cgr_free_kv_val(kv); /* it's safe to call this twice */
	shm_free(kv);
}

static inline struct cgr_kv *cgr_dup_kvlist_shm_kv(struct cgr_kv *kv)
{
	struct cgr_kv *newkv;
	int len = kv->key.len + 1;

	if (kv->flags & CGR_KVF_TYPE_STR)
		len += kv->value.s.len;

	newkv = shm_malloc(sizeof(*newkv) + len);
	if (!newkv) {
		LM_ERR("no more shm memory!\n");
		return NULL;
	}
	newkv->flags = kv->flags | CGR_KVF_TYPE_SHM;
	newkv->key.s = (char *)(newkv + 1);
	newkv->key.len = kv->key.len;
	memcpy(newkv->key.s, kv->key.s, newkv->key.len);
	newkv->key.s[newkv->key.len] = 0;

	if (kv->flags & CGR_KVF_TYPE_STR) {
		newkv->value.s.s = newkv->key.s + newkv->key.len + 1;
		newkv->value.s.len = kv->value.s.len;
		memcpy(newkv->value.s.s, kv->value.s.s, newkv->value.s.len);
	}

	return newkv;
}

int cgr_dup_kvlist_shm(struct list_head *from, struct list_head *to)
{
	struct list_head *l, *lt;
	struct cgr_kv *kv, *newkv;

	INIT_LIST_HEAD(to);
	list_for_each(l, from) {
		kv = list_entry(l, struct cgr_kv, list);
		newkv = cgr_dup_kvlist_shm_kv(kv);
		if (!newkv) {
			LM_ERR("cannot dup kv!\n");
			goto error;
		}
		list_add_tail(&newkv->list, to);
	}

	return 0;
error:
	/* remove whatever we've managed to add */
	list_for_each_safe(l, lt, to)
		cgr_free_kv(list_entry(l, struct cgr_kv, list));
	return -1;
}


/* message builder */

int cgrates_set_reply(int type, int_str *value)
{
	struct cgr_local_ctx *ctx;

	if (type & CGR_KVF_TYPE_NULL)
		return 1;

	/* reset the error */
	ctx = CGR_GET_LOCAL_CTX();
	if (ctx == NULL) {
		/* create a new context */
		ctx = pkg_malloc(sizeof(*ctx));
		if (!ctx) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		memset(ctx, 0, sizeof(*ctx));
		CGR_PUT_LOCAL_CTX(ctx);
		LM_DBG("new local ctx=%p\n", ctx);
	}
	ctx->reply = pkg_malloc(sizeof(int_str) +
			((type & CGR_KVF_TYPE_STR)?value->s.len:0));
	if (!ctx->reply) {
		LM_ERR("out of memory!\n");
		return -1;
	}
	ctx->reply_flags = type;
	if (type & CGR_KVF_TYPE_STR) {
		ctx->reply->s.s = ((char *)ctx->reply) + sizeof(int_str);
		ctx->reply->s.len = value->s.len;
		memcpy(ctx->reply->s.s, value->s.s, ctx->reply->s.len);
		LM_DBG("Setting reply to s=%.*s\n", value->s.len, value->s.s);
	} else {
		ctx->reply->n = value->n;
		LM_DBG("Setting reply to n=%d\n", value->n);
	}
	return 0;
}

#define JSON_CHECK(_c, _s) \
	do { \
		if (!(_c)) { \
			LM_ERR("Cannot create \'%s\' json field \n", _s); \
			goto error; \
		} \
	} while (0)

struct cgr_msg *cgr_get_generic_msg(char *method, struct list_head *list)
{
	static struct cgr_msg cmsg;
	struct cgr_kv *kv;
	struct list_head *l;

	json_object *jtmp = NULL;
	json_object *jarr = NULL;
	cmsg.msg = json_object_new_object();

	JSON_CHECK(cmsg.msg, "new json object");
	JSON_CHECK(jtmp = json_object_new_string(method), "method");
	json_object_object_add(cmsg.msg,"method", jtmp);

	JSON_CHECK(jarr = json_object_new_array(), "params array");
	json_object_object_add(cmsg.msg,"params", jarr);

	JSON_CHECK(cmsg.params = json_object_new_object(), "params object");
	json_object_array_add(jarr, cmsg.params);

#if 0
	/* TODO: delete me! */
	/* add all the values in the context */
	if (prio_list) {
		list_for_each(l, prio_list) {
			kv = list_entry(l, struct cgr_kv, list);
			if (kv->flags & CGR_KVF_TYPE_NULL) {
				jtmp = NULL;
			} else if (kv->flags & CGR_KVF_TYPE_INT) {
				jtmp = json_object_new_int(kv->value.n);
				JSON_CHECK(jtmp, kv->key.s);
			} else {
				jtmp = json_object_new_string_len(kv->value.s.s, kv->value.s.len);
				JSON_CHECK(jtmp, kv->key.s);
			}
			json_object_object_add(jobj, kv->key.s, jtmp);
		}
	}
#endif
	if (list) {
		list_for_each(l, list) {
			kv = list_entry(l, struct cgr_kv, list);
			if (kv->flags & CGR_KVF_TYPE_NULL) {
				jtmp = NULL;
			} else if (kv->flags & CGR_KVF_TYPE_INT) {
				jtmp = json_object_new_int(kv->value.n);
				JSON_CHECK(jtmp, kv->key.s);
			} else {
				jtmp = json_object_new_string_len(kv->value.s.s, kv->value.s.len);
				JSON_CHECK(jtmp, kv->key.s);
			}
			json_object_object_add(cmsg.params, kv->key.s, jtmp);
		}
	}

	return &cmsg;
error:
	json_object_put(cmsg.msg);
	return NULL;
}

int cgr_msg_push_str(struct cgr_msg *cmsg, const char *key, str *value)
{
	json_object *jmsg;
	jmsg = json_object_new_string_len(value->s, value->len);
	JSON_CHECK(jmsg, key);
	json_object_object_add(cmsg->params, key, jmsg);
	return 0;
error:
	return -1;
}

#undef JSON_CHECK

/* context manipulation */
struct cgr_ctx *cgr_try_get_ctx(void)
{
	struct cell* t;
	struct cgr_ctx* ctx = NULL;

	if ((ctx = CGR_GET_CTX()) != NULL)
		return ctx;

	/* local one not found - search in transaction */
	t = cgr_tmb.t_gett ? cgr_tmb.t_gett() : NULL;
	t = t==T_UNDEFINED ? NULL : t;

	return (t ? CGR_GET_TM_CTX(t) : NULL);
}

struct cgr_ctx *cgr_get_ctx(void)
{
	struct cell* t;
	struct cgr_ctx *ctx = CGR_GET_CTX();

	t = cgr_tmb.t_gett ? cgr_tmb.t_gett() : NULL;
	t = t==T_UNDEFINED ? NULL : t;

	if (ctx) {
		/* if it is local, and we have transaction, move it in transaction */
		if (t) {
			CGR_PUT_TM_CTX(t, ctx);
			CGR_PUT_CTX(NULL);
		}
		return ctx;
	}

	ctx = shm_malloc(sizeof *ctx);
	if (!ctx) {
		LM_ERR("out of shm memory\n");
		return NULL;
	}
	memset(ctx, 0, sizeof *ctx);
	ctx->acc = cgr_tryget_acc_ctx();
	if (!ctx->acc) {
		ctx->kv_store = shm_malloc(sizeof *ctx->kv_store);
		if (!ctx->kv_store) {
			LM_ERR("out of shm memory\n");
			shm_free(ctx);
			return NULL;
		}
		INIT_LIST_HEAD(ctx->kv_store);
	} else {
		ctx->kv_store = ctx->acc->kv_store;
	}
	
	if (t)
		CGR_PUT_TM_CTX(t, ctx);
	else
		CGR_PUT_CTX(ctx);
	LM_DBG("new ctx=%p\n", ctx);
	return ctx;
}

/* TODO: delete */
#if 0
struct cgr_ctx *cgr_ctx_new(void)
{
	struct cgr_ctx *ctx = CGR_GET_CTX();
	if (!ctx) {
		ctx = pkg_malloc(sizeof *ctx);
		if (!ctx) {
			LM_ERR("out of pkg memory\n");
			return NULL;
		}
		memset(ctx, 0, sizeof *ctx);
		INIT_LIST_HEAD(&ctx->kv_store);
		CGR_PUT_CTX(ctx);
	}
	return ctx;
}
#endif

#define CGR_RESET_REPLY_CTX() \
	do { \
		struct cgr_local_ctx *_c = CGR_GET_LOCAL_CTX(); \
		if (_c) {\
			if (_c->reply) \
				pkg_free(_c->reply); \
			_c->reply = 0; \
		} \
	} while (0)

/* CGR logic */
/* Returns:
 *   1 - if cgrates successfully engaged
 *  -1 - cgrates returned error
 *  -2 - internal error
 *  -3 - no suitable cgrates server found
 *  -4 - cgrates engaged on invalid message
 */
int cgr_handle_cmd(struct sip_msg *msg, json_object *jmsg,
		cgr_proc_reply_f f, void *p)
{
	struct list_head *l;
	struct cgr_engine *e;
	struct cgr_conn *c = NULL;
	int ret = 1;
	str smsg;
	char *r;

	/* reset the error */
	CGR_RESET_REPLY_CTX();

	smsg.s = (char *)json_object_to_json_string(jmsg);
	smsg.len = strlen(smsg.s);

	r = (char *)json_object_to_json_string(jmsg);
	LM_DBG("sending json string: %s\n", r);

	/* connect to all servers */
	/* go through each server and initialize the state */
	list_for_each(l, &cgrates_engines) {
		e = list_entry(l, struct cgr_engine, list);
		if (!(c = cgr_get_free_conn(e)))
			continue;
		/* found a free connection - build the buffer */
		if (cgrc_send(c, &smsg) > 0)
			break;

		/* not working - closing */
		cgrc_close(c, CGRC_IS_LISTEN(c));
	}

	/* first free the json object built earlier, because it is already sent */
	json_object_put(jmsg);

	if (!c)
		return -3;

	/* message succesfully sent - now fetch the reply */
	do {
		ret = cgrc_async_read(c, f, p);
	} while(async_status == ASYNC_CONTINUE);

	return ret;
}

/* returns the processing status */
int cgrc_async_read(struct cgr_conn *c,
		cgr_proc_reply_f f, void *p)
{
	int len;
	int bytes_read;
	char buffer[CGR_BUFFER_SIZE];
	json_object *jobj = NULL;
	enum json_tokener_error jerr;
	struct cgr_engine *e = c->engine;
	int ret = -1; /* if return is 0, we need to continue */
	int final_ret = ret;

	LM_DBG("Event on fd %d from %.*s:%d\n", c->fd, e->host.len, e->host.s, e->port);

try_again:
	bytes_read = read(c->fd, buffer, CGR_BUFFER_SIZE);
	if (bytes_read < 0) {
		if (errno == EINTR || errno == EAGAIN)
			goto try_again;
		LM_ERR("read() failed with %d(%s)\n from %.*s:%d\n", errno,
				strerror(errno), e->host.len, e->host.s, e->port);
		/* close the connection, since we don't know now to parse what's
		 * coming from now on */
		goto disable;
	} else if (bytes_read == 0) {
		LM_INFO("CGRateS engine closed the connection\n");
		goto disable;
	}
	/* got a bunch of bytes, now parse them */
	LM_DBG("Received (possible partial) json: {%.*s}\n", bytes_read, buffer);

	/* try to parse them */
	jobj = json_tokener_parse_ex(c->jtok, buffer, bytes_read);
reprocess:
	if (jobj) {
		ret = cgrates_process(jobj, c, f, p);
		json_object_put(jobj);
		jobj = NULL;
		if (ret)
			final_ret = ret;
	} else {
		ret = 0;
	}
	/* check to see if there is anything else to process */
	jerr = json_tokener_get_error(c->jtok);
	if (jerr == json_tokener_continue) {
		LM_DBG("we need to read more until this is completed\n");
		async_status = ASYNC_CONTINUE;
		/* we do not release the context yet */
		return 1;
	} else if (jerr != json_tokener_success) {
		LM_ERR("Unable to parse json: %s\n", json_tokener_error_desc(jerr));
		goto disable;
	}
	/* now we need to see if there are any other bytes to read */
	/* XXX: for now there is no other way to check if there are bytes left but
	 * looking into the json tokener */
	if (c->jtok->char_offset < bytes_read) {
		len = c->jtok->char_offset;
		json_tokener_reset(c->jtok);
		LM_DBG("%d more bytes to process in the new request: [%.*s]\n",
				len, bytes_read - len, buffer + len);
		jobj = json_tokener_parse_ex(c->jtok, buffer + len, bytes_read - len);
		/* ret = 0 means that we are waiting for a reply
		 * but did not get one yet */
		if (ret)
			goto done;
		else
			goto reprocess;
	}
	/* all done */
	json_tokener_reset(c->jtok);
done:
	async_status = ASYNC_DONE;
	return final_ret;
disable:
	cgrc_close(c, 0);
	async_status = ASYNC_DONE_CLOSE_FD;
	return -2;
}


/* function ran when an event is sent over a fd */
int cgrates_async_resume_req(int fd, void *param)
{
	if (cgrc_async_read((struct cgr_conn *)param, NULL, NULL) < 0)
		return -1;
	/* if successfull, just continue listening */
	if (async_status == ASYNC_DONE)
		async_status = ASYNC_CONTINUE;
	return 1;
}

static inline int cgrates_process_req(struct cgr_engine *e, json_object *id,
		char *method, json_object *param)
{
	LM_INFO("Received new request method=%s param=%p\n",
			method, param);
	return -1;
}

static inline int cgrates_process_repl(struct cgr_engine *e, json_object *param)
{
	LM_INFO("Received new reply param=%p\n", param);
	return -1;
}

/* Returns:
 * -  1: on success
 * - -1: on error received from CGRateS
 * - -2: on internal error
 * - -3: on malformed JSON
 * -  0: if a request was processed
 */
int cgrates_process(json_object *jobj,
		struct cgr_conn *c, cgr_proc_reply_f proc_reply, void *p)
{
	json_object *jresult = NULL;
	char *error = NULL;
	char *method = NULL;
	json_object *id = NULL;
	int err = 0;
	int l = 0;
	enum cgrm_type msg_type = CGRM_UNSPEC;
	enum json_type type;
	struct cgr_engine *e = c->engine;

	LM_DBG("Processing JSON: %s\n",
			(char *)json_object_to_json_string(jobj));
	json_object_object_foreach(jobj, key, val) {
		/* most likely the compiler will figure out a better way to optimize
		 * this strcmp */
		type = json_object_get_type(val);
		if (strcmp(key, "result") == 0) {
			if (msg_type != CGRM_UNSPEC && msg_type != CGRM_REPL) {
				LM_ERR("Invalid JSON \"result\" property in a JSON-RPC request!\n");
				return -3;
			}
			msg_type = CGRM_REPL;
			if (type != json_type_null)
				jresult = val;
			else
				/* must be an error - result might be updated afterwards, or
				 * has already been set */
				err = 1;
		} else if (strcmp(key, "error") == 0) {
			if (msg_type != CGRM_UNSPEC && msg_type != CGRM_REPL) {
				LM_ERR("Invalid JSON \"error\" property in a JSON-RPC request!\n");
				return -3;
			}
			msg_type = CGRM_REPL;
			switch (type) {
				case json_type_null:
					err = 0;
					break;
				case json_type_string:
					error = (char *)json_object_to_json_string(val);
					break;
				default:
					LM_DBG("Unknown type %d for the \"error\" key\n", type);
					return -3;
			}
		} else if (strcmp(key, "method") == 0) {
			if (msg_type != CGRM_UNSPEC && msg_type != CGRM_REQ) {
				LM_ERR("Invalid JSON \"method\" property in a JSON-RPC reply!\n");
				return -3;
			}
			msg_type = CGRM_REQ;
			if (type != json_type_string) {
				LM_DBG("Unknown type %d for the \"method\" key\n", type);
				return -3;
			}
			method = (char *)json_object_to_json_string(val);
		} else if (strcmp(key, "params") == 0) {
			if (msg_type != CGRM_UNSPEC && msg_type != CGRM_REQ) {
				LM_ERR("Invalid JSON \"params\" property in a JSON-RPC reply!\n");
				return -3;
			}
			msg_type = CGRM_REQ;
			if (type != json_type_array) {
				LM_DBG("Unknown type %d for the \"params\" key\n", type);
				return -3;
			}
			if ((l = json_object_array_length(val)) != 1) {
				LM_ERR("too many elements in JSON array: %d\n", l);
				return -3;
			}
			jresult = json_object_array_get_idx(val, 0);
		} else if (strcmp(key, "id") == 0) {
			if (msg_type != CGRM_UNSPEC && msg_type != CGRM_REQ) {
				LM_ERR("Invalid JSON \"id\" property in a JSON-RPC reply!\n");
				return -3;
			}
			/* we simply preserve the ID as whatever object it was */
			id = val;
		} /* unhandled properties */
	}

	/* check for consistency */
	switch (msg_type) {
		case CGRM_UNSPEC:
			LM_ERR("Unknown JSON properties!\n");
			return -3;
		case CGRM_REPL:
			if (err) {
				if (jresult) {
					LM_ERR("Non-null error and result properties!"
							"Can't handle response!\n");
					return -3;
				}
				if (!error)
					error = "Unknown";
				return proc_reply(c, NULL, p, error);
			} else {
				if (error) {
					LM_ERR("Non-null error and result properties!"
							"Can't handle response!\n");
					return -3;
				}
				if (!jresult) {
					LM_ERR("No result received for reply!\n");
					return -3;
				}
				return proc_reply(c, jresult, p, NULL);
			}
		case CGRM_REQ:
			if (!method || !jresult) {
				LM_ERR("no method or parameters specified!\n");
				return -3;
			}
			cgrates_process_req(e, id, method, jresult);
			return 0;
	}
	/* never gets here */
	return 0;
}

void cgr_free_ctx(void *param)
{
	struct list_head *l;
	struct list_head *t;
	struct cgr_ctx *ctx = (struct cgr_ctx *)param;

	if (!ctx)
		return;
	LM_DBG("release ctx=%p\n", ctx);

	/* if somebody is doing accounting, let them free the list */
	if (!ctx->acc) {
		list_for_each_safe(l, t, ctx->kv_store)
			cgr_free_kv(list_entry(l, struct cgr_kv, list));
		shm_free(ctx->kv_store);
	}
	shm_free(ctx);
}

/* function that moves the context from global context to the transaction one */
void cgr_move_ctx( struct cell* t, int type, struct tmcb_params *ps)
{
	struct cgr_ctx *ctx = (struct cgr_ctx *)*ps->param;

	if (!ctx)
		return; /* nothing to move */

	t = cgr_tmb.t_gett ? cgr_tmb.t_gett() : NULL;
	if (!t || t == T_UNDEFINED) {
		LM_DBG("no transaction - can't move the context - freeing!\n");
		cgr_free_ctx(ctx);
		return;
	}

	LM_DBG("context moved in transaction\n");
	CGR_PUT_TM_CTX(t, ctx);
	CGR_PUT_CTX(NULL);
}

/* function that removes local context */
void cgr_free_local_ctx(void *param)
{
	struct cgr_local_ctx *ctx = (struct cgr_local_ctx *)param;
	LM_DBG("release local ctx=%p\n", ctx);
	if (ctx->reply)
		pkg_free(ctx->reply);
	pkg_free(ctx);
}


/* functions related to parameters fix */
str *cgr_get_acc(struct sip_msg *msg, char *acc_p)
{
	static str acc;
	struct to_body *from;
	struct sip_uri  uri;

	if (acc_p) {
		if (fixup_get_svalue(msg, (gparam_p)acc_p, &acc) < 0)
			goto error;
		else
			return &acc;
	}
	/* get the username from FROM_HDR */
	if (parse_from_header(msg) != 0) {
		LM_ERR("unable to parse from hdr\n");
		goto error;
	}
	from = (struct to_body *)msg->from->parsed;
	if (parse_uri(from->uri.s, from->uri.len, &uri)!=0) {
		LM_ERR("unable to parse from uri\n");
		goto error;
	}
error:
	LM_ERR("failed fo fetch account's name\n");
	return NULL;
}

str *cgr_get_dst(struct sip_msg *msg, char *dst_p)
{
	static str dst;

	if (dst_p) {
		if (fixup_get_svalue(msg, (gparam_p)dst_p, &dst) < 0)
			goto error;
		else
			return &dst;
	}
	if(msg->parsed_uri_ok == 0 && parse_sip_msg_uri(msg)<0) {
		LM_ERR("cannot parse Requst URI!\n");
		return NULL;
	}
	return &msg->parsed_uri.user;
error:
	LM_ERR("failed fo fetch destination\n");
	return NULL;
}
