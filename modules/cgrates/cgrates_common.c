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

#include <string.h>
#include <stdlib.h>
#include "../../dprint.h"
#include "../../str.h"
#include "../../async.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../reactor_defs.h"
#include "cgrates.h"
#include "cgrates_acc.h"
#include "cgrates_common.h"
#include "cgrates_engine.h"

/* key-value manipulation */
struct cgr_kv *cgr_get_kv(struct cgr_session *s, str name)
{
	struct list_head *l;
	struct cgr_kv *kv;

	if (!s)
		return NULL;
	list_for_each(l, &s->kvs) {
		kv = list_entry(l, struct cgr_kv, list);
		if (kv->key.len == name.len && !memcmp(kv->key.s, name.s, name.len))
			return kv;
	}
	return NULL;
}

struct cgr_kv *cgr_get_const_kv(struct cgr_session *s, const char *name)
{
	str sname;
	sname.s = (char *)name;
	sname.len = strlen(name);
	return cgr_get_kv(s, sname);
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
	LM_DBG("created new key %s\n", kv->key.s);
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

static int cgr_id_index = 0;

int cgr_init_common(void)
{
	/*
	 * the format is 'rand | my_pid'
	 * rand is (int) - (unsigned short) long
	 * my_pid is (short) long
	 */
	cgr_id_index = my_pid() & USHRT_MAX;
	cgr_id_index |= rand() << sizeof(unsigned short);

	return 0;
}


static inline int cgr_unique_id(void)
{
	cgr_id_index += (1 << sizeof(unsigned short));
	/* make sure we always return something positive */
	return cgr_id_index < 0 ? -cgr_id_index : cgr_id_index;
}

#define JSON_CHECK(_c, _s) \
	do { \
		if (!(_c)) { \
			LM_ERR("Cannot create \'%s\' json field \n", _s); \
			goto error; \
		} \
	} while (0)

struct cgr_msg *cgr_get_generic_msg(str *method, struct cgr_session *s)
{
	static struct cgr_msg cmsg;
	struct cgr_kv *kv;
	struct list_head *l;

	json_object *jtmp = NULL;
	json_object *jarr = NULL;
	cmsg.msg = json_object_new_object();

	JSON_CHECK(cmsg.msg, "new json object");
	JSON_CHECK(jtmp = json_object_new_string_len(method->s, method->len), "method");
	json_object_object_add(cmsg.msg,"method", jtmp);

	JSON_CHECK(jtmp = json_object_new_int(cgr_unique_id()), "id");
	json_object_object_add(cmsg.msg, "id", jtmp);

	JSON_CHECK(jarr = json_object_new_array(), "params array");
	json_object_object_add(cmsg.msg,"params", jarr);

	JSON_CHECK(cmsg.params = json_object_new_object(), "params object");
	json_object_array_add(jarr, cmsg.params);

	if (s) {
		list_for_each(l, &s->kvs) {
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

int cgr_msg_push_int(struct cgr_msg *cmsg, const char *key, unsigned int value)
{
	json_object *jmsg;
	jmsg = json_object_new_int(value);
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
	struct cgr_ctx *ctx = cgr_try_get_ctx();

	t = cgr_tmb.t_gett ? cgr_tmb.t_gett() : NULL;
	t = t==T_UNDEFINED ? NULL : t;

	if (ctx) {
		/* if it is local, and we have transaction, move it in transaction */
		if (t && CGR_GET_CTX()) {
			LM_DBG("ctx=%p moved in transaction\n", ctx);
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
		ctx->sessions = shm_malloc(sizeof *ctx->sessions);
		if (!ctx->sessions) {
			LM_ERR("out of shm memory\n");
			shm_free(ctx);
			return NULL;
		}
		INIT_LIST_HEAD(ctx->sessions);
	} else {
		ctx->sessions = ctx->acc->sessions;
		cgr_ref_acc_ctx(ctx->acc, 1, "general ctx");
	}
	
	if (t)
		CGR_PUT_TM_CTX(t, ctx);
	else
		CGR_PUT_CTX(ctx);
	LM_DBG("new ctx=%p\n", ctx);
	return ctx;
}

struct cgr_session *cgr_get_sess(struct cgr_ctx *ctx, str *tag)
{
	struct list_head *l;
	struct cgr_session *s;
	if (!ctx || !ctx->sessions)
		return NULL;
	/* if no tag given, return the entry with no tag */
	list_for_each(l, ctx->sessions) {
		s = list_entry(l, struct cgr_session, list);
		if ((!tag && !s->tag.len) || (tag && s->tag.len == tag->len &&
				memcmp(tag->s, s->tag.s, tag->len) == 0))
			return s;
	}
	return NULL;
}
struct cgr_session *cgr_new_sess(str *tag)
{
	struct cgr_session *s;
	/* allocate from scratch, since we don't have anything else */
	s = shm_malloc(sizeof(*s) + (tag ? tag->len : 0));
	if (!s) {
		LM_ERR("out of shm memory!\n");
		return NULL;
	}
	if (tag && tag->len) {
		s->tag.s = (char *)s + sizeof(*s);
		s->tag.len = tag->len;
		memcpy(s->tag.s, tag->s, tag->len);
	} else {
		s->tag.s = 0;
		s->tag.len = 0;
	}
	s->acc_info = 0;
	INIT_LIST_HEAD(&s->kvs);
	return s;
}

struct cgr_session *cgr_get_sess_new(struct cgr_ctx *ctx, str *tag)
{
	struct cgr_session *s;
	if (!ctx)
		return NULL;
	if ((s = cgr_get_sess(ctx, tag)) != NULL)
		return s;
	s = cgr_new_sess(tag);
	if (s)
		list_add(&s->list, ctx->sessions);
	return s;
}

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

	/* reset the error */
	CGR_RESET_REPLY_CTX();

	smsg.s = (char *)json_object_to_json_string(jmsg);
	smsg.len = strlen(smsg.s);

	LM_DBG("sending json string: %s\n", smsg.s);

	/* connect to all servers */
	/* go through each server and initialize the state */
	list_for_each(l, &cgrates_engines) {
		e = list_entry(l, struct cgr_engine, list);
		if (!(c = cgr_get_default_conn(e)))
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

	/* message successfully sent - now fetch the reply */
	do {
		ret = cgrc_async_read(c, f, p);
	} while(async_status == ASYNC_CONTINUE);

	return ret;
}

struct cgr_param {
	struct cgr_conn *c;
	cgr_proc_reply_f reply_f;
	void *reply_p;
};

static int cgrates_async_resume_repl(int fd,
		struct sip_msg *msg, void *param)
{
	int ret;
	struct cgr_param *cp = (struct cgr_param *)param;
	struct cgr_conn *c = cp->c;

	/* reset the error */
	CGR_RESET_REPLY_CTX();

	ret = cgrc_async_read(c, cp->reply_f, cp->reply_p);

	if (async_status == ASYNC_DONE) {
		/* processing done - remove the FD and replace the handler */
		async_status = ASYNC_DONE_NO_IO;
		reactor_del_reader(c->fd, -1, 0);
		if (cgrc_start_listen(c) < 0) {
			LM_CRIT("cannot re-register fd for cgrates events!\n");
			ret = -1;
			goto end;
		}
	}
end:
	/* done with this connection */
	c->state = CGRC_FREE;
	pkg_free(cp);
	return ret;
}

int cgr_handle_async_cmd(struct sip_msg *msg, json_object *jmsg,
		cgr_proc_reply_f f, void *p, async_ctx *ctx )
{
	struct list_head *l;
	struct cgr_engine *e;
	struct cgr_conn *c;
	struct cgr_param *cp = NULL;
	int ret = 1;
	str smsg;

	smsg.s = (char *)json_object_to_json_string(jmsg);
	smsg.len = strlen(smsg.s);

	cp = pkg_malloc(sizeof *cp);
	if (!cp) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	memset(cp, 0, sizeof *cp);
	cp->reply_f = f;
	cp->reply_p = p;

	LM_DBG("sending json string: %s\n", smsg.s);

	list_for_each(l, &cgrates_engines) {
		e = list_entry(l, struct cgr_engine, list);
		if (!(c = cgr_get_free_conn(e)))
			continue;
		/* found a free connection - build the buffer */
		if (cgrc_send(c, &smsg) < 0) {
			cgrc_close(c, CGRC_IS_LISTEN(c));
			continue;
		}
		cp->c = c;
		/* message successfully sent - now fetch the reply */
		if (CGRC_IS_DEFAULT(c)) {
			/* reset the error */
			CGR_RESET_REPLY_CTX();
			do {
				ret = cgrc_async_read(c, f, p);
			} while(async_status == ASYNC_CONTINUE);
			if (async_status == ASYNC_DONE)
				/* do the reading in sync mode */
				async_status = ASYNC_SYNC;
			pkg_free(cp);
			return ret;
		} else {
			c->state = CGRC_USED;
			if (CGRC_IS_LISTEN(c)) {
				/* remove the fd from the reactor because it will be added at the end of
				 * this function */
				reactor_del_reader(c->fd, -1, 0);
				CGRC_UNSET_LISTEN(c);
			}
			async_status = c->fd;
			ctx->resume_f = cgrates_async_resume_repl;
			ctx->resume_param = cp;
		}
		return ret;
	}
	pkg_free(cp);
	return -3;
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
		else if (errno == ECONNRESET) {
			LM_INFO("CGRateS engine reset the connection\n");
			goto disable;
		}
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
#if JSON_LIB_VERSION >= 10
	jerr = json_tokener_get_error(c->jtok);
#else
	jerr = c->jtok->err;
#endif
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
	cgrc_async_read((struct cgr_conn *)param, NULL, NULL);
	/* if successfull, just continue listening */
	if (async_status == ASYNC_DONE)
		async_status = ASYNC_CONTINUE;

	/* XXX: return is only used if fd changes - we are not currently
	 * support this */
	return 1;
}

static inline int cgrates_process_req(struct cgr_conn *c, json_object *id,
		char *method, json_object *param)
{
	int ret;
	json_object *jobj = NULL;
	json_object *jret = NULL;
	str smsg;

	LM_INFO("Received new request method=%s param=%p\n",
			method, param);
	if (strcmp(method, "SMGClientV1.DisconnectSession") == 0) {
		ret = cgr_acc_terminate(param, &jret);
	} else {
		LM_ERR("cannot handle method %s\n", method);
		ret = -1;
		jret = json_object_new_string("Unknown Method");
	}

	jobj = json_object_new_object();
	if (!jobj) {
		LM_ERR("cannot create a new json object!\n");
		if (jret)
			json_object_put(jret);
		return -1;
	}
	if (ret < 0) {
		json_object_object_add(jobj, "error", jret);
		json_object_object_add(jobj, "result", NULL);
	} else {
		json_object_object_add(jobj, "error", NULL);
		json_object_object_add(jobj, "result", jret);
	}
	if (id)
		json_object_object_add(jobj, "id", id);

	smsg.s = (char *)json_object_to_json_string(jobj);
	smsg.len = strlen(smsg.s);

	LM_DBG("sending json response: %s\n", smsg.s);
	cgrc_send(c, &smsg);

	json_object_put(jobj);

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
	json_object *jerror = NULL;
	char *method = NULL;
	json_object *id = NULL;
	json_object *tmp = NULL;
	int l = 0;
	int is_reply = 0;
	enum json_type type;
	char *rpc = (char *)json_object_to_json_string(jobj);

	LM_DBG("Processing JSON-RPC: %s\n", rpc);

	/* check to see if it is a reply */
	if (json_object_object_get_ex(jobj, "result", &jresult) && jresult) {
		is_reply = 1;
		if (json_object_get_type(jresult) == json_type_null)
			jresult = NULL;
	}
	if (json_object_object_get_ex(jobj, "error", &jerror) && jerror) {
		is_reply = 1;
		if (json_object_get_type(jerror) == json_type_null)
			jerror = NULL;
	}

	if (is_reply) {
		LM_DBG("treating JSON-RPC as a reply\n");
		if (jerror) {
			type = json_object_get_type(jerror);
			switch (type) {
			case json_type_null:
				if (!jresult) {
					LM_ERR("Invalid RPC: both \"error\" and \"result\" are null: %s\n", rpc);
					return -3;
				}
				break;
			case json_type_string:
				if (jresult) {
					LM_ERR("Invalid RPC: both \"error\" and \"result\" are not null: %s\n", rpc);
					return -3;
				}
				return proc_reply(c, NULL, p, (char *)json_object_get_string(jerror));
			default:
				LM_DBG("Invalid RPC: Unknown type %d for the \"error\" key\n", type);
				return -3;
			}
		}
		/* if error does not exist, treat it as successful */
		return proc_reply(c, jresult, p, NULL);
	} else {
		LM_DBG("treating JSON-RPC as a request\n");
		if (json_object_object_get_ex(jobj, "method", &tmp) && tmp) {
			if (json_object_get_type(tmp) != json_type_string) {
				LM_ERR("Invalid RPC: \"method\" not string: %s\n", rpc);
				return -3;
			}
			method = (char *)json_object_get_string(tmp);
		} else {
			LM_ERR("Invalid RPC: \"method\" not present in request: %s\n", rpc);
			return -3;
		}
		if (json_object_object_get_ex(jobj, "params", &tmp) && tmp) {
			switch (json_object_get_type(tmp)) {
			case json_type_object:
				jresult = tmp;
				break;
			case json_type_array:
				if ((l = json_object_array_length(tmp)) != 1) {
					LM_ERR("too many elements in JSON array: %d: %s\n", l, rpc);
					return -3;
				}
				jresult = json_object_array_get_idx(tmp, 0);
				break;
			default:
				LM_ERR("Invalid RPC: \"params\" is not array: %s\n", rpc);
				return -3;
			}
		} else {
			LM_ERR("Invalid RPC: \"params\" not present in request: %s\n", rpc);
			return -3;
		}

		/* check to see if there is an id */
		json_object_object_get_ex(jobj, "id", &id);
		cgrates_process_req(c, id, method, jresult);
	}
	return 0;
}


void cgr_free_sess(struct cgr_session *s)
{
	struct list_head *l;
	struct list_head *t;

	if (s->acc_info)
		shm_free(s->acc_info);
	list_for_each_safe(l, t, &s->kvs)
		cgr_free_kv(list_entry(l, struct cgr_kv, list));
	list_del(&s->list);
	shm_free(s);
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
		list_for_each_safe(l, t, ctx->sessions)
			cgr_free_sess(list_entry(l, struct cgr_session, list));
		shm_free(ctx->sessions);
	} else
		cgr_ref_acc_ctx(ctx->acc, -1, "general ctx");
	shm_free(ctx);
}

/* function that moves the context from global context to the transaction one */
void cgr_move_ctx( struct cell* t, int type, struct tmcb_params *ps)
{
	struct cgr_ctx *ctx = cgr_try_get_ctx();

	if (!ctx)
		return; /* nothing to move */

	t = cgr_tmb.t_gett ? cgr_tmb.t_gett() : NULL;
	if (!t || t == T_UNDEFINED) {
		LM_DBG("no transaction - can't move the context - freeing!\n");
		cgr_free_ctx(ctx);
		return;
	}

	LM_DBG("ctx=%p moved in transaction\n", ctx);
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
		LM_ERR("cannot parse Request URI!\n");
		return NULL;
	}
	return &msg->parsed_uri.user;
error:
	LM_ERR("failed fo fetch destination\n");
	return NULL;
}

str *cgr_get_tag(struct sip_msg *msg, char *tag_p)
{
	static str tag;

	if (tag_p && fixup_get_svalue(msg, (gparam_p)tag_p, &tag) >= 0)
		return &tag;
	return NULL;
}
