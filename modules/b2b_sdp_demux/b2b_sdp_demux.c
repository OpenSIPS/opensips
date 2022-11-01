/*
 * Copyright (C) 2021 Five9 Inc.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "../../dprint.h"
#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../b2b_entities/b2be_load.h"
#include "../tm/ut.h"
#include "../../parser/sdp/sdp.h"
#include "../../lib/list.h"
#include "../../msg_translator.h"
#include "../../rw_locking.h"

static dep_export_t mod_deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

static b2b_api_t b2b_api;
static str b2b_sdp_demux_server_cap = str_init("b2b_sdp_demux_server");
static str b2b_sdp_demux_client_cap = str_init("b2b_sdp_demux_client");
static str content_type_sdp_hdr = str_init("Content-Type: application/sdp\r\n");

static enum {
	B2B_SDP_BYE_DISABLE_TERMINATE,
	B2B_SDP_BYE_DISABLE,
	B2B_SDP_BYE_TERMINATE
} b2b_sdp_bye_mode = B2B_SDP_BYE_DISABLE;

static int b2b_sdp_demux(struct sip_msg *msg, str *uri,
		pv_spec_t *hdrs, pv_spec_t *streams);
static int fixup_check_avp(void** param);
static void b2b_sdp_server_event_trigger(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend);
static void b2b_sdp_server_event_received(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend);
static void b2b_sdp_client_event_trigger(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend);
static void b2b_sdp_client_event_received(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend);

static cmd_export_t mod_cmds[] = {
	{"b2b_sdp_demux", (cmd_function)b2b_sdp_demux, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{0,0,0}}, REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

static rw_lock_t *b2b_sdp_contexts_lock;
static struct list_head *b2b_sdp_contexts;

/** Module init function */
static int mod_init(void)
{

	b2b_sdp_contexts_lock = lock_init_rw();
	if (!b2b_sdp_contexts_lock) {
		LM_ERR("could not allocate contexts lock\n");
		return -1;
	}
	b2b_sdp_contexts = shm_malloc(sizeof *b2b_sdp_contexts);
	if (!b2b_sdp_contexts) {
		LM_ERR("cannot create B2B SDP contexts list\n");
		return -1;
	}
	INIT_LIST_HEAD(b2b_sdp_contexts);

	/* load b2b_entities api */
	if(load_b2b_api(&b2b_api) < 0) {
		LM_ERR("Failed to load b2b api\n");
		return -1;
	}

	if (b2b_api.register_cb(b2b_sdp_server_event_received,
			B2BCB_RECV_EVENT, &b2b_sdp_demux_server_cap) < 0) {
		LM_ERR("could not register server event receive callback!\n");
		return -1;
	}

	if (b2b_api.register_cb(b2b_sdp_server_event_trigger,
			B2BCB_TRIGGER_EVENT, &b2b_sdp_demux_server_cap) < 0) {
		LM_ERR("could not register server event trigger callback!\n");
		return -1;
	}

	if (b2b_api.register_cb(b2b_sdp_client_event_received,
			B2BCB_RECV_EVENT, &b2b_sdp_demux_client_cap) < 0) {
		LM_ERR("could not register client event receive callback!\n");
		return -1;
	}

	if (b2b_api.register_cb(b2b_sdp_client_event_trigger,
			B2BCB_TRIGGER_EVENT, &b2b_sdp_demux_client_cap) < 0) {
		LM_ERR("could not register client event trigger callback!\n");
		return -1;
	}

	return 0;
}

static int b2b_sdp_parse_bye_mode(unsigned int type, void *val)
{
	str mode;
	init_str(&mode, (char *)val);

	if (str_strcasecmp(&mode, _str("disable-terminate")) == 0)
		b2b_sdp_bye_mode = B2B_SDP_BYE_DISABLE_TERMINATE;
	else if (str_strcasecmp(&mode, _str("disable")) == 0)
		b2b_sdp_bye_mode = B2B_SDP_BYE_DISABLE;
	else if (str_strcasecmp(&mode, _str("terminate")) == 0)
		b2b_sdp_bye_mode = B2B_SDP_BYE_TERMINATE;
	else
		LM_ERR("unknown client_bye_mode mode: %.*s\n", mode.len, mode.s);

	return 0;
}

static param_export_t mod_params[]={
	{ "client_bye_mode", STR_PARAM|USE_FUNC_PARAM, b2b_sdp_parse_bye_mode },
	{ 0,                 0,                        0                       }
};


/** Module interface */
struct module_exports exports= {
	"b2b_sdp_demux",                /* module name */
	MOD_TYPE_DEFAULT,               /* class of this module */
	MODULE_VERSION,                 /* module version */
	DEFAULT_DLFLAGS,                /* dlopen flags */
	0,                              /* load function */
	&mod_deps,                      /* OpenSIPS module dependencies */
	mod_cmds,                       /* exported functions */
	0,                              /* exported async functions */
	mod_params,                     /* exported parameters */
	0,                              /* exported statistics */
	0,                              /* exported MI functions */
	0,                              /* exported pseudo-variables */
	0,                              /* exported transformations */
	0,                              /* extra processes */
	0,                              /* module pre-initialization function */
	mod_init,                       /* module initialization function */
	0,                              /* response handling function */
	0,                              /* destroy function */
	0,                              /* per-child init function */
	0                               /* reload confirm function */
};


static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("return parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}
struct b2b_sdp_ctx;
struct b2b_sdp_client;

struct b2b_sdp_stream {
	int index;
	int client_index;
	str label;
	str body;
	str disabled_body;
	struct b2b_sdp_client *client;
	struct list_head list;
	struct list_head ordered;
};
static int b2b_sdp_ack(int type, str *key, b2b_dlginfo_t *dlginfo);
static int b2b_sdp_reply(str *b2b_key, b2b_dlginfo_t *dlginfo,
		int type, int method, int code, str *body);
static int b2b_sdp_client_sync(struct b2b_sdp_client *client, str *body);
static struct b2b_sdp_stream *b2b_sdp_stream_raw_new(struct b2b_sdp_client *client,
		str *disabled_body, int index, int client_index);

#define B2B_SDP_CLIENT_EARLY	(1<<0)
#define B2B_SDP_CLIENT_STARTED	(1<<1)
#define B2B_SDP_CLIENT_PENDING	(1<<2)
#define B2B_SDP_CLIENT_REPL	(1<<3)

struct b2b_sdp_client {
	unsigned int flags;
	str hdrs;
	str body;
	str b2b_key;
	b2b_dlginfo_t *dlginfo;
	struct b2b_sdp_ctx *ctx;
	struct list_head streams;
	struct list_head list;
};

#define B2B_SDP_CTX_STARTED		(1<<0)
#define B2B_SDP_CTX_CANCELLED	(1<<1)

struct b2b_sdp_ctx {
	unsigned int flags;
	str callid;
	str b2b_key;
	int clients_no;
	int pending_no;
	int success_no;
	time_t sess_id;
	str sess_ip;
	gen_lock_t lock;
	b2b_dlginfo_t *dlginfo;
	struct list_head clients;
	struct list_head streams;
	struct list_head contexts;
};



static str *b2b_sdp_label_from_sdp(sdp_stream_cell_t *stream)
{
	sdp_attr_t *attr;
	/* check if the stream has a label */
	for (attr = stream->attr; attr; attr = attr->next)
		if (str_match_nt(&attr->attribute, "label"))
			return &attr->value;
	return NULL;
}

static void b2b_add_stream_ctx(struct b2b_sdp_ctx *ctx, struct b2b_sdp_stream *stream)
{
	struct b2b_sdp_stream *ostream;
	struct list_head *it;
	/* insert the streams ordered by their index */
	if (list_empty(&ctx->streams)) {
		list_add(&stream->ordered, &ctx->streams);
		return;
	}
	ostream = list_entry(ctx->streams.next, struct b2b_sdp_stream, ordered);
	if (ostream->index > stream->index) {
		list_add(&stream->ordered, &ctx->streams);
		return;
	}
	ostream = list_last_entry(&ctx->streams, struct b2b_sdp_stream, ordered);
	if (ostream->index < stream->index) {
		list_add_tail(&stream->ordered, &ctx->streams);
		return;
	}
	list_for_each(it, &ctx->streams) {
		ostream = list_entry(it, struct b2b_sdp_stream, ordered);
		if (ostream->index < stream->index)
			continue;
		/* "manual" insert in the middle */
		stream->ordered.next = &ostream->ordered;
		stream->ordered.prev = ostream->ordered.prev;
		stream->ordered.prev->next = &stream->ordered;
		ostream->ordered.prev = &stream->ordered;
		break;
	}
}

static struct b2b_sdp_stream *b2b_sdp_stream_new(sdp_stream_cell_t *sstream,
		struct b2b_sdp_client *client, int client_index)
{
	static str lline = str_init("a=label:");
	str *label = b2b_sdp_label_from_sdp(sstream);
	struct b2b_sdp_stream *stream = shm_malloc(sizeof *stream +
			2 /* 'm=' */ + sstream->media.len + 3 /* ' 0 ' */ +
			sstream->transport.len + 1 /* ' ' */ +
			(sstream->p_payload_attr?sstream->p_payload_attr[0]->rtp_payload.len:1 /* '0' */) +
			CRLF_LEN + (label?lline.len + label->len + CRLF_LEN:0));
	if (!stream) {
		LM_ERR("could not alocate B2B SDP stream\n");
		return NULL;
	}
	memset(stream, 0, sizeof *stream);
	stream->disabled_body.s = (char *)(stream + 1);
	/* copy media type */
	memcpy(stream->disabled_body.s + stream->disabled_body.len, "m=", 2);
	stream->disabled_body.len += 2;
	memcpy(stream->disabled_body.s + stream->disabled_body.len,
			sstream->media.s, sstream->media.len);
	stream->disabled_body.len += sstream->media.len;
	memcpy(stream->disabled_body.s + stream->disabled_body.len, " 0 ", 3);
	stream->disabled_body.len += 3;
	memcpy(stream->disabled_body.s + stream->disabled_body.len,
			sstream->transport.s, sstream->transport.len);
	stream->disabled_body.len += sstream->transport.len;
	memcpy(stream->disabled_body.s + stream->disabled_body.len, " ", 1);
	stream->disabled_body.len += 1;
	if (sstream->p_payload_attr) {
		memcpy(stream->disabled_body.s + stream->disabled_body.len,
				sstream->p_payload_attr[0]->rtp_payload.s,
				sstream->p_payload_attr[0]->rtp_payload.len);
		stream->disabled_body.len += sstream->p_payload_attr[0]->rtp_payload.len;
	} else {
		memcpy(stream->disabled_body.s + stream->disabled_body.len, "0", 1);
		stream->disabled_body.len += 1;
	}
	memcpy(stream->disabled_body.s + stream->disabled_body.len, CRLF, CRLF_LEN);
	stream->disabled_body.len += CRLF_LEN;

	if (label) {
		stream->label.len = label->len;
		memcpy(stream->disabled_body.s + stream->disabled_body.len, lline.s, lline.len);
		stream->disabled_body.len += lline.len;
		stream->label.s = stream->disabled_body.s + stream->disabled_body.len;
		memcpy(stream->disabled_body.s + stream->disabled_body.len, label->s, label->len);
		stream->disabled_body.len += label->len;
		memcpy(stream->disabled_body.s + stream->disabled_body.len, CRLF, CRLF_LEN);
		stream->disabled_body.len += CRLF_LEN;
	}

	stream->index = sstream->stream_num;
	stream->client_index = client_index;
	INIT_LIST_HEAD(&stream->ordered);
	INIT_LIST_HEAD(&stream->list);
	if (client) {
		stream->client = client;
		list_add_tail(&stream->list, &client->streams);
	}
	return stream;
}

static struct b2b_sdp_stream *b2b_sdp_stream_raw_new(struct b2b_sdp_client *client,
		str *disabled_body, int index, int client_index)
{
	struct b2b_sdp_stream *stream = shm_malloc(sizeof *stream + disabled_body->len);
	if (!stream) {
		LM_ERR("could not allocate raw B2B SDP stream!\n");
		return NULL;
	}
	memset(stream, 0, sizeof *stream);
	stream->disabled_body.s = (char *)(stream + 1);
	stream->disabled_body.len = disabled_body->len;
	memcpy(stream->disabled_body.s, disabled_body->s, disabled_body->len);
	stream->index = index;
	stream->client_index = client_index;
	INIT_LIST_HEAD(&stream->ordered);
	INIT_LIST_HEAD(&stream->list);
	if (client) {
		stream->client = client;
		list_add_tail(&stream->list, &client->streams);
	}
	return stream;
}

static void b2b_sdp_stream_free(struct b2b_sdp_stream *stream)
{
	if (stream->body.s)
		shm_free(stream->body.s);
	list_del(&stream->ordered);
	list_del(&stream->list);
	shm_free(stream);
}

static struct b2b_sdp_client *b2b_sdp_client_new(struct b2b_sdp_ctx *ctx)
{
	struct b2b_sdp_client *client = shm_malloc(sizeof *client);
	if (!client) {
		LM_ERR("could not alocate new client\n");
		return NULL;
	}
	memset(client, 0, sizeof *client);
	INIT_LIST_HEAD(&client->streams);
	client->ctx = ctx;
	list_add_tail(&client->list, &ctx->clients);
	ctx->clients_no++;
	return client;
}

static void b2b_sdp_client_terminate(struct b2b_sdp_client *client, str *key)
{
	str method;
	b2b_req_data_t req_data;
	int send_cancel = 0;
	if (!key || key->len == 0) {
		LM_WARN("cannot terminate non-started client\n");
		return;
	}
	lock_get(&client->ctx->lock);
	send_cancel = (client->flags & B2B_SDP_CLIENT_EARLY);
	if (!send_cancel && !(client->flags & B2B_SDP_CLIENT_STARTED)) {
		lock_release(&client->ctx->lock);
		goto delete;
	}
	client->flags &= ~(B2B_SDP_CLIENT_EARLY|B2B_SDP_CLIENT_STARTED);
	lock_release(&client->ctx->lock);
	if (send_cancel)
		init_str(&method, CANCEL);
	else
		init_str(&method, BYE);

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	req_data.no_cb = 1; /* do not call callback */
	req_data.et = B2B_CLIENT;
	req_data.b2b_key = key;
	req_data.dlginfo = client->dlginfo;
	req_data.method = &method;
	b2b_api.send_request(&req_data);
	LM_INFO("[%.*s] client request %.*s sent\n", key->len, key->s, method.len, method.s);
delete:
	b2b_api.entity_delete(B2B_CLIENT, key, client->dlginfo, 1, 1);
}

static void b2b_sdp_client_free(void *param)
{
	struct list_head *it, *safe;

	struct b2b_sdp_client *client = param;

	if (!param)
		return;

	if (client->hdrs.s)
		shm_free(client->hdrs.s);

	if (client->b2b_key.s)
		shm_free(client->b2b_key.s);

	if (client->body.s)
		shm_free(client->body.s);

	list_for_each_safe(it, safe, &client->streams)
		b2b_sdp_stream_free(list_entry(it, struct b2b_sdp_stream, list));
	if (client->dlginfo)
		shm_free(client->dlginfo);
	shm_free(client);
}

static void b2b_sdp_client_release(struct b2b_sdp_client *client, int lock)
{
	struct b2b_sdp_ctx *ctx = client->ctx;

	if (lock)
		lock_get(&ctx->lock);
	list_del(&client->list);
	ctx->clients_no--;
	if (lock)
		lock_release(&ctx->lock);
}

static void b2b_sdp_client_delete(struct b2b_sdp_client *client)
{
	b2b_sdp_client_release(client, 1);
	b2b_sdp_client_terminate(client, &client->b2b_key);
}

static struct b2b_sdp_ctx *b2b_sdp_ctx_new(str *callid)
{
	struct b2b_sdp_ctx *ctx = shm_malloc(sizeof(*ctx) + callid->len);
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof *ctx);
	INIT_LIST_HEAD(&ctx->clients);
	INIT_LIST_HEAD(&ctx->streams);
	lock_init(&ctx->lock);
	time(&ctx->sess_id);
	ctx->callid.len = callid->len;
	ctx->callid.s = (char *)(ctx + 1);
	memcpy(ctx->callid.s, callid->s, callid->len);
	lock_start_write(b2b_sdp_contexts_lock);
	list_add(&ctx->contexts, b2b_sdp_contexts);
	lock_stop_write(b2b_sdp_contexts_lock);
	return ctx;
}

static struct b2b_sdp_ctx *b2b_sdp_ctx_get(str *key)
{
	struct list_head *it;
	struct b2b_sdp_ctx *ctx;

	lock_start_read(b2b_sdp_contexts_lock);
	list_for_each(it, b2b_sdp_contexts) {
		ctx = list_entry(it, struct b2b_sdp_ctx, contexts);
		if (!ctx->b2b_key.len)
			continue;
		if (str_match(key, &ctx->b2b_key)) {
			lock_stop_read(b2b_sdp_contexts_lock);
			return ctx;
		}
	}
	lock_stop_read(b2b_sdp_contexts_lock);
	return NULL;
}


/* has the ctx's lock taken */
static struct b2b_sdp_client *b2b_sdp_client_get(struct b2b_sdp_ctx *ctx, str *key)
{
	struct list_head *it;
	struct b2b_sdp_client *client;

	lock_get(&ctx->lock);
	list_for_each(it, &ctx->clients) {
		client = list_entry(it, struct b2b_sdp_client, list);
		if (!ctx->b2b_key.len)
			continue;
		if (str_match(key, &client->b2b_key))
			return client;
	}
	lock_release(&ctx->lock);
	return NULL;
}

static void b2b_sdp_ctx_release(struct b2b_sdp_ctx *ctx, int replicate)
{
	struct list_head *it, *safe;

	list_for_each_safe(it, safe, &ctx->clients)
		b2b_sdp_client_delete(list_entry(it, struct b2b_sdp_client, list));
	/* free remaining streams */
	list_for_each_safe(it, safe, &ctx->streams)
		b2b_sdp_stream_free(list_entry(it, struct b2b_sdp_stream, ordered));
	lock_start_write(b2b_sdp_contexts_lock);
	list_del(&ctx->contexts);
	lock_stop_write(b2b_sdp_contexts_lock);
	if (ctx->b2b_key.s)
		b2b_api.entity_delete(B2B_SERVER, &ctx->b2b_key, NULL, 1, replicate);
}

static void b2b_sdp_ctx_free(void *param)
{
	struct b2b_sdp_ctx *ctx = param;
	if (!ctx)
		return;
	if (ctx->b2b_key.s)
		shm_free(ctx->b2b_key.s);
	if (ctx->dlginfo)
		shm_free(ctx->dlginfo);
	shm_free(ctx->sess_ip.s);
	shm_free(ctx);
}

static int b2b_sdp_streams_from_sdp(struct b2b_sdp_ctx *ctx,
		sdp_info_t *sdp)
{
	struct b2b_sdp_client *client;
	struct b2b_sdp_stream *bstream;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;

	for (session = sdp->sessions; session; session = session->next) {
		for (stream = session->streams; stream; stream = stream->next) {
			/* for each stream, we have a new client */
			client = b2b_sdp_client_new(ctx);
			if (!client)
				return -1;
			bstream = b2b_sdp_stream_new(stream, client, 0);
			if (!bstream)
				return -1;
			b2b_add_stream_ctx(ctx, bstream);
		}
	}
	return 0;
}

#if 0
static void b2b_sdp_streams_print(struct b2b_sdp_ctx *ctx)
{
	struct list_head *c, *s;
	struct b2b_sdp_client *client;
	struct b2b_sdp_stream *stream;

	list_for_each_prev(c, &ctx->clients) {
		client = list_entry(c, struct b2b_sdp_client, list);
		list_for_each(s, &client->streams) {
			stream = list_entry(s, struct b2b_sdp_stream, list);
			LM_INFO("client=%p hdrs=[%.*s] stream=%d client_index=%d\n", client,
					(client->hdrs.len?client->hdrs.len:0),
					(client->hdrs.len?client->hdrs.s:""), stream->index,
					stream->client_index);
		}
	}
	list_for_each(s, &ctx->streams) {
		stream = list_entry(s, struct b2b_sdp_stream, ordered);
		LM_INFO("stream=%d disabled=%s label=[%.*s] body=[%.*s]\n",
				stream->index, (stream->client?"no":"yes"),
				(stream->label.len?stream->label.len:4),
				(stream->label.len?stream->label.s:"NULL"),
				stream->disabled_body.len, stream->disabled_body.s);
	}
}
#endif

static inline sdp_stream_cell_t *b2b_sdp_get_stream(sdp_info_t *sdp, int idx)
{
	return get_sdp_stream(sdp, 0, idx);
}

static inline sdp_session_cell_t *b2b_sdp_get_session(sdp_info_t *sdp, int idx)
{
	return get_sdp_session(sdp, 0);
}

static struct b2b_sdp_stream *b2b_sdp_get_stream_idx(
		struct b2b_sdp_ctx *ctx, int idx)
{
	struct b2b_sdp_stream *stream;
	struct b2b_sdp_client *client;
	struct list_head *c, *s;
	list_for_each(c, &ctx->clients) {
		client = list_entry(c, struct b2b_sdp_client, list);
		list_for_each(s, &client->streams) {
			stream = list_entry(s, struct b2b_sdp_stream, list);
			if (stream->index == idx)
				return stream;
		}
	}
	return NULL;
}

static struct b2b_sdp_stream *b2b_sdp_get_stream_client_idx(
		struct b2b_sdp_client *client, int idx)
{
	struct b2b_sdp_stream *stream;
	struct list_head *s;
	list_for_each(s, &client->streams) {
		stream = list_entry(s, struct b2b_sdp_stream, list);
		if (stream->client_index == idx)
			return stream;
	}
	return NULL;
}

static int b2b_sdp_stream_new_idx(struct b2b_sdp_ctx *ctx,
		struct b2b_sdp_client *client, int idx, sdp_info_t *sdp, int client_idx)
{
	sdp_stream_cell_t *stream;
	struct b2b_sdp_stream *bstream;

	/* double check there's no other client with the same stream */
	bstream = b2b_sdp_get_stream_idx(ctx, idx);
	if (bstream) {
		LM_WARN("stream already assigned to a client! ignoring...\n");
		return 0;
	}

	stream = b2b_sdp_get_stream(sdp, idx);
	if (!stream) {
		LM_ERR("invalid stream number %d\n", idx);
		return 0;
	}
	bstream = b2b_sdp_stream_new(stream, client, client_idx);
	if (!bstream)
		return -1;
	b2b_add_stream_ctx(ctx, bstream);
	return 0;
}

static int b2b_sdp_streams_from_avps(struct b2b_sdp_ctx *ctx,
		pv_spec_t *streams, sdp_info_t *sdp)
{
	struct b2b_sdp_stream *bstream;
	struct b2b_sdp_client *client;
	struct usr_avp *avp = NULL;
	int_str val;
	char *p, *end;
	unsigned int itmp;
	int client_idx = 0;
	str tmp;
	sdp_stream_cell_t *stream;
	sdp_session_cell_t *session;

	while ((avp = search_first_avp(streams->pvp.pvn.u.isname.type,
				streams->pvp.pvn.u.isname.name.n, &val, avp)) != NULL) {
		if (avp->flags & AVP_VAL_NULL)
			continue;
		/* for each stream, we have a new client */
		client = b2b_sdp_client_new(ctx);
		if (!client)
			return -1;
		client_idx = 0;

		if (avp->flags & AVP_VAL_STR) {
			/* parse the streams inside the string */
			end = val.s.s + val.s.len;
			while (val.s.len > 0) {
				p = val.s.s;
				while (p < end && (*p < '0' || *p > '9')) p++;
				tmp.s = p;
				while (p < end && *p >= '0' && *p <= '9') p++;
				tmp.len = p - tmp.s;
				if (tmp.len == 0)
					break;
				str2int(&tmp, &itmp);
				val.s.len -= (p - val.s.s);
				val.s.s = p;

				if (b2b_sdp_stream_new_idx(ctx, client, itmp, sdp, client_idx++) < 0)
					return -1;
			}
		} else {
			/* if an integer, only one stream is used */
			if (b2b_sdp_stream_new_idx(ctx, client, val.n, sdp, client_idx++) < 0)
				return -1;
		}
		if (list_empty(&client->streams)) {
			LM_WARN("no stream added to client - ignoring!\n");
			b2b_sdp_client_delete(client);
		}
	}
	/* we should also account for any remaining streams and disable them */
	for (session = sdp->sessions; session; session = session->next) {
		for (stream = session->streams; stream; stream = stream->next) {
			if (b2b_sdp_get_stream_idx(ctx, stream->stream_num))
				continue;
			LM_DBG("stream %d not handled - disabling it!\n", stream->stream_num);
			bstream = b2b_sdp_stream_new(stream, NULL, -1);
			if (!bstream)
				return -1;
			b2b_add_stream_ctx(ctx, bstream);
		}
	}
	return 0;
}

static int b2b_sdp_hdrs_from_avps(struct b2b_sdp_ctx *ctx, pv_spec_t *headers)
{
	int_str val;
	struct list_head *c;
	struct usr_avp *avp = NULL;
	struct b2b_sdp_client *client;

	list_for_each(c, &ctx->clients) {
		client = list_entry(c, struct b2b_sdp_client, list);
		avp = search_first_avp(headers->pvp.pvn.u.isname.type,
				headers->pvp.pvn.u.isname.name.n, &val, avp);
		if (!avp)
			break;
		if (avp->flags & AVP_VAL_NULL)
			continue;
		if (!(avp->flags & AVP_VAL_STR)) {
			LM_WARN("invalid header integer type! ignoring...\n");
			continue;
		}
		if (shm_str_sync(&client->hdrs, &val.s) < 0) {
			LM_ERR("could not copy headers!\n");
			return -1;
		}
	}
	return 0;
}

static str *b2b_sdp_mux_body(struct b2b_sdp_ctx *ctx)
{
	/*
	 * SDP body format we use:
	 *
	 * v=0
	 * o=- <timestamp> <version> IN IP4 <mediaip>
	 * s=-
	 * c=IN IP4 <mediaip>
	 * t=0 0
	 * <streams*>
	 */
	int len;
	static str body;
	str tmp;
	str header1 = str_init("v=0" CRLF "o=- ");
	str header2 = str_init(" IN IP4 ");
	str header3 = str_init(CRLF "s=-" CRLF "c=IN IP4 ");
	str header4 = str_init(CRLF "t=0 0" CRLF);
	struct list_head *it;
	struct b2b_sdp_stream *stream;
	time_t now;

	time(&now);

	len = header1.len + 2 * INT2STR_MAX_LEN + 1 /* " " */ +
		header2.len + ctx->sess_ip.len +
		header3.len + ctx->sess_ip.len + header4.len;
	list_for_each(it, &ctx->streams) {
		stream = list_entry(it, struct b2b_sdp_stream, ordered);
		if (stream->client && stream->client->flags & B2B_SDP_CLIENT_STARTED)
			len += stream->body.len;
		else
			/* just disable the media - with the same body, but port 0 */
			len += stream->disabled_body.len;
	}
	body.s = pkg_malloc(len);
	if (!body.s) {
		LM_ERR("could not alocate body len=%d!\n", len);
		return NULL;
	}
	len = 0;
	memcpy(body.s + len, header1.s, header1.len);
	len += header1.len;
	tmp.s = int2str(ctx->sess_id, &tmp.len);
	memcpy(body.s + len, tmp.s, tmp.len);
	len += tmp.len;
	body.s[len++] = ' ';
	tmp.s = int2str(now, &tmp.len);
	memcpy(body.s + len, tmp.s, tmp.len);
	len += tmp.len;
	memcpy(body.s + len, header2.s, header2.len);
	len += header2.len;
	memcpy(body.s + len, ctx->sess_ip.s, ctx->sess_ip.len);
	len += ctx->sess_ip.len;
	memcpy(body.s + len, header3.s, header3.len);
	len += header3.len;
	memcpy(body.s + len, ctx->sess_ip.s, ctx->sess_ip.len);
	len += ctx->sess_ip.len;
	memcpy(body.s + len, header4.s, header4.len);
	len += header4.len;
	list_for_each(it, &ctx->streams) {
		stream = list_entry(it, struct b2b_sdp_stream, ordered);
		if (stream->client && stream->client->flags & B2B_SDP_CLIENT_STARTED) {
			memcpy(body.s + len, stream->body.s, stream->body.len);
			len += stream->body.len;
		} else {
			memcpy(body.s + len, stream->disabled_body.s, stream->disabled_body.len);
			len += stream->disabled_body.len;
		}
	}
	body.len = len;
	return &body;
}

#define B2B_SDP_CLIENT_WAIT_FREE(_ctx) \
	do { \
		while ((_ctx)->pending_no) { \
			lock_release(&(_ctx)->lock); \
			usleep(50); \
			lock_get(&(_ctx)->lock); \
		} \
	} while (0)

static int b2b_sdp_client_reinvite(struct sip_msg *msg, struct b2b_sdp_client *client)
{
	str *body, *rbody = NULL;
	str method = str_init("INVITE");
	b2b_req_data_t req_data;
	int code = 0, ret = -1;

	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!body) {
		LM_INFO("cannot handle re-INVITE without body!\n");
		return -1;
	}
	lock_get(&client->ctx->lock);
	if (client->flags & B2B_SDP_CLIENT_PENDING) {
		LM_INFO("we still have pending requests!\n");
		code = 491;
		goto end;
	}
	B2B_SDP_CLIENT_WAIT_FREE(client->ctx);
	ret = b2b_sdp_client_sync(client, body);
	if (ret < 0) {
		code = 488;
		LM_INFO("cannot parse re-INVITE body!\n");
		goto end;
	} else if (ret == 0) {
		code = 200;
		rbody = &client->body;
		LM_DBG("nothing to update, replying re-INVITE immediately!\n");
		goto end;
	}
	client->ctx->pending_no = 1;
	client->flags |= B2B_SDP_CLIENT_PENDING;
	body = b2b_sdp_mux_body(client->ctx);
end:
	lock_release(&client->ctx->lock);
	if (ret > 0) {
		if (body) {
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			req_data.et = B2B_SERVER;
			req_data.b2b_key = &client->ctx->b2b_key;
			req_data.method = &method;
			req_data.body = body;
			req_data.dlginfo = client->ctx->dlginfo;
			LM_INFO("[%.*s][%.*s] server request INVITE sent\n",
					client->ctx->callid.len, client->ctx->callid.s,
					client->ctx->b2b_key.len, client->ctx->b2b_key.s);
			if (b2b_api.send_request(&req_data) < 0) {
				LM_ERR("cannot send upstream INVITE\n");
				code = 500;
				ret = -1;
			}
		} else {
			LM_ERR("cannot print upstream INVITE body\n");
			code = 500;
			ret = -1;
		}
	}
	if (code)
		b2b_sdp_reply(&client->b2b_key, client->dlginfo, B2B_CLIENT, msg->REQ_METHOD, code, rbody);
	return ret;
}

static void b2b_sdp_client_release_streams(struct b2b_sdp_client *client)
{
	struct list_head *it, *safe;
	struct b2b_sdp_stream *stream;

	/* we need to move all the streams in the disabled list */
	list_for_each_safe(it, safe, &client->streams) {
		stream = list_entry(it, struct b2b_sdp_stream, list);
		list_del(&stream->list);
		INIT_LIST_HEAD(&stream->list);
		stream->client = NULL;
	}
}

static void b2b_sdp_client_remove(struct b2b_sdp_client *client)
{
	struct b2b_sdp_ctx *ctx = client->ctx;

	lock_get(&ctx->lock);
	if (!(client->flags & B2B_SDP_CLIENT_STARTED)) {
		lock_release(&ctx->lock);
		return;
	}
	/* terminate whatever the client was doing */
	client->flags &= ~(B2B_SDP_CLIENT_EARLY|B2B_SDP_CLIENT_STARTED);
	b2b_sdp_client_release_streams(client);
	lock_release(&ctx->lock);
}

static void b2b_sdp_server_send_bye(struct b2b_sdp_ctx *ctx)
{
	str method;
	b2b_req_data_t req_data;

	init_str(&method, "BYE");
	memset(&req_data, 0, sizeof(b2b_req_data_t));
	req_data.et = B2B_SERVER;
	req_data.b2b_key = &ctx->b2b_key;
	req_data.method = &method;
	req_data.dlginfo = ctx->dlginfo;
	if (b2b_api.send_request(&req_data) < 0)
		LM_ERR("cannot send upstream BYE\n");
	else
		LM_INFO("[%.*s] server request BYE sent\n", ctx->b2b_key.len, ctx->b2b_key.s);
}

static int b2b_sdp_client_bye(struct sip_msg *msg, struct b2b_sdp_client *client)
{
	str *body;
	str method;
	b2b_req_data_t req_data;
	struct b2b_sdp_ctx *ctx = client->ctx;

	b2b_sdp_client_remove(client);
	b2b_sdp_reply(&client->b2b_key, client->dlginfo, B2B_CLIENT, METHOD_BYE, 200, NULL);
	b2b_sdp_client_release(client, 1);
	b2b_api.entity_delete(B2B_CLIENT, &client->b2b_key, client->dlginfo, 1, 1);
	lock_get(&ctx->lock);

	switch (b2b_sdp_bye_mode) {

		case B2B_SDP_BYE_TERMINATE:
			if (ctx->pending_no) {
				LM_DBG("already terminating - not interested any more\n");
				lock_release(&ctx->lock);
				return 0;
			}
			ctx->pending_no = 1;
			b2b_sdp_server_send_bye(ctx);
			lock_release(&ctx->lock);
			break;

		case B2B_SDP_BYE_DISABLE_TERMINATE:
			if (list_size(&ctx->clients) == 0) {
				b2b_sdp_server_send_bye(ctx);
				lock_release(&ctx->lock);
				break;
			}
			/* fallback */

		case B2B_SDP_BYE_DISABLE:
			/* also notify the upstream */
			body = b2b_sdp_mux_body(ctx);
			if (body) {
				/* we do a busy waiting if there's a different negociation happening */
				B2B_SDP_CLIENT_WAIT_FREE(ctx);
				ctx->pending_no = 1;
				lock_release(&ctx->lock);
				memset(&req_data, 0, sizeof(b2b_req_data_t));
				init_str(&method, "INVITE");
				req_data.et = B2B_SERVER;
				req_data.b2b_key = &ctx->b2b_key;
				req_data.method = &method;
				req_data.body = body;
				req_data.dlginfo = ctx->dlginfo;
				if (b2b_api.send_request(&req_data) < 0)
					LM_ERR("cannot send upstream INVITE\n");
				else
					LM_INFO("[%.*s] server request INVITE sent\n",
							ctx->b2b_key.len, ctx->b2b_key.s);
			} else {
				lock_release(&ctx->lock);
			}
			break;
	}
	return 0;
}

static int b2b_sdp_reply(str *b2b_key, b2b_dlginfo_t *dlginfo,
		int type, int method, int code, str *body)
{
	char *etype = (type==B2B_CLIENT?"client":"server");
	b2b_rpl_data_t reply_data;
	str text;
	init_str(&text, error_text(code));

	memset(&reply_data, 0, sizeof (reply_data));
	reply_data.et = type;
	reply_data.b2b_key = b2b_key;
	reply_data.method = method;
	reply_data.code = code;
	reply_data.text = &text;
	reply_data.body = body;
	reply_data.dlginfo = dlginfo;
	if (body)
		reply_data.extra_headers = &content_type_sdp_hdr;
	LM_INFO("[%.*s] %s reply %d sent\n", b2b_key->len, b2b_key->s, etype, code);

	return b2b_api.send_reply(&reply_data);
}

static int b2b_sdp_client_sync(struct b2b_sdp_client *client, str *body)
{
	static str lline = str_init("a=label:");
	str cline, mline, nline, eline;
	str *label;
	int ret = -1;
	sdp_info_t sdp;
	memset(&sdp, 0, sizeof sdp);
	struct b2b_sdp_stream *bstream;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;
	int synced_streams = 0;
	str bstream_body;

	if (parse_sdp_session(body, 0, NULL, &sdp) < 0) {
		LM_ERR("could not parse SDP\n");
		return -3;
	}
	for (session = sdp.sessions; session; session = session->next) {
		for (stream = session->streams; stream; stream = stream->next) {
			/* for each stream, we have a new client */
			bstream = b2b_sdp_get_stream_client_idx(client, stream->stream_num);
			if (!bstream) {
				LM_ERR("could not find stream %d\n", stream->stream_num);
				continue;
			}
			nline.s = NULL;
			if (bstream->label.len) {
				label = b2b_sdp_label_from_sdp(stream);
				if (!label) {
					/* if there was no label, we need to add it */
					nline.s = stream->body.s;
					while (nline.s > session->body.s &&
							(*(nline.s - 1) == '\r' || *(nline.s - 1) == '\n'))
						nline.s--;
					nline.len = stream->body.s - nline.s;
				}
			}
			/* create a body that contains all streams's information,
			 * including session c= line if missing in stream */
			if (!stream->ip_addr.len) {
				/* we need to take the connection line from the session */
				for (cline.s = session->ip_addr.s; cline.s > session->body.s; cline.s--)
					if (*cline.s == 'c' && *(cline.s+1) == '=')
						break;
				/* eat the previous new lines as well */
				while (cline.s > session->body.s &&
						(*(cline.s - 1) == '\r' || *(cline.s - 1) == '\n'))
					cline.s--;
				if (cline.s == session->body.s) {
					LM_ERR("could not find connection string in SDP!\n");
					goto end;
				}
				cline.len = (session->ip_addr.s + session->ip_addr.len) - cline.s;
				/* add new lines as well */
				bstream_body.s = pkg_malloc(stream->body.len + cline.len +
						(nline.s?(lline.len + bstream->label.len + nline.len):0));
				if (!bstream_body.s)
					goto end;
				/* now copy the first m= line of the stream */
				mline.s = stream->body.s;
				mline.len = stream->transport.s + stream->transport.len - stream->body.s;
				while (mline.len < stream->body.len && mline.s[mline.len] != '\r' &&
						mline.s[mline.len] != '\n')
					mline.len++;
				memcpy(bstream_body.s, stream->body.s, mline.len);
				memcpy(bstream_body.s + mline.len, cline.s, cline.len);
				/* rest of the stream */
				memcpy(bstream_body.s + mline.len + cline.len,
						mline.s + mline.len, stream->body.len - mline.len);
				bstream_body.len = stream->body.len + cline.len;
			} else {
				/* sync the entire stream just as it is */
				bstream_body.s = pkg_malloc(stream->body.len +
						(nline.s?(lline.len + bstream->label.len + nline.len):0));
				if (!bstream_body.s)
					goto end;
				memcpy(bstream_body.s, stream->body.s, stream->body.len);
				bstream_body.len = stream->body.len;
			}
			/* only add label if it was initially there */
			if (nline.s) {
				/* copy terminator from end of stream to make space for label */
				eline.s = stream->body.s + stream->body.len;
				eline.len = 0;
				while (eline.s > stream->body.s &&
						(*(eline.s - 1) == '\r' || *(eline.s - 1) == '\n')) {
					eline.s--;
					eline.len++;
					bstream_body.s[bstream_body.len + nline.len +
						lline.len + bstream->label.len - eline.len] = *eline.s;
				}
				bstream_body.len -= eline.len;

				memcpy(bstream_body.s + bstream_body.len, nline.s, nline.len);
				bstream_body.len += nline.len;
				memcpy(bstream_body.s + bstream_body.len, lline.s, lline.len);
				bstream_body.len += lline.len;
				memcpy(bstream_body.s + bstream_body.len, bstream->label.s, bstream->label.len);
				bstream_body.len += bstream->label.len;
				bstream_body.len += eline.len;
			}
			if (bstream->body.len && bstream->body.s &&
					str_match(&bstream->body, &bstream_body)) {
				LM_DBG("identical body - not updating!\n");
				pkg_free(bstream_body.s);
			} else {
				LM_DBG("updating stream with new body!\n");
				if (shm_str_sync(&bstream->body, &bstream_body) < 0) {
					pkg_free(bstream_body.s);
					LM_ERR("cannot sync stream body\n");
					goto end;
				}
				pkg_free(bstream_body.s);
				synced_streams++;
			}
		}
	}
	ret = synced_streams;
end:
	free_sdp_content(&sdp);
	return ret;
}

static int b2b_sdp_ack(int type, str *key, b2b_dlginfo_t *dlginfo)
{
	char *etype = (type==B2B_CLIENT?"client":"server");
	str ack = str_init(ACK);
	struct b2b_req_data req;
	memset(&req, 0, sizeof(req));
	req.et = type;
	req.b2b_key = key;
	req.method = &ack;
	req.dlginfo = dlginfo;
	req.no_cb = 1; /* do not call callback */

	LM_INFO("[%.*s] %s request ACK sent\n", key->len, key->s, etype);

	return b2b_api.send_request(&req);
}

static int b2b_sdp_client_reply_invite(struct sip_msg *msg, struct b2b_sdp_client *client)
{
	str *body = NULL;
	int ret = -1;
	struct b2b_sdp_ctx *ctx;

	/* only ACK if not fake reply, or not a dummy message as
	 * built in the dlg.c tm callback */
	if (msg != FAKED_REPLY && msg->REPLY_STATUS < 300) {
		if (b2b_sdp_ack(B2B_CLIENT, &client->b2b_key, client->dlginfo) < 0)
			LM_ERR("[%.*s] Cannot ack session for key %.*s\n",
					client->ctx->callid.len, client->ctx->callid.s,
					client->b2b_key.len, client->b2b_key.s);
	}

	ctx = client->ctx;
	lock_get(&ctx->lock);

	if (ctx->pending_no <= 0) {
		LM_ERR("not expecting any replies!\n");
		goto release;
	}
	/* we have a final reply for this client */
	ctx->pending_no--;
	client->flags &= ~(B2B_SDP_CLIENT_EARLY|B2B_SDP_CLIENT_PENDING);

	if (msg != FAKED_REPLY && msg->REPLY_STATUS < 300) {
		body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
		if (body && b2b_sdp_client_sync(client, body) >= 0) {
			ctx->success_no++;
			client->flags |= B2B_SDP_CLIENT_STARTED;
		} else {
			LM_ERR("no body for client!\n");
		}
	} else {
		if (!(client->flags & B2B_SDP_CLIENT_STARTED)) {
			/* client was not started, thus this is a final negative reply */
			b2b_sdp_client_release_streams(client);
			b2b_sdp_client_release(client, 0);
			b2b_api.entity_delete(B2B_CLIENT, &client->b2b_key, client->dlginfo, 1, 1);
		}
	}
	body = NULL;

	if (ctx->pending_no == 0) {
		/* if there was no successful stream, deny the call */
		if (ctx->success_no == 0) {
			ret = -2;
			goto release;
		}
		/* we've actually completed all the upstream clients
		 * therefore we need to respond to the server */
		body = b2b_sdp_mux_body(ctx);
		if (!body)
			LM_CRIT("could not build to B2B server body!\n");
		ctx->flags |= B2B_SDP_CTX_STARTED;
	}

release:
	lock_release(&ctx->lock);
	/* avoid sending reply under lock */
	if (body) {
		/* we are done - answer the call */
		if (b2b_sdp_reply(&ctx->b2b_key, ctx->dlginfo, B2B_SERVER, METHOD_INVITE, 200, body) < 0)
			LM_CRIT("could not answer B2B call!\n");
		pkg_free(body->s);
	} else if (ret == -2) {
		b2b_sdp_reply(&ctx->b2b_key, ctx->dlginfo, B2B_SERVER, METHOD_INVITE, 503, NULL);
	}
	if (ret < 0 && ctx->clients_no == 0) {
		/* no more remaining clients - terminate the entity as well */
		b2b_sdp_ctx_release(ctx, 1);
	}
	return ret;
}

int b2b_sdp_client_dlginfo(str *logic_key, str *key, int src, b2b_dlginfo_t *info, void *param)
{
	struct b2b_sdp_client *client = (struct b2b_sdp_client *)param;

	client->dlginfo = b2b_dup_dlginfo(info);
	if (!client->dlginfo) {
		LM_ERR("could not duplicate b2be dialog info!\n");
		return -1;
	}

	return 0;
}

static b2b_dlginfo_t *b2b_sdp_server_dlginfo(struct sip_msg *msg, str * b2b_key)
{
	b2b_dlginfo_t *info = b2b_fill_dlginfo(msg, b2b_key);
	if (!info)
		return NULL;

	return b2b_dup_dlginfo(info);
}

static int b2b_sdp_client_notify(struct sip_msg *msg, str *key, int type,
		str *logic_key, void *param, int flags)
{
	struct b2b_sdp_client *client = (struct b2b_sdp_client *)param;

	if (!client || !client->ctx) {
		LM_ERR("No b2b sdp client!\n");
		return -1;
	}

	if (type == B2B_REQUEST) {
		lock_get(&client->ctx->lock);
		if (msg->REQ_METHOD != METHOD_BYE)
			B2B_SDP_CLIENT_WAIT_FREE(client->ctx);
		/*
		if (client->ctx->pending_no) {
			lock_release(&client->ctx->lock);
			LM_INFO("we still have pending clients - let them retransmit!\n");
			b2b_sdp_reply(&client->b2b_key, B2B_CLIENT, msg->REQ_METHOD, 491, NULL);
			return 0;
		}
		*/
		lock_release(&client->ctx->lock);
		LM_INFO("[%.*s][%.*s] %.*s client request received\n",
				client->ctx->callid.len, client->ctx->callid.s, key->len, key->s,
				msg->REQ_METHOD_S.len, msg->REQ_METHOD_S.s);

		switch (msg->REQ_METHOD) {
			case METHOD_ACK:
				return 0;
			case METHOD_INVITE:
				return b2b_sdp_client_reinvite(msg, client);
			case METHOD_BYE:
				return b2b_sdp_client_bye(msg, client);
		}
		LM_INFO("[%.*s][%.*s] client request message %.*s not handled\n",
				client->ctx->callid.len, client->ctx->callid.s, key->len, key->s,
				msg->REQ_METHOD_S.len, msg->REQ_METHOD_S.s);
		LM_ERR("request message %.*s not handled\n", msg->REQ_METHOD_S.len,
				msg->REQ_METHOD_S.s);
	} else {
		/* not interested in provisional replies */
		if (msg->REPLY_STATUS < 200)
			return 0;

		if (!msg->cseq && ((parse_headers(msg, HDR_CSEQ_F, 0) == -1) || !msg->cseq)) {
			LM_ERR("failed to parse CSeq\n");
			return -1;
		}
		LM_INFO("[%.*s][%.*s] client reply %d received for %.*s\n",
				client->ctx->callid.len, client->ctx->callid.s, key->len, key->s,
				msg->REPLY_STATUS, get_cseq(msg)->method.len, get_cseq(msg)->method.s);

		switch (get_cseq(msg)->method_id) {
			case METHOD_INVITE:
				return b2b_sdp_client_reply_invite(msg, client);
		}
		LM_ERR("[%.*s][%.*s] client reply message %d for %.*s not handled\n",
				client->ctx->callid.len, client->ctx->callid.s, key->len, key->s,
				msg->REPLY_STATUS, get_cseq(msg)->method.len, get_cseq(msg)->method.s);
	}
	return -1;
}

static int b2b_sdp_demux_body(struct b2b_sdp_client *client,
		sdp_info_t *sdp)
{
	int len;
	char *p;
	str session_str;
	str body;
	static str media = str_init("m=");
	struct list_head *it;
	struct b2b_sdp_stream *stream;
	sdp_stream_cell_t *sstream;
	sdp_session_cell_t *session = b2b_sdp_get_session(sdp,
			list_last_entry(&client->streams, struct b2b_sdp_stream, list)->index);
	if (!session) {
		LM_ERR("could not locate session\n");
		return -1;
	}
	session_str = session->body;
	do {
		p = str_strstr(&session_str, &media);
		if (!p || (p - session_str.s < 1)) {
			LM_ERR("could not locate first media stream in session\n");
			return -1;
		}
		if (*(p - 1) == '\r' || *(p - 1) == '\n')
			break;
		session_str.len -= p - session_str.s - 1;
		session_str.s = p + 1;
	} while (session_str.len > 0);
	session_str.s = session->body.s;
	session_str.len = p - session->body.s;
	len = session_str.len;
	list_for_each(it, &client->streams) {
		stream = list_entry(it, struct b2b_sdp_stream, list);
		sstream = b2b_sdp_get_stream(sdp, stream->index);
		len += sstream->body.len;
	}

	body.s = pkg_malloc(len);
	if (!body.s) {
		LM_ERR("oom in pkg for body!\n");
		return -1;
	}
	memcpy(body.s, session_str.s, session_str.len);
	body.len = len;
	len = session_str.len;
	list_for_each(it, &client->streams) {
		stream = list_entry(it, struct b2b_sdp_stream, list);
		sstream = b2b_sdp_get_stream(sdp, stream->index);
		memcpy(body.s + len, sstream->body.s, sstream->body.len);
		len += sstream->body.len;
	}
	len = shm_str_sync(&client->body, &body);
	pkg_free(body.s);
	return len;
}

static int b2b_sdp_server_reply_invite(struct sip_msg *msg, struct b2b_sdp_ctx *ctx)
{
	int code;
	str *body = NULL;
	sdp_info_t sdp;
	struct list_head *it;
	struct b2b_sdp_client *client = NULL;

	/* re-INVITE failed - reply the same code to the client
	 * that started the challenging */
	if (msg != FAKED_REPLY && msg->REPLY_STATUS < 300)
		if (b2b_sdp_ack(B2B_SERVER, &ctx->b2b_key, ctx->dlginfo) < 0)
			LM_ERR("Cannot ack recording session for server key %.*s\n",
					ctx->b2b_key.len, ctx->b2b_key.s);

	list_for_each(it, &ctx->clients) {
		client = list_entry(it, struct b2b_sdp_client, list);
		if (client->flags & B2B_SDP_CLIENT_PENDING) {
			client->flags &= ~B2B_SDP_CLIENT_PENDING;
			break;
		} else {
			client = NULL;
		}
	}
	if (!client) {
		ctx->pending_no = 0;
		lock_release(&ctx->lock);
		LM_DBG("cannot identify a pending client!\n");
		return -1;
	}
	if (msg->REPLY_STATUS < 300) {
		body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
		if (body) {
			memset(&sdp, 0, sizeof sdp);
			if (parse_sdp_session(body, 0, NULL, &sdp) < 0) {
				LM_ERR("cannot parse SDP body\n");
				code = 606;
				body = NULL;
			} else {
				if (b2b_sdp_demux_body(client, &sdp) < 0) {
					LM_ERR("cannot get body for client!\n");
					free_sdp_content(&sdp);
				}
				body = &client->body;
				code = msg->REPLY_STATUS;
			}
		} else {
			LM_ERR("message without SDP body\n");
			code = 606;
		}
	} else {
		code = msg->REPLY_STATUS;
	}
	lock_release(&client->ctx->lock);
	b2b_sdp_reply(&client->b2b_key, client->dlginfo, B2B_CLIENT, METHOD_INVITE, code, body);
	if (body)
		free_sdp_content(&sdp);
	lock_get(&client->ctx->lock);
	ctx->pending_no = 0;
	lock_release(&client->ctx->lock);
	return 0;
}

static int b2b_sdp_server_reply_bye(struct sip_msg *msg, struct b2b_sdp_ctx *ctx)
{
	b2b_sdp_ctx_release(ctx, 1);
	return 0;
}

static int b2b_sdp_server_bye(struct sip_msg *msg, struct b2b_sdp_ctx *ctx)
{
	b2b_sdp_reply(&ctx->b2b_key, ctx->dlginfo, B2B_SERVER,
			msg->REQ_METHOD, 200, NULL);
	b2b_sdp_ctx_release(ctx, 1);
	return 0;
}

static int b2b_sdp_server_invite(struct sip_msg *msg, struct b2b_sdp_ctx *ctx)
{
	str method = str_init(INVITE);
	sdp_info_t sdp;
	struct list_head *it;
	str *body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	struct b2b_sdp_client *client;
	b2b_req_data_t req_data;

	if (!body) {
		LM_WARN("re-INVITE without a body - declining\n");
		goto error;
	}
	memset(&sdp, 0, sizeof sdp);
	if (parse_sdp_session(body, 0, NULL, &sdp) < 0) {
		LM_ERR("could not parse re-INVITE body\n");
		goto error;
	}

	lock_get(&ctx->lock);
	list_for_each(it, &ctx->clients) {
		client = list_entry(it, struct b2b_sdp_client, list);
		if (b2b_sdp_demux_body(client, &sdp) < 0) {
			LM_ERR("could not get new body for client!\n");
			continue;
		}
		ctx->pending_no++;
		client->flags |= B2B_SDP_CLIENT_PENDING;
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		req_data.et = B2B_CLIENT;
		req_data.b2b_key = &client->b2b_key;
		req_data.method = &method;
		req_data.dlginfo = client->dlginfo;
		req_data.body = &client->body;
		LM_INFO("[%.*s] client request INVITE sent\n", client->b2b_key.len, client->b2b_key.s);
		if (b2b_api.send_request(&req_data) < 0)
			LM_ERR("could not send re-INVITE to client!\n");
	}
	lock_release(&ctx->lock);
	free_sdp_content(&sdp);

	return 0;
error:
	b2b_sdp_reply(&ctx->b2b_key, ctx->dlginfo, B2B_SERVER,
			METHOD_INVITE, 606, NULL);
	return -1;
}

static int b2b_sdp_server_cancel(struct sip_msg *msg, struct b2b_sdp_ctx *ctx)
{
	/* respond to the initial INVITE */
	b2b_sdp_reply(&ctx->b2b_key, ctx->dlginfo, B2B_SERVER,
			METHOD_INVITE, 487, NULL);
	b2b_sdp_ctx_release(ctx, 0);
	return 0;
}

static int b2b_sdp_server_notify(struct sip_msg *msg, str *key, int type,
		str *logic_key, void *param, int flags)
{
	struct b2b_sdp_ctx *ctx = (struct b2b_sdp_ctx *)param;
	if (!ctx) {
		LM_ERR("No b2b sdp context!\n");
		return -1;
	}
	if (type == B2B_REQUEST) {
		LM_INFO("[%.*s][%.*s] %.*s server request received\n",
				ctx->callid.len, ctx->callid.s, key->len, key->s,
				msg->REQ_METHOD_S.len, msg->REQ_METHOD_S.s);
		lock_get(&ctx->lock);
		if (msg->REQ_METHOD == METHOD_CANCEL) {
			if (ctx->flags & B2B_SDP_CTX_CANCELLED) {
				LM_DBG("[%.*s][%.*s] already canceled\n",
						ctx->callid.len, ctx->callid.s, key->len, key->s);
				lock_release(&ctx->lock);
				return 0;
			}
			ctx->flags |= B2B_SDP_CTX_CANCELLED;
		} else if (ctx->pending_no) {
			lock_release(&ctx->lock);
			LM_INFO("we still have pending clients!\n");
			b2b_sdp_reply(&ctx->b2b_key, ctx->dlginfo, B2B_SERVER,
					msg->REQ_METHOD, 491, NULL);
			return -1;
		}
		lock_release(&ctx->lock);
		switch (msg->REQ_METHOD) {
			case METHOD_ACK:
				return 0;
			case METHOD_INVITE:
				return b2b_sdp_server_invite(msg, ctx);
			case METHOD_BYE:
				return b2b_sdp_server_bye(msg, ctx);
			case METHOD_CANCEL:
				return b2b_sdp_server_cancel(msg, ctx);
		}
		LM_ERR("[%.*s][%.*s] server request message %.*s not handled\n",
				ctx->callid.len, ctx->callid.s, key->len, key->s,
				msg->REQ_METHOD_S.len, msg->REQ_METHOD_S.s);
	} else {
		/* not interested in provisional replies */
		if (msg->REPLY_STATUS < 200)
			return 0;

		if (!msg->cseq && ((parse_headers(msg, HDR_CSEQ_F, 0) == -1) || !msg->cseq)) {
			LM_ERR("failed to parse CSeq\n");
			return -1;
		}
		LM_INFO("[%.*s][%.*s] server reply %d received for %.*s\n",
				ctx->callid.len, ctx->callid.s, key->len, key->s,
				msg->REPLY_STATUS, get_cseq(msg)->method.len, get_cseq(msg)->method.s);

		switch (get_cseq(msg)->method_id) {
			case METHOD_INVITE:
				return b2b_sdp_server_reply_invite(msg, ctx);
			case METHOD_BYE:
				return b2b_sdp_server_reply_bye(msg, ctx);
		}
		LM_ERR("[%.*s][%.*s] server reply message %d for %.*s not handled\n",
				ctx->callid.len, ctx->callid.s, key->len, key->s, msg->REPLY_STATUS,
				get_cseq(msg)->method.len, get_cseq(msg)->method.s);
	}
	return -1;
}

static int b2b_sdp_demux_start(struct sip_msg *msg, str *uri,
		struct b2b_sdp_ctx *ctx, sdp_info_t *sdp)
{
	str *b2b_key;
	str contact;
	union sockaddr_union tmp_su;
	struct list_head *it;
	struct b2b_sdp_client *client;
	client_info_t ci;
	struct socket_info *si;
	str *sess_ip;

	if (!msg->force_send_socket) {
		si = uri2sock(msg, uri, &tmp_su, PROTO_NONE);
		if (!si) {
			LM_ERR("could not find an available send socket!\n");
			return -1;
		}
	} else {
		si = msg->force_send_socket;
	}

	contact.s = contact_builder(msg->rcv.bind_address, &contact.len);
	sess_ip = get_adv_host(msg->rcv.bind_address);
	if (shm_str_dup(&ctx->sess_ip, sess_ip) < 0) {
		LM_ERR("could not fetch session IP\n");
		return -1;
	}
	/* we will use the callid as the ideantifier */

	b2b_key = b2b_api.server_new(msg, &contact, b2b_sdp_server_notify,
			&b2b_sdp_demux_server_cap, &msg->callid->body, NULL,
			ctx, b2b_sdp_ctx_free);
	if (!b2b_key) {
		LM_ERR("could not create b2b sdp demux server!\n");
		return -1;
	}
	if (shm_str_dup(&ctx->b2b_key, b2b_key) < 0) {
		LM_ERR("could not copy b2b server key\n");
		/* key is not yet stored, so cannot be deleted */
		b2b_api.entity_delete(B2B_SERVER, b2b_key, NULL, 1, 1);
		return -1;
	}
	ctx->dlginfo = b2b_sdp_server_dlginfo(msg, b2b_key);
	/* we need to wait for all pending clients */
	ctx->pending_no = ctx->clients_no;

	contact.s = contact_builder(si, &contact.len);
	memset(&ci, 0, sizeof ci);
	ci.send_sock = si;
	ci.local_contact = contact;
	ci.method.s = INVITE;
	ci.method.len = INVITE_LEN;
	/* try the first srs_uri */
	ci.req_uri = *uri;
	ci.to_uri = ci.req_uri;
	ci.from_uri = ci.to_uri;

	list_for_each(it, &ctx->clients) {
		client = list_entry(it, struct b2b_sdp_client, list);
		if (b2b_sdp_demux_body(client, sdp) < 0) {
			LM_ERR("could not get body for client!\n");
			return -1;
		}
		/* per client stuff */
		ci.body = &client->body;
		ci.extra_headers = &client->hdrs;
		ci.avps = clone_avp_list( *get_avp_list() );

		client->flags |= B2B_SDP_CLIENT_EARLY|B2B_SDP_CLIENT_PENDING;
		b2b_key = b2b_api.client_new(&ci, b2b_sdp_client_notify, b2b_sdp_client_dlginfo,
				&b2b_sdp_demux_client_cap, &ctx->callid, NULL,
				client, b2b_sdp_client_free);
		if (!b2b_key) {
			destroy_avp_list(&ci.avps);
			LM_ERR("could not create b2b sdp demux client!\n");
			return -1;
		}
		if (shm_str_dup(&client->b2b_key, b2b_key) < 0) {
			LM_ERR("could not copy b2b client key\n");
			/* key is not yet stored, but INVITE sent - terminate it */
			b2b_sdp_client_terminate(client, b2b_key);
			pkg_free(b2b_key);
			return -1;
		}
		pkg_free(b2b_key);
	}

	return 0;
}

static int b2b_sdp_demux(struct sip_msg *msg, str *uri,
		pv_spec_t *hdrs, pv_spec_t *streams)
{
	int ret;
	str *body;
	sdp_info_t sdp;
	struct b2b_sdp_ctx *ctx;

	if (msg->REQ_METHOD != METHOD_INVITE || get_to(msg)->tag_value.len) {
		LM_ERR("SDP demux can only be done on initial INVITEs\n");
		return -2;
	}

	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!body) {
		LM_ERR("message without SDP!\n");
		return -3;
	}

	if ((parse_headers(msg, HDR_CALLID_F, 0) < -1 ||
			msg->callid == NULL)) {
		LM_ERR("could not extract Call-ID!\n");
		return -1;
	}

	ctx = b2b_sdp_ctx_new(&msg->callid->body);
	if (!ctx) {
		LM_ERR("could not allocate new B2B SDP ctx\n");
		return -1;
	}

	memset(&sdp, 0, sizeof sdp);
	if (parse_sdp_session(body, 0, NULL, &sdp) < 0) {
		LM_ERR("could not parse SDP\n");
		return -3;
	}
	if (sdp.sessions_num != 1) {
		LM_ERR("multiple sessions not supported\n");
		goto error;
	}

	if (!streams) {
		ret = b2b_sdp_streams_from_sdp(ctx, &sdp);
	} else {
		ret = b2b_sdp_streams_from_avps(ctx, streams, &sdp);
	}
	if (ret < 0) {
		LM_ERR("could not create all clients and streams\n");
		goto error;
	}
	if (hdrs) {
		if (b2b_sdp_hdrs_from_avps(ctx, hdrs) < 0) {
			LM_ERR("could assign headers to clients\n");
			goto error;
		}
	}

	if (b2b_sdp_demux_start(msg, uri, ctx, &sdp) < 0) {
		LM_ERR("could not start B2B SDP demux\n");
		goto error;
	}
	LM_DBG("B2B SDP successfully engaged!\n");
	free_sdp_content(&sdp);
	return 0;
error:
	free_sdp_content(&sdp);
	b2b_sdp_ctx_release(ctx, 1);
	return -1;
}

static void bin_push_stream(bin_packet_t *store, struct b2b_sdp_stream *stream)
{
	bin_push_int(store, stream->index);
	bin_push_int(store, stream->client_index);
	bin_push_str(store, &stream->disabled_body);
	bin_push_int(store, stream->label.len);
	if (stream->label.len) /* only push label offset */
		bin_push_int(store, stream->label.s - stream->disabled_body.s);
	bin_push_str(store, &stream->body);
}

static struct b2b_sdp_stream *bin_pop_stream(bin_packet_t *store, struct b2b_sdp_client *client)
{
	str tmp;
	int index, client_index, offset;
	struct b2b_sdp_stream *stream;
	bin_pop_int(store, &index);
	bin_pop_int(store, &client_index);
	bin_pop_str(store, &tmp);
	stream = b2b_sdp_stream_raw_new(client, &tmp, index, client_index);
	if (!stream) {
		LM_ERR("could not allocate new stream!\n");
		return NULL;
	}
	bin_pop_int(store, &stream->label.len);
	if (stream->label.len) {
		bin_pop_int(store, &offset);
		stream->label.s = stream->disabled_body.s + offset;
	}
	bin_pop_str(store, &tmp);
	if (tmp.len && shm_str_sync(&stream->body, &tmp) < 0) {
		LM_ERR("could not duplicate b2b stream body!\n");
		shm_free(stream);
		return NULL;
	}
	return stream;
}

static void b2b_sdp_server_event_trigger_create(struct b2b_sdp_ctx *ctx, bin_packet_t *store)
{
	struct list_head *c, *s;
	struct b2b_sdp_client *client;
	struct b2b_sdp_stream *stream;
	int pushed_streams = 0;

	bin_push_str(store, &ctx->callid);
	bin_push_int(store, ctx->clients_no);
	bin_push_int(store, ctx->sess_id);
	bin_push_str(store, &ctx->sess_ip);

	list_for_each(c, &ctx->clients) {
		client = list_entry(c, struct b2b_sdp_client, list);
		bin_push_int(store, client->flags);
		bin_push_str(store, &client->b2b_key);
		bin_push_str(store, &client->hdrs);
		bin_push_str(store, &client->body);
		bin_push_int(store, list_size(&client->streams));
		list_for_each(s, &client->streams) {
			stream = list_entry(s, struct b2b_sdp_stream, list);
			bin_push_stream(store, stream);
			pushed_streams++;
		}
	}
	/* now handle disabled streams - skip already pushed ones */
	bin_push_int(store, list_size(&ctx->streams) - pushed_streams);
	list_for_each(s, &ctx->streams) {
		stream = list_entry(s, struct b2b_sdp_stream, list);
		if (!stream->client)
			bin_push_stream(store, stream);
	}
}

static int b2b_sdp_ctx_restore(struct b2b_sdp_ctx *ctx)
{
	if (b2b_api.update_b2bl_param(B2B_SERVER, &ctx->b2b_key, &ctx->callid, 0) < 0) {
		LM_ERR("could not update restore param!\n");
		return -1;
	}
	if (b2b_api.restore_logic_info(B2B_SERVER, &ctx->b2b_key,
			b2b_sdp_server_notify, ctx, NULL) < 0) {
		LM_ERR("could not register restore logic!\n");
		return -1;
	}

	return 0;
}

static int b2b_sdp_client_restore(struct b2b_sdp_client *client)
{
	if ((client->flags & B2B_SDP_CLIENT_REPL) == 0)
		return 0;

	if (b2b_api.update_b2bl_param(B2B_CLIENT, &client->b2b_key,
			&client->ctx->callid, 0) < 0) {
		LM_ERR("could not update restore param!\n");
		return -1;
	}
	if (b2b_api.restore_logic_info(B2B_CLIENT, &client->b2b_key,
			b2b_sdp_client_notify, client, NULL) < 0) {
		LM_ERR("could not register restore logic!\n");
		return -1;
	}
	client->flags &= ~B2B_SDP_CLIENT_REPL;

	return 0;
}

static void b2b_sdp_server_event_received_create(str *key, bin_packet_t *store)
{
	str tmp;
	int clients, streams;
	time_t sess_id;
	struct b2b_sdp_ctx *ctx;
	struct b2b_sdp_client *client;
	struct b2b_sdp_stream *stream;

	bin_pop_str(store, &tmp);
	bin_pop_int(store, &clients);
	bin_pop_int(store, &sess_id);

	ctx = b2b_sdp_ctx_new(&tmp);
	if (!ctx) {
		LM_INFO("cannot create new context!\n");
		return;
	}
	/* only started dialogs end up here */
	ctx->flags |= B2B_SDP_CTX_STARTED;
	bin_pop_str(store, &tmp);
	if (shm_str_sync(&ctx->sess_ip, &tmp) < 0) {
		LM_ERR("could not duplicate session ip!\n");
		goto error;
	}
	if (shm_str_sync(&ctx->b2b_key, key) < 0) {
		LM_ERR("could not duplicate b2b key!\n");
		goto error;
	}
	if (b2b_sdp_ctx_restore(ctx) < 0) {
		LM_ERR("could not restore b2b ctx logic!\n");
		goto error;
	}
	ctx->sess_id = sess_id;

	while (clients-- > 0) {
		client = b2b_sdp_client_new(ctx);
		if (!client) {
			LM_ERR("cannot create new client\n");
			goto error;
		}
		bin_pop_int(store, &client->flags);
		bin_pop_str(store, &tmp);
		if (shm_str_sync(&client->b2b_key, &tmp) < 0) {
			LM_ERR("could not duplicate b2b client key!\n");
			goto error;
		}
		client->flags |= B2B_SDP_CLIENT_REPL;

		/* check if the key exists */
		if (b2b_api.entity_exists(B2B_CLIENT, &client->b2b_key) &&
				b2b_sdp_client_restore(client) < 0) {
			LM_ERR("could not restore b2b client logic!\n");
			goto error;
		}

		bin_pop_str(store, &tmp);
		if (tmp.len && shm_str_sync(&client->hdrs, &tmp) < 0) {
			LM_ERR("could not duplicate b2b client headers!\n");
			goto error;
		}
		bin_pop_str(store, &tmp);
		if (tmp.len && shm_str_sync(&client->body, &tmp) < 0) {
			LM_ERR("could not duplicate b2b client body!\n");
			goto error;
		}
		bin_pop_int(store, &streams);
		while (streams-- > 0) {
			stream = bin_pop_stream(store, client);
			if (!stream)
				goto error;
			b2b_add_stream_ctx(ctx, stream);
		}
	}

	/* also handle disabled streams */
	bin_pop_int(store, &streams);
	while (streams-- > 0) {
		stream = bin_pop_stream(store, NULL);
		if (!stream)
			goto error;
		b2b_add_stream_ctx(ctx, stream);
	}
	return;
error:
	b2b_sdp_ctx_release(ctx, 0);
}

static void b2b_sdp_server_event_received_delete(struct b2b_sdp_ctx *ctx, bin_packet_t *store)
{
	b2b_sdp_ctx_release(ctx, 0);
}

static void b2b_sdp_server_event_trigger(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend)
{
	struct b2b_sdp_ctx *ctx = (struct b2b_sdp_ctx *)param;

	switch (event_type) {
		case B2B_EVENT_ACK:
			/*
			 * for DB backend, the entity is stored during ACK,
			 * but for clusterer, during CREATE, thus we don't need to store
			 * it one more type on the ACK
			 */
			if (backend & B2BCB_BACKEND_CLUSTER)
				return;
		case B2B_EVENT_CREATE:
			b2b_sdp_server_event_trigger_create(ctx, store);
			break;
		default:
			/* nothing else for now */
			break;
	}
}

static void b2b_sdp_server_event_received(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend)
{
	struct b2b_sdp_ctx *ctx = param;

	if (!store)
		return;

	switch (event_type) {
		case B2B_EVENT_CREATE:
			b2b_sdp_server_event_received_create(key, store);
			break;
		case B2B_EVENT_DELETE:
			b2b_sdp_server_event_received_delete(ctx, store);
			break;
		default:
			/* nothing else for now */
			break;
	}
}

static void b2b_sdp_client_event_trigger_create(struct b2b_sdp_client *client,
		bin_packet_t *store)
{
	bin_push_str(store, &client->ctx->b2b_key);
}

static void b2b_sdp_client_event_trigger_update(struct b2b_sdp_client *client,
		bin_packet_t *store)
{
	struct list_head *s;
	struct b2b_sdp_stream *stream;

	bin_push_int(store, client->flags);
	bin_push_str(store, &client->body);
	bin_push_int(store, list_size(&client->streams));
	list_for_each(s, &client->streams) {
		stream = list_entry(s, struct b2b_sdp_stream, list);
		bin_push_int(store, stream->index);
		bin_push_str(store, &stream->body);
	}
}

static void b2b_sdp_client_event_receive_update(struct b2b_sdp_client *client,
		bin_packet_t *store)
{
	str tmp;
	int streams, index;
	struct b2b_sdp_stream *stream;

	lock_get(&client->ctx->lock);
	bin_pop_int(store, &client->flags);
	bin_pop_str(store, &tmp);
	if (shm_str_sync(&client->body, &tmp) < 0) {
		LM_ERR("could not duplicate body for client!\n");
		goto end;
	}
	bin_pop_int(store, &streams);
	while (streams-- > 0) {
		bin_pop_int(store, &index);
		stream = b2b_sdp_get_stream_client_idx(client, index);
		if (!stream) {
			LM_ERR("could not find stream index %d\n", index);
			continue;
		}
		bin_pop_str(store, &tmp);
		if (shm_str_sync(&stream->body, &tmp) < 0) {
			LM_ERR("could not duplicate body for stream %d!\n", index);
			continue;
		}
	}
end:
	lock_release(&client->ctx->lock);
}

static void b2b_sdp_client_event_receive_create(str *key, bin_packet_t *store)
{
	str ctx_key;
	struct b2b_sdp_ctx *ctx;
	struct b2b_sdp_client *client;

	/* in the packet, we have the server's key */
	bin_pop_str(store, &ctx_key);
	ctx = b2b_sdp_ctx_get(&ctx_key);
	if (!ctx) {
		LM_DBG("no ctx available for %.*s\n", ctx_key.len, ctx_key.s);
		return;
	}
	client = b2b_sdp_client_get(ctx, key);
	if (!client) {
		LM_DBG("no client %.*s available for ctx %.*s\n", key->len, key->s,
				ctx_key.len, ctx_key.s);
		return;
	}

	if (b2b_sdp_client_restore(client) < 0)
		LM_ERR("could not restore b2b client logic!\n");
	lock_release(&ctx->lock);
}

static void b2b_sdp_client_event_receive_delete(struct b2b_sdp_client *client,
		bin_packet_t *store)
{
	b2b_sdp_client_release(client, 1);
	b2b_sdp_client_remove(client);
}

static void b2b_sdp_client_event_trigger(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend)
{
	struct b2b_sdp_client *client = (struct b2b_sdp_client *)param;

	switch (event_type) {
		case B2B_EVENT_CREATE:
			b2b_sdp_client_event_trigger_create(client, store);
			break;
		case B2B_EVENT_UPDATE:
			b2b_sdp_client_event_trigger_update(client, store);
			break;
		case B2B_EVENT_DELETE:
			/* nothing to do, as all we need is the b2b key */
			break;
		default:
			/* nothing else for now */
			break;
	}
}

static void b2b_sdp_client_event_received(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend)
{
	struct b2b_sdp_client *client = param;
	if (!store)
		return;

	switch (event_type) {
		case B2B_EVENT_CREATE:
			b2b_sdp_client_event_receive_create(key, store);
			break;
		case B2B_EVENT_UPDATE:
			b2b_sdp_client_event_receive_update(client, store);
			break;
		case B2B_EVENT_DELETE:
			b2b_sdp_client_event_receive_delete(client, store);
			break;
		default:
			/* nothing else for now */
			break;
	}
}
