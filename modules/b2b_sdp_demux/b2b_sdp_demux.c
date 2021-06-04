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

static dep_export_t mod_deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
	},
};

static b2b_api_t b2b_api;
static str b2b_sdp_demux_cap = str_init("b2b_sdp_demux");
static str content_type_sdp_hdr = str_init("Content-Type: application/sdp\r\n");

static int b2b_sdp_demux(struct sip_msg *msg, str *uri,
		pv_spec_t *hdrs, pv_spec_t *streams);
static int fixup_check_avp(void** param);

static cmd_export_t mod_cmds[] = {
	{"b2b_sdp_demux", (cmd_function)b2b_sdp_demux, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{0,0,0}}, REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/** Module init function */
static int mod_init(void)
{

	/* load b2b_entities api */
	if(load_b2b_api(&b2b_api)< 0)
	{
		LM_ERR("Failed to load b2b api\n");
		return -1;
	}
	return 0;
}


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
	0,                              /* exported parameters */
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
static int b2b_sdp_ack(int type, str *key);
static int b2b_sdp_reply(str *b2b_key, int type, int method, int code, str *body);
static int b2b_sdp_client_sync(struct b2b_sdp_client *client, str *body);

#define B2B_SDP_CLIENT_EARLY	(1<<0)
#define B2B_SDP_CLIENT_STARTED	(1<<1)
#define B2B_SDP_CLIENT_PENDING	(1<<2)

struct b2b_sdp_client {
	unsigned int flags;
	str hdrs;
	str body;
	str b2b_key;
	struct b2b_sdp_ctx *ctx;
	struct list_head streams;
	struct list_head list;
};

struct b2b_sdp_ctx {
	str b2b_key;
	int clients_no;
	int pending_no;
	int success_no;
	time_t sess_id;
	str *sess_ip;
	gen_lock_t lock;
	struct socket_info *si;
	struct list_head clients;
	struct list_head streams;
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
	if (!key) {
		key = &client->b2b_key;
		if (!key || key->len == 0)
			return;
	} else if (key->len == 0) {
		LM_WARN("cannot terminate non-started client\n");
		return;
	}
	lock_get(&client->ctx->lock);
	send_cancel = (client->flags & B2B_SDP_CLIENT_EARLY);
	if (!send_cancel && !(client->flags & B2B_SDP_CLIENT_STARTED)) {
		lock_release(&client->ctx->lock);
		return;
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
	req_data.method = &method;
	b2b_api.send_request(&req_data);
	b2b_api.entity_delete(B2B_CLIENT, key, NULL, 1, 1);
}


static void b2b_sdp_client_release(struct b2b_sdp_client *client)
{
	struct list_head *it, *safe;
	if (client->hdrs.s)
		shm_free(client->hdrs.s);

	if (client->b2b_key.s)
		shm_free(client->b2b_key.s);

	list_for_each_safe(it, safe, &client->streams)
		b2b_sdp_stream_free(list_entry(it, struct b2b_sdp_stream, list));
	lock_get(&client->ctx->lock);
	list_del(&client->list);
	client->ctx->clients_no--;
	lock_release(&client->ctx->lock);
	shm_free(client);
}

static void b2b_sdp_client_free(struct b2b_sdp_client *client)
{

	b2b_sdp_client_terminate(client, NULL);
	b2b_sdp_client_release(client);

}

static struct b2b_sdp_ctx *b2b_sdp_ctx_new(void)
{
	struct b2b_sdp_ctx *ctx = shm_malloc(sizeof *ctx);
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof *ctx);
	INIT_LIST_HEAD(&ctx->clients);
	INIT_LIST_HEAD(&ctx->streams);
	lock_init(&ctx->lock);
	time(&ctx->sess_id);
	return ctx;
}

static void b2b_sdp_ctx_free(struct b2b_sdp_ctx *ctx)
{
	struct list_head *it, *safe;

	list_for_each_safe(it, safe, &ctx->clients)
		b2b_sdp_client_free(list_entry(it, struct b2b_sdp_client, list));
	/* free remaining streams */
	list_for_each_safe(it, safe, &ctx->streams)
		b2b_sdp_stream_free(list_entry(it, struct b2b_sdp_stream, list));
	if (ctx->b2b_key.s) {
		b2b_api.entity_delete(B2B_SERVER, &ctx->b2b_key, NULL, 1, 1);
		shm_free(ctx->b2b_key.s);
	}
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
			b2b_sdp_client_free(client);
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
		header2.len + ctx->sess_ip->len +
		header3.len + ctx->sess_ip->len + header4.len;
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
	memcpy(body.s + len, ctx->sess_ip->s, ctx->sess_ip->len);
	len += ctx->sess_ip->len;
	memcpy(body.s + len, header3.s, header3.len);
	len += header3.len;
	memcpy(body.s + len, ctx->sess_ip->s, ctx->sess_ip->len);
	len += ctx->sess_ip->len;
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

static int b2b_sdp_client_reinvite(struct sip_msg *msg, struct b2b_sdp_client *client)
{
	str *body;
	str method = str_init("INVITE");
	b2b_req_data_t req_data;
	int code = 0, ret = -1;

	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!body) {
		LM_INFO("cannot handle re-INVITE without body!\n");
		return -1;
	}
	lock_get(&client->ctx->lock);
	if (client->ctx->pending_no || client->flags & B2B_SDP_CLIENT_PENDING) {
		LM_INFO("we still have pending requests!\n");
		code = 491;
		goto end;
	}
	client->ctx->pending_no = 1;
	if (b2b_sdp_client_sync(client, body) < 0) {
		LM_INFO("cannot parse re-INVITE body!\n");
		goto end;
	}
	client->flags |= B2B_SDP_CLIENT_PENDING;
	body = b2b_sdp_mux_body(client->ctx);
	ret = 0;
end:
	lock_release(&client->ctx->lock);
	if (ret == 0) {
		if (body) {
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			req_data.et = B2B_SERVER;
			req_data.b2b_key = &client->ctx->b2b_key;
			req_data.method = &method;
			req_data.body = body;
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
		b2b_sdp_reply(&client->b2b_key, B2B_CLIENT, msg->REQ_METHOD, code, NULL);
	return ret;
}

static int b2b_sdp_client_bye(struct sip_msg *msg, struct b2b_sdp_client *client)
{
	str *body;
	str method = str_init("INVITE");
	b2b_req_data_t req_data;
	struct b2b_sdp_stream *stream;
	struct list_head *it, *safe;
	struct b2b_sdp_ctx *ctx = client->ctx;
	lock_get(&ctx->lock);
	/* terminate whatever the client was doing */
	client->flags &= ~(B2B_SDP_CLIENT_EARLY|B2B_SDP_CLIENT_STARTED);
	/* we need to move all the streams in the disabled list */
	list_for_each_safe(it, safe, &client->streams) {
		stream = list_entry(it, struct b2b_sdp_stream, list);
		list_del(&stream->list);
		stream->client = NULL;
	}
	lock_release(&ctx->lock);
	b2b_sdp_reply(&client->b2b_key, B2B_CLIENT, METHOD_BYE, 200, NULL);
	b2b_api.entity_delete(B2B_CLIENT, &client->b2b_key, NULL, 1, 1);
	b2b_sdp_client_release(client);
	/* also notify the upstream */
	body = b2b_sdp_mux_body(ctx);
	if (body) {
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		req_data.et = B2B_SERVER;
		req_data.b2b_key = &ctx->b2b_key;
		req_data.method = &method;
		req_data.body = body;
		req_data.no_cb = 1;
		if (b2b_api.send_request(&req_data) < 0)
			LM_ERR("cannot send upstream INVITE\n");
	}
	return 0;
}

static int b2b_sdp_reply(str *b2b_key, int type, int method, int code, str *body)
{
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
	if (body)
		reply_data.extra_headers = &content_type_sdp_hdr;

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
				bstream->body.s = shm_realloc(bstream->body.s, stream->body.len + cline.len +
						((bstream->label.len && !label)?
						 (lline.len + bstream->label.len + nline.len):0));
				if (!bstream->body.s)
					goto end;
				/* now copy the first m= line of the stream */
				mline.s = stream->body.s;
				mline.len = stream->transport.s + stream->transport.len - stream->body.s;
				while (mline.len < stream->body.len && mline.s[mline.len] != '\r' &&
						mline.s[mline.len] != '\n')
					mline.len++;
				memcpy(bstream->body.s, stream->body.s, mline.len);
				memcpy(bstream->body.s + mline.len, cline.s, cline.len);
				/* rest of the stream */
				memcpy(bstream->body.s + mline.len + cline.len,
						mline.s + mline.len, stream->body.len - mline.len);
				bstream->body.len = stream->body.len + cline.len;
			} else {
				/* sync the entire stream just as it is */
				bstream->body.s = shm_realloc(bstream->body.s, stream->body.len +
						((bstream->label.len && !label)?
						 (lline.len + bstream->label.len + nline.len):0));
				if (!bstream->body.s)
					goto end;
				memcpy(bstream->body.s, stream->body.s, stream->body.len);
				bstream->body.len = stream->body.len;
			}
			/* only add label if it was initially there */
			if (bstream->label.len && !label) {
				/* copy terminator from end of stream to make space for label */
				eline.s = bstream->body.s + bstream->body.len;
				eline.len = 0;
				while (eline.s > stream->body.s &&
						(*(eline.s - 1) == '\r' || *(eline.s - 1) == '\n')) {
					eline.s--;
					eline.len++;
					bstream->body.s[bstream->body.len + nline.len +
						lline.len + bstream->label.len - eline.len] = *eline.s;
				}
				bstream->body.len -= eline.len;

				memcpy(bstream->body.s + bstream->body.len, nline.s, nline.len);
				bstream->body.len += nline.len;
				memcpy(bstream->body.s + bstream->body.len, lline.s, lline.len);
				bstream->body.len += lline.len;
				memcpy(bstream->body.s + bstream->body.len, bstream->label.s, bstream->label.len);
				bstream->body.len += bstream->label.len;
				bstream->body.len += eline.len;
			}
		}
	}
	ret = 0;
end:
	free_sdp_content(&sdp);
	return ret;
}

static int b2b_sdp_ack(int type, str *key)
{
	str ack = str_init(ACK);
	struct b2b_req_data req;
	memset(&req, 0, sizeof(req));
	req.et = type;
	req.b2b_key = key;
	req.method = &ack;
	req.no_cb = 1; /* do not call callback */

	return b2b_api.send_request(&req);
}

static int b2b_sdp_client_reply_invite(struct sip_msg *msg, struct b2b_sdp_client *client)
{
	str *body;
	int ret = -1;
	if (b2b_sdp_ack(B2B_CLIENT, &client->b2b_key) < 0)
		LM_ERR("Cannot ack recording session for key %.*s\n",
				client->b2b_key.len, client->b2b_key.s);

	lock_get(&client->ctx->lock);

	if (client->ctx->pending_no <= 0) {
		LM_ERR("not expecting any replies!\n");
		goto release;
	}
	/* we have a final reply for this client */
	client->ctx->pending_no--;
	client->flags &= ~B2B_SDP_CLIENT_EARLY;

	if (msg->REPLY_STATUS < 300) {
		body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
		if (body && b2b_sdp_client_sync(client, body) >= 0) {
			client->ctx->success_no++;
			client->flags |= B2B_SDP_CLIENT_STARTED;
		} else {
			LM_ERR("no body for client!\n");
		}
	}
	body = NULL;

	if (client->ctx->pending_no == 0) {
		/* we've actually completed all the upstream clients
		 * therefore we need to respond to the server */
		body = b2b_sdp_mux_body(client->ctx);
		if (!body) {
			LM_CRIT("could not build to B2B server body!\n");
			ret = -2;
		}
	}

release:
	lock_release(&client->ctx->lock);
	/* avoid sending reply under lock */
	if (ret == -2) {
		b2b_sdp_reply(&client->ctx->b2b_key, B2B_SERVER, METHOD_INVITE, 503, NULL);
		b2b_sdp_ctx_free(client->ctx);
	} else if (body) {
		/* we are done - answer the call */
		if (b2b_sdp_reply(&client->ctx->b2b_key, B2B_SERVER, METHOD_INVITE, 200, body) < 0)
			LM_CRIT("could not answer B2B call!\n");
		pkg_free(body->s);
	}
	return ret;
}

static int b2b_sdp_client_notify(struct sip_msg *msg, str *key, int type, void *param)
{
	struct b2b_sdp_client *client = *(struct b2b_sdp_client **)
		((str *)param)->s;

	if (!client) {
		LM_ERR("No b2b sdp client!\n");
		return -1;
	}

	if (type == B2B_REQUEST) {
		lock_get(&client->ctx->lock);
		if (client->ctx->pending_no) {
			lock_release(&client->ctx->lock);
			LM_INFO("we still have pending clients!\n");
			b2b_sdp_reply(&client->b2b_key, B2B_CLIENT, msg->REQ_METHOD, 491, NULL);
			return -1;
		}
		lock_release(&client->ctx->lock);
		switch (msg->REQ_METHOD) {
			case METHOD_ACK:
				return 0;
			case METHOD_INVITE:
				return b2b_sdp_client_reinvite(msg, client);
			case METHOD_BYE:
				return b2b_sdp_client_bye(msg, client);
		}
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

		switch (get_cseq(msg)->method_id) {
			case METHOD_INVITE:
				return b2b_sdp_client_reply_invite(msg, client);
		}
		LM_ERR("reply message %d for %.*s not handled\n", msg->REPLY_STATUS,
				get_cseq(msg)->method.len, get_cseq(msg)->method.s);
	}
	return -1;
}

static str *b2b_sdp_demux_body(struct b2b_sdp_client *client,
		sdp_info_t *sdp)
{
	int len;
	char *p;
	str session_str;
	static str body;
	static str media = str_init("m=");
	struct list_head *it;
	struct b2b_sdp_stream *stream;
	sdp_stream_cell_t *sstream;
	sdp_session_cell_t *session = b2b_sdp_get_session(sdp,
			list_last_entry(&client->streams, struct b2b_sdp_stream, list)->index);
	if (!session) {
		LM_ERR("could not locate session\n");
		return NULL;
	}
	session_str = session->body;
	do {
		p = str_strstr(&session_str, &media);
		if (!p || (p - session_str.s < 1)) {
			LM_ERR("could not locate first media stream in session\n");
			return NULL;
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
		return NULL;
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
	return &body;
}

static int b2b_sdp_server_reply_invite(struct sip_msg *msg, struct b2b_sdp_ctx *ctx)
{
	int code;
	str *body = NULL;
	sdp_info_t sdp;
	struct list_head *it;
	struct b2b_sdp_client *client;

	/* re-INVITE failed - reply the same code to the client
	 * that started the challenging */
	b2b_sdp_ack(B2B_SERVER, &ctx->b2b_key);
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
		lock_release(&client->ctx->lock);
		LM_WARN("cannot identify a pending client!\n");
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
				body = b2b_sdp_demux_body(client, &sdp);
				if (!body) {
					LM_ERR("cannot get body for client!\n");
					free_sdp_content(&sdp);
				}
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
	b2b_sdp_reply(&client->b2b_key, B2B_CLIENT, METHOD_INVITE, code, body);
	if (body) {
		free_sdp_content(&sdp);
		pkg_free(body->s);
	}
	lock_get(&client->ctx->lock);
	ctx->pending_no = 0;
	lock_release(&client->ctx->lock);
	return 0;
}

static int b2b_sdp_server_bye(struct sip_msg *msg, struct b2b_sdp_ctx *ctx)
{
	b2b_sdp_reply(&ctx->b2b_key, B2B_SERVER, msg->REQ_METHOD, 200, NULL);
	b2b_sdp_ctx_free(ctx);
	return 0;
}

static int b2b_sdp_server_notify(struct sip_msg *msg, str *key, int type, void *param)
{
	struct b2b_sdp_ctx *ctx = *(struct b2b_sdp_ctx **)((str *)param)->s;
	if (!ctx) {
		LM_ERR("No b2b sdp context!\n");
		return -1;
	}
	if (type == B2B_REQUEST) {
		lock_get(&ctx->lock);
		if (ctx->pending_no) {
			lock_release(&ctx->lock);
			LM_INFO("we still have pending clients!\n");
			b2b_sdp_reply(&ctx->b2b_key, B2B_SERVER, msg->REQ_METHOD, 491, NULL);
			return -1;
		}
		lock_release(&ctx->lock);
		switch (msg->REQ_METHOD) {
			case METHOD_ACK:
				return 0;
			case METHOD_BYE:
				return b2b_sdp_server_bye(msg, ctx);
		}
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
		switch (get_cseq(msg)->method_id) {
			case METHOD_INVITE:
				return b2b_sdp_server_reply_invite(msg, ctx);
		}
		LM_ERR("reply message %d for %.*s not handled\n", msg->REPLY_STATUS,
				get_cseq(msg)->method.len, get_cseq(msg)->method.s);
	}
	return -1;
}

static int b2b_sdp_demux_start(struct sip_msg *msg, str *uri,
		struct b2b_sdp_ctx *ctx, sdp_info_t *sdp)
{
	str *b2b_key, *body;
	str hack, contact;
	union sockaddr_union tmp_su;
	struct list_head *it;
	struct b2b_sdp_client *client;
	client_info_t ci;

	hack.s = (char *)&ctx;
	hack.len = sizeof(void *);

	if (!msg->force_send_socket) {
		ctx->si = uri2sock(msg, uri, &tmp_su, PROTO_NONE);
		if (!ctx->si) {
			LM_ERR("could not find an available send socket!\n");
			return -1;
		}
	} else {
		ctx->si = msg->force_send_socket;
	}

	contact.s = contact_builder(msg->rcv.bind_address, &contact.len);
	ctx->sess_ip = get_adv_host(msg->rcv.bind_address);

	b2b_key = b2b_api.server_new(msg, &contact, b2b_sdp_server_notify,
			&b2b_sdp_demux_cap, &hack, NULL);
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
	/* we need to wait for all pending clients */
	ctx->pending_no = ctx->clients_no;

	contact.s = contact_builder(ctx->si, &contact.len);
	memset(&ci, 0, sizeof ci);
	ci.send_sock = ctx->si;
	ci.local_contact = contact;
	ci.method.s = INVITE;
	ci.method.len = INVITE_LEN;
	/* try the first srs_uri */
	ci.req_uri = *uri;
	ci.to_uri = ci.req_uri;
	ci.from_uri = ci.to_uri;

	list_for_each(it, &ctx->clients) {
		client = list_entry(it, struct b2b_sdp_client, list);
		body = b2b_sdp_demux_body(client, sdp);
		if (!body) {
			LM_ERR("could not get body for client!\n");
			return -1;
		}
		/* per client stuff */
		hack.s = (char *)&client;
		ci.body = body;
		ci.extra_headers = &client->hdrs;

		client->flags |= B2B_SDP_CLIENT_EARLY;
		b2b_key = b2b_api.client_new(&ci, b2b_sdp_client_notify, NULL,
				&b2b_sdp_demux_cap, &hack, NULL);
		pkg_free(body->s);
		if (!b2b_key) {
			LM_ERR("could not create b2b sdp demux client!\n");
			return -1;
		}
		if (shm_str_dup(&client->b2b_key, b2b_key) < 0) {
			LM_ERR("could not copy b2b client key\n");
			/* key is not yet stored, but INVITE sent - terminate it */
			b2b_sdp_client_terminate(client, b2b_key);
			return -1;
		}
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

	ctx = b2b_sdp_ctx_new();
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
	if (b2b_sdp_hdrs_from_avps(ctx, hdrs) < 0) {
		LM_ERR("could assign headers to clients\n");
		goto error;
	}

	b2b_sdp_streams_print(ctx);
	if (b2b_sdp_demux_start(msg, uri, ctx, &sdp) < 0) {
		LM_ERR("could not start B2B SDP demux\n");
		goto error;
	}
	LM_DBG("B2B SDP successfully engaged!\n");
	free_sdp_content(&sdp);
	return 0;
error:
	free_sdp_content(&sdp);
	b2b_sdp_ctx_free(ctx);
	return -1;
}
