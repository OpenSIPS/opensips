/*
 * Copyright (C) 2021 TODO
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
#include "../../parser/sdp/sdp.h"
#include "../../lib/list.h"

/* we use this to index the streams within different sessions */
#define MAX_SESSIONS_STREAMS 100

static dep_export_t mod_deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
	},
};

static b2b_api_t b2b_api;

static int b2b_sdp_demux(struct sip_msg *msg,
		pv_spec_t *hdrs, pv_spec_t *streams);
static int fixup_check_avp(void** param);

static cmd_export_t mod_cmds[] = {
	{"b2b_sdp_demux", (cmd_function)b2b_sdp_demux, {
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

struct b2b_sdp_stream {
	int index;
	str label;
	struct list_head list;
	char label_buf[0];
};

struct b2b_sdp_client {
	str hdrs;
	struct list_head streams;
	struct list_head list;
};

struct b2b_sdp_ctx {
	int clients_no;
	struct list_head clients;
};

static struct b2b_sdp_stream *b2b_sdp_stream_new(
		struct b2b_sdp_client *client, str *label, int idx)
{
	struct b2b_sdp_stream *stream = shm_malloc(sizeof *stream +
			(label?label->len:0));
	if (!stream) {
		LM_ERR("could not alocate B2B SDP stream\n");
		return NULL;
	}
	memset(stream, 0, sizeof *stream);
	if (label) {
		stream->label.s = stream->label_buf;
		memcpy(stream->label.s, label->s, label->len);
		stream->label.len = label->len;
	}
	stream->index = idx;
	list_add_tail(&stream->list, &client->streams);
	return stream;
}

static void b2b_sdp_stream_free(struct b2b_sdp_stream *stream)
{
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
	list_add_tail(&client->list, &ctx->clients);
	ctx->clients_no++;
	return client;
}

static void b2b_sdp_client_free(struct b2b_sdp_client *client)
{
	struct list_head *it, *safe;

	list_for_each_safe(it, safe, &client->streams)
		b2b_sdp_stream_free(list_entry(it, struct b2b_sdp_stream, list));
	list_del(&client->list);
	shm_free(client);
}

static struct b2b_sdp_ctx *b2b_sdp_ctx_new(void)
{
	struct b2b_sdp_ctx *ctx = shm_malloc(sizeof *ctx);
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof *ctx);
	INIT_LIST_HEAD(&ctx->clients);
	return ctx;
}

static void b2b_sdp_ctx_free(struct b2b_sdp_ctx *ctx)
{
	struct list_head *it, *safe;

	list_for_each_safe(it, safe, &ctx->clients)
		b2b_sdp_client_free(list_entry(it, struct b2b_sdp_client, list));
	shm_free(ctx);
}

static str *b2b_sdp_label_from_sdp(sdp_stream_cell_t *stream)
{
	sdp_attr_t *attr;
	/* check if the stream has a label */
	for (attr = stream->attr; attr; attr = attr->next)
		if (str_match_nt(&attr->attribute, "label"))
			return &attr->value;
	return NULL;
}

static int b2b_sdp_streams_from_sdp(struct b2b_sdp_ctx *ctx,
		sdp_info_t *sdp)
{
	struct b2b_sdp_client *client;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;
	int stream_num;
	str *label;

	for (session = sdp->sessions; session; session = session->next) {
		for (stream = session->streams; stream; stream = stream->next) {
			/* for each stream, we have a new client */
			client = b2b_sdp_client_new(ctx);
			if (!client)
				return -1;
			label = b2b_sdp_label_from_sdp(stream);
			stream_num = stream->stream_num +
				session->session_num * MAX_SESSIONS_STREAMS;
			if (b2b_sdp_stream_new(client, label, stream_num) < 0)
				return -1;
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
			LM_INFO("client=%p hdrs=[%.*s] stream=%d label=[%.*s]\n", client,
					(client->hdrs.len?client->hdrs.len:0),
					(client->hdrs.len?client->hdrs.s:""),
					stream->index, (stream->label.len?stream->label.len:4),
					(stream->label.len?stream->label.s:"NULL"));
		}
	}
}

static sdp_stream_cell_t *b2b_sdp_get_stream(sdp_info_t *sdp, int idx)
{
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;

	for (session = sdp->sessions; session; session = session->next)
		for (stream = session->streams; stream; stream = stream->next)
			if (stream->stream_num + session->session_num * MAX_SESSIONS_STREAMS == idx)
				return stream;
	return NULL;
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

static int b2b_sdp_stream_new_idx(struct b2b_sdp_ctx *ctx,
		struct b2b_sdp_client *client, int idx, sdp_info_t *sdp)
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
	if (b2b_sdp_stream_new(client,
				b2b_sdp_label_from_sdp(stream), idx) < 0)
		return -1;
	return 0;
}

static int b2b_sdp_streams_from_avps(struct b2b_sdp_ctx *ctx,
		pv_spec_t *streams, sdp_info_t *sdp)
{
	struct b2b_sdp_client *client;
	struct usr_avp *avp = NULL;
	int_str val;
	char *p, *end;
	unsigned int itmp;
	str tmp;

	while ((avp = search_first_avp(streams->pvp.pvn.u.isname.type,
				streams->pvp.pvn.u.isname.name.n, &val, avp)) != NULL) {
		if (avp->flags & AVP_VAL_NULL)
			continue;
		/* for each stream, we have a new client */
		client = b2b_sdp_client_new(ctx);
		if (!client)
			return -1;

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
				if (b2b_sdp_stream_new_idx(ctx, client, itmp, sdp) < 0)
					return -1;
				val.s.len -= (p - val.s.s);
				val.s.s = p;
			}
		} else {
			/* if an integer, only one stream is used */
			if (b2b_sdp_stream_new_idx(ctx, client, val.n, sdp) < 0)
				return -1;
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

static int b2b_sdp_demux(struct sip_msg *msg,
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
error:
	b2b_sdp_ctx_free(ctx);
	return -1;
}
