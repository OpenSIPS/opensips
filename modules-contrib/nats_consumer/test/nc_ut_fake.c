/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 *
 * The nats_consumer suite's fixture: a fake libnats table that replaces
 * the module's bound one (nats_api.dl) for one scenario and records the
 * calls the module makes.  Only the functions a scenario reaches are
 * set; any other call through the table is a NULL call, so a scenario
 * that strays crashes the suite instead of reaching a real broker.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../dprint.h"
#include "../../nats/nats_bind.h"
#include "../../nats/test/nats_ut_log.h"

#include "nc_ut.h"

struct nc_ut_fake nf;

static struct nats_binds nc_ut_real_api;
static nats_dl_funcs_t fake_dl;

static natsStatus f_ConsumerConfigInit(jsConsumerConfig *cc)
{
	memset(cc, 0, sizeof *cc);
	return NATS_OK;
}

static natsStatus f_GetStreamInfo(jsStreamInfo **si, jsCtx *js,
	const char *stream, jsOptions *opts, jsErrCode *errCode)
{
	(void)js; (void)opts; (void)errCode;
	nf.n_stream_info++;
	snprintf(nf.stream_info_name, sizeof nf.stream_info_name, "%s",
		stream ? stream : "");
	if (nf.stream_info_status != NATS_OK)
		return nf.stream_info_status;
	*si = calloc(1, sizeof **si);
	if (!*si)
		return NATS_NO_MEMORY;
	(*si)->Created = nf.stream_created;
	return NATS_OK;
}

static void f_StreamInfoDestroy(jsStreamInfo *si)
{
	nf.n_stream_info_destroy++;
	free(si);
}

static int f_pool_is_connected(void)
{
	return nf.connected;
}

static int f_pool_get_reconnect_epoch(void)
{
	return nf.epoch;
}

static natsConnection *f_pool_get(void)
{
	return nf.pool_nc;
}

static natsStatus f_RequestMsg(natsMsg **reply, natsConnection *nc,
	natsMsg *req, int64_t timeout)
{
	(void)reply; (void)nc; (void)req; (void)timeout;
	nf.n_request++;
	return NATS_TIMEOUT;
}

static char fake_out_msg;

static natsStatus f_MsgCreate(natsMsg **m, const char *subj, const char *reply,
	const char *data, int len)
{
	nf.n_msg_create++;
	snprintf(nf.created_subject, sizeof nf.created_subject, "%s", subj ? subj : "");
	snprintf(nf.created_reply, sizeof nf.created_reply, "%s", reply ? reply : "");
	snprintf(nf.created_data, sizeof nf.created_data, "%.*s",
		len > 0 ? len : 0, data ? data : "");
	if (nf.msg_create_status != NATS_OK)
		return nf.msg_create_status;
	*m = (natsMsg *)&fake_out_msg;
	return NATS_OK;
}

static natsStatus f_HeaderSet(natsMsg *m, const char *key, const char *value)
{
	(void)m;
	if (nf.n_hdr_set < 4) {
		snprintf(nf.hdr_set_key[nf.n_hdr_set], 64, "%s", key);
		snprintf(nf.hdr_set_val[nf.n_hdr_set], 64, "%s", value);
	}
	nf.n_hdr_set++;
	nf.seq_last_hdr_set = ++nf.seq;
	return NATS_OK;
}

static natsStatus f_PublishMsg(natsConnection *nc, natsMsg *m)
{
	(void)nc; (void)m;
	nf.n_publish++;
	nf.seq_publish = ++nf.seq;
	return nf.publish_status;
}

static char fake_inbox_sub;

static natsStatus f_Subscribe(natsSubscription **sub, natsConnection *nc,
	const char *subject, natsMsgHandler cb, void *closure)
{
	(void)nc; (void)subject; (void)cb; (void)closure;
	nf.n_subscribe++;
	if (nf.subscribe_status != NATS_OK)
		return nf.subscribe_status;
	*sub = (natsSubscription *)&fake_inbox_sub;
	return NATS_OK;
}

static const char *f_GetText(natsStatus s)
{
	return s == NATS_OK ? "OK" : "fake error";
}

static natsStatus f_SubOptionsInit(jsSubOptions *so)
{
	memset(so, 0, sizeof *so);
	return NATS_OK;
}

static natsStatus f_OptionsInit(jsOptions *o)
{
	memset(o, 0, sizeof *o);
	return NATS_OK;
}

static natsStatus f_AddConsumer(jsConsumerInfo **ci, jsCtx *js,
	const char *stream, jsConsumerConfig *cfg, jsOptions *opts,
	jsErrCode *errCode)
{
	(void)ci; (void)js; (void)stream; (void)cfg; (void)opts; (void)errCode;
	nf.n_add_consumer++;
	return nf.add_consumer_status;
}

static natsStatus f_UpdateConsumer(jsConsumerInfo **ci, jsCtx *js,
	const char *stream, jsConsumerConfig *cfg, jsOptions *opts,
	jsErrCode *errCode)
{
	(void)ci; (void)js; (void)stream; (void)cfg; (void)opts; (void)errCode;
	nf.n_update_consumer++;
	return nf.add_consumer_status;
}

static natsStatus f_Fetch(natsMsgList *list, natsSubscription *sub,
	int batch, int64_t timeout, jsErrCode *errCode)
{
	(void)sub; (void)errCode;
	nf.n_fetch++;
	nf.fetch_batch = batch;
	nf.fetch_timeout = timeout;
	memset(list, 0, sizeof *list);
	return nf.fetch_status;
}

static void f_MsgDestroy(natsMsg *m)
{
	if (nf.n_msg_destroy < (int)(sizeof nf.destroyed / sizeof nf.destroyed[0]))
		nf.destroyed[nf.n_msg_destroy] = m;
	nf.n_msg_destroy++;
}

static natsStatus f_Unsubscribe(natsSubscription *sub)
{
	(void)sub;
	nf.n_unsubscribe++;
	return NATS_OK;
}

static void f_SubDestroy(natsSubscription *sub)
{
	nf.n_sub_destroy++;
	nf.sub_destroyed = sub;
}

static const char *f_MsgSubject(const natsMsg *m) { (void)m; return nf.msg_subject; }
static const char *f_MsgData(const natsMsg *m) { (void)m; return nf.msg_data; }
static int f_MsgDataLength(const natsMsg *m) { (void)m; return nf.msg_len; }
static const char *f_MsgReply(const natsMsg *m) { (void)m; return nf.msg_reply; }

static natsStatus f_HeaderKeys(natsMsg *m, const char* **keys, int *count)
{
	const char **k;
	int i;

	(void)m;
	*keys = NULL;
	*count = 0;
	if (nf.n_hdr <= 0)
		return NATS_NOT_FOUND;   /* no headers */
	k = malloc(sizeof *k * (size_t)nf.n_hdr);   /* the caller frees it */
	if (!k)
		return NATS_NO_MEMORY;
	for (i = 0; i < nf.n_hdr; i++)
		k[i] = nf.hdr_key[i];
	*keys = k;
	*count = nf.n_hdr;
	return NATS_OK;
}

static int hdr_find(const char *key)
{
	int i;

	for (i = 0; i < nf.n_hdr; i++)
		if (strcmp(nf.hdr_key[i], key) == 0)
			return i;
	return -1;
}

static natsStatus f_HeaderValues(natsMsg *m, const char *key,
	const char* **values, int *count)
{
	const char **v;
	int i = hdr_find(key);

	(void)m;
	if (i < 0)
		return NATS_NOT_FOUND;
	v = malloc(sizeof *v);
	if (!v)
		return NATS_NO_MEMORY;
	v[0] = nf.hdr_val[i];
	*values = v;
	*count = 1;
	return NATS_OK;
}

static natsStatus f_HeaderGet(natsMsg *m, const char *key, const char **value)
{
	int i = hdr_find(key);

	(void)m;
	if (i < 0)
		return NATS_NOT_FOUND;
	*value = nf.hdr_val[i];
	return NATS_OK;
}

static natsStatus f_GetMetaData(jsMsgMetaData **md, natsMsg *m)
{
	(void)m;
	if (!nf.has_md)
		return NATS_ERR;
	*md = calloc(1, sizeof **md);
	if (!*md)
		return NATS_NO_MEMORY;
	(*md)->NumDelivered = nf.md_delivered;
	(*md)->Sequence.Stream = nf.md_stream_seq;
	return NATS_OK;
}

static void f_MetaDataDestroy(jsMsgMetaData *md)
{
	free(md);
}

static natsStatus f_Term(natsMsg *m, jsOptions *o)
{
	(void)m; (void)o;
	nf.n_term++;
	return NATS_OK;
}

static natsStatus f_PullSubscribe(natsSubscription **sub, jsCtx *js,
	const char *subject, const char *durable, jsOptions *opts,
	jsSubOptions *so, jsErrCode *errCode)
{
	(void)sub; (void)js; (void)subject; (void)durable; (void)opts;
	(void)so; (void)errCode;
	nf.n_pull_subscribe++;
	return nf.pull_subscribe_status;
}

void nc_ut_begin(void)
{
	nc_ut_real_api = nats_api;
	memset(&nf, 0, sizeof nf);

	memset(&fake_dl, 0, sizeof fake_dl);
	fake_dl.jsConsumerConfig_Init = f_ConsumerConfigInit;
	fake_dl.js_GetStreamInfo = f_GetStreamInfo;
	fake_dl.jsStreamInfo_Destroy = f_StreamInfoDestroy;

	fake_dl.natsStatus_GetText = f_GetText;
	fake_dl.jsSubOptions_Init = f_SubOptionsInit;
	fake_dl.jsOptions_Init = f_OptionsInit;
	fake_dl.js_AddConsumer = f_AddConsumer;
	fake_dl.js_UpdateConsumer = f_UpdateConsumer;
	fake_dl.js_PullSubscribe = f_PullSubscribe;
	nf.add_consumer_status = NATS_ERR;
	nf.pull_subscribe_status = NATS_ERR;
	fake_dl.natsSubscription_Fetch = f_Fetch;
	fake_dl.natsMsg_Destroy = f_MsgDestroy;
	fake_dl.natsSubscription_Unsubscribe = f_Unsubscribe;
	fake_dl.natsSubscription_Destroy = f_SubDestroy;
	fake_dl.natsMsg_GetSubject = f_MsgSubject;
	fake_dl.natsMsg_GetData = f_MsgData;
	fake_dl.natsMsg_GetDataLength = f_MsgDataLength;
	fake_dl.natsMsg_GetReply = f_MsgReply;
	fake_dl.natsMsgHeader_Keys = f_HeaderKeys;
	fake_dl.natsMsgHeader_Values = f_HeaderValues;
	fake_dl.natsMsgHeader_Get = f_HeaderGet;
	fake_dl.natsMsg_GetMetaData = f_GetMetaData;
	fake_dl.jsMsgMetaData_Destroy = f_MetaDataDestroy;
	fake_dl.natsMsg_Term = f_Term;
	nf.fetch_status = NATS_TIMEOUT;

	nats_api.dl = &fake_dl;
	nats_api.pool_is_connected = f_pool_is_connected;
	nats_api.pool_get = f_pool_get;
	nats_api.pool_get_reconnect_epoch = f_pool_get_reconnect_epoch;
	fake_dl.natsConnection_RequestMsg = f_RequestMsg;
	fake_dl.natsMsg_Create = f_MsgCreate;
	fake_dl.natsMsgHeader_Set = f_HeaderSet;
	fake_dl.natsConnection_PublishMsg = f_PublishMsg;
	fake_dl.natsConnection_Subscribe = f_Subscribe;
	nf.msg_create_status = NATS_ERR;
	ut_log_start(L_WARN);
}

void nc_ut_end(void)
{
	ut_log_stop();
	nats_api = nc_ut_real_api;
}

const char *nc_ut_log(void) { return ut_log(); }
void nc_ut_log_clear(void) { ut_log_clear(); }
size_t nc_ut_log_raw(char *buf, size_t size) { return ut_log_raw(buf, size); }
