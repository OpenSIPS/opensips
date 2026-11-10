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
 * Fixture of the event_nats tests (en_ut.h).
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../../nats/nats_bind.h"
#include "../nats_producer.h"
#include "../nats_stats.h"
#include "../event_nats.h"

#include "en_ut.h"
#include "../../nats/test/nats_ut_log.h"

struct en_ut_fake ef;
struct nats_binds en_ut_real_api;

static nats_dl_funcs_t fake_dl;
static int obj_nc, obj_js, obj_msg, obj_sub;

natsConnection *en_ut_nc(void) { return (natsConnection *)&obj_nc; }
jsCtx *en_ut_js(void) { return (jsCtx *)&obj_js; }
natsMsg *en_ut_msg(void) { return (natsMsg *)&obj_msg; }

/* ── fake nats module API ───────────────────────────────────────── */

static natsConnection *f_pool_get(void)
{ ef.n_pool_get++; return ef.pool_nc; }
static jsCtx *f_pool_get_js(void)
{ ef.n_pool_get_js++; return ef.pool_js; }
static int f_pool_is_connected(void)
{ return ef.connected; }
static int f_pool_get_reconnect_epoch(void)
{ return ef.epoch; }
static int f_pool_should_init(int rank)
{ (void)rank; return ef.should_init; }
static void f_pool_set_pub_ack_cb(void (*cb)(int))
{
	ef.pub_ack_cb = cb;
	ef.n_set_pub_ack_cb++;
	ef.seq_set_pub_ack_cb = ++ef.seq;
}
static void f_pool_unregister(void)
{
	ef.n_unregister++;
	ef.seq_unregister = ++ef.seq;
	ef.stats_alive_at_unregister = nats_stats != NULL;
}
static const char *f_pool_get_server_info(void)
{ return ef.connected ? "nats://fake:4222" : "not connected"; }

/* ── fake libnats ───────────────────────────────────────────────── */

static const char *f_GetText(natsStatus s)
{ (void)s; return "fake"; }

static natsStatus f_Publish(natsConnection *nc, const char *subj,
	const void *data, int len)
{
	(void)nc;
	ef.n_publish++;
	snprintf(ef.pub_subject, sizeof ef.pub_subject, "%s", subj);
	ef.pub_len = len;
	if (len >= 0 && (size_t)len < sizeof ef.pub_data) {
		memcpy(ef.pub_data, data, (size_t)len);
		ef.pub_data[len] = '\0';
	}
	return ef.publish_status;
}

static natsStatus f_PubOptInit(jsPubOptions *o)
{ memset(o, 0, sizeof *o); return NATS_OK; }
static natsStatus f_PublishAsync(jsCtx *js, const char *subj,
	const void *data, int len, jsPubOptions *o)
{
	(void)js;
	ef.n_js_publish++;
	snprintf(ef.js_subject, sizeof ef.js_subject, "%s", subj);
	ef.pub_len = len;
	if (len >= 0 && (size_t)len < sizeof ef.pub_data) {
		memcpy(ef.pub_data, data, (size_t)len);
		ef.pub_data[len] = '\0';
	}
	snprintf(ef.js_msg_id, sizeof ef.js_msg_id, "%s",
		o && o->MsgId ? o->MsgId : "(none)");
	ef.js_max_wait = o ? o->MaxWait : -1;
	return ef.js_publish_status;
}

static const char *f_MsgSubject(const natsMsg *m)
{ (void)m; return ef.msg_subject; }
static const char *f_MsgData(const natsMsg *m)
{ (void)m; return ef.msg_data; }
static int f_MsgDataLength(const natsMsg *m)
{ (void)m; return ef.msg_len; }
static void f_MsgDestroy(natsMsg *m)
{ (void)m; ef.n_msg_destroy++; }

static natsStatus f_Subscribe(natsSubscription **sub, natsConnection *nc,
	const char *subject, natsMsgHandler cb, void *closure)
{
	ef.n_subscribe++;
	ef.sub_nc = nc;
	snprintf(ef.sub_subject, sizeof ef.sub_subject, "%s", subject);
	ef.sub_queue[0] = '\0';
	ef.sub_handler = cb;
	ef.sub_closure = closure;
	if (ef.subscribe_status == NATS_OK)
		*sub = (natsSubscription *)&obj_sub;
	return ef.subscribe_status;
}
static natsStatus f_QueueSubscribe(natsSubscription **sub, natsConnection *nc,
	const char *subject, const char *queue, natsMsgHandler cb, void *closure)
{
	ef.n_queue_subscribe++;
	ef.sub_nc = nc;
	snprintf(ef.sub_subject, sizeof ef.sub_subject, "%s", subject);
	snprintf(ef.sub_queue, sizeof ef.sub_queue, "%s", queue);
	ef.sub_handler = cb;
	ef.sub_closure = closure;
	if (ef.subscribe_status == NATS_OK)
		*sub = (natsSubscription *)&obj_sub;
	return ef.subscribe_status;
}
static bool f_SubIsValid(natsSubscription *sub)
{
	(void)sub;
	if (ef.reconnect_in_check && ef.n_is_valid == 0)
		ef.epoch++;
	ef.n_is_valid++;
	return ef.sub_valid ? true : false;
}
static void f_SubDestroy(natsSubscription *sub)
{ (void)sub; ef.n_sub_destroy++; }

static natsStatus f_GetMsg(natsMsg **msg, jsCtx *js, const char *stream,
	uint64_t seq, jsOptions *o, jsErrCode *jerr)
{
	(void)js; (void)o;
	ef.n_get_msg++;
	ef.msg_seq = seq;
	snprintf(ef.msg_stream, sizeof ef.msg_stream, "%s", stream);
	if (jerr)
		*jerr = ef.jerr;
	if (ef.get_msg_status == NATS_OK)
		*msg = (natsMsg *)&obj_msg;
	return ef.get_msg_status;
}
static natsStatus f_DeleteMsg(jsCtx *js, const char *stream, uint64_t seq,
	jsOptions *o, jsErrCode *jerr)
{
	(void)js; (void)o;
	ef.n_delete_msg++;
	ef.msg_seq = seq;
	snprintf(ef.msg_stream, sizeof ef.msg_stream, "%s", stream);
	if (jerr)
		*jerr = ef.jerr;
	return ef.delete_msg_status;
}

/* ── scenarios ──────────────────────────────────────────────────── */

void en_ut_begin(void)
{
	en_ut_real_api = nats_api;

	memset(&ef, 0, sizeof ef);
	ef.should_init = 1;
	ef.sub_valid = 1;

	memset(&fake_dl, 0, sizeof fake_dl);
	fake_dl.natsStatus_GetText = f_GetText;
	fake_dl.natsConnection_Publish = f_Publish;
	fake_dl.jsPubOptions_Init = f_PubOptInit;
	fake_dl.js_PublishAsync = f_PublishAsync;
	fake_dl.natsMsg_GetSubject = f_MsgSubject;
	fake_dl.natsMsg_GetData = f_MsgData;
	fake_dl.natsMsg_GetDataLength = f_MsgDataLength;
	fake_dl.natsMsg_Destroy = f_MsgDestroy;
	fake_dl.natsConnection_Subscribe = f_Subscribe;
	fake_dl.natsConnection_QueueSubscribe = f_QueueSubscribe;
	fake_dl.natsSubscription_IsValid = f_SubIsValid;
	fake_dl.natsSubscription_Destroy = f_SubDestroy;
	fake_dl.js_GetMsg = f_GetMsg;
	fake_dl.js_DeleteMsg = f_DeleteMsg;

	nats_api.dl = &fake_dl;
	nats_api.pool_get = f_pool_get;
	nats_api.pool_get_js = f_pool_get_js;
	nats_api.pool_is_connected = f_pool_is_connected;
	nats_api.pool_get_reconnect_epoch = f_pool_get_reconnect_epoch;
	nats_api.pool_should_init = f_pool_should_init;
	nats_api.pool_set_pub_ack_cb = f_pool_set_pub_ack_cb;
	nats_api.pool_unregister = f_pool_unregister;
	nats_api.pool_get_server_info = f_pool_get_server_info;

	nats_producer_set_connection(NULL);
	nats_producer_set_js(NULL);
	ut_log_start(L_WARN);
}

void en_ut_end(void)
{
	ut_log_stop();
	nats_api = en_ut_real_api;
	/* what child_init() gave the producer of this process */
	nats_producer_set_connection(nats_api.pool_get());
	nats_producer_set_js(nats_jetstream ? nats_api.pool_get_js() : NULL);
}

const char *en_ut_log(void) { return ut_log(); }
void en_ut_log_clear(void) { ut_log_clear(); }
size_t en_ut_log_raw(char *buf, size_t size) { return ut_log_raw(buf, size); }

void en_ut_run(const char *name, en_ut_scenario_f f)
{
	static char log[4096];
	int passed;

	en_ut_begin();
	passed = f();
	if (!passed)
		snprintf(log, sizeof log, "%s", en_ut_log());
	en_ut_end();
	ok(passed, "%s", name);
	if (!passed)
		diag("log of the failed scenario:\n%s", log);
}
