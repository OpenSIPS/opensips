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
 * Fixture of the pool tests (nats_ut_fake.h).
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "../../../dprint.h"
#include "../nats_dl.h"
#include "../nats_pool.h"

#include "nats_ut_fake.h"
#include "nats_ut_log.h"

struct nats_ut_fake nf;

static int fake_obj;

void *nats_ut_fake_obj(void)
{
	return &fake_obj;
}

/* ── fake libnats ───────────────────────────────────────────────── */

static natsStatus f_Open(int64_t spin)
{ (void)spin; nf.n_open++; return NATS_OK; }
static natsStatus f_CloseAndWait(int64_t ms)
{ (void)ms; nf.n_close++; return NATS_OK; }
static void f_Sleep(int64_t ms)
{ nf.n_sleep++; nf.slept_ms += ms; }
static const char *f_GetText(natsStatus s)
{ (void)s; return "fake"; }
static const char *f_LastError(natsStatus *s)
{ (void)s; return NULL; }
static natsStatus f_ErrStack(char *buf, size_t len)
{
	if (len)
		snprintf(buf, len, "%s", nf.err_stack ? nf.err_stack : "");
	return NATS_OK;
}

static natsStatus f_OptCreate(natsOptions **o)
{ *o = (natsOptions *)&fake_obj; return NATS_OK; }
static void f_OptDestroy(natsOptions *o)
{ (void)o; }
static natsStatus f_DisconnectedCB(natsOptions *o, natsConnectionHandler cb,
	void *cl)
{ (void)o; (void)cl; nf.disconnected_cb = cb; return NATS_OK; }
static natsStatus f_ReconnectedCB(natsOptions *o, natsConnectionHandler cb,
	void *cl)
{ (void)o; (void)cl; nf.reconnected_cb = cb; return NATS_OK; }
static natsStatus f_MaxPingsOut(natsOptions *o, int v)
{ (void)o; nf.last_max_pings_out = v; return NATS_OK; }
static natsStatus f_MaxReconnect(natsOptions *o, int v)
{ (void)o; nf.last_max_reconnect = v; return NATS_OK; }
static natsStatus f_NoRandomize(natsOptions *o, bool v)
{ (void)o; nf.last_no_randomize = v ? 1 : 0; return NATS_OK; }
static natsStatus f_PingInterval(natsOptions *o, int64_t v)
{ (void)o; nf.last_ping_interval = v; return NATS_OK; }
static natsStatus f_ReconnectWait(natsOptions *o, int64_t v)
{ (void)o; nf.last_reconnect_wait = v; return NATS_OK; }
static natsStatus f_ReconnectJitter(natsOptions *o, int64_t a, int64_t b)
{ (void)o; nf.last_jitter = a; nf.last_jitter_tls = b; return NATS_OK; }
static natsStatus f_ReconnectBufSize(natsOptions *o, int v)
{ (void)o; nf.last_reconnect_buf = v; return NATS_OK; }
static natsStatus f_RetryOnFailedConnect(natsOptions *o, bool retry,
	natsConnectionHandler cb, void *cl)
{ (void)o; (void)cl; nf.last_retry_on_failed = retry ? 1 : 0;
  nf.retry_cb = cb; return NATS_OK; }
static natsStatus f_Secure(natsOptions *o, bool v)
{ (void)o; nf.last_secure = v ? 1 : 0; return NATS_OK; }
static natsStatus f_Servers(natsOptions *o, const char **s, int n)
{
	size_t room;
	int i;

	(void)o;
	nf.last_servers[0] = '\0';
	for (i = 0; i < n; i++) {
		room = sizeof(nf.last_servers) - strlen(nf.last_servers) - 1;
		if (i) {
			strncat(nf.last_servers, ",", room);
			room = sizeof(nf.last_servers) - strlen(nf.last_servers) - 1;
		}
		strncat(nf.last_servers, s[i], room);
	}
	return nf.servers_status;
}

static void cp(char *d, size_t size, const char *s)
{ snprintf(d, size, "%s", s ? s : "(null)"); }
static natsStatus f_UserInfo(natsOptions *o, const char *u, const char *p)
{ (void)o; nf.n_auth_calls++; cp(nf.a_user, sizeof nf.a_user, u);
  cp(nf.a_pw, sizeof nf.a_pw, p); return nf.auth_status; }
static natsStatus f_Token(natsOptions *o, const char *t)
{ (void)o; nf.n_auth_calls++; cp(nf.a_token, sizeof nf.a_token, t);
  return nf.auth_status; }
static natsStatus f_Creds(natsOptions *o, const char *f, const char *s)
{ (void)o; nf.n_auth_calls++; cp(nf.a_creds, sizeof nf.a_creds, f);
  cp(nf.a_creds_seed, sizeof nf.a_creds_seed, s); return nf.auth_status; }
static natsStatus f_NKey(natsOptions *o, const char *k, const char *f)
{ (void)o; nf.n_auth_calls++; cp(nf.a_nkey, sizeof nf.a_nkey, k);
  cp(nf.a_seed, sizeof nf.a_seed, f); return nf.auth_status; }

static natsStatus f_Connect(natsConnection **nc, natsOptions *o)
{
	(void)o;
	nf.n_connect++;
	/* libnats hands out the connection on a degraded start too */
	if (nf.connect_status == NATS_OK ||
	    nf.connect_status == NATS_NOT_YET_CONNECTED)
		*nc = (natsConnection *)&fake_obj;
	return nf.connect_status;
}
static natsStatus f_ConnUrl(natsConnection *nc, char *buf, size_t len)
{
	(void)nc;
	if (nf.connurl_status == NATS_OK)
		snprintf(buf, len, "%s", nf.connurl ? nf.connurl : "nats://fake:4222");
	return nf.connurl_status;
}
static natsStatus f_DrainTimeout(natsConnection *nc, int64_t ms)
{ (void)nc; nf.n_drain++; nf.drain_wait = ms; nf.seq_drain = ++nf.seq;
  return NATS_OK; }
static void f_ConnDestroy(natsConnection *nc)
{ (void)nc; nf.n_conn_destroy++; nf.seq_conn_destroy = ++nf.seq; }

static natsStatus f_jsOptInit(jsOptions *o)
{ memset(o, 0, sizeof *o); return NATS_OK; }
static natsStatus f_PubOptInit(jsPubOptions *o)
{ memset(o, 0, sizeof *o); return NATS_OK; }
static natsStatus f_JetStream(jsCtx **js, natsConnection *nc, jsOptions *o)
{
	(void)nc;
	nf.ack_handler = o->PublishAsync.AckHandler;
	nf.js_wait = o->Wait;
	*js = (jsCtx *)&fake_obj;
	return NATS_OK;
}
static void f_jsDestroy(jsCtx *js)
{ (void)js; nf.n_js_destroy++; nf.seq_js_destroy = ++nf.seq; }
static natsStatus f_PubAsyncComplete(jsCtx *js, jsPubOptions *o)
{ (void)js; nf.async_complete_wait = o ? o->MaxWait : -1;
  nf.seq_async_complete = ++nf.seq; return NATS_OK; }
static void f_MsgDestroy(natsMsg *m)
{
	char *p = (char *)m;

	if (p >= nf.msgs && p < nf.msgs + NATS_UT_NMSG)
		nf.destroyed[p - nf.msgs]++;
}
/* on success libnats takes the message (clears the caller's pointer);
 * on failure the caller keeps it */
static natsStatus f_PubMsgAsync(jsCtx *js, natsMsg **m, jsPubOptions *o)
{
	(void)js;
	nf.n_resend++;
	nf.last_resent = *m;
	nf.last_maxwait = o ? o->MaxWait : -1;
	nf.last_msgid = o ? o->MsgId : "no-options";
	if (nf.resend_status == NATS_OK)
		*m = NULL;
	return nf.resend_status;
}

/* each bound bucket gets its own handle, so a leak or a double destroy
 * shows in the counters */
static char kv_handles[64];
static natsStatus f_KeyValue(kvStore **kv, jsCtx *js, const char *bucket)
{
	(void)js; (void)bucket;
	if (nf.kv_bind_status != NATS_OK)
		return nf.kv_bind_status;
	*kv = (kvStore *)&kv_handles[nf.n_kv_bind++ % (int)sizeof(kv_handles)];
	return NATS_OK;
}
static natsStatus f_CreateKeyValue(kvStore **kv, jsCtx *js, kvConfig *cfg)
{
	(void)js; (void)cfg;
	*kv = (kvStore *)&kv_handles[nf.n_kv_create++ % (int)sizeof(kv_handles)];
	return NATS_OK;
}
static void f_kvDestroy(kvStore *kv)
{ (void)kv; nf.n_kv_destroy++; nf.seq_kv_destroy = ++nf.seq; }

static void fill_table(void)
{
	nats_dl.nats_Open = f_Open;
	nats_dl.nats_CloseAndWait = f_CloseAndWait;
	nats_dl.nats_Sleep = f_Sleep;
	nats_dl.natsStatus_GetText = f_GetText;
	nats_dl.nats_GetLastError = f_LastError;
	nats_dl.nats_GetLastErrorStack = f_ErrStack;
	nats_dl.natsOptions_Create = f_OptCreate;
	nats_dl.natsOptions_Destroy = f_OptDestroy;
	nats_dl.natsOptions_SetDisconnectedCB = f_DisconnectedCB;
	nats_dl.natsOptions_SetReconnectedCB = f_ReconnectedCB;
	nats_dl.natsOptions_SetMaxPingsOut = f_MaxPingsOut;
	nats_dl.natsOptions_SetMaxReconnect = f_MaxReconnect;
	nats_dl.natsOptions_SetNoRandomize = f_NoRandomize;
	nats_dl.natsOptions_SetPingInterval = f_PingInterval;
	nats_dl.natsOptions_SetReconnectWait = f_ReconnectWait;
	nats_dl.natsOptions_SetReconnectJitter = f_ReconnectJitter;
	nats_dl.natsOptions_SetReconnectBufSize = f_ReconnectBufSize;
	nats_dl.natsOptions_SetRetryOnFailedConnect = f_RetryOnFailedConnect;
	nats_dl.natsOptions_SetSecure = f_Secure;
	nats_dl.natsOptions_SetServers = f_Servers;
	nats_dl.natsOptions_SetUserInfo = f_UserInfo;
	nats_dl.natsOptions_SetToken = f_Token;
	nats_dl.natsOptions_SetUserCredentialsFromFiles = f_Creds;
	nats_dl.natsOptions_SetNKeyFromSeed = f_NKey;
	nats_dl.natsConnection_Connect = f_Connect;
	nats_dl.natsConnection_GetConnectedUrl = f_ConnUrl;
	nats_dl.natsConnection_DrainTimeout = f_DrainTimeout;
	nats_dl.natsConnection_Destroy = f_ConnDestroy;
	nats_dl.jsOptions_Init = f_jsOptInit;
	nats_dl.jsPubOptions_Init = f_PubOptInit;
	nats_dl.natsConnection_JetStream = f_JetStream;
	nats_dl.jsCtx_Destroy = f_jsDestroy;
	nats_dl.js_PublishAsyncComplete = f_PubAsyncComplete;
	nats_dl.natsMsg_Destroy = f_MsgDestroy;
	nats_dl.js_PublishMsgAsync = f_PubMsgAsync;
	nats_dl.js_KeyValue = f_KeyValue;
	nats_dl.js_CreateKeyValue = f_CreateKeyValue;
	nats_dl.kvStore_Destroy = f_kvDestroy;
}

static void reset_recorders(void)
{
	memset(&nf, 0, sizeof nf);
	nf.auth_status = NATS_OK;
	nf.connect_status = NATS_OK;
	nf.servers_status = NATS_OK;
	nf.resend_status = NATS_OK;
	nf.kv_bind_status = NATS_OK;
	nf.connurl_status = NATS_OK;
	nf.last_no_randomize = -1;
	nf.last_reconnect_buf = -1;
	nf.last_secure = -1;
	nf.last_max_reconnect = -2;
	nf.last_max_pings_out = -1;
	nf.last_retry_on_failed = -1;
	nf.last_ping_interval = -1;
	nf.last_reconnect_wait = -1;
	nf.last_jitter = -1;
	nf.last_jitter_tls = -1;
	nf.last_maxwait = -1;
	nf.last_msgid = "unset";
}

/* ── log capture (nats_ut_log.h) ─────────────────────────────────── */

size_t nats_ut_log_raw(char *buf, size_t size)
{ return ut_log_raw(buf, size); }

const char *nats_ut_log(void)
{ return ut_log(); }

void nats_ut_log_clear(void)
{ ut_log_clear(); }

/* ── scenarios ──────────────────────────────────────────────────── */

void nats_ut_begin(void)
{
	nats_dl_test_fake(1);
	fill_table();
	reset_recorders();
	nats_pool_test_reset();
	ut_log_start(L_WARN);
}

void nats_ut_end(void)
{
	/* the pool is closed through the fakes, before they go */
	nats_pool_test_reset();
	ut_log_stop();
	nats_dl_test_fake(0);
}

void nats_ut_run(const char *name, nats_ut_scenario_f f)
{
	const char *log = "";
	int passed;

	nats_ut_begin();
	passed = f();
	if (!passed)
		log = nats_ut_log();
	nats_ut_end();
	ok(passed, "%s", name);
	if (!passed)
		diag("log of the failed scenario:\n%s", log);
}
