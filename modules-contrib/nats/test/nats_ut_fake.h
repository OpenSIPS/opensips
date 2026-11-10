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
 * Fixture of the pool tests: a fake libnats in place of the function
 * table (nats_dl.h), recording what the pool asks it for, and a capture
 * of what the scenario logs.  No library is loaded and nothing connects.
 */

#ifndef NATS_UT_FAKE_H
#define NATS_UT_FAKE_H

#include <nats/nats.h>

#define NATS_UT_NMSG 4

/* what the fake libnats was asked for, and what it answers */
struct nats_ut_fake {
	/* answers, set by a scenario before it calls the pool */
	natsStatus auth_status;        /* of the four credential calls */
	natsStatus connect_status;     /* of natsConnection_Connect */
	natsStatus servers_status;     /* of natsOptions_SetServers */
	natsStatus resend_status;      /* of js_PublishMsgAsync */
	natsStatus kv_bind_status;     /* of js_KeyValue */
	const char *err_stack;         /* of nats_GetLastErrorStack */
	natsStatus connurl_status;     /* of natsConnection_GetConnectedUrl;
	                                * on an error the buffer is left alone */
	const char *connurl;           /* NULL: "nats://fake:4222" */

	/* connection options; -1: the setter was not called */
	int last_no_randomize;
	int last_reconnect_buf;
	int last_secure;
	int last_max_reconnect;
	int last_max_pings_out;
	int last_retry_on_failed;
	long long last_ping_interval;
	long long last_reconnect_wait;
	long long last_jitter, last_jitter_tls;
	natsConnectionHandler retry_cb, disconnected_cb, reconnected_cb;
	char last_servers[512];

	/* credentials */
	int n_auth_calls;
	char a_user[64], a_pw[64], a_token[64], a_nkey[64];
	char a_creds[256], a_creds_seed[256], a_seed[256];

	/* library and connection life cycle */
	int n_open, n_close, n_connect, n_sleep;
	long long slept_ms;
	int n_conn_destroy, n_js_destroy, n_kv_destroy, n_drain;
	int n_kv_bind, n_kv_create;
	/* order of the teardown calls: each takes the next number, 0 = never */
	int seq;
	int seq_kv_destroy, seq_async_complete, seq_js_destroy, seq_drain,
	    seq_conn_destroy;
	long long async_complete_wait; /* MaxWait of js_PublishAsyncComplete */
	long long drain_wait;          /* of natsConnection_DrainTimeout */

	/* JetStream publish acks */
	jsPubAckHandler ack_handler;   /* the one the pool installed */
	long long js_wait;             /* jsOptions.Wait handed to libnats */
	char msgs[NATS_UT_NMSG];       /* messages are plain objects */
	int destroyed[NATS_UT_NMSG];
	int n_resend;
	natsMsg *last_resent;
	long long last_maxwait;
	const char *last_msgid;
};

extern struct nats_ut_fake nf;

/* any non-NULL handle */
void *nats_ut_fake_obj(void);

/* Start a scenario: the fake table in place, the pool as at startup
 * (nothing registered, no connection, default modparams), an empty log
 * capture, log level L_WARN.  nats_ut_end() undoes all of it. */
void nats_ut_begin(void);
void nats_ut_end(void);

/* everything logged since nats_ut_begin() / nats_ut_log_clear() */
const char *nats_ut_log(void);
void nats_ut_log_clear(void);
/* the raw bytes of the capture: length, and a copy in @buf */
size_t nats_ut_log_raw(char *buf, size_t size);

/* run one scenario in a pristine pool: ok() if it returns non-zero */
typedef int (*nats_ut_scenario_f)(void);
void nats_ut_run(const char *name, nats_ut_scenario_f f);

#endif /* NATS_UT_FAKE_H */
