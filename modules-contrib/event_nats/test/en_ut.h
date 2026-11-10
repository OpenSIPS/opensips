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
 * Unit test suite of the event_nats module: one entry point per test
 * file, all run from mod_tests() (test.c), and the fixture they share
 * (en_ut_fake.c): a fake nats module API and libnats in place of the
 * bound ones, recording what the module asks them for.
 */

#ifndef EN_UT_H
#define EN_UT_H

#include <stdint.h>
#include <nats/nats.h>

void en_ut_msg_id(void);
void en_ut_stats(void);
void en_ut_publish(void);
void en_ut_degraded(void);
void en_ut_inbound(void);
void en_ut_subscription(void);
void en_ut_mi_commands(void);
void en_ut_mi_seq(void);
void en_ut_shared_params(void);

/* what the fakes were asked for, and what they answer */
struct en_ut_fake {
	/* the nats module's pool */
	natsConnection *pool_nc;       /* NULL: no connection (broker down) */
	jsCtx *pool_js;                /* NULL: no JetStream context */
	int connected, epoch;
	int should_init;               /* answer of pool_should_init() */
	int n_pool_get, n_pool_get_js, n_unregister;
	void (*pub_ack_cb)(int);       /* last one given to the pool */
	int n_set_pub_ack_cb;
	int seq;                       /* order of the calls below */
	int seq_set_pub_ack_cb, seq_unregister;
	int stats_alive_at_unregister; /* the stats table when the pool went */

	/* core publish */
	natsStatus publish_status;
	int n_publish;
	char pub_subject[600];
	char pub_data[2048];
	int pub_len;

	/* JetStream publish */
	natsStatus js_publish_status;
	int n_js_publish;
	char js_subject[600];
	char js_msg_id[300];
	long long js_max_wait;

	/* an inbound message */
	const char *msg_subject, *msg_data;
	int msg_len;
	int n_msg_destroy;

	/* subscriptions */
	natsStatus subscribe_status;
	int n_subscribe, n_queue_subscribe, n_sub_destroy, n_is_valid;
	char sub_subject[256], sub_queue[128];
	void *sub_closure;
	natsMsgHandler sub_handler;
	natsConnection *sub_nc;
	int sub_valid;                 /* answer of natsSubscription_IsValid */
	int reconnect_in_check;        /* the first IsValid call bumps the epoch */

	/* JetStream messages (MI) */
	natsStatus get_msg_status, delete_msg_status;
	jsErrCode jerr;
	int n_get_msg, n_delete_msg;
	uint64_t msg_seq;
	char msg_stream[300];
};

extern struct en_ut_fake ef;

/* any non-NULL handles */
natsConnection *en_ut_nc(void);
jsCtx *en_ut_js(void);
natsMsg *en_ut_msg(void);

/* Start a scenario: the fake API and libnats in place of the bound ones,
 * the producer without a connection, an empty log capture at L_WARN.
 * en_ut_end() puts the module back as the startup left it. */
void en_ut_begin(void);
void en_ut_end(void);

const char *en_ut_log(void);
void en_ut_log_clear(void);
size_t en_ut_log_raw(char *buf, size_t size);

/* run one scenario between en_ut_begin() and en_ut_end(): ok() if it
 * returns non-zero */
typedef int (*en_ut_scenario_f)(void);
void en_ut_run(const char *name, en_ut_scenario_f f);

/* the module's real API, as bound at startup (valid inside a scenario) */
extern struct nats_binds en_ut_real_api;

#endif /* EN_UT_H */
