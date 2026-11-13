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
 * Unit test suite of the nats_consumer module: one entry point per test
 * file, all run from mod_tests() (test.c), and the fixture they share
 * (nc_ut_fake.c): a fake libnats table in place of the bound one for the
 * length of a scenario, recording what the module asks it for.
 */

#ifndef NC_UT_H
#define NC_UT_H

#include <stddef.h>
#include <stdint.h>
#include <nats/nats.h>

void nc_ut_parser(void);
void nc_ut_parser_adversarial(void);
void nc_ut_ack_token(void);
void nc_ut_rpc_ipc_pack(void);
void nc_ut_slot_prefix_copy(void);
void nc_ut_consumer_config(void);
void nc_ut_module(void);
void nc_ut_reconcile(void);
void nc_ut_fetch(void);
void nc_ut_rpc_tunables(void);
void nc_ut_bind_bounds(void);
void nc_ut_boot_retry(void);
void nc_ut_rpc_subject(void);
void nc_ut_msg_ref(void);
void nc_ut_registry(void);
void nc_ut_ring(void);
void nc_ut_ring_spin(void);
void nc_ut_rpc_slot_lifecycle(void);
void nc_ut_rpc_slot_reaper(void);
void nc_ut_rpc_ipc_generation(void);
void nc_ut_ack_ipc_actions(void);
void nc_ut_rpc_inbox(void);
void nc_ut_rpc_wake_ipc(void);
void nc_ut_request(void);
void nc_ut_request_async(void);
void nc_ut_push(void);
void nc_ut_mi(void);
void nc_ut_mi_stats(void);
void nc_ut_doc_bind_examples(void);
void nc_ut_rpc_publish(void);
void nc_ut_resume(void);

/* module internals the suite reads (UNIT_TESTS builds only) */
int nc_ut_pool_registered(void);
void nc_ut_on_inbox_reply(natsMsg *msg);
void nc_ut_publish_slot(uint32_t slot_idx, uint32_t generation,
	natsConnection *nc);
struct nats_ring_slot;
int nc_ut_cur_set(uint16_t handle_idx, const struct nats_ring_slot *slot);
unsigned nc_ut_ensure_backoff_seconds(unsigned failures);
long nc_ut_async_poll_ns(void);
int64_t nc_ut_now_us(void);
struct nats_rpc_slot;
int nc_ut_resume_request(struct nats_rpc_slot *s, uint32_t gen,
	int64_t deadline_us, int fd);

/* what the fake libnats was asked for, and what it answers */
struct nc_ut_fake {
	/* js_GetStreamInfo / jsStreamInfo_Destroy */
	natsStatus stream_info_status;
	int64_t stream_created;        /* Created of the info answered */
	int n_stream_info, n_stream_info_destroy;
	char stream_info_name[256];

	/* the nats module's pool */
	int connected;                 /* answer of pool_is_connected() */
	int epoch;                     /* answer of pool_get_reconnect_epoch() */

	/* consumer create / subscribe (all fail unless set) */
	natsStatus add_consumer_status, pull_subscribe_status;
	int n_add_consumer, n_update_consumer, n_pull_subscribe;

	/* natsSubscription_Fetch: answers fetch_status with no messages */
	natsStatus fetch_status;
	int n_fetch, fetch_batch;
	int64_t fetch_timeout;

	/* natsMsg_Destroy: how many, and the last ones (by address) */
	int n_msg_destroy;
	natsMsg *destroyed[16];

	/* natsSubscription_Unsubscribe / _Destroy */
	int n_unsubscribe, n_sub_destroy;
	natsSubscription *sub_destroyed;

	/* the message the natsMsg_Get* fakes describe (any natsMsg *) */
	const char *msg_subject, *msg_data, *msg_reply;
	int msg_len;

	/* pool_get (NULL: no connection object), RequestMsg, natsMsg_Create */
	natsConnection *pool_nc;
	int n_request, n_msg_create;

	/* natsMsg_GetMetaData (NATS_OK when has_md) and natsMsg_Term */
	int has_md;
	uint64_t md_delivered, md_stream_seq;
	int n_term;

	/* headers: n_hdr pairs (natsMsgHeader_Keys/_Values/_Get) */
	int n_hdr;
	const char *hdr_key[4], *hdr_val[4];

	/* natsMsg_Create answers msg_create_status (a fake message on OK);
	 * natsMsgHeader_Set, natsConnection_PublishMsg and _Subscribe record,
	 * each with its place in the call order (seq) */
	natsStatus msg_create_status, publish_status, subscribe_status;
	char created_subject[256], created_reply[256], created_data[64];
	int n_hdr_set, n_publish, n_subscribe, seq, seq_last_hdr_set, seq_publish;
	char hdr_set_key[4][64], hdr_set_val[4][64];
};
extern struct nc_ut_fake nf;

/* Put the fake libnats table in place of the module's, with every
 * recorder cleared; nc_ut_end() puts the real one back. */
void nc_ut_begin(void);
void nc_ut_end(void);

/* What the module logged at WARN and above since nc_ut_begin(). */
const char *nc_ut_log(void);
void nc_ut_log_clear(void);
/* the raw bytes logged, NUL bytes and all */
size_t nc_ut_log_raw(char *buf, size_t size);

#endif /* NC_UT_H */
