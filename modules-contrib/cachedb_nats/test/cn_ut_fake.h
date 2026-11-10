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
 * Fake nats module API for the cachedb_nats tests: cn_ut_fake_begin()
 * swaps this module's nats_api (pool + libnats table) and its FTS binds
 * for recorders, cn_ut_fake_end() puts the real ones back.  The fakes
 * append what they were called with to cf.seq ("get_kv,watch,rebuild,").
 */

#ifndef CN_UT_FAKE_H
#define CN_UT_FAKE_H

#include <stdint.h>

/* one KV entry a fake hands out (kvWatcher_Next / kvStore_Get) */
struct cn_ut_entry {
	int         status;          /* natsStatus of the call */
	const char *key;
	int         op;              /* kvOperation */
	const char *val;
	int         val_len;
	uint64_t    rev;
	int         disconnect;      /* Next: drop the connection first */
	int         reconnect;       /* Next: a reconnect (epoch bump) first */
};

#define CN_UT_MAX_ENTRIES 8
#define CN_UT_MAX_EVENTS  8

struct cn_ut_fake {
	char seq[1024];              /* "name," per recorded call */
	int  connected;
	int  epoch;
	int  kv_null;                /* pool_get_kv returns NULL */
	int  watch_status;
	int  updates_only;           /* the WatchMulti options seen */
	uint64_t resume_from;
	struct cn_ut_entry next[CN_UT_MAX_ENTRIES];
	int  n_next, i_next;
	struct cn_ut_entry get;      /* kvStore_Get's answer */
	int  create_status;          /* kvStore_CreateWithTTL */
	int  publish_status;         /* js_PublishMsg */
	int  publish_jerr;
	uint64_t publish_seq;        /* the ack's sequence */
	uint64_t expect_last_seq;    /* the CAS revision published at */
	char published[512];         /* the last row value written */
	const char *msg_data;        /* ... as handed to natsMsg_Create */
	int  msg_len;
	int  have_stream_last;       /* js_GetStreamInfo answers */
	uint64_t stream_last;
	char val_buf[128];           /* a mutable value (see scribble) */
	int  scribble;               /* kvEntry_Destroy overwrites val_buf */
	char *match[4];              /* query_match_keys answers these */
	int  n_match;
	int  n_release;
	int  rebuild_rc;
	int  revmap_rc;
	int  stop_on_destroy;        /* kvWatcher_Destroy ends the loop */
	int  n_entry_destroy;
	/* events the watcher dispatched (KV_CHANGE_DISPATCH) */
	int  n_events;
	int  ev_op[CN_UT_MAX_EVENTS];
	char ev_key[CN_UT_MAX_EVENTS][64];
	int  ev_val_len[CN_UT_MAX_EVENTS];
};

extern struct cn_ut_fake cf;

void cn_ut_fake_begin(void);
void cn_ut_fake_end(void);
const char *cn_ut_fake_log(void);
void cn_ut_fake_log_clear(void);
unsigned long cn_ut_fake_log_raw(char *buf, unsigned long size);
void *cn_ut_fake_kv(void);

/* A primary-key read (nats_cache_query) of AoR @aor on a fake connection
 * whose kvStore_Get returns @stored (NULL: not found).  Returns the rows
 * read (-1 on error); *n_contacts: contacts in the first row (-1 when it
 * has no contacts dict); *n_private: row_exp / schema_version peers
 * left in it. */
int cn_ut_pk_read(const char *aor, const char *stored, int *n_contacts,
	int *n_private);

/* UNIT_TESTS seams in the module */
void cn_ut_watcher_run(void);
void cn_ut_watcher_stop(void);
int  cn_ut_kv_change_ev(void *ev, int *op, const char **key, int *val_len);
extern int (*cn_ut_kv_change_dispatch)(void (*rpc)(int, void *), void *param);

#endif
