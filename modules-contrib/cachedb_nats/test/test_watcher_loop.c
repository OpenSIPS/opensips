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
 * The KV watcher loop (watcher_loop, cachedb_nats_watch.c), run in this
 * process on fakes (cn_ut_fake.h) through the UNIT_TESTS seam
 * cn_ut_watcher_run():
 *   - it subscribes BEFORE it rebuilds the index: a Put/Delete landing
 *     during the O(N) rebuild is queued by the watcher, not lost
 *     (test_watcher_subscribe_order);
 *   - on a disconnect, a reconnect and a Next failure it Stops AND
 *     Destroys the watcher handle, and watcher_handle_leaks stays put
 *     (test_watcher_destroy_policy, test_watcher_leak_stat; LOST: the MI
 *     emitting the counter);
 *   - an entry with a NULL key is dropped, nothing indexed or raised
 *     (test_watch_null_key_guard);
 *   - an empty-value Put (a server-side MaxAge expiry as cnats surfaces
 *     it) removes the key from the index (test_ttl_watch_marker) and is
 *     raised to E_NATS_KV_CHANGE as a delete (test_watch_evi_expire_op);
 *     a Put with a value is indexed (prefix keys only) and raised as a put.
 * Replaces those five source-pattern / model tests.
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../evi/evi_modules.h"
#include "../cachedb_nats_stats.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

extern event_id_t evi_kv_change_id;
extern int index_resync_on_reconnect;

#define CHECK(cond, msg) ok((cond), "watcher_loop: %s", (msg))

/* this process's watcher_handle_leaks (-1: no stats) */
static long leaks(void)
{
	nats_cdb_stats_t *s = nats_cdb_stats_slot();

	return s ? (long)atomic_load(&s->watcher_handle_leaks) : -1;
}

static void entry(int i, int status, const char *key, int op, const char *val)
{
	cf.next[i].status = status;
	cf.next[i].key = key;
	cf.next[i].op = op;
	cf.next[i].val = val;
	cf.next[i].val_len = val ? (int)strlen(val) : 0;
	cf.next[i].rev = (uint64_t)(i + 10);
	if (i + 1 > cf.n_next)
		cf.n_next = i + 1;
}

void cn_ut_watcher_loop(void)
{
	long leaks0;
	int got;

	diag("subscribe first, then rebuild:");
	cn_ut_fake_begin();
	cn_ut_watcher_run();
	got = strncmp(cf.seq, "get_kv,stream_info:KV_unit_tests,watch,rebuild,", 47) == 0;
	CHECK(got, "get_kv, then the watcher, then the index rebuild");
	CHECK(strstr(cf.seq, "stop,destroy,") != NULL, "the watcher is torn down at the end");
	CHECK(cf.updates_only, "first build without stream state: updates only");
	diag("seq: %s", cf.seq);
	cn_ut_fake_end();

	cn_ut_fake_begin();
	index_resync_on_reconnect = 0;
	cn_ut_watcher_run();
	CHECK(strstr(cf.seq, "rebuild") == NULL,
		"index_resync_on_reconnect=0: no rebuild after the subscribe");
	cn_ut_fake_end();

	diag("disconnect: Stop + Destroy, no leak counted:");
	cn_ut_fake_begin();
	leaks0 = leaks();
	entry(0, NATS_OK, NULL, 0, NULL);      /* caught up ... */
	cf.next[0].disconnect = 1;             /* ... and the broker drops */
	cf.stop_on_destroy = 1;
	cn_ut_watcher_run();
	CHECK(strstr(cf.seq, "watch,rebuild,stop,destroy,") != NULL,
		"disconnected: the claimed handle is stopped and destroyed");
	CHECK(leaks() == leaks0,
		"watcher_handle_leaks unchanged");
	cn_ut_fake_end();

	diag("teardown destroys in every state (test_watcher_leak_stat):");
	cn_ut_fake_begin();
	leaks0 = leaks();
	cf.next[0].status = NATS_OK;           /* a reconnect: rebuild */
	cf.next[0].reconnect = 1;
	cf.next[1].status = NATS_ERR;          /* then a Next failure */
	cf.n_next = 2;
	cn_ut_watcher_run();
	{
		int sd = 0;
		const char *p = cf.seq;
		while ((p = strstr(p, "stop,destroy,"))) { sd++; p++; }
		CHECK(sd == 3, "reconnect, Next failure and the end each Stop + Destroy the handle");
	}
	CHECK(leaks() == leaks0, "watcher_handle_leaks unchanged on every path");
	cn_ut_fake_end();

	diag("entries:");
	cn_ut_fake_begin();
	evi_kv_change_id = 1;                  /* someone subscribed */
	entry(0, NATS_OK, "json_alice", kvOp_Put, "{\"aor\":\"alice\"}");
	entry(1, NATS_OK, NULL, kvOp_Put, "{\"x\":1}");      /* NULL key */
	entry(2, NATS_OK, "json_bob", kvOp_Put, NULL);        /* MaxAge expiry */
	entry(3, NATS_OK, "json_carol", kvOp_Delete, NULL);
	entry(4, NATS_OK, "other_key", kvOp_Put, "{\"y\":2}");  /* not json_ */
	cn_ut_watcher_run();
	diag("seq: %s", cf.seq);
	CHECK(strstr(cf.seq, "add:json_alice,") != NULL, "a Put with a value is indexed");
	CHECK(strstr(cf.seq, "add:json_bob") == NULL && strstr(cf.seq, "revmap:json_bob,") != NULL,
		"an empty-value Put is REMOVED from the index, not added");
	CHECK(strstr(cf.seq, "revmap:json_bob,remove:json_bob,") != NULL,
		"revmap miss falls back to the full-walk remove");
	CHECK(strstr(cf.seq, "revmap:json_carol,") != NULL, "a Delete is removed");
	CHECK(strstr(cf.seq, "other_key") == NULL, "a key without the json_ prefix is not indexed");
	CHECK(cf.n_entry_destroy == 5, "every entry destroyed, the NULL-key one too");
	CHECK(cf.n_events == 4, "four events raised: none for the NULL key");
	CHECK(cf.n_events >= 2 && !strcmp(cf.ev_key[0], "json_alice") && cf.ev_op[0] == kvOp_Put
		&& cf.ev_val_len[0] > 0, "the Put is raised as a put with its value");
	CHECK(cf.n_events >= 2 && !strcmp(cf.ev_key[1], "json_bob") && cf.ev_op[1] == kvOp_Delete
		&& cf.ev_val_len[1] == 0, "the empty-value Put is raised as a DELETE");
	CHECK(cf.n_events >= 3 && cf.ev_op[2] == kvOp_Delete, "the Delete is raised as a delete");
	CHECK(strstr(cn_ut_fake_log(), "NULL key") != NULL, "the NULL key is logged");
	cn_ut_fake_end();
}
