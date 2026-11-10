/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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

/*
 * cachedb_nats_watch.c -- Self-healing KV watcher for NATS JetStream
 *
 * Architecture overview:
 *
 * This module implements a resilient, self-healing watcher that
 * monitors a NATS JetStream KV bucket for changes.  The watcher runs
 * in its own dedicated OpenSIPS child process (nats_watcher_proc_main,
 * forked via proc_export_t) for the lifetime of the server and drives
 * two downstream subsystems:
 *
 *   1. JSON full-text search index -- kept in sync with live KV mutations
 *      so that script-level FTS queries always reflect the latest state.
 *
 *   2. EVI events (E_NATS_KV_CHANGE) -- raised for every put/delete/purge
 *      so that OpenSIPS routing scripts can react to KV changes in real time.
 *
 * The thread follows a four-step loop:
 *
 *   1. Wait for NATS connectivity (poll nats_pool_is_connected).
 *   2. Acquire a fresh KV handle and create a kvWatcher on the bucket
 *      (UpdatesOnly, with optional key pattern).
 *   3. Rebuild the search index from the full bucket contents
 *      (crash-recovery path), with the watcher already buffering any
 *      concurrent mutations.
 *   4. Process live nats_dl.kvWatcher_Next() updates until disconnect or
 *      reconnect-epoch change, then loop back to step 1.
 *
 * On disconnect, the watcher is stopped BEFORE nats.c tears down internal
 * subscription state, avoiding a use-after-free race.  On reconnect, the
 * epoch check triggers a full index rebuild so the index never drifts.
 *
 * Thread safety: _watcher_running is an atomic_int accessed with
 * atomic_load/atomic_store.  An acquire fence after epoch-change detection
 * ensures subsequent KV operations see the new connection state.
 */

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <nats/nats.h>

#include "../../dprint.h"
#include "../../str.h"
#include "../../ipc.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

/* Module-scope params defined in cachedb_nats.c. */
extern int index_resync_on_reconnect;

/* EVI support (evi_publish_event / evi_raise_event).  The Makefile
 * always defines HAVE_EVI for this module, so the former #ifdef guards
 * and standalone-stub arm were dead and have been removed. */
#include "../../evi/evi.h"
#include "../../evi/evi_params.h"

#include "cachedb_nats_json.h"
#include "cachedb_nats_watch.h"
#include "cachedb_nats_watch_resume.h"
#include "cachedb_nats_dbase.h"
#include "cachedb_nats_stats.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"

/* Module globals from cachedb_nats.c are declared extern in
 * cachedb_nats_dbase.h (kv_bucket, kv_replicas, kv_history, kv_ttl)
 * which is included above; redeclaring them here triggers gcc's
 * -Wredundant-decls under -Werror.  fts_json_prefix isn't yet in a
 * header, so it stays as a single extern below. */
extern char *fts_json_prefix;
extern int   fts_json_prefix_len;   /* cached at mod_init */

/* ---- watcher state (process-local to the dedicated watcher proc) ---- */
static atomic_int      _watcher_running = 0;
/* _watcher is written by the watcher loop (create + per-iteration
 * teardown); every teardown path atomic_exchange()s it to NULL so only
 * the caller that observes the non-NULL value owns the Stop/Destroy —
 * overlapping teardown can never double-free.  (Kept atomic even though
 * the dedicated process is single-threaded: cnats callbacks run on
 * library threads.) */
static _Atomic(kvWatcher *) _watcher    = NULL;

/* Multiple watch patterns -- set by nats_watcher_proc_main() from the
 * kv_watch modparam list, read by the loop.
 * When _num_patterns == 0, watches all keys via nats_dl.kvStore_WatchAll().
 * When > 0, uses nats_dl.kvStore_WatchMulti() for selective watching. */
static const char    **_watch_patterns  = NULL;
static int             _num_patterns    = 0;

/* ---- EVI event for E_NATS_KV_CHANGE ---- */
/* Non-static: set by mod_init() in cachedb_nats.c via evi_publish_event() */
event_id_t evi_kv_change_id = EVI_ERROR;

/* ---- forward declarations ---- */
static void  watcher_loop(void);
static void  raise_kv_change_event(kvEntry *entry, kvOperation op);

/* ------------------------------------------------------------------ */
/*  EVI event raising via IPC (thread-safe)                            */
/* ------------------------------------------------------------------ */

/*
 * Architecture: The watcher runs in the dedicated watcher process, not
 * in a SIP worker.  EVI subscribers run in SIP workers, so the watcher
 * copies event data into a shm_malloc'd struct and dispatches an IPC
 * RPC to a SIP worker, where the EVI functions (which use pkg_malloc)
 * run safely in the reactor context.
 *
 * Flow:  watcher proc → shm_malloc + copy → ipc_dispatch_rpc → worker raises EVI → shm_free
 */

/**
 * IPC event struct -- carries KV change data from the watcher proc to a worker.
 * Single allocation with flexible array for key + value strings.
 */
struct kv_change_ipc_event {
	kvOperation op;
	int         revision;
	int         key_len;
	int         val_len;   /* 0 when op != kvOp_Put */
	char        data[0];   /* key\0[value\0] packed */
};

/**
 * kv_change_rpc_cb() -- IPC callback that raises the EVI event.
 *
 * Runs in a SIP worker's reactor context where pkg_malloc is safe.
 * Reconstructs the event parameters from the shm struct, raises the
 * EVI event, then frees the shm allocation.
 */
static void kv_change_rpc_cb(int sender, void *param)
{
	struct kv_change_ipc_event *ev = (struct kv_change_ipc_event *)param;
	evi_params_t *params;
	str key_str, op_str, val_str;
	int rev;

	static str pn_key = str_init("key");
	static str pn_op  = str_init("operation");
	static str pn_val = str_init("value");
	static str pn_rev = str_init("revision");

	LM_DBG("kv-change worker handler: sender=%d evi_id=%d probe=%d "
		"key_len=%d val_len=%d\n",
		sender, (int)evi_kv_change_id,
		evi_probe_event(evi_kv_change_id),
		ev->key_len, ev->val_len);

	/* Short-circuit if no subscribers */
	if (evi_kv_change_id == EVI_ERROR || !evi_probe_event(evi_kv_change_id))
		goto done;

	params = evi_get_params();
	if (!params)
		goto done;

	/* Reconstruct strings from packed data */
	key_str.s   = ev->data;
	key_str.len = ev->key_len;

	switch (ev->op) {
		case kvOp_Put:    op_str = (str){.s = "put",    .len = 3}; break;
		case kvOp_Delete: op_str = (str){.s = "delete", .len = 6}; break;
		default:          op_str = (str){.s = "purge",  .len = 5}; break;
	}

	if (evi_param_add_str(params, &pn_key, &key_str) < 0)
		goto err;
	if (evi_param_add_str(params, &pn_op, &op_str) < 0)
		goto err;

	if (ev->op == kvOp_Put && ev->val_len > 0) {
		val_str.s   = ev->data + ev->key_len + 1; /* after key\0 */
		val_str.len = ev->val_len;
		if (evi_param_add_str(params, &pn_val, &val_str) < 0)
			goto err;
	}

	rev = ev->revision;
	if (evi_param_add_int(params, &pn_rev, &rev) < 0)
		goto err;

	if (evi_raise_event(evi_kv_change_id, params) < 0)
		LM_ERR("failed to raise E_NATS_KV_CHANGE event\n");
	goto done;

err:
	evi_free_params(params);
done:
	shm_free(ev);
}

/**
 * raise_kv_change_event() -- Dispatch a KV change to the EVI subsystem.
 *
 * Called from the watcher process.  Copies event data into shared memory
 * and dispatches an IPC RPC to a SIP worker for safe EVI event raising.
 * No pkg_malloc is used in this function -- only shm_malloc (thread-safe)
 * and ipc_dispatch_rpc (atomic pipe write, thread-safe).
 *
 * @param entry  The kvEntry delivered by nats_dl.kvWatcher_Next().
 * @param op     The KV operation type (put, delete, or purge).
 */
#ifdef UNIT_TESTS
/* the unit tests see the events the watcher raises */
int (*cn_ut_kv_change_dispatch)(ipc_rpc_f *rpc, void *param) = ipc_dispatch_rpc;
#define KV_CHANGE_DISPATCH(cb, ev) cn_ut_kv_change_dispatch((cb), (ev))
#else
#define KV_CHANGE_DISPATCH(cb, ev) ipc_dispatch_rpc((cb), (ev))
#endif

static void raise_kv_change_event(kvEntry *entry, kvOperation op)
{
	struct kv_change_ipc_event *ev;
	const char *key;
	const char *val = NULL;
	int key_len, val_len = 0;
	unsigned long alloc_size;
	kvOperation eff_op = op;

	if (evi_kv_change_id == EVI_ERROR)
		return;

	key     = nats_dl.kvEntry_Key(entry);
	if (!key) {
		LM_WARN("kv-change: entry has NULL key, skipping event\n");
		return;
	}
	key_len = strlen(key);

	if (op == kvOp_Put) {
		val     = nats_dl.kvEntry_ValueString(entry);
		val_len = nats_dl.kvEntry_ValueLen(entry);
		if (!val) val_len = 0;
		/* A server-side MaxAge/TTL expiry (and our own delete markers)
		 * surface via cnats (<=3.12) as an empty-value Put.  The index
		 * treats that as a REMOVE (watch_index_action); raise it to EVI
		 * subscribers as a delete too, so presence-tracking scripts see the
		 * key vanish rather than a phantom "put" for a now-absent key. */
		if (val_len == 0)
			eff_op = kvOp_Delete;
	}

	/* Single shm allocation: struct + key\0 + [value\0] */
	alloc_size = sizeof(*ev) + key_len + 1
		+ (val_len > 0 ? val_len + 1 : 0);

	ev = shm_malloc(alloc_size);
	if (!ev) {
		LM_ERR("shm_malloc failed for KV change event (%lu bytes)\n",
			alloc_size);
		return;
	}

	ev->op       = eff_op;
	ev->revision = (int)nats_dl.kvEntry_Revision(entry);
	ev->key_len  = key_len;
	ev->val_len  = val_len;

	/* Pack key into data[] */
	memcpy(ev->data, key, key_len);
	ev->data[key_len] = '\0';

	/* Pack value after key (put operations only) */
	if (val_len > 0) {
		memcpy(ev->data + key_len + 1, val, val_len);
		ev->data[key_len + 1 + val_len] = '\0';
	}

	/* Dispatch to a SIP worker -- atomic pipe write, pthread-safe */
	LM_DBG("kv-change dispatch: key=%s op=%d val_len=%d\n",
		key, (int)op, val_len);
	if (KV_CHANGE_DISPATCH(kv_change_rpc_cb, ev) < 0) {
		LM_ERR("ipc_dispatch_rpc failed for KV change event\n");
		shm_free(ev);
	}
}

/* ------------------------------------------------------------------ */
/*  watcher_loop() -- shared self-healing event loop                  */
/* ------------------------------------------------------------------ */

/*
 * The self-healing loop body, called by the dedicated-process main
 * (nats_watcher_proc_main).  Loops while
 * _watcher_running is non-zero; the running flag is set to 1 before
 * this is called and is
 * cleared only by the OpenSIPS core sending SIGTERM (which
 * terminates the process directly).
 */

/*: classify the index action for a
 * watched KV entry.  cnats 3.12 surfaces a server-side MaxAge TTL-expiry as an
 * EMPTY-VALUE kvOp_Put (NOT a Delete/Purge op); treating that as a REMOVAL is
 * what keeps the forward index from pointing at a vanished key once per-message
 * TTL is enabled.  Pure (carried-copy unit: test/test_watcher_loop.c). */
enum watch_idx_action { WATCH_IDX_SKIP = 0, WATCH_IDX_ADD = 1, WATCH_IDX_REMOVE = 2 };
static enum watch_idx_action watch_index_action(int op, int val_len, char val0)
{
	if (op == kvOp_Delete || op == kvOp_Purge)
		return WATCH_IDX_REMOVE;
	if (op == kvOp_Put) {
		if (val_len <= 0)
			return WATCH_IDX_REMOVE;   /* empty-value Put = MaxAge tombstone */
		if (val0 == '{')
			return WATCH_IDX_ADD;      /* JSON doc; prefix checked at call site */
	}
	return WATCH_IDX_SKIP;
}

/* Last sequence of the bucket's stream (KV_<bucket>); 0 on success. */
static int watch_stream_last_seq(uint64_t *last)
{
	char          sname[160];
	jsCtx        *js;
	jsStreamInfo *si = NULL;
	jsErrCode     jerr = 0;
	int           n;

	js = nats_pool_get_js();
	if (!js)
		return -1;
	n = snprintf(sname, sizeof sname, "KV_%s", kv_bucket);
	if (n < 0 || n >= (int)sizeof sname)
		return -1;
	if (nats_dl.js_GetStreamInfo(&si, js, sname, NULL, &jerr) != NATS_OK
			|| !si) {
		if (si)
			nats_dl.jsStreamInfo_Destroy(si);
		return -1;
	}
	*last = si->State.LastSeq;
	nats_dl.jsStreamInfo_Destroy(si);
	return 0;
}

static void watcher_loop(void)
{
	kvEntry        *entry = NULL;
	natsStatus      s;
	kvWatchOptions  opts;
	kvStore        *kv;
	kvWatcher      *w;
	nats_epoch_t    watch_epoch;   /* tag of this build's KV */
	int             prefix_len;
	int             builds = 0;   /* successful watcher (re)builds so far */
	struct watch_resume resume = {0};  /* next revision to deliver */
	uint64_t        stream_last, start_rev;
	int             have_last, reset;

	prefix_len = fts_json_prefix_len;   /* cached */

	while (atomic_load(&_watcher_running)) {

		/* ---- Wait for NATS connection ----
		 * Poll every 500ms until the pool reports connectivity.
		 * This covers both initial startup and post-disconnect recovery. */
		while (atomic_load(&_watcher_running) && !nats_pool_is_connected()) {
			usleep(500000); /* 500ms */
		}
		if (!atomic_load(&_watcher_running))
			break;

		nats_epoch_save(&watch_epoch);

		/* ---- Get fresh KV handle + rebuild search index ----
		 * After every reconnect the old KV handle is stale.  We obtain
		 * a new one from the pool and do a full index rebuild so the
		 * search index is consistent with the actual bucket state. */
		kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
			(int64_t)kv_ttl);
		if (!kv) {
			LM_ERR("watcher: failed to get KV handle, retrying in 2s\n");
			sleep(2);
			continue;
		}

		/* ---- Create the kvWatcher BEFORE the snapshot rebuild ----
		 * The first build starts at the end of the bucket's stream (new
		 * changes only); every rebuild resumes right after the last
		 * revision delivered, so the changes made while the connection
		 * was down -- and while this loop noticed the reconnect -- still
		 * raise E_NATS_KV_CHANGE, and none is delivered twice.  Only when
		 * the stream state cannot be read before the first build does it
		 * fall back to UpdatesOnly.  Subscribing FIRST means any Put/Delete that lands during
		 * the (potentially slow, O(N)) rebuild below is captured in the
		 * watcher's pending queue and applied by the consume loop after the
		 * index swap -- closing the (snapshot, subscribe) window that would
		 * otherwise drop those mutations from the FTS index until the next
		 * reconnect.  The overlap (a key present in both the snapshot and a
		 * buffered update) is idempotent: entry_add_key dedups on the
		 * interned key and the remove paths are membership-gated.
		 *
		 * Create into a local handle, then publish it atomically -- libnats
		 * wants a plain kvWatcher**, so we cannot pass &_watcher (_Atomic). */
		stream_last = 0;
		have_last = (watch_stream_last_seq(&stream_last) == 0);
		start_rev = watch_resume_start(&resume, have_last, stream_last,
			&reset);
		if (reset)
			LM_WARN("watcher: KV bucket '%s' restarted at revision %llu "
				"(bucket recreated?); changes before that are not "
				"replayed\n", kv_bucket, (unsigned long long)stream_last);
		nats_dl.kvWatchOptions_Init(&opts);
		if (start_rev)
			opts.ResumeFromRevision = start_rev;
		else
			opts.UpdatesOnly = true;
		w = NULL;
		s = nats_dl.kvStore_WatchMulti(&w, kv,
			_watch_patterns, _num_patterns, &opts);
		if (s != NATS_OK) {
			LM_ERR("watcher: kvStore_WatchMulti failed: %s, "
				"retrying in 2s\n", nats_dl.natsStatus_GetText(s));
			sleep(2);
			continue;
		}
		atomic_store(&_watcher, w);

		/* index_resync_on_reconnect (default 1): rebuild the JSON index in
		 * full from KV, now that the watcher above is already capturing
		 * concurrent mutations.  The query path has stale-entry self-heal, so
		 * operators may opt out of the O(N) rebuild for hot-reconnect
		 * topologies and accept a brief window where queries may evict a few
		 * stale entries before the index converges. */
		if (cdbn_fts_on && index_resync_on_reconnect) {
			if (cdbn_fts.rebuild(kv, fts_json_prefix) < 0)
				LM_WARN("post-reconnect index rebuild failed; "
					"keeping the prior index (periodic resync "
					"will retry)\n");
		} else
			LM_DBG("watcher: index_resync_on_reconnect=0; "
				"skipping post-reconnect rebuild and "
				"deferring to lazy self-heal\n");

		/* Count every (re)build after the initial one as a restart:
		 * the loop only re-enters here after a reconnect/disconnect tore
		 * down the previous watcher + KV handle.  A climbing counter
		 * flags a flapping broker connection. */
		if (builds++ > 0)
			NATS_CDB_STATS_INC(watcher_restarts);

		LM_INFO("watcher: watching KV (%d pattern(s), epoch: %d, "
			"from revision %llu)\n", _num_patterns, watch_epoch.seen,
			(unsigned long long)start_rev);

		/* ---- Event loop ----
		 * Process live KV updates until a reconnect or disconnect
		 * invalidates the current watcher and KV handle. */
		unsigned orphan_poll = 0;
		while (atomic_load(&_watcher_running)) {
			/* Orphan watchdog (dedicated watcher process): if the parent
			 * died and PR_SET_PDEATHSIG didn't fire, the kernel reparents us
			 * to PID 1.  The NATS_TIMEOUT arm below also checks this, but a
			 * broker delivering a steady update stream never times out -- so
			 * poll here too, rate-limited (every 256 iterations) to keep
			 * getppid() off the per-event hot path.
			 * NB: compare against the pre-fork pid, not 1 — opensips main
			 * is PID 1 in a container, see nats_cdb_parent_gone(). */
			if ((++orphan_poll & 0xFF) == 0 && nats_cdb_parent_gone()) {
				LM_NOTICE("watcher: parent gone (reparented to init); "
					"exiting\n");
				atomic_store(&_watcher_running, 0);
				break;
			}

			/* Check for reconnect -- epoch changed means connection
			 * was lost and restored; our KV handle and watcher are
			 * stale. Break out for a full rebuild. */
			if (!nats_epoch_current(&watch_epoch)) {
				/* Memory barrier: ensure subsequent KV operations
				 * (the rebuild path above) see the new connection
				 * state established by the reconnect callback thread. */
				atomic_thread_fence(memory_order_acquire);
				LM_INFO("watcher: reconnect detected (epoch %d->%d), "
					"restarting\n", watch_epoch.seen,
					nats_pool_get_reconnect_epoch());
				break;
			}

			/* Check for disconnect -- if NATS is down, stop the
			 * watcher BEFORE nats.c's reconnection logic destroys
			 * internal subscription state (race -> free(): invalid
			 * pointer).  Short timeout (500ms) minimizes the window
			 * where nats_dl.kvWatcher_Next() is blocked with stale state. */
			if (!nats_pool_is_connected()) {
				LM_INFO("watcher: disconnect detected, stopping "
					"watcher to prevent use-after-free\n");
				break;
			}

			s = nats_dl.kvWatcher_Next(&entry,
				atomic_load(&_watcher), 500);

			if (s == NATS_TIMEOUT) {
				/* Belt-and-suspenders for the dedicated-process
				 * topology (dedicated watcher process): if our parent died and
				 * PR_SET_PDEATHSIG somehow didn't fire (kernel
				 * version with the bug, prctl rejected, etc.),
				 * the kernel re-parents us to PID 1.  Detect
				 * that here and exit so we never become an
				 * orphan watcher.  Cheap on every 500 ms tick.
				 * NB: pre-fork pid, not 1 — main is PID 1 in a
				 * container, see nats_cdb_parent_gone(). */
				if (nats_cdb_parent_gone()) {
					LM_NOTICE("watcher: parent gone "
						"(reparented to init); exiting\n");
					atomic_store(&_watcher_running, 0);
					break;
				}
				continue;
			}

			if (s != NATS_OK) {
				if (atomic_load(&_watcher_running))
					LM_WARN("watcher: kvWatcher_Next failed: %s\n",
						nats_dl.natsStatus_GetText(s));
				break;
			}

			/* a resumed watcher signals "caught up" with no entry */
			if (!entry)
				continue;

			watch_resume_seen(&resume, nats_dl.kvEntry_Revision(entry));

			const char   *key = nats_dl.kvEntry_Key(entry);
			kvOperation   op  = nats_dl.kvEntry_Operation(entry);

			/* A NULL key would crash strncmp / index_add below.
			 * Drop the entry and keep watching. */
			if (!key) {
				LM_WARN("watcher: entry has NULL key, skipping\n");
				nats_dl.kvEntry_Destroy(entry);
				entry = NULL;
				continue;
			}

			if (cdbn_fts_on) {
				/* one strlen at the cnats boundary; the
				 * index entry points take (key, key_len). */
				int         fts_key_len = (int)strlen(key);
				const char *val     = (op == kvOp_Put) ?
					nats_dl.kvEntry_ValueString(entry) : NULL;
				int         val_len = (op == kvOp_Put) ?
					nats_dl.kvEntry_ValueLen(entry) : 0;
				enum watch_idx_action act =
					watch_index_action(op, val_len, val ? val[0] : 0);

				if (act == WATCH_IDX_ADD) {
					/* Only index keys that match the JSON prefix.
					 * Non-JSON keys are silently skipped -- no spam. */
					if (prefix_len == 0 ||
					    strncmp(key, fts_json_prefix, prefix_len) == 0)
						cdbn_fts.add(key, fts_key_len,
							val, val_len);
				} else if (act == WATCH_IDX_REMOVE) {
					/* Delete/Purge OR an empty-value Put (MaxAge
					 * tombstone).  Fast path: remove only the
					 * entries this doc was indexed under (O(fields));
					 * on a reverse-map miss fall back to the full walk.
					 * The revmap return is the PRECISE membership signal:
					 * 0 => the key WAS indexed (revmap had its fv set) and
					 * is now removed; <0 => no revmap record (a full-walk
					 * fallback covers a possibly-stale entry). */
					int before = cdbn_fts.count();
					int was_indexed =
						(cdbn_fts.remove_by_revmap(key,
							fts_key_len) == 0);
					if (!was_indexed)
						cdbn_fts.remove(key, fts_key_len);
					/* Observability: a server-side TTL expiry
					 * surfaces (cnats <=3.12) as an empty-value Put;
					 * logged at DBG: it fires once per expired
					 * registration on the watcher hot path (a steady
					 * per-expiry stream at scale), exactly like its
					 * delete/purge sibling below.  The
					 * "was indexed -> removed" membership outcome is the
					 * authoritative signal that the index (not just the
					 * read-path filter) released the key; num_documents is
					 * a supplementary delta-counter (note: it over-counts
					 * a node's own writes because they are indexed both
					 * inline and via this watcher echo — a known stat
					 * caveat, not a membership error).  Ordinary
					 * Delete/Purge markers from our own writes are
					 * frequent, so they stay at DBG to avoid log spam. */
					if (op == kvOp_Put)
						LM_DBG("watcher: MaxAge tombstone (empty-value) "
							"on '%s' -> index entry %s (num_documents "
							"%d->%d)\n", key,
							was_indexed ? "removed (was indexed)"
							            : "not in revmap; full-walk fallback",
							before, cdbn_fts.count());
					else
						LM_DBG("watcher: delete/purge marker on '%s' -> "
							"index entry %s (num_documents %d->%d)\n", key,
							was_indexed ? "removed" : "full-walk fallback",
							before, cdbn_fts.count());
				}
			}

			/* Raise EVI event for downstream script consumers */
			raise_kv_change_event(entry, op);

			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
		}

		/* ---- Cleanup before retry ----
		 * Destroy the stale watcher.  atomic_exchange claims the
		 * handle: whoever swaps the non-NULL value to NULL owns the
		 * Stop/Destroy, so an overlapping teardown can never
		 * double Stop/Destroy. */
		{
			kvWatcher *w_claim = atomic_exchange(&_watcher, NULL);
			if (w_claim) {
				nats_dl.kvWatcher_Stop(w_claim);
				/* Destroy unconditionally.  The old code skipped
				 * this when the broker was down (suspected
				 * double-free against nats.c's I/O thread) and
				 * leaked one handle per flap cycle into
				 * watcher_handle_leaks.  The suspicion was
				 * refuted live: 10 SIGKILL broker-flap cycles,
				 * Stop+Destroy on a disconnected connection with
				 * the reconnect thread running, ASan-clean on the
				 * pinned libnats (10 SIGKILL broker-flap cycles).
				 * nats.c refcounts the underlying
				 * subscription, so user-thread Destroy is safe in
				 * any connection state. */
				nats_dl.kvWatcher_Destroy(w_claim);
			}
		}

		/* Brief pause before restarting to avoid tight loop on
		 * repeated failures.  Wait longer if disconnected -- let
		 * nats.c finish reconnection before we retry. */
		if (atomic_load(&_watcher_running)) {
			if (nats_pool_is_connected())
				usleep(250000);  /* 250ms */
			else
				usleep(1000000); /* 1s -- wait for reconnect */
		}
	}
}
/* ------------------------------------------------------------------ */

/* The kv_watch_list / kv_watch_count globals are owned by
 * cachedb_nats.c; their declarations live in cachedb_nats_watch.h
 * so this translation unit can read them without a duplicate decl. */

/**
 * nats_watcher_proc_main() -- dedicated-process watcher entry point.
 *
 * Forked by the OpenSIPS core via the proc_export_t entry registered
 * in cachedb_nats.c when at least one kv_watch pattern is
 * configured.  The function never returns.
 * This is the ONLY watcher mode: the process runs a single thread
 * against the connection pool, so it has none of the pool races the
 * removed in-worker pthread mode had.
 *
 * It calls nats_pool_get() to bring up the
 * per-process NATS connection (nats_pool_register having seeded the
 * shared config in mod_init pre-fork), validates the KV bucket, and
 * enters the self-healing loop.  Index updates are
 * written to the SHM-backed g_idx that every SIP worker also maps;
 * the per-shard locks added in commit 43ceca02b serialise the
 * cross-process writes safely without any new synchronisation.
 *
 * Signal handling: relies on the OpenSIPS core's default SIGTERM
 * delivery to children -- the kernel terminates the process on
 * shutdown, the SHM handles are released as part of process exit,
 * and the parent's destroy() path frees g_idx itself.
 */
/*
 * Shared bring-up for the module's dedicated processes (the KV
 * watcher and the reaper).  Parent-death handling: if the OpenSIPS
 * master process exits (orderly shutdown OR a pre-fork abort like a
 * failed mi_init_datagram_server), the kernel must reap us.  Without
 * this we orphan: linux re-parents to PID 1, the proc loop keeps
 * running forever, and the next OpenSIPS startup races with a stale
 * child writing to the SHM of a freshly-allocated bucket.  Reproduces
 * 100% of the time when the master aborts after the proc_export_t fork
 * but before start_module_procs returns successfully -- e.g., when a
 * sibling module's pre-fork hook fails.
 *
 * Use SIGKILL rather than SIGTERM.  OpenSIPS core installs a SIGTERM
 * handler in every forked child that does graceful shutdown via
 * destroy(); under PDEATHSIG that handler runs but its cleanup waits
 * on shared resources owned by the already-dead parent, leaving us
 * hung.  SIGKILL is uncatchable -- the kernel kills the process
 * immediately and reclaims its pages on schedule.  Parent-owned SHM is
 * freed when the parent's destroy() path runs (orderly shutdown) or
 * when the kernel reaps the SHM segment after the last attached
 * process exits.
 *
 * Also brings up the per-process NATS connection: nats_pool_get() is
 * lazy-init -- the first call in this process opens the connection
 * from the shared pool config that mod_init built.
 *
 * Returns 0 to proceed, -1 when the caller must exit (parent already
 * dead, or no NATS connection can be established).
 */
/* Captured by cachedb_nats mod_init() in the MAIN process, before any fork.
 * 0 until then, which nats_cdb_parent_gone() treats as "cannot tell". */
pid_t nats_cdb_parent_pid;

int nats_cdb_parent_gone(void)
{
	/* Never claim orphanhood we cannot prove: if mod_init did not run in
	 * this process image (or ran after a fork), stay alive rather than
	 * take the whole daemon down via SIGCHLD. */
	if (nats_cdb_parent_pid == 0)
		return 0;

	return getppid() != nats_cdb_parent_pid;
}

int nats_cdb_dedicated_proc_guard(const char *who)
{
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
		LM_WARN("%s proc: prctl(PR_SET_PDEATHSIG) failed: "
			"%s; orphan-on-parent-death not protected\n",
			who, strerror(errno));
	}

	/* Race window: the parent could have died between our fork() and
	 * the prctl() above.  prctl arms only future deaths, so we'd miss
	 * an already-dead parent and run forever.  Re-check the parent --
	 * against the pid captured pre-fork, NOT against 1: opensips main
	 * is itself PID 1 under Docker, so `getppid()==1` is true for every
	 * healthy child there.  See nats_cdb_parent_gone(). */
	if (nats_cdb_parent_gone()) {
		LM_NOTICE("%s proc: parent died before we armed "
			"PR_SET_PDEATHSIG (re-parented, ppid=%d, expected %d); "
			"exiting\n", who, (int)getppid(),
			(int)nats_cdb_parent_pid);
		return -1;
	}

	/* No NATS connection (no usable server configured): keep the
	 * process running, degraded, rather than take the daemon down.  Its
	 * loop gets the pool and the KV handle on every pass and skips the
	 * work while they are unavailable. */
	if (!nats_pool_get())
		LM_WARN("%s proc: NATS connection unavailable, running "
			"degraded\n", who);
	return 0;
}

void nats_watcher_proc_main(int rank)
{
	kvStore                  *kv;
	struct kv_watch_entry    *e;
	const char              **patterns;
	int                       i;

	(void)rank;

	LM_INFO("NATS watcher proc starting (pid=%d, ppid=%d)\n",
		(int)getpid(), (int)getppid());

	if (nats_cdb_dedicated_proc_guard("watcher") < 0)
		return;

	/* Validate the KV bucket exists.  The watcher loop fetches its
	 * own KV handle from the pool on each iteration anyway, but we
	 * keep this gate here for symmetry with the rank-1 child_init flow:
	 * if the bucket is missing or the broker is unreachable at
	 * startup, fail loudly rather than silently entering the
	 * reconnect loop. */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("watcher proc: failed to open KV bucket '%s'\n",
			kv_bucket);
		/* fall through -- the loop's reconnect-wait step will keep
		 * trying so a transient broker outage doesn't kill the
		 * process. */
	}

	/* Build the patterns array from the modparam-fed kv_watch_list.
	 * Single-threaded process here, so pkg memory is safe and gives
	 * OpenSIPS's accounting; it stays alive for the lifetime of the
	 * process (reclaimed on SIGTERM), so it is never freed.
	 *
	 * mod_init forks this process ONLY when kv_watch_count > 0 (see the
	 * exports.procs gate in cachedb_nats.c), so the count is always
	 * positive here -- no _num_patterns == 0 fallback is reachable. */
	patterns = pkg_malloc((kv_watch_count + 1) * sizeof(char *));
	if (!patterns) {
		LM_ERR("watcher proc: no more pkg memory for patterns\n");
		return;
	}
	i = 0;
	for (e = kv_watch_list; e; e = e->next)
		patterns[i++] = e->pattern;
	patterns[i] = NULL;
	_watch_patterns = patterns;
	_num_patterns = kv_watch_count;

	atomic_store(&_watcher_running, 1);

	LM_INFO("watcher proc: watching %d pattern(s)\n", _num_patterns);

	/* Run forever.  SIGTERM from main on shutdown will terminate the
	 * process directly. */
	watcher_loop();

	LM_INFO("NATS watcher proc exiting\n");
}

/*
 * Periodic full-index resync handler, registered when
 * index_resync_interval_secs > 0. Acquires a fresh KV handle from the
 * pool and rebuilds the JSON-FTS search index in place. Skips silently
 * when NATS is disconnected; the next reconnect (or the next tick)
 * will retry.
 */
#ifdef UNIT_TESTS
/* run the watcher loop in this process until cn_ut_watcher_stop() */
void cn_ut_watcher_run(void)
{
	atomic_store(&_watcher_running, 1);
	watcher_loop();
}

void cn_ut_watcher_stop(void)
{
	atomic_store(&_watcher_running, 0);
}

/* what a dispatched E_NATS_KV_CHANGE event carries */
int cn_ut_kv_change_ev(void *param, int *op, const char **key, int *val_len)
{
	struct kv_change_ipc_event *ev = param;

	*op = (int)ev->op;
	*key = ev->data;
	*val_len = ev->val_len;
	return 0;
}
#endif

void nats_cdb_periodic_resync(unsigned int ticks, void *param)
{
	kvStore *kv;

	(void)ticks; (void)param;

	/* Do NOT gate on the pool's process-local "connected" flag: this
	 * handler runs in the OpenSIPS timer process, which never calls
	 * nats_pool_get() on its own, so that flag is permanently 0 and every
	 * tick used to be skipped (the periodic rebuild never ran).
	 * nats_pool_get_kv() lazily establishes the connection on first use;
	 * if the broker is genuinely down it returns NULL and we skip just
	 * this tick, retrying on the next. */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_DBG("periodic resync: no KV handle (broker down?); "
			"skipping tick\n");
		return;
	}

	if (cdbn_fts.rebuild(kv, fts_json_prefix) < 0)
		LM_WARN("periodic resync: index rebuild failed\n");
	else
		LM_DBG("periodic resync: index rebuilt\n");
}
