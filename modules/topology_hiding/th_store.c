/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <string.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../ut.h"
#include "../../md5utils.h"
#include "../../cachedb/cachedb.h"
#include "th_store.h"

str th_state_url = {NULL, 0};
int th_state_ttl = 3600;
int th_state_ttl_short = 60;

static enum th_store_type th_store_be = TH_STORE_NONE;

static cachedb_funcs th_cdbf;
static cachedb_con *th_cdbc;

/* the stored keys are prefixed, so that the storage may be shared with
 * other users without clashing over the key names */
#define TH_KEY_PREFIX     "th:"
#define TH_KEY_PREFIX_LEN (sizeof(TH_KEY_PREFIX)-1)

int th_store_enabled(void)
{
	return th_store_be != TH_STORE_NONE;
}


/*
 * Write-coalescing cache (shared memory, one per node).
 *
 * The stored state is immutable, so re-storing it on every sequential
 * request of a dialog only ever pushes its expiration further out. This
 * cache remembers, per key, the expiry this node last wrote, and lets
 * th_store_put()/th_store_refresh() skip the backend write while the state
 * still has plenty of life left - turning a busy dialog's stream of
 * identical writes into an occasional TTL bump. With anycast/ECMP a
 * dialog's requests reach the same node, whose workers share this cache,
 * so the repeats are seen and collapsed.
 *
 * Skipping only ever drops a *redundant* write: a request that asks for a
 * shorter life than is stored (a teardown lowering the TTL) still writes,
 * and a stale or evicted entry just causes one extra write. The only
 * residual effect is that, across a node change, a state might expire
 * slightly early - which the user agent recovers from by re-establishing.
 * It is a plain best-effort hint, so a single small lock guards it.
 */
#define TH_WC_BITS  12
#define TH_WC_SIZE  (1 << TH_WC_BITS)
#define TH_WC_MASK  (TH_WC_SIZE - 1)

struct th_wc_entry {
	char   key[TH_KEY_LEN];
	int    used;
	time_t deadline;   /* absolute expiry this node last stored */
};

static struct th_wc_entry *th_wc;        /* direct-mapped, in shm */
static gen_lock_t         *th_wc_lock;

static unsigned int th_wc_slot(const char *s)
{
	unsigned int h = 2166136261u;   /* FNV-1a over the wire key */
	int i;

	for (i = 0; i < TH_KEY_LEN; i++)
		h = (h ^ (unsigned char)s[i]) * 16777619u;

	return h & TH_WC_MASK;
}

/*
 * Whether the state under @key still has to be written to last @ttl more
 * seconds. Returns 1 to write (and records the new expiry), 0 to skip
 * because a write this node already made covers it.
 */
static int th_wc_need_write(str *key, int ttl)
{
	struct th_wc_entry *e;
	time_t now;
	int    write;

	if (!th_wc || key->len != TH_KEY_LEN)
		return 1;

	now = time(NULL);
	e = &th_wc[th_wc_slot(key->s)];

	lock_get(th_wc_lock);
	if (e->used && memcmp(e->key, key->s, TH_KEY_LEN) == 0 &&
	    now + ttl >= e->deadline &&      /* not asking for a shorter life */
	    e->deadline - now >= ttl / 2) {  /* still at least half of it left */
		write = 0;
	} else {
		memcpy(e->key, key->s, TH_KEY_LEN);
		e->used = 1;
		e->deadline = now + ttl;
		write = 1;
	}
	lock_release(th_wc_lock);

	return write;
}

static void th_wc_forget(str *key)
{
	struct th_wc_entry *e;

	if (!th_wc || key->len != TH_KEY_LEN)
		return;

	e = &th_wc[th_wc_slot(key->s)];
	lock_get(th_wc_lock);
	if (e->used && memcmp(e->key, key->s, TH_KEY_LEN) == 0)
		e->used = 0;
	lock_release(th_wc_lock);
}


/*
 * The states are only ever removed by the expiration of the stored value,
 * so a backend which does not implement it would pile them up forever.
 * The cachedb interface has no way of telling whether a backend honours
 * the expire argument of its set(), hence the check on the URL scheme.
 */
static int th_store_check_scheme(void)
{
	str scheme;
	char *p;

	p = memchr(th_state_url.s, ':', th_state_url.len);
	if (!p) {
		LM_ERR("cannot extract the backend out of th_state_url %s\n",
			db_url_escape(&th_state_url));
		return -1;
	}

	scheme.s = th_state_url.s;
	scheme.len = p - th_state_url.s;

	if (str_casematch_nt(&scheme, "mongodb")) {
		LM_ERR("the mongodb backend ignores the expiration of the values "
			"it stores, so the topology hiding states would never be "
			"removed from it - use a backend which expires its values, "
			"such as redis, memcached or local\n");
		return -1;
	}

	return 0;
}


int th_store_init(void)
{
	if (!th_state_url.s)
		return 0;

	th_state_url.len = strlen(th_state_url.s);

	if (th_store_check_scheme() < 0)
		return -1;

	if (cachedb_bind_mod(&th_state_url, &th_cdbf) < 0) {
		LM_ERR("cannot bind functions for th_state_url %s\n",
			db_url_escape(&th_state_url));
		return -1;
	}

	if (!CACHEDB_CAPABILITY(&th_cdbf,
	CACHEDB_CAP_GET|CACHEDB_CAP_SET|CACHEDB_CAP_REMOVE)) {
		LM_ERR("the cachedb backend of th_state_url does not provide "
			"the needed get/set/remove support\n");
		return -1;
	}

	if (th_state_ttl <= 0) {
		LM_ERR("th_state_ttl must be a positive value\n");
		return -1;
	}
	if (th_state_ttl_short <= 0) {
		LM_ERR("th_state_ttl_short must be a positive value\n");
		return -1;
	}

	th_store_be = TH_STORE_CACHEDB;

	/* Best-effort write-coalescing cache. If it cannot be set up, leave it
	 * off (th_wc == NULL) and simply write on every request - a slower but
	 * equally correct fallback, so this never fails mod_init. */
	th_wc_lock = lock_alloc();
	if (th_wc_lock && lock_init(th_wc_lock)) {
		th_wc = shm_malloc(TH_WC_SIZE * sizeof *th_wc);
		if (th_wc) {
			memset(th_wc, 0, TH_WC_SIZE * sizeof *th_wc);
		} else {
			lock_destroy(th_wc_lock);
			lock_dealloc(th_wc_lock);
			th_wc_lock = NULL;
			LM_WARN("no shm for the write-coalescing cache - will store on "
				"every request\n");
		}
	} else {
		if (th_wc_lock)
			lock_dealloc(th_wc_lock);
		th_wc_lock = NULL;
		LM_WARN("cannot init the write-coalescing lock - will store on "
			"every request\n");
	}

	LM_INFO("topology hiding state kept in the shared store, "
		"ttl %d s (%d s for the dialog-less methods)\n",
		th_state_ttl, th_state_ttl_short);

	return 0;
}


int th_store_child_init(void)
{
	if (!th_store_enabled())
		return 0;

	th_cdbc = th_cdbf.init(&th_state_url);
	if (!th_cdbc) {
		LM_ERR("cannot connect to th_state_url %s\n",
			db_url_escape(&th_state_url));
		return -1;
	}

	return 0;
}


void th_store_destroy(void)
{
	if (th_cdbc) {
		th_cdbf.destroy(th_cdbc);
		th_cdbc = NULL;
	}
	if (th_wc) {
		shm_free(th_wc);
		th_wc = NULL;
	}
	if (th_wc_lock) {
		lock_destroy(th_wc_lock);
		lock_dealloc(th_wc_lock);
		th_wc_lock = NULL;
	}
}


/*
 * Derive the wire key of a state from the given seeds, straight into
 * @out (which must hold TH_KEY_LEN bytes).
 *
 * The key is deterministic on purpose: the seeds identify the dialog leg
 * whose state this is (its stable identifiers - the call and the tag of
 * the party the state belongs to), so every refresh of that same leg
 * derives the very same key. Its stored value is then simply overwritten
 * and its expiration pushed further, instead of a fresh random key being
 * piled up next to the previous one on each refresh - those would then
 * linger in the store until they expired, with no dialog to ever clean
 * them up (this mode exists precisely because there is no dialog).
 *
 * One of the seeds is expected to be a secret (the contact-encoding
 * password), which is what keeps the key impossible to guess from one
 * dialog to another: without it, knowing a dialog's call-id and tags -
 * which travel in the clear - would hand out its hidden topology.
 */
void th_store_make_key(str seeds[], int n, char *out)
{
	char md5[MD5_LEN];

	MD5StringArray(md5, seeds, n);
	/* MD5StringArray emits MD5_LEN(32) hex chars; TH_KEY_LEN of them
	 * make for a 64-bit key, as wide as the former random one */
	memcpy(out, md5, TH_KEY_LEN);
}


/* build the full storage key ("th:" + wire key) into @buf */
static inline void th_store_key(str *key, char *buf, str *out)
{
	memcpy(buf, TH_KEY_PREFIX, TH_KEY_PREFIX_LEN);
	memcpy(buf + TH_KEY_PREFIX_LEN, key->s, key->len);
	out->s = buf;
	out->len = TH_KEY_PREFIX_LEN + key->len;
}


int th_store_put(str *blob, str *key, int ttl)
{
	char buf[TH_KEY_PREFIX_LEN + TH_KEY_LEN];
	str full_key;

	if (!th_store_enabled()) {
		LM_BUG("no topology hiding storage configured\n");
		return -1;
	}
	if (!th_cdbc) {
		LM_ERR("not connected to the topology hiding storage\n");
		return -1;
	}
	if (ttl <= 0) {
		LM_BUG("bad ttl %d for the topology hiding state\n", ttl);
		return -1;
	}

	if (!th_wc_need_write(key, ttl)) {
		LM_DBG("topology hiding state under the key is already stored with "
			"enough TTL, skipping the write\n");
		return 0;
	}

	th_store_key(key, buf, &full_key);

	if (th_cdbf.set(th_cdbc, &full_key, blob, ttl) < 0) {
		LM_ERR("failed to store the topology hiding state under <%.*s>\n",
			full_key.len, full_key.s);
		return -1;
	}

	LM_DBG("stored %d bytes of topology hiding state under <%.*s>, "
		"expiring in %d s\n", blob->len, full_key.len, full_key.s, ttl);
	return 0;
}


int th_store_get(str *key, str *blob)
{
	char buf[TH_KEY_PREFIX_LEN + TH_KEY_LEN];
	str full_key;

	if (!th_store_enabled()) {
		LM_BUG("no topology hiding storage configured\n");
		return -1;
	}
	if (!th_cdbc) {
		LM_ERR("not connected to the topology hiding storage\n");
		return -1;
	}

	if (key->len != TH_KEY_LEN) {
		LM_DBG("bad topology hiding key length %d, expected %d - the "
			"user agent may have truncated it\n", key->len, TH_KEY_LEN);
		return -1;
	}

	th_store_key(key, buf, &full_key);

	blob->s = NULL;
	blob->len = 0;

	if (th_cdbf.get(th_cdbc, &full_key, blob) < 0) {
		LM_ERR("failed to fetch the topology hiding state of <%.*s>\n",
			full_key.len, full_key.s);
		return -1;
	}
	if (!blob->s || !blob->len) {
		LM_WARN("no topology hiding state found for <%.*s> - it may have "
			"expired, check the th_state_ttl* parameters against the "
			"lifetime of the hidden calls\n", full_key.len, full_key.s);
		if (blob->s) {
			pkg_free(blob->s);
			blob->s = NULL;
		}
		return -1;
	}

	LM_DBG("fetched %d bytes of topology hiding state for <%.*s>\n",
		blob->len, full_key.len, full_key.s);
	return 0;
}


void th_store_refresh(str *key, str *blob, int ttl)
{
	char buf[TH_KEY_PREFIX_LEN + TH_KEY_LEN];
	str full_key;

	if (!th_store_enabled() || !th_cdbc)
		return;
	if (key->len != TH_KEY_LEN || !blob->s || !blob->len || ttl <= 0)
		return;

	if (!th_wc_need_write(key, ttl)) {
		LM_DBG("topology hiding state already refreshed with enough TTL, "
			"skipping\n");
		return;
	}

	th_store_key(key, buf, &full_key);

	/* there is no way of just pushing the expiration of a value further
	 * through the cachedb interface, so store it again as it is */
	if (th_cdbf.set(th_cdbc, &full_key, blob, ttl) < 0)
		LM_WARN("failed to refresh the topology hiding state of <%.*s>, "
			"it may expire while still in use\n",
			full_key.len, full_key.s);
	else
		LM_DBG("refreshed the topology hiding state of <%.*s> for "
			"another %d s\n", full_key.len, full_key.s, ttl);
}


void th_store_del(str *key)
{
	char buf[TH_KEY_PREFIX_LEN + TH_KEY_LEN];
	str full_key;

	if (!th_store_enabled() || !th_cdbc)
		return;
	if (key->len != TH_KEY_LEN)
		return;

	/* forget any cached expiry, so a later re-create of this key writes */
	th_wc_forget(key);

	th_store_key(key, buf, &full_key);

	/* the state expires on its own anyway, so a failure here is not
	 * worth failing the request over */
	if (th_cdbf.remove(th_cdbc, &full_key) < 0)
		LM_WARN("failed to drop the topology hiding state of <%.*s>, "
			"leaving it to expire\n", full_key.len, full_key.s);
	else
		LM_DBG("dropped the topology hiding state of <%.*s>\n",
			full_key.len, full_key.s);
}
