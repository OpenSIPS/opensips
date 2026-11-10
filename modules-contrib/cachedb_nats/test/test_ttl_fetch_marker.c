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
 * The CAS-loop fetch step (update_fetch_or_seed, cachedb_nats_json.c)
 * through the UNIT_TESTS wrapper cn_ut_update_fetch_or_seed(), on a fake
 * kvStore_Get.  cnats surfaces a server-side MaxAge delete marker as
 * NATS_OK with an empty value, not NATS_NOT_FOUND: the save must then
 * re-create the AoR OVER the marker -- an indexable seed as the merge base
 * and the marker's revision kept, so the write CAS-updates at it (a create,
 * ExpectNoMessage, is rejected over a marker).
 *   live doc          -> the doc, its revision
 *   empty marker      -> a seed, the marker's revision   (needs an identity)
 *   NOT_FOUND         -> a seed, revision 0 (create)     (needs an identity)
 *   no identity       -> -1
 *   any other error   -> -1
 * Replaces tests/test_ttl_fetch_marker.c (its fetch_decide() model is gone).
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../mem/mem.h"
#include "../../../cachedb/cachedb_types.h"
#include "../cachedb_nats.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

int cn_ut_update_fetch_or_seed(nats_cachedb_con *ncon, const cdb_filter_t *f,
	const char *key, char **json, int *len, uint64_t *rev);

static int run(int status, const char *val, uint64_t rev, int is_str,
	char **json, int *len, uint64_t *out_rev)
{
	nats_cachedb_con con;
	cdb_filter_t f;
	int rc;

	memset(&con, 0, sizeof con);
	con.kv = (kvStore *)cn_ut_fake_kv();
	memset(&f, 0, sizeof f);
	f.key.name.s = "aor";
	f.key.name.len = 3;
	f.val.is_str = is_str;
	f.val.s.s = "alice";
	f.val.s.len = 5;
	cf.get.status = status;
	cf.get.val = val;
	cf.get.val_len = val ? (int)strlen(val) : 0;
	cf.get.rev = rev;
	*json = NULL;
	*len = -1;
	*out_rev = 12345;
	cf.n_entry_destroy = 0;
	rc = cn_ut_update_fetch_or_seed(&con, &f, "json_alice", json, len, out_rev);
	return rc;
}

void cn_ut_ttl_fetch_marker(void)
{
	char *json;
	int len, rc;
	uint64_t rev;

	cn_ut_fake_begin();

	rc = run(NATS_OK, "{\"aor\":\"alice\",\"x\":1}", 7, 1, &json, &len, &rev);
	ok(rc == 0 && json && !strcmp(json, "{\"aor\":\"alice\",\"x\":1}") && rev == 7,
		"ttl_fetch_marker: live doc -> the doc at its revision (rc %d, rev %llu)",
		rc, (unsigned long long)rev);
	if (json) pkg_free(json);
	ok(cf.n_entry_destroy == 1, "ttl_fetch_marker: the live entry is destroyed");

	rc = run(NATS_OK, NULL, 9, 1, &json, &len, &rev);
	ok(rc == 0 && json && !strcmp(json, "{\"aor\":\"alice\"}") && rev == 9,
		"ttl_fetch_marker: empty marker -> a seed CAS'd at the marker's revision (rc %d, rev %llu)",
		rc, (unsigned long long)rev);
	if (json) pkg_free(json);
	ok(cf.n_entry_destroy == 1, "ttl_fetch_marker: the marker entry is destroyed");

	rc = run(NATS_OK, NULL, 9, 0, &json, &len, &rev);
	ok(rc == -1 && !json, "ttl_fetch_marker: empty marker, no string identity -> -1");
	ok(cf.n_entry_destroy == 1, "ttl_fetch_marker: ... and its entry is destroyed");

	rc = run(NATS_NOT_FOUND, NULL, 0, 1, &json, &len, &rev);
	ok(rc == 0 && json && !strcmp(json, "{\"aor\":\"alice\"}") && rev == 0,
		"ttl_fetch_marker: NOT_FOUND -> a seed with revision 0 (create)");
	if (json) pkg_free(json);

	rc = run(NATS_NOT_FOUND, NULL, 0, 0, &json, &len, &rev);
	ok(rc == -1 && !json, "ttl_fetch_marker: NOT_FOUND, no string identity -> -1");

	rc = run(NATS_ERR, NULL, 0, 1, &json, &len, &rev);
	ok(rc == -1 && !json, "ttl_fetch_marker: hard Get error -> -1");

	ok(strstr(cf.seq, "get:json_alice,") != NULL, "ttl_fetch_marker: the Get is on the target key");
	cn_ut_fake_end();
}
