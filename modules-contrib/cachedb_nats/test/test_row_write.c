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
 * Every usrloc-row write is ONE CAS write through nats_kv_write_row_cas():
 * a create (ExpectNoMessage) for a new row, a publish at the last revision
 * (ExpectLastSubjectSeq) otherwise -- never a plain kvStore_UpdateString /
 * PutString, which would skip the CAS.  On fakes (cn_ut_fake.h):
 *   - the helper's outcomes: committed 0, CAS conflict 1 (lost create race,
 *     10071 wrong-last-sequence), fail-the-save -1 (broker down, any other
 *     JetStream error);
 *   - a registration (nats_cache_update) on a fake connection writes the
 *     merged row through the helper only (test_ttl_write_invariant);
 *   - nats_cas_should_retry(): a conflict retries, a timeout / closed /
 *     disconnected connection bails (test_cas_retry_policy);
 *   - nats_kv_update() (the script CAS): 1 committed, -2 only for a real
 *     revision conflict (10071), -1 for any other failure, never a write
 *     while disconnected (test_kv_update_cas_classify).
 * The reaper's survivor write is in test_reap_pass.c.  LOST: the counter
 * loop's use of the predicate is not driven here.
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../mem/mem.h"
#include "../../../cachedb/cachedb.h"
#include "../../../cachedb/cachedb_dict.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_dbase.h"
#include "../cachedb_nats_json.h"
#include "../cachedb_nats_native.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

static const char *JSON = "{\"aor\":\"alice\"}";

static int write_at(uint64_t rev, uint64_t *out)
{
	*out = 0;
	return nats_kv_write_row_cas((kvStore *)cn_ut_fake_kv(), "unit_tests",
		"json_alice", JSON, (int)strlen(JSON), rev, out);
}

void cn_ut_row_write(void)
{
	uint64_t out;
	int rc;
	cachedb_con con;
	nats_cachedb_con ncon;
	cdb_filter_t f;
	cdb_dict_t pairs;

	diag("a new row: create (ExpectNoMessage):");
	cn_ut_fake_begin();
	rc = write_at(0, &out);
	ok(rc == 0 && out == 1 && !strcmp(cf.seq, "create:json_alice,"),
		"row_write: rev 0 -> one create, committed (rc %d, %s)", rc, cf.seq);
	cf.create_status = NATS_ERR;
	ok(write_at(0, &out) == 1, "row_write: create lost to a concurrent create -> conflict (1)");
	cf.create_status = NATS_CONNECTION_DISCONNECTED;
	ok(write_at(0, &out) == -1, "row_write: create with the broker down -> fail the save (-1)");
	cn_ut_fake_end();

	diag("an existing row: publish at its revision (ExpectLastSubjectSeq):");
	cn_ut_fake_begin();
	rc = write_at(7, &out);
	ok(rc == 0 && out == 42 && cf.expect_last_seq == 7 &&
		strstr(cf.seq, "msg:$KV.unit_tests.json_alice,publish:7,") != NULL,
		"row_write: rev 7 -> one publish on the key's subject at 7, ack rev kept (%s)", cf.seq);
	ok(!strcmp(cf.published, JSON), "row_write: the value published is the row");
	cf.publish_status = NATS_ERR;
	cf.publish_jerr = 10071;
	ok(write_at(7, &out) == 1, "row_write: 10071 wrong last sequence -> conflict (1)");
	cf.publish_jerr = 10999;
	ok(write_at(7, &out) == -1, "row_write: any other JetStream error -> fail the save (-1)");
	cf.publish_status = NATS_TIMEOUT;
	cf.publish_jerr = 10071;
	ok(write_at(7, &out) == -1, "row_write: timeout -> fail the save, stale jerr ignored (-1)");
	ok(strstr(cf.seq, "update_string") == NULL && strstr(cf.seq, "put_string") == NULL,
		"row_write: no unconditional write anywhere");
	cn_ut_fake_end();

	diag("a registration goes through the CAS helper only:");
	cn_ut_fake_begin();
	memset(&con, 0, sizeof con);
	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)cn_ut_fake_kv();
	con.data = &ncon;
	memset(&f, 0, sizeof f);
	f.key.name.s = "aor";
	f.key.name.len = 3;
	f.key.is_pk = 1;
	f.op = CDB_OP_EQ;
	f.val.is_str = 1;
	f.val.s.s = "alice";
	f.val.s.len = 5;
	INIT_LIST_HEAD(&pairs);
	cdb_dict_add_int32(&pairs, "x", 1, 5);
	cf.get.status = NATS_NOT_FOUND;           /* first REGISTER of the AoR */
	rc = nats_cache_update(&con, &f, &pairs);
	ok(rc == 0, "row_write: update of a new AoR succeeds (rc %d)", rc);
	ok(strstr(cf.seq, "get:json_alice,") && strstr(cf.seq, "create:json_alice,"),
		"row_write: ... read, then one CAS create (%s)", cf.seq);
	ok(strstr(cf.published, "\"aor\":\"alice\"") && strstr(cf.published, "\"x\":5"),
		"row_write: ... of the merged row (seed + the pair)");

	cf.seq[0] = '\0';
	cf.get.status = NATS_OK;                  /* a live row at revision 3 */
	cf.get.val = "{\"aor\":\"alice\",\"y\":1}";
	cf.get.val_len = (int)strlen(cf.get.val);
	cf.get.rev = 3;
	rc = nats_cache_update(&con, &f, &pairs);
	ok(rc == 0 && cf.expect_last_seq == 3,
		"row_write: update of a live row publishes at its revision (rc %d, at %llu)",
		rc, (unsigned long long)cf.expect_last_seq);
	ok(strstr(cf.published, "\"y\":1") && strstr(cf.published, "\"x\":5"),
		"row_write: ... keeping the stored fields");
	ok(strstr(cf.seq, "update_string") == NULL && strstr(cf.seq, "put_string") == NULL,
		"row_write: the registration never writes without the CAS");
	cdb_free_entries(&pairs, NULL);
	cn_ut_fake_end();

	diag("nats_kv_update(): conflict vs failure:");
	{
		str b = str_init(""), k = str_init("call.1.state"), v = str_init("ringing");
		int er = 5;

		cn_ut_fake_begin();
		ok(w_nats_kv_update(NULL, &b, &k, &v, &er) == 1 && cf.expect_last_seq == 5,
			"row_write: kv_update committed -> 1, published at the expected revision");
		cf.publish_status = NATS_ERR;
		cf.publish_jerr = 10071;
		ok(w_nats_kv_update(NULL, &b, &k, &v, &er) == -2,
			"row_write: kv_update wrong last sequence (10071) -> -2 (retry)");
		cf.publish_jerr = 10999;
		ok(w_nats_kv_update(NULL, &b, &k, &v, &er) == -1,
			"row_write: kv_update other JetStream error -> -1 (NOT a retryable conflict)");
		cf.publish_status = NATS_OK;
		cf.connected = 0;
		cf.seq[0] = '\0';
		ok(w_nats_kv_update(NULL, &b, &k, &v, &er) == -1 && strstr(cf.seq, "publish") == NULL,
			"row_write: kv_update disconnected -> -1, nothing written");
		cn_ut_fake_end();
	}

	diag("the CAS retry predicate:");
	ok(nats_cas_should_retry(NATS_ERR) == 1, "row_write: NATS_ERR (conflict) retried");
	ok(nats_cas_should_retry(NATS_MISMATCH) == 1, "row_write: NATS_MISMATCH retried");
	ok(nats_cas_should_retry(NATS_TIMEOUT) == 0, "row_write: a timeout bails");
	ok(nats_cas_should_retry(NATS_CONNECTION_CLOSED) == 0, "row_write: connection closed bails");
	ok(nats_cas_should_retry(NATS_CONNECTION_DISCONNECTED) == 0, "row_write: disconnected bails");
}
