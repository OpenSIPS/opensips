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
 *: nats_expired_linger slack composition.
 *
 * Linger is an operator retention policy: how long a row is PHYSICALLY kept
 * past its logical expiry (expires + grace).  It is added to every physical-
 * reclamation cutoff -- the reaper due-gate and survivor projection, and
 * write hygiene -- as slack = grace + linger at
 * the CALL SITES (the pure helpers keep their single-slack signatures).  It
 * is NEVER added to the read filter: an expired contact is not served,
 * lingering or not.  This test locks the composition:
 *
 *   - linger=0 reproduces today's values exactly (pure default-compat);
 *   - the reaper due-gate with slack=grace+linger is NOT due during the
 *     linger window and IS due after it (else the reaper defeats linger);
 *   - boundary: exp + grace + linger == now.
 *
 *                               the reaper reclaims during the linger window
 * On the real code: the reaper due-gate cdbn_reap_row_due at slack =
 * grace + linger, and at the call sites -- a reaper pass
 * (nats_cdb_reaper_tick) keeps a just-expired row while it lingers and
 * reaps it with linger 0, and a primary-key read hides the expired
 * contact whatever the linger (read filter = grace only).  The carried
 * helpers are gone.
 */
#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <nats/nats.h>

#include "../cachedb_nats_expiry.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

extern int nats_expired_linger, nats_reap_grace;

#define CHECK(cond, msg) ok((cond), "ttl_linger_slack: %s", (msg))

/* the reaper due-gate as the call sites compose it */
static int reap_due(int64_t row_exp, time_t now, int grace, int linger)
{
	return cdbn_reap_row_due(row_exp, now, grace + linger);
}

static char row[256];

static int pass_reaps(int linger)
{
	int saved = nats_expired_linger, reaped;

	cn_ut_fake_begin();
	cf.next[0].status = NATS_OK;
	cf.next[0].key = "json_alice";
	cf.next[0].op = kvOp_Put;
	cf.next[0].val = row;
	cf.next[0].val_len = (int)strlen(row);
	cf.next[0].rev = 8;
	cf.next[1].status = NATS_OK;          /* enumerated */
	cf.n_next = 2;
	nats_expired_linger = linger;
	nats_cdb_reaper_tick(0, NULL);
	nats_expired_linger = saved;
	reaped = strstr(cf.seq, "publish:8") != NULL;
	cn_ut_fake_end();
	return reaped;
}

void cn_ut_ttl_linger_slack(void)
{
	const int64_t EXPIRES = 1000;
	const int G = 5;
	long long exp;
	int saved, rows, nc, np;

	diag("linger=0 is byte-identical to the grace-only gate:");
	CHECK(reap_due(EXPIRES, 1006, G, 0) == 1, "due at exp+grace+1, linger 0");
	CHECK(reap_due(EXPIRES, 1004, G, 0) == 0, "not due before exp+grace, linger 0");
	diag("linger extends PHYSICAL retention by exactly linger:");
	CHECK(reap_due(EXPIRES, 1006, G, 30) == 0, "reaper NOT due during linger window");
	CHECK(reap_due(EXPIRES, 1034, G, 30) == 0, "still lingering at exp+grace+29");
	CHECK(reap_due(EXPIRES, 1035, G, 30) == 1, "due exactly at exp+grace+linger");
	CHECK(reap_due(0, 999999, G, 30) == 0, "permanent rows are never due, any linger");

	diag("at the call sites:");
	exp = (long long)time(NULL) - nats_reap_grace - 60;  /* expired a minute ago */
	snprintf(row, sizeof row, "{\"aor\":\"alice\",\"contacts\":{\"c1\":"
		"{\"expires\":%lld}},\"row_exp\":%lld}", exp, exp);
	CHECK(pass_reaps(0) == 1, "reaper pass, linger 0: the expired row is reclaimed");
	CHECK(pass_reaps(3600) == 0, "reaper pass, linger 3600: the row lingers");

	cn_ut_fake_begin();
	saved = nats_expired_linger;
	nats_expired_linger = 3600;
	rows = cn_ut_pk_read("alice", row, &nc, &np);
	nats_expired_linger = saved;
	CHECK(rows <= 1 && nc <= 0, "read while lingering: the expired contact is NOT served");
	cn_ut_fake_end();
}
