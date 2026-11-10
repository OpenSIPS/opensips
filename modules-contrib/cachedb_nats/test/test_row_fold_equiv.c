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
 * Behavioural: cdbn_row_hygiene_finalize
 * — the single-walk fold of the update path's two passes — must be
 * BYTE-IDENTICAL to the sequential reference composition
 *     cdbn_row_finalize_metadata(cdbn_row_drop_expired_own(doc))
 * on every input, including the eligibility out-params (row_exp,
 * n_contacts, all_same), the non-usrloc byte-for-byte contract, and
 * every edge (permanent sentinel, post-2038 int64,
 * negative expiry, untouched-expired no-collateral, unset pairs, the
 * NATS_MAX_DROP_IDS overflow deferral).  Runs in the module (pkg
 * memory; the old ASan/LSan net and the stand-ins are gone).
 *
 * The old pair stays in production (the reaper uses finalize alone), so
 * the reference is the real code, not a carried copy.  The old relative
 * micro-bench (it asserted nothing) is dropped.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "../../../mem/mem.h"
#include "../../../cachedb/cachedb_types.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

/* ── harness ────────────────────────────────────────────────────── */

#define ASSERT(cond, msg) do { \
	if (!(cond)) { fail("row_fold_equiv: %s", msg); } \
	else         { pass("row_fold_equiv: %s", msg);            } \
} while (0)

/* Build one "contacts"/<subkey> set-pair whose value dict carries an
 * integer "expires".  Storage is caller-provided (stack arrays). */
struct pair_slot {
	cdb_pair_t pair;
	cdb_pair_t exp_field;
	cdb_dict_t val_dict;
};

static void mk_contact_pair(struct pair_slot *sl, const char *subkey,
	int64_t expires, int use_i64, int unset, cdb_dict_t *into)
{
	memset(sl, 0, sizeof(*sl));
	sl->pair.key.name.s = "contacts";
	sl->pair.key.name.len = 8;
	sl->pair.subkey.s = (char *)subkey;
	sl->pair.subkey.len = (int)strlen(subkey);
	sl->pair.unset = (char)unset;
	INIT_LIST_HEAD(&sl->val_dict);
	if (!unset) {
		sl->pair.val.type = CDB_DICT;
		INIT_LIST_HEAD(&sl->pair.val.val.dict);
		sl->exp_field.key.name.s = "expires";
		sl->exp_field.key.name.len = 7;
		if (use_i64) {
			sl->exp_field.val.type = CDB_INT64;
			sl->exp_field.val.val.i64 = expires;
		} else {
			sl->exp_field.val.type = CDB_INT32;
			sl->exp_field.val.val.i32 = (int32_t)expires;
		}
		list_add_tail(&sl->exp_field.list, &sl->pair.val.val.dict);
	}
	list_add_tail(&sl->pair.list, into);
}

/* Run the sequential reference and the fold; assert byte + out-param
 * equality.  Either side may legally return NULL (malformed input) —
 * then BOTH must. */
static void check_equiv(const char *label, const char *json,
	const cdb_dict_t *pairs, time_t now, int grace)
{
	int old_len = 0, new_len = 0, tmp_len = 0;
	int64_t o_exp = -77, n_exp = -77;
	int o_n = -77, n_n = -77, o_same = -77, n_same = -77;
	char *dropped, *oldr = NULL, *newr;
	char msg[256];

	dropped = cdbn_row_drop_expired_own(json, (int)strlen(json), pairs,
		now, grace, &tmp_len);
	if (dropped) {
		oldr = cdbn_row_finalize_metadata(dropped, tmp_len, &old_len,
			&o_exp, &o_n, &o_same);
		pkg_free(dropped);
	}
	newr = cdbn_row_hygiene_finalize(json, (int)strlen(json), pairs,
		now, grace, &new_len,
		&n_exp, &n_n, &n_same);

	snprintf(msg, sizeof(msg), "%s: fold == reference", label);
	if (!oldr || !newr) {
		ASSERT(oldr == newr, msg);
	} else {
		ASSERT(old_len == new_len && memcmp(oldr, newr, old_len) == 0, msg);
		snprintf(msg, sizeof(msg), "%s: eligibility outs match "
			"(row_exp %lld/%lld n %d/%d same %d/%d)", label,
			(long long)o_exp, (long long)n_exp, o_n, n_n, o_same, n_same);
		ASSERT(o_exp == n_exp && o_n == n_n && o_same == n_same, msg);
	}
	if (oldr)
		pkg_free(oldr);
	if (newr)
		pkg_free(newr);
}

void cn_ut_row_fold_equiv(void)
{
	time_t now = 1000000;
	int grace = 30;
	cdb_dict_t pairs;
	struct pair_slot sl[4];

	/* 1. touched expired contact dropped + live survivor recomputed */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YWxpY2U=", 999900, 0, 0, &pairs);  /* expired */
	mk_contact_pair(&sl[1], "Ym9i",     1000600, 0, 0, &pairs); /* live */
	check_equiv("drop one + survivor",
		"{\"aor\":\"alice@h\",\"contacts\":{"
		"\"YWxpY2U=\":{\"expires\":999900,\"q\":1},"
		"\"Ym9i\":{\"expires\":1000600}},"
		"\"row_exp\":42,\"schema_version\":1}", &pairs, now, grace);

	/* 2. nothing due: no-drop fast path */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "Ym9i", 1000600, 0, 0, &pairs);
	check_equiv("no drop",
		"{\"contacts\":{\"Ym9i\":{\"expires\":1000600}}}",
		&pairs, now, grace);

	/* 3. permanent contact => permanent row (sentinel 0) */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "cGVybQ==", 0, 0, 0, &pairs);
	check_equiv("permanent sentinel",
		"{\"contacts\":{\"cGVybQ==\":{\"expires\":0},"
		"\"Ym9i\":{\"expires\":1000600}}}", &pairs, now, grace);

	/* 4. all-same vs mixed expiries (TTL eligibility) */
	check_equiv("all same",
		"{\"contacts\":{\"YQ==\":{\"expires\":1000500},"
		"\"Yg==\":{\"expires\":1000500}}}", NULL, now, grace);
	check_equiv("mixed",
		"{\"contacts\":{\"YQ==\":{\"expires\":1000500},"
		"\"Yg==\":{\"expires\":1000900}}}", NULL, now, grace);

	/* 5. non-usrloc doc: byte-for-byte verbatim (odd spacing kept) */
	check_equiv("non-usrloc verbatim",
		"{ \"k\" :\t{\"x\": [1,2 ,3]} , \"y\":\"z\\\"esc\" }",
		NULL, now, grace);

	/* 6. unset pair never enters the drop set */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YWxpY2U=", 999900, 0, 1 /* unset */, &pairs);
	check_equiv("unset pair ignored",
		"{\"contacts\":{\"YWxpY2U=\":{\"expires\":999900}}}",
		&pairs, now, grace);

	/* 7. untouched expired merged-in contact is NOT dropped */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "Ym9i", 1000600, 0, 0, &pairs);
	check_equiv("no collateral delete",
		"{\"contacts\":{\"c3RhbGU=\":{\"expires\":5},"
		"\"Ym9i\":{\"expires\":1000600}}}", &pairs, now, grace);

	/* 8. post-2038 int64 expiry survives */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "ZnV0dXJl", 4102444800LL, 1, 0, &pairs);
	check_equiv("post-2038 int64",
		"{\"contacts\":{\"ZnV0dXJl\":{\"expires\":4102444800}}}",
		&pairs, now, grace);

	/* 9. negative expiry: real candidate, dropped when touched */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "bmVn", -5, 1, 0, &pairs);
	check_equiv("negative expiry touched",
		"{\"contacts\":{\"bmVn\":{\"expires\":-5},"
		"\"Ym9i\":{\"expires\":1000600}}}", &pairs, now, grace);

	/* 10. malformed input: both sides NULL */
	check_equiv("malformed json", "{\"contacts\":{", NULL, now, grace);
	check_equiv("not an object", "[1,2,3]", NULL, now, grace);

	/* 11. empty contacts object */
	check_equiv("empty contacts", "{\"contacts\":{}}", NULL, now, grace);

	/* 12. adversarial value bytes: escapes, UTF-8, format specifiers */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YWRz", 999900, 0, 0, &pairs);
	check_equiv("adversarial bytes",
		"{\"contacts\":{\"YWRz\":{\"expires\":999900,"
		"\"ua\":\"sipp\\\\1.0 %s %n \\u00e9\\\"x\"},"
		"\"Ym9i\":{\"expires\":1000600,\"note\":\"caf\xc3\xa9\"}},"
		"\"blob\":\"a\\\\b\"}", &pairs, now, grace);

	/* 13. duplicate top-level contacts keys (last occurrence wins) */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YQ==", 999900, 0, 0, &pairs);
	check_equiv("duplicate contacts key",
		"{\"contacts\":{\"YQ==\":{\"expires\":999900}},"
		"\"contacts\":{\"Yg==\":{\"expires\":1000700}}}",
		&pairs, now, grace);

	/* 14. NATS_MAX_DROP_IDS overflow: 300 touched-expired contacts —
	 * excess past 256 is deferred to the reaper, identically. */
	{
		static struct pair_slot big_sl[300];
		static char keys[300][16];
		static char doc[300 * 48 + 64];
		char *w = doc;
		int i;

		INIT_LIST_HEAD(&pairs);
		w += sprintf(w, "{\"contacts\":{");
		for (i = 0; i < 300; i++) {
			sprintf(keys[i], "k%03d", i);
			mk_contact_pair(&big_sl[i], keys[i], 999900, 0, 0, &pairs);
			w += sprintf(w, "%s\"%s\":{\"expires\":999900}",
				i ? "," : "", keys[i]);
		}
		sprintf(w, "}}");
		check_equiv("drop-id overflow (300 touched)", doc, &pairs,
			now, grace);
	}

	/* 15. odd interior whitespace through both emission arms */
	INIT_LIST_HEAD(&pairs);
	mk_contact_pair(&sl[0], "YQ==", 999900, 0, 0, &pairs);
	check_equiv("whitespace, drop arm",
		"{ \"contacts\" : { \"YQ==\" :\t{ \"expires\" : 999900 } ,"
		" \"Yg==\": {\"expires\":1000700} } }", &pairs, now, grace);
	check_equiv("whitespace, bulk arm",
		"{ \"contacts\" : { \"Yg==\":\t{ \"expires\" : 1000700 } } }",
		NULL, now, grace);
}
