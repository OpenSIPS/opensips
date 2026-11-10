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
 * Generic KV/stream introspection MI: the filter language shared by
 * nats_stream_list and nats_kv_keys.  Same shape as the nats_reg_list
 * language (';'-separated key=value, unknown keys refused, limit hard-capped
 * at 200 for the MI datagram), different key set:
 *
 *   bucket=<name>   which KV bucket to list keys from (default: the
 *                   module's kv_bucket)
 *   key=<glob>      fnmatch over KV key names       (nats_kv_keys)
 *   name=<glob>     fnmatch over stream names       (nats_stream_list)
 *   kv=0|1          only KV backing streams (KV_*)  (nats_stream_list)
 *   detail=0|1      per-key revision/created/size for the returned PAGE
 *                   (one Get per returned key -- bounded by the limit cap)
 *   limit=<n>       default 50, hard cap 200
 *   offset=<n>
 *
 * On the real cdbn_kvobs_filter_parse / cdbn_kvobs_bucket_of_stream
 * (cachedb_nats_kvobs.c); the carried struct and parser are gone.  Added:
 * the filter ends at its length; a backslash in a glob is kept verbatim;
 * an embedded NUL in a value is refused.
 */

#include <tap.h>
#include <string.h>

#include "../cachedb_nats_kvobs.h"

#include "cn_ut.h"

#define CHECK(cond, msg) ok((cond), "kvobs_filter: %s", (msg))

void cn_ut_kvobs_filter(void)
{
	struct kvobs_filter f;

	diag("defaults and happy path:");
	CHECK(cdbn_kvobs_filter_parse("", 0, &f) == 0 && f.limit == KVOBS_LIMIT_DEFAULT &&
	      f.offset == 0 && !f.kv_only && !f.detail && !f.bucket[0],
	      "empty filter => defaults");
	{
		const char *q = "bucket=other_bucket; key=json_*;detail=1;limit=25;offset=50";
		CHECK(cdbn_kvobs_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.bucket, "other_bucket") == 0 &&
		      strcmp(f.key_glob, "json_*") == 0 &&
		      f.detail == 1 && f.limit == 25 && f.offset == 50,
		      "kv_keys filter round-trips (any bucket, not just the module's)");
	}
	{
		const char *q = "name=KV_*;kv=1";
		CHECK(cdbn_kvobs_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.name_glob, "KV_*") == 0 && f.kv_only == 1,
		      "stream_list filter round-trips");
	}

	diag("fail loudly on bad input:");
	CHECK(cdbn_kvobs_filter_parse("wat=1", 5, &f) == -1, "unknown key => refused");
	CHECK(cdbn_kvobs_filter_parse("kv=2", 4, &f) == -1, "kv flag not 0/1 => refused");
	CHECK(cdbn_kvobs_filter_parse("detail=yes", 10, &f) == -1, "non-numeric flag => refused");
	CHECK(cdbn_kvobs_filter_parse("limit=0", 7, &f) == -1, "limit 0 => refused");
	CHECK(cdbn_kvobs_filter_parse("bucket=", 7, &f) == -1, "empty value => refused");
	CHECK(cdbn_kvobs_filter_parse("limit=999999", 12, &f) == 0 && f.limit == KVOBS_LIMIT_CAP,
	      "limit clamps to the 200 cap (not an error)");
	{
		char big[300];
		memset(big, 'b', sizeof(big));
		memcpy(big, "bucket=", 7);
		CHECK(cdbn_kvobs_filter_parse(big, (int)sizeof(big), &f) == -1,
		      "oversize bucket name refused, never truncated");
	}

	diag("output-format keys:");
	{
		const char *q = "key=json_*;format=csv;eol=lf;header=0";
		CHECK(cdbn_kvobs_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      f.format == 1 && f.eol_lf == 1 && f.header == 0 &&
		      strcmp(f.key_glob, "json_*") == 0,
		      "format/eol/header compose with kv keys");
	}
	CHECK(cdbn_kvobs_filter_parse("format=tsv", 10, &f) == -1,
	      "unknown format value refused");
	CHECK(cdbn_kvobs_filter_parse("", 0, &f) == 0 && f.format == 0 && f.header == 1,
	      "defaults: json + header on");

	diag("KV bucket name derived from the backing-stream name:");
	{
		const char *b; int bl;
		CHECK(cdbn_kvobs_bucket_of_stream("KV_opensips", 11, &b, &bl) == 0 &&
		      bl == 8 && memcmp(b, "opensips", 8) == 0,
		      "KV_opensips => bucket 'opensips'");
		CHECK(cdbn_kvobs_bucket_of_stream("EVENTS", 6, &b, &bl) == -1,
		      "non-KV stream => no bucket");
		CHECK(cdbn_kvobs_bucket_of_stream("KV_", 3, &b, &bl) == -1,
		      "bare 'KV_' => no bucket (empty name)");
	}

	diag("adversarial:");
	{
		static const char nb[] = "bucket=a\0b";
		static const char nk[] = "key=json_\0*";
		CHECK(cdbn_kvobs_filter_parse(nb, (int)sizeof nb - 1, &f) == -1,
			"an embedded NUL in a value is refused (would select bucket \"a\")");
		CHECK(cdbn_kvobs_filter_parse(nk, (int)sizeof nk - 1, &f) == -1,
			"an embedded NUL in a glob is refused");
	}
	CHECK(cdbn_kvobs_filter_parse("limit=25;wat=1", 8, &f) == 0 && f.limit == 25,
	      "the filter ends at its length (a bad key past it is not read)");
	CHECK(cdbn_kvobs_filter_parse("limit=25", 7, &f) == 0 && f.limit == 2,
	      "a number ends at the length too");
	{
		const char *q = "key=a\b*";
		CHECK(cdbn_kvobs_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.key_glob, "a\b*") == 0,
		      "a backslash in a glob is kept verbatim");
	}
}
