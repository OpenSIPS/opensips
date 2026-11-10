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
 * /: js_PublishMsg outcome routing.
 *
 *   NATS_OK                              -> DONE (record ack->Sequence as rev)
 *   jerr 10071 (WrongLastSequence)       -> RETRY  (CAS conflict; re-read)
 *   jerr 10166 (MessageTTLDisabled)      -> LATCH_OFF (stream lacks AllowMsgTTL;
 *                                           fall back to plain CAS + reaper)
 *   jerr 10165 (MessageTTLInvalid)       -> ASSERT_BUG
 *   NATS_TIMEOUT / NATS_CONNECTION_CLOSED-> FAIL_SAVE (non-2xx; client retries)
 *
 * The natsStatus return is NATS_ERR for JS rejections, so jsErrCode is what
 * actually distinguishes them — hence js_PublishMsg over the fire-and-forget
 * js_PublishAsync.  The caller normalizes natsStatus to ttl_pub_status so this
 * decision is broker-less.
 *
 *   gcc ...                   -> the FIXED classifier => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_errcode_classify test_ttl_errcode_classify.c
 */
#include <tap.h>
#include <stdio.h>
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"



#define EQ(got, want, msg) do { int _g=(got),_w=(want); \
	if (_g != _w) { fail("ttl_errcode_classify: %s (got %d want %d)", msg,_g,_w); } \
	else pass("ttl_errcode_classify: %s", msg); } while (0)

void cn_ut_ttl_errcode_classify(void)
{

	diag("outcome routing:");
	EQ(cdbn_ttl_classify(TTL_PUB_OK, 0), TTL_DONE, "NATS_OK => DONE");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 10071), TTL_RETRY, "10071 WrongLastSeq => RETRY");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 10166), TTL_FAIL_SAVE, "10166 TTLDisabled => FAIL_SAVE (no TTL latch since the per-key TTL path was removed)");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 10165), TTL_FAIL_SAVE, "10165 TTLInvalid => FAIL_SAVE (likewise)");
	EQ(cdbn_ttl_classify(TTL_PUB_CONN_DOWN, 0), TTL_FAIL_SAVE, "TIMEOUT/CLOSED => FAIL_SAVE");

	diag("OK ignores any stale jerr; unknown JS error fails the save:");
	EQ(cdbn_ttl_classify(TTL_PUB_OK, 10071), TTL_DONE, "OK + stale jerr => still DONE");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 99999), TTL_FAIL_SAVE, "unknown JS error => FAIL_SAVE");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 0), TTL_FAIL_SAVE, "JS error with no code => FAIL_SAVE");
	EQ(cdbn_ttl_classify(TTL_PUB_CONN_DOWN, 10071), TTL_FAIL_SAVE, "conn down ignores jerr => FAIL_SAVE");

}
