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

#include <stdio.h>
#include <arpa/inet.h>
#include <tap.h>

#include "../../../str.h"
#include "../../../mem/mem.h"
#include "../../../mem/shm_mem.h"
#include "../../../context.h"
#include "../../../cmds.h"
#include "../../../sr_module.h"
#include "../../../parser/msg_parser.h"
#include "../../../locking.h"
#include "../../../db/db.h"
#include "../../../async.h"
#include "../../../pvar.h"

#include "../../proto_hep/hep.h"
#include "../../proto_hep/hep_cb.h"

/* mirrors of the sipcapture.c batched insert state */
#define TEST_MAX_QUERY 65535
struct test_async_query {
	str last_query_suffix;
	int curr_async_queries;
	int query_len;
	char query_buf[TEST_MAX_QUERY];
	gen_lock_t query_lock;
};

struct test_tz_table_list {
	void *table;
	struct test_async_query *as_qry;
	struct test_tz_table_list *next;
};

extern db_func_t db_funcs;
extern struct test_tz_table_list tz_global;
extern struct test_tz_table_list rc_global;
extern int *capture_on_flag;
extern char tz_table[];
extern char rc_table[];

static int async_capture_hepv3_body(const char *body, int body_len);

/* run the async sip_capture() on a HEPv3 message whose SIP body is @body_len */
static int async_capture_hepv3(int body_len)
{
	char *body;
	int ret;

	body = pkg_malloc(body_len + 1);
	if (!body)
		return -2;
	memset(body, 'a', body_len);
	ret = async_capture_hepv3_body(body, body_len);
	pkg_free(body);
	return ret;
}

/* run the async sip_capture() on a HEPv3 message carrying @body */
static int async_capture_hepv3_body(const char *body, int body_len)
{
	static const char hdrs[] =
		"MESSAGE sip:a@127.0.0.1 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1\r\n"
		"From: <sip:b@127.0.0.1>;tag=1\r\n"
		"To: <sip:a@127.0.0.1>\r\n"
		"Call-ID: 1@127.0.0.1\r\n"
		"CSeq: 1 MESSAGE\r\n"
		"Content-Length: %d\r\n\r\n";
	const acmd_export_t *acmd;
	proto_hep_api_t api;
	load_hep_f load_hep;
	struct hep_context *hctx;
	struct sip_msg msg;
	async_ctx actx;
	context_p ctx;
	char *buf;
	int len, ret;

	acmd = find_mod_acmd_export_t("sip_capture");
	load_hep = (load_hep_f)find_export("load_hep", 0);
	if (!acmd || !load_hep || load_hep(&api) < 0)
		return -2;

	buf = pkg_malloc(sizeof hdrs + 16 + body_len);
	hctx = shm_malloc(sizeof *hctx);
	ctx = context_alloc(CONTEXT_GLOBAL);
	if (!buf || !hctx || !ctx)
		return -2;
	len = sprintf(buf, hdrs, body_len);
	memcpy(buf + len, body, body_len);
	len += body_len;

	memset(hctx, 0, sizeof *hctx);
	hctx->h.version = 3;
	hctx->h.u.hepv3.hg.ip_family.data = AF_INET;
	hctx->h.u.hepv3.hg.ip_proto.data = IPPROTO_UDP;
	hctx->h.u.hepv3.hg.proto_t.data = 1;
	inet_pton(AF_INET, "127.0.0.1", &hctx->h.u.hepv3.addr.ip4_addr.src_ip4.data);
	inet_pton(AF_INET, "127.0.0.1", &hctx->h.u.hepv3.addr.ip4_addr.dst_ip4.data);
	hctx->h.u.hepv3.payload_chunk.chunk.type_id = HEP_PAYLOAD;
	hctx->h.u.hepv3.payload_chunk.chunk.length = len + sizeof(hep_chunk_t);
	hctx->h.u.hepv3.payload_chunk.data = buf;

	memset(ctx, 0, context_size(CONTEXT_GLOBAL));
	context_put_ptr(CONTEXT_GLOBAL, ctx, api.get_hep_ctx_id(), hctx);
	set_global_context(ctx);

	memset(&msg, 0, sizeof msg);
	msg.buf = buf;
	msg.len = len;
	if (parse_msg(buf, len, &msg) != 0)
		return -2;

	memset(&actx, 0, sizeof actx);
	ret = acmd->function(&msg, &actx, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL);

	free_sip_msg(&msg);
	set_global_context(NULL);
	shm_free(hctx);
	pkg_free(buf);
	return ret;
}


static void test_async_capture_size(void)
{
	struct test_async_query *q;

	/* a DB with async raw queries, batching max_async_queries inserts */
	db_funcs.cap |= DB_CAP_ASYNC_RAW_QUERY;
	q = malloc(sizeof *q);
	memset(q, 0, sizeof *q);
	lock_init(&q->query_lock);
	tz_global.table = (void *)tz_table;
	tz_global.as_qry = q;
	*capture_on_flag = 1;

	ok(async_capture_hepv3(100) == 1, "small captured message is queued");
	ok(async_capture_hepv3(65000) < 0,
		"captured message larger than the query buffer is refused");
	ok(q->query_len <= TEST_MAX_QUERY, "query length stays within the buffer");
	ok(async_capture_hepv3(100) == 1,
		"next small captured message is queued after a refused one");
	ok(q->query_len <= TEST_MAX_QUERY, "query length still within the buffer");

	tz_global.as_qry = NULL;
	db_funcs.cap &= ~DB_CAP_ASYNC_RAW_QUERY;
}


/*
 * Read the rows queued after VALUES the way MySQL does; return the number of
 * rows if each has @nvals values and nothing follows, -1 otherwise. String
 * value @idx of the last row is decoded into @val.
 */
static int parse_async_rows(const char *q, int qlen, int nvals, int idx,
	char *val, int *val_len)
{
	const char *p, *end = q + qlen;
	int rows = 0, n;

	p = strstr(q, ") VALUES");
	if (!p || p > end)
		return -1;
	p += 8;

	for (;;) {
		if (p >= end || *p++ != '(')
			return -1;
		for (n = 0; ; n++) {
			if (p < end && *p == '\'') {
				if (n == idx)
					*val_len = 0;
				for (p++; ; p++) {
					if (p >= end)
						return -1;
					if (*p == '\\' && p + 1 < end) {
						p++;
						if (n == idx)
							val[(*val_len)++] = (*p == '0') ? '\0' : *p;
					} else if (*p == '\'' && p + 1 < end && p[1] == '\'') {
						p++;
						if (n == idx)
							val[(*val_len)++] = '\'';
					} else if (*p == '\'') {
						p++;
						break;
					} else if (n == idx) {
						val[(*val_len)++] = *p;
					}
				}
			} else {
				while (p < end && (*p == '-' || (*p >= '0' && *p <= '9')))
					p++;
			}
			if (p < end && *p == ',') {
				p++;
				while (p < end && *p == ' ')
					p++;
			} else {
				break;
			}
		}
		if (p >= end || *p++ != ')' || n + 1 != nvals)
			return -1;
		rows++;
		if (p == end)
			return rows;
		if (*p++ != ',')
			return -1;
	}
}

static void test_async_capture_values(void)
{
	static const char body[] = "x'),(1,2) -- \\'y\\";
	struct test_async_query *q;
	char val[1024];
	int val_len = -1;

	db_funcs.cap |= DB_CAP_ASYNC_RAW_QUERY;
	q = malloc(sizeof *q);
	memset(q, 0, sizeof *q);
	lock_init(&q->query_lock);
	tz_global.table = (void *)tz_table;
	tz_global.as_qry = q;
	*capture_on_flag = 1;

	ok(async_capture_hepv3_body("plain", 5) == 1, "plain captured message is queued");
	ok(parse_async_rows(q->query_buf, q->query_len, 43, 39, val, &val_len) == 1 &&
		val_len >= 5 && !memcmp(val + val_len - 5, "plain", 5),
		"plain queued row reads back unchanged");
	q->curr_async_queries = 0;
	q->query_len = 0;

	ok(async_capture_hepv3_body(body, sizeof body - 1) == 1,
		"captured message with quotes and backslashes is queued");
	/* 43 columns; the raw message is value 39 */
	ok(parse_async_rows(q->query_buf, q->query_len, 43, 39, val, &val_len) == 1,
		"queued row keeps one value per column");
	ok(val_len >= (int)sizeof body - 1 &&
		!memcmp(val + val_len - (sizeof body - 1), body, sizeof body - 1),
		"queued message value reads back unchanged");

	ok(async_capture_hepv3_body("a\0b'", 4) == 1,
		"captured message with a NUL byte is queued");
	ok(parse_async_rows(q->query_buf, q->query_len, 43, 39, val, &val_len) == 2,
		"both queued rows keep one value per column");
	ok(val_len >= 4 && !memcmp(val + val_len - 4, "a\0b'", 4),
		"queued NUL byte reads back unchanged");
	ok(q->query_buf[q->query_len] == '\0', "queued query is NUL terminated");

	tz_global.as_qry = NULL;
	free(q);
	db_funcs.cap &= ~DB_CAP_ASYNC_RAW_QUERY;
}


/* run the async report_capture() for a HEPv3 message carrying @json */
static int async_report_hepv3(const char *json)
{
	static str cor_id = str_init("cid-'1");
	const acmd_export_t *acmd;
	proto_hep_api_t api;
	load_hep_f load_hep;
	struct hep_context *hctx;
	struct sip_msg msg;
	async_ctx actx;
	context_p ctx;
	int proto_t = 5, len, ret;
	char *buf;

	acmd = find_mod_acmd_export_t("report_capture");
	load_hep = (load_hep_f)find_export("load_hep", 0);
	if (!acmd || !load_hep || load_hep(&api) < 0)
		return -2;

	len = strlen(json);
	buf = pkg_malloc(len + 1);
	hctx = shm_malloc(sizeof *hctx);
	ctx = context_alloc(CONTEXT_GLOBAL);
	if (!buf || !hctx || !ctx)
		return -2;
	memcpy(buf, json, len + 1);

	memset(hctx, 0, sizeof *hctx);
	hctx->h.version = 3;
	hctx->h.u.hepv3.hg.ip_family.data = AF_INET;
	hctx->h.u.hepv3.hg.ip_proto.data = IPPROTO_UDP;
	hctx->h.u.hepv3.payload_chunk.chunk.type_id = HEP_PAYLOAD;
	hctx->h.u.hepv3.payload_chunk.chunk.length = len + sizeof(hep_chunk_t);
	hctx->h.u.hepv3.payload_chunk.data = buf;
	hctx->ri.dst_ip.af = AF_INET;

	memset(ctx, 0, context_size(CONTEXT_GLOBAL));
	context_put_ptr(CONTEXT_GLOBAL, ctx, api.get_hep_ctx_id(), hctx);
	set_global_context(ctx);

	memset(&msg, 0, sizeof msg);
	memset(&actx, 0, sizeof actx);
	ret = acmd->function(&msg, &actx, &cor_id, NULL, &proto_t, NULL,
		NULL, NULL, NULL, NULL);

	set_global_context(NULL);
	shm_free(hctx);
	pkg_free(buf);
	return ret;
}

static void test_async_report_values(void)
{
	static const char json[] = "{\"Event\":\"a'),(b\\\\\"}";
	struct test_async_query *q;
	char val[1024];
	int val_len = -1;

	db_funcs.cap |= DB_CAP_ASYNC_RAW_QUERY;
	q = malloc(sizeof *q);
	memset(q, 0, sizeof *q);
	lock_init(&q->query_lock);
	rc_global.table = (void *)rc_table;
	rc_global.as_qry = q;

	ok(async_report_hepv3(json) == 1, "report with quotes is queued");
	/* homer6 report: 17 columns; the payload is value 11 */
	ok(parse_async_rows(q->query_buf, q->query_len, 17, 11, val, &val_len) == 1,
		"queued report row keeps one value per column");
	ok(val_len == (int)sizeof json - 1 && !memcmp(val, json, val_len),
		"queued report payload reads back unchanged");
	ok(parse_async_rows(q->query_buf, q->query_len, 17, 2, val, &val_len) == 1 &&
		val_len == 6 && !memcmp(val, "cid-'1", 6),
		"queued correlation id reads back unchanged");

	rc_global.as_qry = NULL;
	free(q);
	db_funcs.cap &= ~DB_CAP_ASYNC_RAW_QUERY;
}



typedef int (*relay_f)(struct sip_msg *msg);

/* run hep_relay() for a HEPv3 message carrying a @payload_len payload */
static int relay_hepv3(int payload_len)
{
	static char dst[] = "sip:127.0.0.1:9062";
	const cmd_export_t *cmd;
	proto_hep_api_t api;
	load_hep_f load_hep;
	struct hep_context *hctx;
	struct sip_msg msg;
	context_p ctx;
	char *payload;
	int ret;

	cmd = find_cmd_export_t("hep_relay", 0);
	load_hep = (load_hep_f)find_export("load_hep", 0);
	if (!cmd || !load_hep || load_hep(&api) < 0)
		return -2;

	hctx = shm_malloc(sizeof *hctx);
	payload = pkg_malloc(payload_len);
	ctx = context_alloc(CONTEXT_GLOBAL);
	if (!hctx || !payload || !ctx)
		return -2;
	memset(hctx, 0, sizeof *hctx);
	memset(payload, 'a', payload_len);
	memset(ctx, 0, context_size(CONTEXT_GLOBAL));

	hctx->h.version = 3;
	hctx->h.u.hepv3.payload_chunk.chunk.type_id = HEP_PAYLOAD;
	hctx->h.u.hepv3.payload_chunk.chunk.length =
		payload_len + sizeof(hep_chunk_t);
	hctx->h.u.hepv3.payload_chunk.data = payload;

	context_put_ptr(CONTEXT_GLOBAL, ctx, api.get_hep_ctx_id(), hctx);
	set_global_context(ctx);

	memset(&msg, 0, sizeof msg);
	msg.dst_uri.s = dst;
	msg.dst_uri.len = sizeof dst - 1;

	ret = ((relay_f)cmd->function)(&msg);

	set_global_context(NULL);
	pkg_free(payload);
	shm_free(hctx);
	return ret;
}


static void test_hep_relay_size(void)
{
	ok(relay_hepv3(100) == 1, "small HEPv3 packet is relayed");
	ok(relay_hepv3(40000) == 1,
		"HEPv3 packet larger than the capture payload buffer is relayed");
	/* the payload chunk alone takes the whole 16 bit HEPv3 length */
	ok(relay_hepv3(65535 - sizeof(hep_chunk_t)) < 0,
		"HEPv3 packet longer than a HEP frame is not relayed");
}


/* db_text table for report_capture() with the homer6 columns */
static void make_rtcp_table(void)
{
	FILE *f = fopen("/tmp/rtcp_capture", "w");

	if (!f)
		return;
	fputs("tss(int) tsu(int) transaction_id(string) source_ip(string) "
		"source_port(int) destination_ip(string) destination_port(int) "
		"proto(int) family(int) type(int) node(string) data(string) "
		"payload_len(int) correlation_id(string) capture_ip(string) "
		"capt_id(int) event(string,null)\n", f);
	fclose(f);
}


/* run the sync report_capture() for a HEPv3 message carrying @json */
static int report_hepv3(const char *json)
{
	static str cor_id = str_init("cid-1");
	const cmd_export_t *cmd;
	proto_hep_api_t api;
	load_hep_f load_hep;
	struct hep_context *hctx;
	struct sip_msg msg;
	context_p ctx;
	int proto_t = 5, len, ret;
	char *buf;

	cmd = find_cmd_export_t("report_capture", 0);
	load_hep = (load_hep_f)find_export("load_hep", 0);
	if (!cmd || !load_hep || load_hep(&api) < 0)
		return -2;

	len = strlen(json);
	buf = pkg_malloc(len + 1);
	hctx = shm_malloc(sizeof *hctx);
	ctx = context_alloc(CONTEXT_GLOBAL);
	if (!buf || !hctx || !ctx)
		return -2;
	memcpy(buf, json, len + 1);

	memset(hctx, 0, sizeof *hctx);
	hctx->h.version = 3;
	hctx->h.u.hepv3.hg.ip_family.data = AF_INET;
	hctx->h.u.hepv3.hg.ip_proto.data = IPPROTO_UDP;
	hctx->h.u.hepv3.payload_chunk.chunk.type_id = HEP_PAYLOAD;
	hctx->h.u.hepv3.payload_chunk.chunk.length = len + sizeof(hep_chunk_t);
	hctx->h.u.hepv3.payload_chunk.data = buf;
	hctx->ri.dst_ip.af = AF_INET;

	memset(ctx, 0, context_size(CONTEXT_GLOBAL));
	context_put_ptr(CONTEXT_GLOBAL, ctx, api.get_hep_ctx_id(), hctx);
	set_global_context(ctx);

	memset(&msg, 0, sizeof msg);
	ret = cmd->function(&msg, &cor_id, NULL, &proto_t, NULL, NULL, NULL,
		NULL, NULL);

	set_global_context(NULL);
	shm_free(hctx);
	pkg_free(buf);
	return ret;
}


static void test_report_event(void)
{
	make_rtcp_table();
	ok(report_hepv3("{\"Event\":\"rtcp-xr\",\"pad\":\"abcdefgh\"}") == 1,
		"report with a string Event is stored");
}

static void test_report_event_type(void)
{
	ok(report_hepv3("{\"Event\":42}") == 1,
		"report with a non-string Event is stored");
}


/* run hep_get() as @type on a custom chunk carrying @data_len bytes */
static int get_custom_chunk(int type, int data_len)
{
	static str var = str_init("$var(hep_data)");
	const cmd_export_t *cmd;
	proto_hep_api_t api;
	load_hep_f load_hep;
	struct hep_context *hctx;
	generic_chunk_t *ch;
	struct sip_msg msg;
	pv_spec_t data_pv;
	context_p ctx;
	int ret;

	cmd = find_cmd_export_t("hep_get", 0);
	load_hep = (load_hep_f)find_export("load_hep", 0);
	if (!cmd || !load_hep || load_hep(&api) < 0 ||
			!pv_parse_spec(&var, &data_pv))
		return -2;

	hctx = shm_malloc(sizeof *hctx);
	ch = malloc(sizeof *ch);
	ctx = context_alloc(CONTEXT_GLOBAL);
	if (!hctx || !ch || !ctx)
		return -2;
	memset(hctx, 0, sizeof *hctx);
	memset(ch, 0, sizeof *ch);
	ch->chunk.type_id = 31;
	ch->chunk.length = sizeof(hep_chunk_t) + data_len;
	ch->data = malloc(data_len);
	if (!ch->data)
		return -2;
	memset(ch->data, 1, data_len);
	hctx->h.version = 3;
	hctx->h.u.hepv3.chunk_list = ch;

	memset(ctx, 0, context_size(CONTEXT_GLOBAL));
	context_put_ptr(CONTEXT_GLOBAL, ctx, api.get_hep_ctx_id(), hctx);
	set_global_context(ctx);

	memset(&msg, 0, sizeof msg);
	ret = cmd->function(&msg, (void *)31UL, (void *)(long)type, &data_pv,
		NULL, NULL, NULL, NULL, NULL);

	set_global_context(NULL);
	free(ch->data);
	free(ch);
	shm_free(hctx);
	return ret;
}


static void test_hep_get_custom_len(void)
{
	ok(get_custom_chunk(4, 4) == 1, "4-byte custom chunk is read as uint32");
	ok(get_custom_chunk(4, 1) < 0,
		"1-byte custom chunk is not read as uint32");
	ok(get_custom_chunk(16, 2) < 0,
		"2-byte custom chunk is not read as an IPv6 address");
	ok(get_custom_chunk(1, 0) < 0, "empty custom chunk is not read as uint8");
}


void mod_tests(void)
{
	test_async_capture_size();
	test_report_event();
	test_hep_get_custom_len();
	test_hep_relay_size();
	test_report_event_type();
	test_async_capture_values();
	test_async_report_values();
}
