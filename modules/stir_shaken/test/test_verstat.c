/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <tap.h>
#include "../verstat.h"
#include "../../../context.h"
#include "../../../data_lump.h"
#include "../../../msg_translator.h"
#include "../../../parser/parse_to.h"

static const char invite[] =
	"INVITE sip:b@example.test SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-verstat\r\n"
	"From: \"verstat=display\" <sip:+12025550100;VERSTAT=old;foo=x@example.test;verstat=old;user=phone?Subject=verstat%3Dkept>;tag=abc\r\n"
	"To: <sip:b@example.test>\r\n"
	"P-Asserted-Identity: <sip:+12025550100@example.test;user=phone>, <tel:+12025550100;phone-context=example.test;verstat=old;verstat=old>\r\n"
	"P-Asserted-Identity: sip:+12025550101@example.test\r\n"
	"Call-ID: verstat-test\r\n"
	"CSeq: 1 INVITE\r\n"
	"Content-Length: 0\r\n\r\n";

static int occurrences(char *s, const char *word)
{
	int count = 0;
	while ((s = strstr(s, word))) { count++; s += strlen(word); }
	return count;
}

static int lump_count(struct sip_msg *msg)
{
	int count = 0;
	struct lump *p;
	for (p = msg->add_rm; p; p = p->next) count++;
	return count;
}

/* Exercise the actual serializer and reparse its output, not just lump data. */
static char *serialize(struct sip_msg *msg)
{
	struct socket_info sock = {0};
	struct sip_msg parsed = {0};
	unsigned int len;
	char *wire = build_req_buf_from_sip_req(msg, &len, &sock, PROTO_UDP,
		NULL, MSG_TRANS_NOVIA_FLAG);
	struct hdr_field *hf;
	struct to_body *body;
	if (!wire) return NULL;
	if (parse_msg(wire, len, &parsed) < 0 ||
		parse_headers(&parsed, HDR_EOH_F, 0) < 0) goto bad;
	for (hf = parsed.headers; hf; hf = hf->next) {
		if (hf->type != HDR_FROM_T && hf->type != HDR_PAI_T) continue;
		body = pkg_malloc(sizeof(*body));
		if (!body) goto bad;
		memset(body, 0, sizeof(*body));
		parse_multi_to(hf->body.s, hf->body.s+hf->body.len+1, body);
		if (body->error == PARSE_ERROR) {
			body->next = NULL;
			free_to(body);
			goto bad;
		}
		free_to(body);
	}
	free_sip_msg(&parsed);
	return wire;
bad:
	free_sip_msg(&parsed);
	pkg_free(wire);
	return NULL;
}

void test_verstat(void)
{
	struct sip_msg msg = {0};
	str both = str_init("both"), from = str_init("from"), pai = str_init("pai");
	str pass = str_init("TN-Validation-Passed"), fail = str_init("TN-Validation-Failed");
	str none = str_init("No-TN-Validation"), invalid = str_init("TN-Validation-Passed-A");
	str bad_target = str_init("all");
	char input[sizeof(invite)], *wire;
	int i, rc = 1;

	push_new_global_context();
	memcpy(input, invite, sizeof(input));
	msg.buf = input; msg.len = sizeof(input)-1; msg.ruri_q = Q_UNSPECIFIED;
	if (parse_msg(input, msg.len, &msg) < 0) {
		ok(0, "verstat fixture setup");
		goto done;
	}
	for (i = 0; i < 25; i++)
		if (stir_shaken_set_verstat(&msg, &both, &pass) != 1) rc = -1;
	ok(rc == 1 && lump_count(&msg) == 3,
		"repeated verstat set keeps one replacement per selected header");
	wire = serialize(&msg);
	ok(wire && occurrences(wire, ";verstat=TN-Validation-Passed") == 4 &&
		!strstr(wire, ";verstat=old") && !strstr(wire, ";VERSTAT="),
		"wire output has one verstat per identity across all PAI fields");
	ok(wire && strstr(wire, "sip:+12025550100;foo=x;verstat=TN-Validation-Passed@example.test;user=phone?Subject=verstat%3Dkept") &&
		strstr(wire, ";phone-context=example.test;verstat=") &&
		strstr(wire, "\"verstat=display\"") && strstr(wire, ";tag=abc"),
		"verstat edits preserve display, tag, other parameters and URI headers");
	if (wire) pkg_free(wire);
	ok(stir_shaken_set_verstat(&msg, &from, &fail) == 1,
		"a later from-only set replaces the earlier both value");
	wire = serialize(&msg);
	ok(wire && occurrences(wire, ";verstat=TN-Validation-Passed") == 3 &&
		occurrences(wire, ";verstat=TN-Validation-Failed") == 1,
		"mixed target calls retain distinct final From and PAI values");
	if (wire) pkg_free(wire);
	ok(stir_shaken_remove_verstat(&msg, &pai) == 1 &&
		stir_shaken_remove_verstat(&msg, &pai) == 1,
		"repeated verstat removal succeeds");
	wire = serialize(&msg);
	ok(wire && occurrences(wire, ";verstat=") == 1,
		"PAI removal cancels pending sets without touching From");
	if (wire) pkg_free(wire);
	ok(stir_shaken_set_verstat(&msg, &both, &none) == 1 &&
		stir_shaken_set_verstat(&msg, &both, &invalid) == -3 &&
		stir_shaken_set_verstat(&msg, &bad_target, &pass) == -3,
		"only standardized values and supported targets are accepted");
	wire = serialize(&msg);
	ok(wire && occurrences(wire, ";verstat=No-TN-Validation") == 4,
		"invalid calls leave the previous successful result intact");
	if (wire) pkg_free(wire);
	ok(stir_shaken_remove_verstat(&msg, &both) == 1,
		"remove both after repeated mixed updates succeeds");
	wire = serialize(&msg);
	ok(wire && !strstr(wire, ";verstat=") && lump_count(&msg) == 3,
		"final removal leaves valid SIP and no verstat parameters");
	if (wire) pkg_free(wire);
	/* Simulate another script function discarding every pending edit. */
	free_lump_list(msg.add_rm); msg.add_rm = NULL;
	ok(stir_shaken_set_verstat(&msg, &both, &pass) == -4,
		"discarded lumps are detected without dereferencing stale state");
done:
	free_sip_msg(&msg);
	pop_pushed_global_context();
}

static void test_verstat_edge(const char *fields, int malformed)
{
	char input[2048], *wire, *space;
	struct sip_msg msg = {0};
	struct hdr_field *hf;
	struct lump *anchor;
	str both = str_init("both"), pass = str_init("TN-Validation-Passed");
	int len;

	len = snprintf(input, sizeof(input),
		"INVITE sip:b@example.test SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-edge\r\n"
		"From: tel:+12025550100;tag=abc;verstat=\"old\"\r\n"
		"To: <sip:b@example.test>\r\n%s"
		"Call-ID: edge\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", fields);
	push_new_global_context();
	msg.buf = input; msg.len = len; msg.ruri_q = Q_UNSPECIFIED;
	if (parse_msg(input, len, &msg) < 0) {
		ok(0, "verstat edge fixture setup");
		goto done;
	}
	if (malformed) {
		ok(stir_shaken_set_verstat(&msg, &both, &pass) == -2 &&
			!msg.add_rm, "malformed multi-PAI rejects both atomically without a lump crash");
		goto done;
	}
	ok(stir_shaken_set_verstat(&msg, &both, &pass) == 1,
		"bare TEL URI and misplaced quoted verstat can be normalized");
	wire = serialize(&msg);
	ok(wire && strstr(wire, "From: <tel:+12025550100;verstat=TN-Validation-Passed>;tag=abc") &&
		!strstr(wire, "old"), "bare TEL becomes name-addr while retaining the From tag");
	if (wire) pkg_free(wire);
	/* Attach another function's edit to our owned deletion anchor. */
	hf = get_header_by_static_name(&msg, "P-Asserted-Identity");
	anchor = msg.add_rm;
	while (anchor && anchor->u.offset != (unsigned int)(hf->body.s-msg.buf))
		anchor = anchor->next;
	space = pkg_malloc(1); *space = ' ';
	insert_new_lump_after(anchor, space, 1, 0);
	ok(stir_shaken_remove_verstat(&msg, &both) == -4,
		"foreign edits attached to a managed header are refused");
	/* Existing From must still have its prior value: both did not half-apply. */
	wire = serialize(&msg);
	ok(wire && occurrences(wire, ";verstat=TN-Validation-Passed") == 2,
		"conflicting both call preserves both previously committed results");
	if (wire) pkg_free(wire);
done:
	free_sip_msg(&msg);
	pop_pushed_global_context();
}

void test_verstat_edges(void)
{
	test_verstat_edge("P-Asserted-Identity: <tel:+12025550100>\r\n", 0);
	test_verstat_edge("P-Asserted-Identity: <tel:+12025550100>, <broken\r\n", 1);
}
