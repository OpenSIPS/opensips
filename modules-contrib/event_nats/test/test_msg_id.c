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
 * test_msg_id.c -- the Nats-Msg-Id of a JetStream publish (nats_msg_id.c):
 *   - the msg_id modparam "EVENT: param, param, ..." names the event
 *     parameters that form the id of that event;
 *   - the id is "EVENT:value:value..." -- the same event parameters always
 *     give the same id, different ones a different id, with ':' and '%'
 *     and bytes outside printable ASCII percent-encoded so that two value
 *     lists can never produce one id;
 *   - a parameter missing from the raised event, or an id over 255 bytes,
 *     is an error (the caller then uses a generated id);
 *   - an id given to nats_publish() is checked: 1..255 printable bytes;
 *   - a generated id is "<16 hex digits>-<sequence>".
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_msg_id.h"

#include "en_ut.h"

#define ASSERT(cond, label) ok((cond), "%s", (label))

/* an EVI parameter list built on the stack */
static evi_param_t P[8];
static evi_params_t L;

static void params_reset(void)
{
	memset(P, 0, sizeof P);
	memset(&L, 0, sizeof L);
}

static void add_int(const char *name, int v)
{
	evi_param_t *p = &P[0];

	while (p->name.s)
		p++;
	p->flags = EVI_INT_VAL;
	p->val.n = v;
	p->name.s = (char *)name;
	p->name.len = strlen(name);
	if (L.last)
		L.last->next = p;
	else
		L.first = p;
	L.last = p;
}

static void add_str(const char *name, const char *v)
{
	evi_param_t *p = &P[0];

	while (p->name.s)
		p++;
	p->flags = EVI_STR_VAL;
	p->val.s.s = (char *)v;
	p->val.s.len = strlen(v);
	p->name.s = (char *)name;
	p->name.len = strlen(name);
	if (L.last)
		L.last->next = p;
	else
		L.first = p;
	L.last = p;
}

static int parse(const char *spec, nats_msg_id_rule *r)
{
	return nats_msg_id_rule_parse(spec, (int)strlen(spec), r);
}

static int build(const nats_msg_id_rule *r, char *out)
{
	return nats_msg_id_build(r, &L, out, NATS_MSG_ID_BUF);
}

static void test_parse(void)
{
	nats_msg_id_rule r;

	ASSERT(parse("E_DLG_STATE_CHANGED: hash_entry, hash_id, new_state", &r) == 0,
		"a rule with three parameters parses");
	ASSERT(r.event.len == 19 && memcmp(r.event.s, "E_DLG_STATE_CHANGED", 19) == 0,
		"...the event name is kept without the spaces");
	ASSERT(r.nparams == 3 && r.params[2].len == 9 &&
		memcmp(r.params[2].s, "new_state", 9) == 0,
		"...and the parameter names, trimmed");
	ASSERT(parse("E_X:a", &r) == 0 && r.nparams == 1, "one parameter, no spaces");
	ASSERT(parse("E_X:", &r) < 0, "no parameter: refused");
	ASSERT(parse("E_X", &r) < 0, "no ':': refused");
	ASSERT(parse(":a,b", &r) < 0, "no event name: refused");
	ASSERT(parse("E_X:a,,b", &r) < 0, "an empty parameter name: refused");
	ASSERT(parse("E_X:a,b,", &r) < 0, "a trailing comma: refused");
	ASSERT(parse("E X:a", &r) < 0, "a space inside the event name: refused");
	ASSERT(parse("E_X:a b", &r) < 0, "a space inside a parameter name: refused");
	ASSERT(parse("E_X:a,b,c,d,e,f,g,h", &r) == 0 && r.nparams == 8,
		"eight parameters: accepted");
	ASSERT(parse("E_X:a,b,c,d,e,f,g,h,i", &r) < 0, "nine parameters: refused");
	ASSERT(parse("E_X:a,a", &r) < 0, "the same parameter twice: refused");
}

static void test_build(void)
{
	nats_msg_id_rule r;
	char out[NATS_MSG_ID_BUF], out2[NATS_MSG_ID_BUF];
	int n;

	parse("E_DLG_STATE_CHANGED:hash_entry,hash_id,new_state", &r);

	params_reset();
	add_int("hash_entry", 1234);
	add_str("callid", "abc@example.com");
	add_int("hash_id", 5678);
	add_int("old_state", 3);
	add_int("new_state", 4);
	n = build(&r, out);
	ASSERT(n > 0 && strcmp(out, "E_DLG_STATE_CHANGED:1234:5678:4") == 0,
		"the id is EVENT:value:value:value in the rule's order");
	ASSERT(n == (int)strlen(out), "...and the length is returned");

	build(&r, out2);
	ASSERT(strcmp(out, out2) == 0, "the same parameters give the same id");

	P[4].val.n = 5;
	build(&r, out2);
	ASSERT(strcmp(out, out2) != 0, "a different parameter value gives another id");

	P[2].val.n = -7;
	build(&r, out2);
	ASSERT(strcmp(out2, "E_DLG_STATE_CHANGED:1234:-7:5") == 0,
		"a negative integer is written with its sign");

	/* string values and the escaping */
	parse("E_X:a,b", &r);
	params_reset();
	add_str("a", "x:y");
	add_str("b", "z");
	build(&r, out);
	params_reset();
	add_str("a", "x");
	add_str("b", "y:z");
	build(&r, out2);
	ASSERT(strcmp(out, "E_X:x%3Ay:z") == 0 && strcmp(out2, "E_X:x:y%3Az") == 0 &&
		strcmp(out, out2) != 0,
		"':' inside a value is encoded, so (x:y, z) and (x, y:z) differ");

	params_reset();
	add_str("a", "100%");
	add_str("b", "a b\r\n\x7f\xc3\xa9");
	build(&r, out);
	ASSERT(strcmp(out, "E_X:100%25:a%20b%0D%0A%7F%C3%A9") == 0,
		"'%', space, CR, LF, DEL and non-ASCII bytes are percent-encoded");

	params_reset();
	add_str("a", "");
	add_str("b", "q");
	ASSERT(build(&r, out) > 0 && strcmp(out, "E_X::q") == 0,
		"an empty string value is kept as empty");

	params_reset();
	add_str("a", "only-a");
	ASSERT(build(&r, out) == NATS_MSG_ID_EMISSING,
		"a parameter missing from the event: NATS_MSG_ID_EMISSING");

	params_reset();
	add_str("A", "1");
	add_str("b", "2");
	ASSERT(build(&r, out) == NATS_MSG_ID_EMISSING,
		"parameter names match case-sensitively, as EVI names do");
}

static void test_too_long(void)
{
	nats_msg_id_rule r;
	char out[NATS_MSG_ID_BUF];
	char big[300];
	int n;

	parse("E_X:a", &r);
	memset(big, 'v', sizeof big - 1);
	big[sizeof big - 1] = '\0';

	params_reset();
	big[NATS_MSG_ID_MAX - 4] = '\0';   /* "E_X:" + value = exactly the max */
	add_str("a", big);
	n = build(&r, out);
	ASSERT(n == NATS_MSG_ID_MAX && (int)strlen(out) == NATS_MSG_ID_MAX,
		"an id of exactly 255 bytes is accepted");

	params_reset();
	big[NATS_MSG_ID_MAX - 4] = 'v';
	big[NATS_MSG_ID_MAX - 3] = '\0';
	add_str("a", big);
	ASSERT(build(&r, out) == NATS_MSG_ID_ETOOLONG, "256 bytes: NATS_MSG_ID_ETOOLONG");

	params_reset();
	memset(big, ':', 100);
	big[100] = '\0';
	add_str("a", big);
	ASSERT(build(&r, out) == NATS_MSG_ID_ETOOLONG,
		"the length after encoding is what counts (100 ':' -> 300 bytes)");
}

static void test_check(void)
{
	char big[300];

	ASSERT(nats_msg_id_check("call-42:ringing", 15) == 0, "a printable id is accepted");
	ASSERT(nats_msg_id_check("", 0) < 0, "an empty id is refused");
	ASSERT(nats_msg_id_check("a b", 3) < 0, "a space is refused");
	ASSERT(nats_msg_id_check("a\r\nX-Evil: 1", 12) < 0,
		"CR/LF is refused (it would end the header)");
	ASSERT(nats_msg_id_check("a\x7f", 2) < 0, "DEL is refused");
	ASSERT(nats_msg_id_check("\xc3\xa9", 2) < 0, "non-ASCII bytes are refused");
	memset(big, 'x', sizeof big);
	ASSERT(nats_msg_id_check(big, NATS_MSG_ID_MAX) == 0, "255 bytes are accepted");
	ASSERT(nats_msg_id_check(big, NATS_MSG_ID_MAX + 1) < 0, "256 bytes are refused");
	ASSERT(nats_msg_id_check("a\0b", 3) < 0, "an embedded NUL is refused");
}

static void test_generated(void)
{
	char a[NATS_MSG_ID_BUF], b[NATS_MSG_ID_BUF];
	int n;

	n = nats_msg_id_generated(0x0123456789abcdefULL, 1, a, sizeof a);
	ASSERT(n > 0 && strcmp(a, "0123456789abcdef-1") == 0,
		"generated: 16 hex digits of the process prefix, '-', the sequence");
	nats_msg_id_generated(0x0123456789abcdefULL, 2, b, sizeof b);
	ASSERT(strcmp(a, b) != 0, "the next sequence gives another id");
	nats_msg_id_generated(0x0123456789abcdeeULL, 1, b, sizeof b);
	ASSERT(strcmp(a, b) != 0, "another process prefix gives another id");
	nats_msg_id_generated(0, 18446744073709551615ULL, b, sizeof b);
	ASSERT(strcmp(b, "0000000000000000-18446744073709551615") == 0,
		"the largest sequence fits");
	ASSERT(nats_msg_id_check(b, (int)strlen(b)) == 0,
		"a generated id passes the id check");
	ASSERT(nats_msg_id_generated(1, 1, b, 10) < 0, "a buffer too small is an error");
}

void en_ut_msg_id(void)
{
	test_parse();
	test_build();
	test_too_long();
	test_check();
	test_generated();

}
