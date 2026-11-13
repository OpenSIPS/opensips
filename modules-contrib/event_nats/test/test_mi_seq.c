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
 * The "seq" parameter of nats_msg_get and nats_msg_delete: a stream
 * sequence is 64 bits wide, so it is taken as a string and parsed in
 * full; an MI integer is accepted too.  Zero, a negative number and
 * anything that is not a number are refused before JetStream is asked:
 * cast to 64 bits, -1 would name the last message a stream can hold.
 *
 * The two MI handlers themselves, against the fake JetStream of
 * en_ut_fake.c, which records the sequence it is asked for.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "../../../mi/mi.h"
#include "../../../lib/cJSON.h"
#include "../nats_jetstream.h"

#include "en_ut.h"

/* the code of an MI error reply, 0 for a result, -1 for no reply */
static int reply_code(mi_response_t *resp)
{
	cJSON *err, *code;
	int rc = 0;

	if (!resp)
		return -1;
	err = cJSON_GetObjectItem(resp, "error");
	if (err) {
		code = cJSON_GetObjectItem(err, "code");
		rc = code ? code->valueint : -2;
	}
	free_mi_response(resp);
	return rc;
}

/* nats_msg_get / nats_msg_delete with stream "S" and @seq, a string
 * (seq_str) or an integer */
static int call(mi_cmd_f *cmd, const char *stream, const char *seq_str,
	int seq_int)
{
	mi_params_t params;
	int rc;

	params.item = cJSON_CreateObject();
	params.list = NULL;
	if (stream)
		cJSON_AddItemToObject(params.item, "stream",
			cJSON_CreateString(stream));
	if (seq_str)
		cJSON_AddItemToObject(params.item, "seq",
			cJSON_CreateString(seq_str));
	else if (seq_int != INT_MIN)
		cJSON_AddItemToObject(params.item, "seq",
			cJSON_CreateNumber(seq_int));
	rc = reply_code(cmd(&params, NULL));
	cJSON_Delete(params.item);
	return rc;
}

#define NO_SEQ INT_MIN

/* accepted: JetStream is asked once, for exactly @want */
static int accepted(mi_cmd_f *cmd, const char *seq_str, int seq_int,
	uint64_t want)
{
	int before = ef.n_get_msg + ef.n_delete_msg;

	ef.msg_seq = 0;
	return call(cmd, "S", seq_str, seq_int) == 0
		&& ef.n_get_msg + ef.n_delete_msg == before + 1
		&& ef.msg_seq == want && strcmp(ef.msg_stream, "S") == 0;
}

/* refused with 400, and JetStream is not asked */
static int refused(mi_cmd_f *cmd, const char *seq_str, int seq_int)
{
	int before = ef.n_get_msg + ef.n_delete_msg;

	return call(cmd, "S", seq_str, seq_int) == 400
		&& ef.n_get_msg + ef.n_delete_msg == before;
}

static mi_cmd_f *cmd_under_test;

static int s_string_seq(void)
{
	ef.pool_js = en_ut_js();
	ef.msg_subject = "s";
	ef.msg_data = "d";
	ef.msg_len = 1;
	return accepted(cmd_under_test, "42", 0, 42)
		&& accepted(cmd_under_test, "1", 0, 1)
		/* past 32 and past 63 bits */
		&& accepted(cmd_under_test, "5000000000", 0, 5000000000ULL)
		&& accepted(cmd_under_test, "18446744073709551615", 0,
			18446744073709551615ULL)
		&& accepted(cmd_under_test, "007", 0, 7);
}

static int s_int_seq(void)
{
	ef.pool_js = en_ut_js();
	ef.msg_subject = "s";
	ef.msg_data = "d";
	ef.msg_len = 1;
	return accepted(cmd_under_test, NULL, 1, 1)
		&& accepted(cmd_under_test, NULL, INT_MAX, (uint64_t)INT_MAX);
}

static int s_refused_numbers(void)
{
	ef.pool_js = en_ut_js();
	return refused(cmd_under_test, "0", 0)
		&& refused(cmd_under_test, NULL, 0)
		&& refused(cmd_under_test, NULL, -1)
		&& refused(cmd_under_test, NULL, INT_MIN + 1)
		/* one past 64 bits, and far past */
		&& refused(cmd_under_test, "18446744073709551616", 0)
		&& refused(cmd_under_test, "99999999999999999999999", 0)
		&& refused(cmd_under_test, "999999999999999999999999", 0);
}

static int s_refused_text(void)
{
	ef.pool_js = en_ut_js();
	/* strtoull() would take a sign or a leading blank, and turn "-1"
	 * into the largest sequence there is */
	return refused(cmd_under_test, "-1", 0)
		&& refused(cmd_under_test, "-0", 0)
		&& refused(cmd_under_test, "+5", 0)
		&& refused(cmd_under_test, " 5", 0)
		&& refused(cmd_under_test, "\t5", 0)
		&& refused(cmd_under_test, "abc", 0)
		&& refused(cmd_under_test, "12abc", 0)
		&& refused(cmd_under_test, "12 ", 0)
		&& refused(cmd_under_test, " ", 0)
		&& refused(cmd_under_test, "1.5", 0)
		&& refused(cmd_under_test, "1e3", 0)
		&& refused(cmd_under_test, "0x10", 0)
		&& refused(cmd_under_test, "12\\3", 0)
		&& refused(cmd_under_test, "\"5\"", 0)
		&& refused(cmd_under_test, "5;drop", 0);
}

static int s_missing(void)
{
	ef.pool_js = en_ut_js();
	return call(cmd_under_test, "S", NULL, NO_SEQ) == 400
		&& call(cmd_under_test, NULL, "5", 0) == 400
		/* an empty string is no string: no usable seq */
		&& call(cmd_under_test, "S", "", 0) == 400
		&& ef.n_get_msg + ef.n_delete_msg == 0;
}

static int s_bad_stream(void)
{
	char name[300];

	ef.pool_js = en_ut_js();
	memset(name, 'a', sizeof name - 1);
	name[sizeof name - 1] = '\0';
	return call(cmd_under_test, name, "5", 0) == 400
		&& call(cmd_under_test, "a.b", "5", 0) == 400
		&& call(cmd_under_test, "a b", "5", 0) == 400
		&& call(cmd_under_test, "a*", "5", 0) == 400
		&& call(cmd_under_test, "a>", "5", 0) == 400
		&& ef.n_get_msg + ef.n_delete_msg == 0;
}

static int s_no_jetstream(void)
{
	/* a valid request, but no JetStream context: 500, nothing asked */
	return call(cmd_under_test, "S", "5", 0) == 500
		&& ef.n_get_msg + ef.n_delete_msg == 0;
}

static int s_not_found(void)
{
	ef.pool_js = en_ut_js();
	ef.get_msg_status = NATS_ERR;
	ef.delete_msg_status = NATS_ERR;
	ef.jerr = (jsErrCode)10037;   /* no message found */
	return call(cmd_under_test, "S", "5", 0) == 404;
}

static int s_get_reply(void)
{
	mi_params_t params;
	mi_response_t *resp;
	cJSON *result, *item;
	int good;

	ef.pool_js = en_ut_js();
	ef.msg_subject = "orders.new";
	ef.msg_data = "{\"a\":\"b\\\\c\"}";
	ef.msg_len = (int)strlen(ef.msg_data);
	params.item = cJSON_CreateObject();
	params.list = NULL;
	cJSON_AddItemToObject(params.item, "stream", cJSON_CreateString("S"));
	cJSON_AddItemToObject(params.item, "seq", cJSON_CreateString("77"));
	resp = mi_nats_msg_get(&params, NULL);
	cJSON_Delete(params.item);
	if (!resp)
		return 0;
	result = cJSON_GetObjectItem(resp, "result");
	good = result != NULL;
	item = good ? cJSON_GetObjectItem(result, "subject") : NULL;
	good = good && item && !strcmp(item->valuestring, "orders.new");
	item = good ? cJSON_GetObjectItem(result, "data") : NULL;
	good = good && item && !strcmp(item->valuestring, ef.msg_data);
	item = good ? cJSON_GetObjectItem(result, "sequence") : NULL;
	good = good && item && item->valuedouble == 77;
	free_mi_response(resp);
	/* the message is the handler's to destroy, once */
	return good && ef.n_msg_destroy == 1;
}

static void both(const char *what, en_ut_scenario_f f)
{
	char name[160];

	cmd_under_test = mi_nats_msg_get;
	snprintf(name, sizeof name, "nats_msg_get: %s", what);
	en_ut_run(name, f);
	cmd_under_test = mi_nats_msg_delete;
	snprintf(name, sizeof name, "nats_msg_delete: %s", what);
	en_ut_run(name, f);
}

void en_ut_mi_seq(void)
{
	both("seq as a string, up to 64 bits", s_string_seq);
	both("seq as an MI integer", s_int_seq);
	both("zero, negative and over-long numbers refused", s_refused_numbers);
	both("text that is not a whole number refused", s_refused_text);
	both("missing stream or seq refused", s_missing);
	both("an invalid stream name refused", s_bad_stream);
	both("no JetStream context: 500", s_no_jetstream);
	both("message not found: 404", s_not_found);
	en_ut_run("nats_msg_get: subject, data and sequence in the reply",
		s_get_reply);
}
