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
 * What the JetStream ack handler logs for a failed publish: the error
 * text comes from the broker and may be longer than the 256-byte buffer
 * the line is built in.  The line handed to write(2) must end with the
 * buffer -- snprintf() returns the length it would have written, and
 * writing that many bytes sends the stack next to the buffer to the log.
 *
 * The real handler (pool_js_pub_ack_handler, installed by
 * nats_pool_get_js()) called as libnats would; the bytes it writes to
 * fd 2 are read back from the log capture of nats_ut_fake.c.
 */

#include <tap.h>
#include <string.h>

#include "../nats_pool.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

#define PREFIX "NATS JetStream async publish error: "
#define LINE_MAX_LEN 255   /* the 256-byte buffer, less the NUL */

/* one failed ack with @text; the bytes written, in @raw */
static size_t ack_error(const char *text, char *raw, size_t size)
{
	jsPubAckErr pae;

	memset(&pae, 0, sizeof pae);
	pae.Err = NATS_ERR;
	pae.ErrCode = JSStreamNotFoundErr;   /* not retried */
	pae.ErrText = text;
	nats_ut_log_clear();
	nf.ack_handler((jsCtx *)nats_ut_fake_obj(), (natsMsg *)&nf.msgs[0],
		NULL, &pae, NULL);
	return nats_ut_log_raw(raw, size);
}

static int setup(void)
{
	return nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) == 0
		&& nats_pool_get_js() != NULL && nf.ack_handler != NULL;
}

static int s_short_text(void)
{
	char raw[4096];
	size_t n;

	if (!setup())
		return 0;
	n = ack_error("stream not found", raw, sizeof raw);
	return n == strlen(PREFIX "stream not found\n")
		&& memcmp(raw, PREFIX "stream not found\n", n) == 0;
}

static int long_text(size_t text_len)
{
	char text[5000], raw[8192];
	size_t n, i, plen = strlen(PREFIX);

	if (!setup() || text_len >= sizeof text)
		return 0;
	memset(text, 'E', text_len);
	text[text_len] = '\0';
	n = ack_error(text, raw, sizeof raw);
	if (n != LINE_MAX_LEN || memcmp(raw, PREFIX, plen) != 0)
		return 0;
	/* nothing but the broker's text follows the prefix */
	for (i = plen; i < n; i++)
		if (raw[i] != 'E')
			return 0;
	return 1;
}

static int s_text_fills_the_buffer(void)
{
	/* prefix + text + newline is exactly one byte too many */
	return long_text(LINE_MAX_LEN - strlen(PREFIX));
}

static int s_text_longer_than_the_buffer(void)
{ return long_text(1000); }

static int s_text_much_longer(void)
{ return long_text(4500); }

static int s_longest_text_that_fits(void)
{
	char text[256], raw[1024];
	size_t n, len = LINE_MAX_LEN - strlen(PREFIX) - 1;

	if (!setup())
		return 0;
	memset(text, 'E', len);
	text[len] = '\0';
	n = ack_error(text, raw, sizeof raw);
	return n == LINE_MAX_LEN && raw[n - 1] == '\n';
}

static int s_special_bytes(void)
{
	/* backslashes, quotes and a percent sign are data, not a format */
	char raw[1024];
	const char *text = "a\\b \"q\" 100%s %n";
	size_t n;

	if (!setup())
		return 0;
	n = ack_error(text, raw, sizeof raw);
	return n == strlen(PREFIX) + strlen(text) + 1
		&& memcmp(raw + strlen(PREFIX), text, strlen(text)) == 0;
}

static int s_empty_text(void)
{
	char raw[1024];

	if (!setup())
		return 0;
	return ack_error("", raw, sizeof raw) == strlen(PREFIX "\n");
}

static int s_no_text_is_a_success(void)
{
	/* libnats reports an error by its text: none is a stored message,
	 * nothing logged */
	char raw[64];
	jsPubAckErr pae;

	if (!setup())
		return 0;
	memset(&pae, 0, sizeof pae);
	nats_ut_log_clear();
	nf.ack_handler((jsCtx *)nats_ut_fake_obj(), (natsMsg *)&nf.msgs[1],
		NULL, &pae, NULL);
	return nats_ut_log_raw(raw, sizeof raw) == 0 && nf.destroyed[1] == 1;
}

void nats_ut_unsafe_log_clamp(void)
{
	nats_ut_run("a short error text is logged whole", s_short_text);
	nats_ut_run("the longest text that fits: 255 bytes, newline kept",
		s_longest_text_that_fits);
	nats_ut_run("one byte too many: 255 bytes written", s_text_fills_the_buffer);
	nats_ut_run("1000-byte text: 255 bytes written, all of them the text",
		s_text_longer_than_the_buffer);
	nats_ut_run("4500-byte text: 255 bytes written", s_text_much_longer);
	nats_ut_run("backslash, quote and percent in the text are logged as data",
		s_special_bytes);
	nats_ut_run("an empty text logs the prefix alone", s_empty_text);
	nats_ut_run("an ack error without a text logs nothing",
		s_no_text_is_a_success);
}
