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
 */

/*
 * test_err_text.c -- nats_err_text() turns a failed libnats call into a
 * log-ready message: the status name plus the detail libnats recorded
 * (nats_GetLastError), e.g. "Error: replicas > 1 not supported in
 * non-clustered mode" instead of a bare "Error".
 *
 * The detail can carry broker-supplied text, so control characters are
 * replaced (no log-line injection), and the result always fits and is
 * NUL-terminated in the caller's buffer.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../nats_err.h"

#include "nats_ut.h"


static const char *fake_last;          /* what nats_GetLastError returns */

static const char *fake_status_text(natsStatus s)
{
	switch (s) {
	case NATS_OK:          return "OK";
	case NATS_ERR:         return "Error";
	case NATS_INVALID_ARG: return "Invalid Argument";
	default:               return "Other";
	}
}

static const char *fake_last_error(natsStatus *status)
{
	(void)status;
	return fake_last;
}

static void expect(const char *label, natsStatus s, const char *last,
		size_t bufsz, const char *want)
{
	char buf[256];
	const char *got;

	fake_last = last;
	memset(buf, 'X', sizeof(buf));
	got = nats_err_text(s, buf, bufsz);
	ok(got && strcmp(got, want) == 0 && strlen(got) < bufsz,
		"%s (want \"%s\" got \"%s\")", label, want, got ? got : "(null)");
}

void nats_ut_err_text(void)
{
	/* nats_err_text() reads two slots of the libnats table: borrow them */
	const char *(*saved_text)(natsStatus) = nats_dl.natsStatus_GetText;
	const char *(*saved_last)(natsStatus *) = nats_dl.nats_GetLastError;

	nats_dl.natsStatus_GetText = fake_status_text;
	nats_dl.nats_GetLastError = fake_last_error;

	expect("detail appended", NATS_ERR,
		"replicas > 1 not supported in non-clustered mode", 256,
		"Error: replicas > 1 not supported in non-clustered mode");
	expect("no detail (NULL)", NATS_ERR, NULL, 256, "Error");
	expect("no detail (empty)", NATS_ERR, "", 256, "Error");
	expect("detail equal to the status name is not repeated",
		NATS_INVALID_ARG, "Invalid Argument", 256, "Invalid Argument");
	expect("detail for invalid argument", NATS_INVALID_ARG,
		"Invalid key", 256, "Invalid Argument: Invalid key");
	expect("CR/LF in broker text cannot split the log line", NATS_ERR,
		"bad\r\nFAKE: injected", 256, "Error: bad??FAKE: injected");
	expect("other control bytes replaced", NATS_ERR, "a\tb\x1b", 256,
		"Error: a?b?");
	expect("truncated to the buffer, still terminated", NATS_ERR,
		"0123456789", 12, "Error: 0123");
	expect("tiny buffer", NATS_ERR, "detail", 4, "Err");
	expect("one-byte buffer", NATS_ERR, "detail", 1, "");

	/* NATS_ERR_TEXT(s): same text, buffer supplied by the macro, usable
	 * directly as a printf argument */
	{
		char line[2 * NATS_ERR_TEXT_BUF + 32];
		fake_last = "stream not found";
		snprintf(line, sizeof(line), "failed: %s / %s",
			NATS_ERR_TEXT(NATS_ERR), NATS_ERR_TEXT(NATS_INVALID_ARG));
		is(line, "failed: Error: stream not found / "
			"Invalid Argument: stream not found", "NATS_ERR_TEXT");
	}

	nats_dl.natsStatus_GetText = saved_text;
	nats_dl.nats_GetLastError = saved_last;

}
