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
 * nats_err.h -- log text for a failed libnats call.
 *
 * natsStatus_GetText() alone gives only the status name ("Error",
 * "Invalid Argument"); the useful part -- often the broker's own
 * message, e.g. "replicas > 1 not supported in non-clustered mode" --
 * is in nats_GetLastError().  nats_err_text() joins the two:
 *
 *	LM_ERR("... failed: %s\n", NATS_ERR_TEXT(s));
 *
 * Control characters in the detail are replaced with '?', so broker text
 * cannot split or forge log lines.  The result always fits @n and is
 * NUL-terminated.  Call it on the thread that made the failing call
 * (libnats keeps the last error per thread).
 */

#ifndef LIB_NATS_NATS_ERR_H
#define LIB_NATS_NATS_ERR_H

#include <stdio.h>
#include <string.h>

#include "nats_dl.h"

#define NATS_ERR_TEXT_BUF 256

static inline const char *nats_err_text(natsStatus s, char *buf, size_t n)
{
	const char *name = nats_dl.natsStatus_GetText(s);
	const char *detail = nats_dl.nats_GetLastError(NULL);
	size_t i;

	if (!buf || n == 0)
		return "";
	if (!name)
		name = "";
	if (detail && *detail && strcmp(detail, name) != 0)
		snprintf(buf, n, "%s: %s", name, detail);
	else
		snprintf(buf, n, "%s", name);

	for (i = 0; buf[i]; i++)
		if ((unsigned char)buf[i] < 0x20 || buf[i] == 0x7f)
			buf[i] = '?';
	return buf;
}

/* nats_err_text() with a buffer that lives until the end of the
 * enclosing full expression -- for direct use as a log argument:
 *	LM_ERR("put failed: %s\n", NATS_ERR_TEXT(s)); */
#define NATS_ERR_TEXT(s) \
	nats_err_text((s), (char [NATS_ERR_TEXT_BUF]){0}, NATS_ERR_TEXT_BUF)

#endif /* LIB_NATS_NATS_ERR_H */
