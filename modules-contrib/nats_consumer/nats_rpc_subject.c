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

#include "nats_rpc_subject.h"

#include <stdio.h>

int nats_rpc_subject_build(char *out, size_t out_sz,
                           const char *prefix, uint32_t slot, uint32_t gen,
                           const char *corr_id, int corr_id_len)
{
	int n, i;

	if (!out || out_sz == 0 || !prefix)
		return -1;

	/* corr_id is mandatory -- it is the unguessable token that
	 * authenticates the reply against forgery. */
	if (!corr_id || corr_id_len <= 0)
		return -1;

	/* It must be a single clean NATS token: no '.' (our segment
	 * separator), no whitespace, no wildcards, no control bytes. */
	for (i = 0; i < corr_id_len; i++) {
		unsigned char c = (unsigned char)corr_id[i];
		if (c == '.' || c == ' ' || c == '\t' || c == '*' ||
		    c == '>' || c < 0x20 || c == 0x7f)
			return -1;
	}

	n = snprintf(out, out_sz, "%s.%u.%u.%.*s", prefix,
		(unsigned)slot, (unsigned)gen, corr_id_len, corr_id);
	if (n <= 0 || (size_t)n >= out_sz)
		return -1;   /* truncated */
	return n;
}

int nats_rpc_subject_parse(const char *subject, int len,
                           uint32_t *slot, uint32_t *gen,
                           char *corr_out, size_t corr_sz)
{
	int         i, cdot = -1, gdot = -1, sdot = -1, corr_len;
	long        sv, gv;
	const char *p;

	if (!subject || len <= 0 || !slot || !gen || !corr_out || corr_sz == 0)
		return -1;

	/* last '.' separates the <corr_id> tail */
	for (i = len - 1; i >= 0; i--)
		if (subject[i] == '.') { cdot = i; break; }
	if (cdot < 0 || cdot >= len - 1)
		return -1;   /* no dot, or empty <corr_id> */

	/* preceding '.' separates the <gen> segment */
	for (i = cdot - 1; i >= 0; i--)
		if (subject[i] == '.') { gdot = i; break; }
	if (gdot < 0 || gdot >= cdot - 1)
		return -1;   /* no second dot, or empty <gen> segment */

	/* preceding '.' separates the <slot> segment */
	for (i = gdot - 1; i >= 0; i--)
		if (subject[i] == '.') { sdot = i; break; }
	if (sdot < 0 || sdot >= gdot - 1)
		return -1;   /* no third dot, or empty <slot> segment */

	/* <slot> digits live in (sdot, gdot) -- clamp to INT32_MAX to
	 * match the slot-index domain. */
	sv = 0;
	for (p = subject + sdot + 1; p < subject + gdot; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		sv = sv * 10 + (*p - '0');
		if (sv > 0x7fffffffL)
			return -1;
	}

	/* <gen> digits live in (gdot, cdot) -- full uint32 domain. */
	gv = 0;
	for (p = subject + gdot + 1; p < subject + cdot; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		gv = gv * 10 + (*p - '0');
		if (gv > 0xffffffffL)
			return -1;
	}

	/* <corr_id> bytes live in (cdot, len) -- copy out NUL-terminated. */
	corr_len = len - (cdot + 1);
	if (corr_len <= 0 || (size_t)corr_len >= corr_sz)
		return -1;
	for (i = 0; i < corr_len; i++)
		corr_out[i] = subject[cdot + 1 + i];
	corr_out[corr_len] = '\0';

	*slot = (uint32_t)sv;
	*gen  = (uint32_t)gv;
	return 0;
}
