/*
 * contact param handling
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include "encode.h"
#include "mid_registrar.h"
#include "../../lib/reg/common.h"

#include "../../ut.h"

static str aor_buf;
int mid_reg_escape_aor(const str *aor, str *out)
{
	char c, *p, *end, *w;
	int found_at = 0;

	if (pkg_str_extend(&aor_buf, 3 * aor->len + at_escape_str.len) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	w = aor_buf.s;

	for (p = aor->s, end = p + aor->len; p < end; p++) {
		c = *p;

		if (c < 0) {
			LM_ERR("bad char in AoR '%.*s': '%c' (%d)\n",
			       aor->len, aor->s, c, c);
			return -1;
		}

		if (is_username_char(c)) {
			*w++ = c;
		} else if (reg_use_domain && c == '@' && !found_at) {
			memcpy(w, at_escape_str.s, at_escape_str.len);
			w += at_escape_str.len;
			found_at = 1;
		} else {
			*w++ = '%';
			*w++ = fourbits2char[c >> 4];
			*w++ = fourbits2char[c & 0xFF];
		}
	}

	out->s = aor_buf.s;
	out->len = w - aor_buf.s;

	return 0;
}


int mid_reg_unescape_at_char(const str *aor, str *out)
{
	char c, *p, *end, *w, fc;

	if (pkg_str_extend(&aor_buf, aor->len) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	fc = at_escape_str.s[0];
	w = aor_buf.s;

	for (p = aor->s, end = p + aor->len; p < end; p++) {
		c = *p;

		if (c == fc && (end - p) >= at_escape_str.len &&
		        !memcmp(p, at_escape_str.s, at_escape_str.len)) {
			*w++ = '@';
			memcpy(w, p + at_escape_str.len, end - (p + at_escape_str.len));
			w += end - (p + at_escape_str.len);
			goto out;
		} else {
			*w++ = c;
		}
	}

out:
	out->s = aor_buf.s;
	out->len = w - aor_buf.s;

	return 0;
}


/* the AoR is already unescaped, per RFC specs.  We only need to unescape
 * our custom-escaped '@' sign, if the case */
int mid_reg_update_aor(str *aor)
{
	if (!reg_use_domain)
		return 0;

	if (mid_reg_unescape_at_char(aor, aor) < 0) {
		LM_ERR("failed to un-escape the '@' symbol in AoR: '%.*s'\n",
		       aor->len, aor->s);
		return -1;
	}

	return 0;
}


int encrypt_str(str *in, str *out)
{
	if (in->len == 0 || !in->s) {
		out->len = 0;
		out->s = NULL;
		return 0;
	}

	out->len = calc_word64_encode_len(in->len);
	out->s = pkg_malloc(out->len);
	if (!out->s) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	memset(out->s, 0, out->len);

	word64encode((unsigned char *)out->s, (unsigned char *)in->s, in->len);
	return 0;
}


int decrypt_str(str *in, str *out)
{
	out->len = calc_max_word64_decode_len(in->len);
	out->s = pkg_malloc(out->len);
	if (!out->s) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	out->len = word64decode((unsigned char *)out->s,
	             (unsigned char *)in->s, in->len);
	return 0;
}
