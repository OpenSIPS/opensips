/*
 * Copyright (C) 2026 OpenSIPS Project
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

#include <tap.h>
#include <string.h>

#include "../../../str.h"
#include "../../../mem/mem.h"
#include "../sca_records.h"
#include "../sca_logic.h"

int build_absoluteURI(str *host, str *port, str *call_info_uri);
int build_publish_call_info_header(b2b_sca_record_t *rec, str *publish_hdr);

static char hostbuf[256], uribuf[512];

static void test_absolute_uri(void)
{
	str host, port = str_init("5060"), out;
	int hlen, ok_all = 1;

	/* every host length around the 64 byte static buffer */
	for (hlen = 50; hlen <= 64; hlen++) {
		memset(hostbuf, 'h', hlen);
		host.s = hostbuf;
		host.len = hlen;
		if (build_absoluteURI(&host, &port, &out) != 0) {
			ok_all = 0;
			continue;
		}
		if (out.len != 4 + hlen + 1 + port.len ||
				memcmp(out.s, "sip:", 4) ||
				out.s[4 + hlen] != ':' ||
				memcmp(out.s + 4 + hlen + 1, "5060", 4))
			ok_all = 0;
	}
	ok(ok_all, "absoluteURI with a port fits its buffer");
}

static void test_publish_hdr(void)
{
	b2b_sca_record_t rec;
	b2b_sca_call_t calls[2];
	str out;
	int i, total, ok_all = 1;

	memset(uribuf, 'u', sizeof uribuf);

	/* every split of the URIs around the 512 byte static buffer */
	for (total = 300; total <= 340; total++) {
		memset(&rec, 0, sizeof rec);
		memset(calls, 0, sizeof calls);
		for (i = 0; i < 2; i++) {
			calls[i].appearance_index_str.s = i ? "2" : "1";
			calls[i].appearance_index_str.len = 1;
			calls[i].call_state = 0;
			calls[i].call_info_uri.s = uribuf;
			calls[i].call_info_uri.len = total / 4;
			calls[i].call_info_apperance_uri.s = uribuf;
			calls[i].call_info_apperance_uri.len =
				total / 2 - total / 4 + (i ? total % 2 : 0);
			rec.call[i] = &calls[i];
		}

		if (build_publish_call_info_header(&rec, &out) != 0) {
			ok_all = 0;
			continue;
		}
		if (out.len < 2 || memcmp(out.s + out.len - 2, "\r\n", 2))
			ok_all = 0;
	}
	ok(ok_all, "PUBLISH Call-Info with two calls fits its buffer");
}

void mod_tests(void)
{
	test_absolute_uri();
	test_publish_hdr();
}
