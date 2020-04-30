/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#include "../../str.h"
#include "../../ut.h"

#include "../../parser/parse_fcaps.h"

void test_parse_fcaps(void)
{
	struct hdr_field hf;
	fcaps_body_t *fcaps;
	str *hdr;

	hdr = _str("Feature-Caps: +sip.pns=\"apns\"\r\n");
	memset(&hf, 0, sizeof hf);
	get_hdr_field(hdr->s, hdr->s + hdr->len, &hf);
	ok(hf.type == HDR_FEATURE_CAPS_T, "fcaps-1");
	ok(str_match(&hf.body, _str("+sip.pns=\"apns\"")), "fcaps-2");

	hdr = _str("fEATURE-cAPS:+sip.pns=\"apns\"\r\n");
	memset(&hf, 0, sizeof hf);
	get_hdr_field(hdr->s, hdr->s + hdr->len, &hf);
	ok(hf.type == HDR_FEATURE_CAPS_T, "fcaps-3");
	ok(str_match(&hf.body, _str("+sip.pns=\"apns\"")), "fcaps-4");

	hdr = _str("feature-caps:      +sip.pns=\"apns\";+sip.pnsreg=\"130\"\r\n");
	memset(&hf, 0, sizeof hf);
	get_hdr_field(hdr->s, hdr->s + hdr->len, &hf);
	ok(hf.type == HDR_FEATURE_CAPS_T, "fcaps-5");
	ok(str_match(&hf.body, _str("+sip.pns=\"apns\";+sip.pnsreg=\"130\"")), "fcaps-6");
	free_fcaps((fcaps_body_t**)&hf.parsed);
	ok(!hf.parsed, "fcaps-7");

	ok(parse_fcaps(&hf) == 0, "fcaps-8");
	fcaps = (fcaps_body_t *)hf.parsed;
	ok(str_match(&fcaps->pns, _str("apns")), "fcaps-9");
	free_fcaps((fcaps_body_t**)&hf.parsed);

	hf.body = *_str("");
	ok(parse_fcaps(&hf) != 0, "fcaps-10");

	hf.body = *_str("+sip.pns");
	ok(parse_fcaps(&hf) != 0, "fcaps-11");

	hf.body = *_str("+sip.pns=");
	ok(parse_fcaps(&hf) != 0, "fcaps-12");

	hf.body = *_str("+sip.pns=x");
	ok(parse_fcaps(&hf) != 0, "fcaps-13");

	hf.body = *_str("+sip.pns=\"");
	ok(parse_fcaps(&hf) != 0, "fcaps-14");

	hf.body = *_str("+sip.pns=\"x");
	ok(parse_fcaps(&hf) != 0, "fcaps-15");

	hf.body = *_str("+sip.pns=x\"");
	ok(parse_fcaps(&hf) != 0, "fcaps-16");

	hf.body = *_str("+sip.pns=\"x\"");
	ok(parse_fcaps(&hf) == 0, "fcaps-17");
	fcaps = (fcaps_body_t *)hf.parsed;
	ok(str_match(&fcaps->pns, _str("x")), "fcaps-18");
	free_fcaps((fcaps_body_t**)&hf.parsed);

	hf.body = *_str("+sip.pns=\"apns\";+sip.pns=130\";+sip.pns=\"fcm\"+sip.pns+sip.pns=\"x");
	ok(parse_fcaps(&hf) == 0, "fcaps-19");
	fcaps = (fcaps_body_t *)hf.parsed;
	ok(str_match(&fcaps->pns, _str("fcm")), "fcaps-20");
	free_fcaps((fcaps_body_t**)&hf.parsed);

	hf.body = *_str("+sip.pns=\"apns\";+sip.pns=130\";+sip.pns=\"fcm\"+sip.pns+sip.pns=\"x");
	ok(parse_fcaps(&hf) == 0, "fcaps-21");
	fcaps = (fcaps_body_t *)hf.parsed;
	ok(str_match(&fcaps->pns, _str("fcm")), "fcaps-22");
	free_fcaps((fcaps_body_t**)&hf.parsed);

	hf.body = *_str("+sip.pns=\"apns\";+sip.pns=130\";+sip.pns=\"fcm\"+sip.pns+sip.pns=\"3");
	ok(parse_fcaps(&hf) == 0, "fcaps-23");
	fcaps = (fcaps_body_t *)hf.parsed;
	ok(str_match(&fcaps->pns, _str("fcm")), "fcaps-24");
	free_fcaps((fcaps_body_t**)&hf.parsed);

	hf.body = *_str("+sip.pns=\"apns\";+sip.pns=130\";+sip.pns=\"fcm\"+sip.pns+sip.pns=3;+sip.pns=\"webpush\"");
	ok(parse_fcaps(&hf) == 0, "fcaps-25");
	fcaps = (fcaps_body_t *)hf.parsed;
	ok(str_match(&fcaps->pns, _str("webpush")), "fcaps-26");
	free_fcaps((fcaps_body_t**)&hf.parsed);
}
