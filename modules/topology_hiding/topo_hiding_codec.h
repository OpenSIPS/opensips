/*
 * Copyright (C) 2026 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _TOPO_HIDING_CODEC_H_
#define _TOPO_HIDING_CODEC_H_

#include "../../str.h"

enum th_callid_encode_scheme {
	TH_CALLID_ENC_XOR_WORD64 = 0,
	TH_CALLID_ENC_FF1_ALNUM62
};

int th_callid_codec_init(enum th_callid_encode_scheme scheme,
		const str *password, const str *prefix);
void th_callid_codec_cleanup(void);
int th_callid_codec_is_encoded(const str *callid);
int th_callid_codec_encode(const str *callid, str *encoded);
int th_callid_codec_decode(const str *encoded, str *callid);

#ifdef UNIT_TESTS
int th_callid_codec_test_ff1(const unsigned char *key, int key_bits,
		const unsigned char *input, int len, int radix,
		unsigned char *output, int decrypt);
#endif

#endif
