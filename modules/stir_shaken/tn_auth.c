/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "verify.h"
#include <stdint.h>
#include "../../ut.h"

/* Bounded DER reader for RFC 8226's EXPLICIT TAGS TNAuthorizationList. */
struct der { const unsigned char *p; size_t n; };
static int take(struct der *in, unsigned int tag, struct der *out)
{
	size_t len, bytes, i;
	if (in->n < 2 || in->p[0] != tag) return -1;
	len = in->p[1]; bytes = 2;
	if (len & 0x80) {
		len &= 0x7f;
		if (!len || len > sizeof(size_t) || in->n < 2+len || !in->p[2]) return -1;
		bytes += len;
		for (i = 2, len = 0; i < bytes; i++) len = (len << 8) | in->p[i];
		if (len < 128) return -1;
	}
	if (len > in->n-bytes) return -1;
	out->p = in->p+bytes; out->n = len;
	in->p += bytes+len; in->n -= bytes+len;
	return 0;
}

static int decimal(struct der d, uint64_t *out)
{
	size_t i;
	*out = 0;
	if (!d.n || d.n > 15) return -1;
	for (i = 0; i < d.n; i++) {
		if (d.p[i] < '0' || d.p[i] > '9') return -1;
		*out = *out*10 + d.p[i]-'0';
	}
	return 0;
}

int passport_authority_der(str *encoded, str *identity)
{
	struct der all = {(unsigned char *)encoded->s, encoded->len};
	struct der list, choice, value, range, first, count;
	uint64_t number = 0, start, total, max;
	size_t j;
	int match = 0;
	struct der id = {(unsigned char *)identity->s, identity->len};
	int numeric = decimal(id, &number) == 0;
	if (take(&all, 0x30, &list) || all.n || !list.n) return 0;
	while (list.n) {
		unsigned int tag = list.p[0];
		if (tag < 0xa0 || tag > 0xa2 || take(&list, tag, &choice)) return 0;
		if (tag == 0xa0 || tag == 0xa2) {
			if (take(&choice, 0x16, &value) || choice.n || !value.n) return 0;
			for (j = 0; j < value.n; j++)
				if (value.p[j] < 0x21 || value.p[j] > 0x7e) return 0;
			if (tag == 0xa0) {
				/* Trusted SHAKEN SPC credentials attest on behalf of the SP.
				 * SPC-to-TN registry lookup is not encoded in the certificate. */
				match = 1;
			} else {
				if (decimal(value, &start)) return 0;
				if (numeric && value.n == id.n && !memcmp(value.p, id.p, id.n)) match = 1;
			}
		} else {
			if (take(&choice, 0x30, &range) || choice.n ||
				take(&range, 0x16, &first) || decimal(first, &start) ||
				take(&range, 0x02, &count) || range.n || !count.n ||
				count.n > 8 || (count.p[0] & 0x80)) return 0;
			total = 0;
			for (j = 0; j < count.n; j++) total = (total << 8) | count.p[j];
			max = 1;
			for (j = 0; j < first.n; j++) max *= 10;
			if (total < 2 || total > max-start) return 0;
			if (numeric && id.n == first.n && number >= start && number-start < total) match = 1;
		}
	}
	return match;
}

int passport_certificate_authority(X509 *cert, str *identity)
{
	X509_EXTENSION *ext;
	ASN1_OCTET_STRING *data;
	char oid[128];
	str encoded;
	int i, seen = 0, match = 0;
	for (i = 0; i < X509_get_ext_count(cert); i++) {
		ext = X509_get_ext(cert, i);
		if (!ext || OBJ_obj2txt(oid, sizeof(oid), X509_EXTENSION_get_object(ext), 1) <= 0 ||
			strcmp(oid, "1.3.6.1.5.5.7.1.26")) continue;
		if (seen++) return 0;
		data = X509_EXTENSION_get_data(ext);
		if (!data || ASN1_STRING_length(data) <= 0) return 0;
		encoded.s = (char *)ASN1_STRING_data(data);
		encoded.len = ASN1_STRING_length(data);
		match = passport_authority_der(&encoded, identity);
	}
	return seen && match;
}
