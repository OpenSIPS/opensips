/*
 * Radix-preserving Call-ID codec for the topology_hiding module.
 *
 * Copyright (C) 2026 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <limits.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "topo_hiding_codec.h"

#define TH_FF1_RADIX 62
#define TH_WORD_RADIX 85
#define TH_FF1_MIN_LEN 4
#define TH_CALLID_MAX_PLAIN_LEN 4096
/* ceil(log_62(domain(4096))) for the structured radix-85 Call-ID domain. */
#define TH_CALLID_MAX_STRUCTURED_PAYLOAD_LEN 4411

/* The marker encodes both the wire version and the input domain. */
#define TH_FF1_MARK_NATIVE 'A'
#define TH_FF1_MARK_WORD   'B'
#define TH_FF1_MARK_LEGACY 'C'

static const unsigned char alnum62[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static const unsigned char word85[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.!%*_+`'~()<>:\\\"/[]?{}";

static signed short alnum62_idx[256];
static signed short word85_idx[256];
static enum th_callid_encode_scheme callid_scheme;
static str callid_password;
static str callid_prefix;
static unsigned char ff1_key[32];
static int ff1_key_bits;

static int init_alphabet(signed short idx[256], const unsigned char *symbols,
		int radix)
{
	int i;

	for (i = 0; i < 256; i++)
		idx[i] = -1;
	for (i = 0; i < radix; i++) {
		if (idx[symbols[i]] >= 0) {
			LM_ERR("duplicate symbol in Call-ID alphabet\n");
			return -1;
		}
		idx[symbols[i]] = i;
	}

	return 0;
}

static int hkdf_ff1_key(const str *password, unsigned char key[32])
{
	static const unsigned char salt[] =
		"OpenSIPS topology_hiding FF1 key v1";
	static const unsigned char info[] =
		"Call-ID ff1-alnum62\x01";
	unsigned char prk[EVP_MAX_MD_SIZE];
	unsigned int prk_len, key_len;

	if (!HMAC(EVP_sha256(), salt, sizeof(salt) - 1,
			(unsigned char *)password->s, password->len, prk, &prk_len))
		return -1;
	if (!HMAC(EVP_sha256(), prk, prk_len, info, sizeof(info) - 1,
			key, &key_len)) {
		OPENSSL_cleanse(prk, sizeof(prk));
		return -1;
	}
	OPENSSL_cleanse(prk, sizeof(prk));

	return key_len == 32 ? 0 : -1;
}

int th_callid_codec_init(enum th_callid_encode_scheme scheme,
		const str *password, const str *prefix)
{
	unsigned char key[32];
	int i;

	if (!password || !password->s || password->len <= 0 ||
			!prefix || !prefix->s || prefix->len <= 0) {
		LM_ERR("Call-ID password and prefix must not be empty\n");
		return -1;
	}

	if (init_alphabet(alnum62_idx, alnum62, TH_FF1_RADIX) < 0 ||
			init_alphabet(word85_idx, word85, TH_WORD_RADIX) < 0)
		return -1;

	OPENSSL_cleanse(ff1_key, sizeof(ff1_key));
	ff1_key_bits = 0;
	callid_scheme = scheme;
	callid_password = *password;
	callid_prefix = *prefix;

	if (scheme == TH_CALLID_ENC_XOR_WORD64)
		return 0;
	if (scheme != TH_CALLID_ENC_FF1_ALNUM62) {
		LM_ERR("unknown Call-ID encode scheme %d\n", scheme);
		return -1;
	}

	for (i = 0; i < prefix->len; i++) {
		if (alnum62_idx[(unsigned char)prefix->s[i]] < 0) {
			LM_ERR("ff1-alnum62 requires an alphanumeric th_callid_prefix\n");
			return -1;
		}
	}
	if (password->len == 8 && !memcmp(password->s, "OpenSIPS", 8)) {
		LM_ERR("ff1-alnum62 cannot be used with the default th_callid_passwd\n");
		return -1;
	}
	if (password->len < 32)
		LM_WARN("ff1-alnum62 should use a high-entropy password of at least 32 characters\n");

	if (hkdf_ff1_key(password, key) < 0) {
		OPENSSL_cleanse(key, sizeof(key));
		LM_ERR("failed to initialize the FF1 AES key\n");
		return -1;
	}
	memcpy(ff1_key, key, sizeof(ff1_key));
	ff1_key_bits = 256;
	OPENSSL_cleanse(key, sizeof(key));

	return 0;
}

void th_callid_codec_cleanup(void)
{
	OPENSSL_cleanse(ff1_key, sizeof(ff1_key));
	ff1_key_bits = 0;
}

static int bn_from_digits(const unsigned char *digits, int len, int radix,
		BIGNUM *number)
{
	int i;

	BN_zero(number);
	for (i = 0; i < len; i++) {
		if (!BN_mul_word(number, radix) || !BN_add_word(number, digits[i]))
			return -1;
	}
	return 0;
}

static int bn_to_digits(const BIGNUM *number, int len, int radix,
		unsigned char *digits)
{
	BIGNUM *tmp;
	BN_ULONG rem;
	int i;

	tmp = BN_dup(number);
	if (!tmp)
		return -1;
	for (i = len - 1; i >= 0; i--) {
		rem = BN_div_word(tmp, radix);
		if (rem == (BN_ULONG)-1)
			goto error;
		digits[i] = (unsigned char)rem;
	}
	if (!BN_is_zero(tmp))
		goto error;
	BN_free(tmp);
	return 0;

error:
	BN_free(tmp);
	return -1;
}

static int bn_pow_word(BIGNUM *out, int radix, int exponent)
{
	int i;

	if (!BN_one(out))
		return -1;
	for (i = 0; i < exponent; i++)
		if (!BN_mul_word(out, radix))
			return -1;
	return 0;
}

static int bn_to_fixed_bytes(const BIGNUM *number, unsigned char *out, int len)
{
	int bytes = BN_num_bytes(number);

	if (bytes > len)
		return -1;
	memset(out, 0, len - bytes);
	if (bytes && BN_bn2bin(number, out + len - bytes) != bytes)
		return -1;
	return 0;
}

static int ff1_encrypt_block(EVP_CIPHER_CTX *ctx, const unsigned char *input,
		unsigned char output[16])
{
	int out_len;

	return EVP_EncryptUpdate(ctx, output, &out_len, input, 16) == 1 &&
		out_len == 16 ? 0 : -1;
}

static int ff1_cbc_mac(EVP_CIPHER_CTX *ctx, const unsigned char *data, int len,
		unsigned char out[16])
{
	const EVP_CIPHER *cipher;
	unsigned char block[16] = {0};
	int i, j;

	cipher = ff1_key_bits == 128 ? EVP_aes_128_ecb() :
		ff1_key_bits == 192 ? EVP_aes_192_ecb() : EVP_aes_256_ecb();
	if (EVP_EncryptInit_ex(ctx, cipher, NULL, ff1_key, NULL) != 1 ||
			EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
		return -1;

	for (i = 0; i < len; i += 16) {
		for (j = 0; j < 16; j++)
			block[j] ^= data[i + j];
		if (ff1_encrypt_block(ctx, block, block) < 0)
			return -1;
	}
	memcpy(out, block, 16);
	return 0;
}

static int ff1_crypt(const unsigned char *input, int len, int radix,
		unsigned char *output, int decrypt)
{
	unsigned char p[16] = {0};
	unsigned char r[16], block[16];
	unsigned char *a = NULL, *b_digits = NULL, *c = NULL, *tmp;
	unsigned char *pq = NULL, *s = NULL;
	BIGNUM *pow_v = NULL, *modulus = NULL, *anum = NULL, *y = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	int u, v, b, d, qpad, qlen, pq_len;
	int alen, blen, m, round, i, j, take;
	int rc = -1;

	if (len < TH_FF1_MIN_LEN)
		return -1;
	u = len / 2;
	v = len - u;

	pow_v = BN_new();
	modulus = BN_new();
	anum = BN_new();
	y = BN_new();
	bn_ctx = BN_CTX_new();
	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!pow_v || !modulus || !anum || !y || !bn_ctx || !cipher_ctx ||
			bn_pow_word(pow_v, radix, v) < 0 ||
			!BN_sub_word(pow_v, 1))
		goto done;
	b = (BN_num_bits(pow_v) + 7) / 8;
	d = 4 * ((b + 3) / 4) + 4;
	qpad = (16 - ((b + 1) % 16)) % 16;
	qlen = qpad + 1 + b;
	pq_len = 16 + qlen;

	a = pkg_malloc(len);
	b_digits = pkg_malloc(len);
	c = pkg_malloc(len);
	pq = pkg_malloc(pq_len);
	s = pkg_malloc(d);
	if (!a || !b_digits || !c || !pq || !s)
		goto done;
	memcpy(a, input, u);
	memcpy(b_digits, input + u, v);
	alen = u;
	blen = v;

	p[0] = 1;
	p[1] = 2;
	p[2] = 1;
	p[3] = (radix >> 16) & 0xff;
	p[4] = (radix >> 8) & 0xff;
	p[5] = radix & 0xff;
	p[6] = 10;
	p[7] = u & 0xff;
	p[8] = (len >> 24) & 0xff;
	p[9] = (len >> 16) & 0xff;
	p[10] = (len >> 8) & 0xff;
	p[11] = len & 0xff;
	/* P[12..15] is the empty tweak length. */
	memcpy(pq, p, 16);

	for (round = decrypt ? 9 : 0;
			decrypt ? round >= 0 : round < 10;
			decrypt ? round-- : round++) {
		m = (round % 2 == 0) ? u : v;
		memset(pq + 16, 0, qlen);
		pq[16 + qpad] = round;

		if (bn_from_digits(decrypt ? a : b_digits,
				decrypt ? alen : blen, radix, anum) < 0 ||
				bn_to_fixed_bytes(anum, pq + pq_len - b, b) < 0)
			goto done;
		if (ff1_cbc_mac(cipher_ctx, pq, pq_len, r) < 0)
			goto done;

		take = d < 16 ? d : 16;
		memcpy(s, r, take);
		for (i = 16, j = 1; i < d; i += 16, j++) {
			memcpy(block, r, 16);
			block[12] ^= (j >> 24) & 0xff;
			block[13] ^= (j >> 16) & 0xff;
			block[14] ^= (j >> 8) & 0xff;
			block[15] ^= j & 0xff;
			if (ff1_encrypt_block(cipher_ctx, block, block) < 0)
				goto done;
			take = d - i < 16 ? d - i : 16;
			memcpy(s + i, block, take);
		}
		if (!BN_bin2bn(s, d, y) || bn_pow_word(modulus, radix, m) < 0)
			goto done;

		if (!decrypt) {
			if (bn_from_digits(a, alen, radix, anum) < 0 ||
					!BN_mod_add(anum, anum, y, modulus, bn_ctx) ||
					bn_to_digits(anum, m, radix, c) < 0)
				goto done;
			tmp = a;
			a = b_digits;
			alen = blen;
			b_digits = c;
			blen = m;
			c = tmp;
		} else {
			if (bn_from_digits(b_digits, blen, radix, anum) < 0 ||
					!BN_mod_sub(anum, anum, y, modulus, bn_ctx) ||
					bn_to_digits(anum, m, radix, c) < 0)
				goto done;
			tmp = b_digits;
			b_digits = a;
			blen = alen;
			a = c;
			alen = m;
			c = tmp;
		}
	}

	memcpy(output, a, alen);
	memcpy(output + alen, b_digits, blen);
	rc = 0;

done:
	if (a) pkg_free(a);
	if (b_digits) pkg_free(b_digits);
	if (c) pkg_free(c);
	if (pq) pkg_free(pq);
	if (s) pkg_free(s);
	BN_free(pow_v);
	BN_free(modulus);
	BN_free(anum);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	EVP_CIPHER_CTX_free(cipher_ctx);
	return rc;
}

#ifdef UNIT_TESTS
int th_callid_codec_test_ff1(const unsigned char *key, int key_bits,
		const unsigned char *input, int len, int radix,
		unsigned char *output, int decrypt)
{
	if (key_bits != 128 && key_bits != 192 && key_bits != 256)
		return -1;
	memcpy(ff1_key, key, key_bits / 8);
	ff1_key_bits = key_bits;
	return ff1_crypt(input, len, radix, output, decrypt);
}
#endif

static int chars_to_digits(const str *input, const signed short idx[256],
		unsigned char *digits)
{
	int i;

	for (i = 0; i < input->len; i++) {
		digits[i] = idx[(unsigned char)input->s[i]];
		if (digits[i] == (unsigned char)-1)
			return -1;
	}
	return 0;
}

static void digits_to_chars(const unsigned char *digits, int len,
		const unsigned char *symbols, char *output)
{
	int i;

	for (i = 0; i < len; i++)
		output[i] = symbols[digits[i]];
}

static int is_native_alnum(const str *input)
{
	int i;

	for (i = 0; i < input->len; i++)
		if (alnum62_idx[(unsigned char)input->s[i]] < 0)
			return 0;
	return 1;
}

/* Rank the RFC 3261 callid = word [ "@" word ] language for a fixed length. */
static int rank_word_callid(const str *input, BIGNUM *rank, BIGNUM *domain)
{
	BIGNUM *word_count = NULL, *suffix_count = NULL, *digits_num = NULL;
	unsigned char *digits = NULL;
	int at = -1, digits_len = 0, i, rc = -1;

	if (input->len <= 0)
		return -1;
	digits = pkg_malloc(input->len);
	word_count = BN_new();
	suffix_count = BN_new();
	digits_num = BN_new();
	if (!digits || !word_count || !suffix_count || !digits_num)
		goto done;

	for (i = 0; i < input->len; i++) {
		if (input->s[i] == '@') {
			if (at >= 0 || i == 0 || i == input->len - 1)
				goto done;
			at = i;
			continue;
		}
		if (word85_idx[(unsigned char)input->s[i]] < 0)
			goto done;
		digits[digits_len++] = word85_idx[(unsigned char)input->s[i]];
	}

	if (bn_pow_word(word_count, TH_WORD_RADIX, input->len) < 0 ||
			bn_pow_word(suffix_count, TH_WORD_RADIX, input->len - 1) < 0)
		goto done;
	if (!BN_copy(domain, word_count))
		goto done;
	if (input->len > 2) {
		if (!BN_mul_word(suffix_count, input->len - 2) ||
				!BN_add(domain, domain, suffix_count))
			goto done;
	}

	if (bn_from_digits(digits, digits_len, TH_WORD_RADIX, digits_num) < 0)
		goto done;
	if (at < 0) {
		if (!BN_copy(rank, digits_num))
			goto done;
	} else {
		if (bn_pow_word(suffix_count, TH_WORD_RADIX, input->len - 1) < 0 ||
				!BN_mul_word(suffix_count, at - 1) ||
				!BN_add(rank, word_count, suffix_count) ||
				!BN_add(rank, rank, digits_num))
			goto done;
	}
	rc = 0;

done:
	if (digits) pkg_free(digits);
	BN_free(word_count);
	BN_free(suffix_count);
	BN_free(digits_num);
	return rc;
}

static int radix62_len_for_domain(const BIGNUM *domain)
{
	BIGNUM *capacity;
	int len = 0;

	capacity = BN_new();
	if (!capacity || !BN_one(capacity)) {
		BN_free(capacity);
		return -1;
	}
	while (BN_cmp(capacity, domain) < 0) {
		if (!BN_mul_word(capacity, TH_FF1_RADIX) || len == INT_MAX) {
			BN_free(capacity);
			return -1;
		}
		len++;
	}
	BN_free(capacity);
	return len;
}

static int encode_rank62(const str *input, unsigned char **digits, int *len)
{
	BIGNUM *rank = NULL, *domain = NULL;
	int rc = -1;

	rank = BN_new();
	domain = BN_new();
	if (!rank || !domain || rank_word_callid(input, rank, domain) < 0)
		goto done;
	*len = radix62_len_for_domain(domain);
	if (*len < 0)
		goto done;
	*digits = pkg_malloc(*len);
	if (!*digits || bn_to_digits(rank, *len, TH_FF1_RADIX, *digits) < 0)
		goto done;
	rc = 0;

done:
	if (rc < 0 && *digits) {
		pkg_free(*digits);
		*digits = NULL;
	}
	BN_free(rank);
	BN_free(domain);
	return rc;
}

static int domain_for_word_len(int len, BIGNUM *domain)
{
	BIGNUM *extra = NULL;
	int rc = -1;

	if (len <= 0 || bn_pow_word(domain, TH_WORD_RADIX, len) < 0)
		return -1;
	if (len <= 2)
		return 0;
	extra = BN_new();
	if (!extra || bn_pow_word(extra, TH_WORD_RADIX, len - 1) < 0 ||
			!BN_mul_word(extra, len - 2) || !BN_add(domain, domain, extra))
		goto done;
	rc = 0;
done:
	BN_free(extra);
	return rc;
}

static int word_len_for_radix62_len(int radix_len, BIGNUM *domain)
{
	int low = 1, high = radix_len;
	int n, encoded_len;

	while (low <= high) {
		n = low + (high - low) / 2;
		if (domain_for_word_len(n, domain) < 0)
			return -1;
		encoded_len = radix62_len_for_domain(domain);
		if (encoded_len == radix_len)
			return n;
		if (encoded_len < radix_len)
			low = n + 1;
		else
			high = n - 1;
	}
	return -1;
}

static int decode_rank62(const unsigned char *digits, int len, str *output)
{
	BIGNUM *rank = NULL, *domain = NULL, *word_count = NULL;
	BIGNUM *position = NULL, *remainder = NULL, *span = NULL;
	unsigned char *word_digits = NULL;
	BN_ULONG at_offset;
	BN_CTX *bn_ctx = NULL;
	int word_len, digits_len, digit_pos, i, at = -1, rc = -1;

	rank = BN_new();
	domain = BN_new();
	word_count = BN_new();
	position = BN_new();
	remainder = BN_new();
	span = BN_new();
	bn_ctx = BN_CTX_new();
	if (!rank || !domain || !word_count || !position || !remainder || !span ||
			!bn_ctx ||
			bn_from_digits(digits, len, TH_FF1_RADIX, rank) < 0)
		goto done;
	word_len = word_len_for_radix62_len(len, domain);
	if (word_len < 0 || BN_cmp(rank, domain) >= 0 ||
			bn_pow_word(word_count, TH_WORD_RADIX, word_len) < 0)
		goto done;

	if (BN_cmp(rank, word_count) < 0) {
		digits_len = word_len;
		if (!BN_copy(remainder, rank))
			goto done;
	} else {
		digits_len = word_len - 1;
		if (bn_pow_word(span, TH_WORD_RADIX, digits_len) < 0 ||
				!BN_sub(position, rank, word_count) ||
				!BN_div(position, remainder, position, span, bn_ctx))
			goto done;
		at_offset = BN_get_word(position);
		if (at_offset == (BN_ULONG)-1 || at_offset >= (BN_ULONG)(word_len - 2))
			goto done;
		at = (int)at_offset + 1;
	}

	word_digits = pkg_malloc(digits_len);
	output->s = pkg_malloc(word_len);
	if (!word_digits || !output->s ||
			bn_to_digits(remainder, digits_len, TH_WORD_RADIX, word_digits) < 0)
		goto done;
	for (i = 0; i < word_len; i++) {
		if (i == at)
			output->s[i] = '@';
		else {
			digit_pos = at >= 0 && i > at ? i - 1 : i;
			if (digit_pos >= digits_len)
				goto done;
			output->s[i] = word85[word_digits[digit_pos]];
		}
	}
	output->len = word_len;
	rc = 0;

done:
	if (rc < 0 && output->s) {
		pkg_free(output->s);
		output->s = NULL;
		output->len = 0;
	}
	if (word_digits) pkg_free(word_digits);
	BN_free(rank);
	BN_free(domain);
	BN_free(word_count);
	BN_free(position);
	BN_free(remainder);
	BN_free(span);
	BN_CTX_free(bn_ctx);
	return rc;
}

static int legacy_encode(const str *input, str *output, int include_prefix)
{
	unsigned char *masked;
	int i, payload_len, offset = include_prefix ? callid_prefix.len : 0;

	payload_len = calc_word64_encode_len(input->len);
	if (payload_len < 0 || offset > INT_MAX - payload_len)
		return -1;
	output->len = offset + payload_len;
	output->s = pkg_malloc(output->len);
	masked = pkg_malloc(input->len);
	if (!output->s || !masked)
		goto error;
	if (include_prefix)
		memcpy(output->s, callid_prefix.s, callid_prefix.len);
	for (i = 0; i < input->len; i++)
		masked[i] = input->s[i] ^ callid_password.s[i % callid_password.len];
	word64encode((unsigned char *)output->s + offset, masked, input->len);
	pkg_free(masked);
	return 0;

error:
	if (output->s) pkg_free(output->s);
	if (masked) pkg_free(masked);
	output->s = NULL;
	output->len = 0;
	return -1;
}

static int safe_legacy_plaintext(const str *input)
{
	int i;
	unsigned char c;

	/* Keep compatibility for visible non-RFC characters, but never allow a
	 * decoded fallback value to inject or truncate a SIP header. */
	for (i = 0; i < input->len; i++) {
		c = input->s[i];
		if (c < 0x20 || c == 0x7f)
			return 0;
	}
	return input->len > 0;
}

static int legacy_decode(const str *input, str *output)
{
	int i, max_len;
	unsigned char c;

	if (input->len < 4 || input->len % 4)
		return -1;
	for (i = 0; i < input->len; i++) {
		c = input->s[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '+' || c == '.')
			continue;
		if (c != '-' || i < input->len - 2)
			return -1;
	}
	if (input->s[input->len - 2] == '-' && input->s[input->len - 1] != '-')
		return -1;

	max_len = calc_max_word64_decode_len(input->len);
	output->s = pkg_malloc(max_len);
	if (!output->s)
		return -1;
	output->len = word64decode((unsigned char *)output->s,
			(unsigned char *)input->s, input->len);
	for (i = 0; i < output->len; i++)
		output->s[i] ^= callid_password.s[i % callid_password.len];
	if (!safe_legacy_plaintext(output)) {
		pkg_free(output->s);
		output->s = NULL;
		output->len = 0;
		return -1;
	}
	return 0;
}

int th_callid_codec_is_encoded(const str *callid)
{
	char marker;

	if (!callid || callid->len <= callid_prefix.len ||
			memcmp(callid->s, callid_prefix.s, callid_prefix.len))
		return 0;
	if (callid_scheme == TH_CALLID_ENC_XOR_WORD64)
		return 1;
	if (callid->len <= callid_prefix.len + 1)
		return 0;
	marker = callid->s[callid_prefix.len];
	return marker == TH_FF1_MARK_NATIVE || marker == TH_FF1_MARK_WORD ||
		marker == TH_FF1_MARK_LEGACY;
}

int th_callid_codec_encode(const str *callid, str *encoded)
{
	unsigned char *plain_digits = NULL, *cipher_digits = NULL;
	str legacy = STR_NULL;
	int i, payload_len = 0, rc = -1;
	char marker;

	encoded->s = NULL;
	encoded->len = 0;
	if (callid_scheme == TH_CALLID_ENC_XOR_WORD64) {
		if (!safe_legacy_plaintext(callid))
			return -1;
		return legacy_encode(callid, encoded, 1);
	}

	if (callid->len >= TH_FF1_MIN_LEN &&
			callid->len <= TH_CALLID_MAX_PLAIN_LEN && is_native_alnum(callid)) {
		marker = TH_FF1_MARK_NATIVE;
		payload_len = callid->len;
		plain_digits = pkg_malloc(payload_len);
		if (!plain_digits || chars_to_digits(callid, alnum62_idx, plain_digits) < 0)
			goto done;
	} else if (callid->len <= TH_CALLID_MAX_PLAIN_LEN &&
			encode_rank62(callid, &plain_digits, &payload_len) == 0 &&
			payload_len >= TH_FF1_MIN_LEN) {
		marker = TH_FF1_MARK_WORD;
	} else {
		if (plain_digits) {
			pkg_free(plain_digits);
			plain_digits = NULL;
		}
		marker = TH_FF1_MARK_LEGACY;
		if (!safe_legacy_plaintext(callid))
			goto done;
		if (legacy_encode(callid, &legacy, 0) < 0)
			goto done;
		payload_len = legacy.len;
	}

	if (callid_prefix.len > INT_MAX - 1 - payload_len)
		goto done;
	encoded->len = callid_prefix.len + 1 + payload_len;
	encoded->s = pkg_malloc(encoded->len);
	if (!encoded->s)
		goto done;
	memcpy(encoded->s, callid_prefix.s, callid_prefix.len);
	encoded->s[callid_prefix.len] = marker;

	if (marker == TH_FF1_MARK_LEGACY) {
		memcpy(encoded->s + callid_prefix.len + 1, legacy.s, legacy.len);
	} else {
		cipher_digits = pkg_malloc(payload_len);
		if (!cipher_digits || ff1_crypt(plain_digits, payload_len, TH_FF1_RADIX,
				cipher_digits, 0) < 0)
			goto done;
		for (i = 0; i < payload_len; i++)
			encoded->s[callid_prefix.len + 1 + i] = alnum62[cipher_digits[i]];
	}
	rc = 0;

done:
	if (plain_digits) pkg_free(plain_digits);
	if (cipher_digits) pkg_free(cipher_digits);
	if (legacy.s) pkg_free(legacy.s);
	if (rc < 0 && encoded->s) {
		pkg_free(encoded->s);
		encoded->s = NULL;
		encoded->len = 0;
	}
	return rc;
}

int th_callid_codec_decode(const str *encoded, str *callid)
{
	str payload;
	unsigned char *cipher_digits = NULL, *plain_digits = NULL;
	char marker;
	int rc = -1;

	callid->s = NULL;
	callid->len = 0;
	if (!th_callid_codec_is_encoded(encoded))
		return -1;
	payload.s = encoded->s + callid_prefix.len;
	payload.len = encoded->len - callid_prefix.len;
	if (callid_scheme == TH_CALLID_ENC_XOR_WORD64)
		return legacy_decode(&payload, callid);

	marker = payload.s[0];
	payload.s++;
	payload.len--;
	if (marker == TH_FF1_MARK_LEGACY)
		return legacy_decode(&payload, callid);
	if (payload.len < TH_FF1_MIN_LEN ||
			(marker == TH_FF1_MARK_NATIVE &&
			 payload.len > TH_CALLID_MAX_PLAIN_LEN) ||
			(marker == TH_FF1_MARK_WORD &&
			 payload.len > TH_CALLID_MAX_STRUCTURED_PAYLOAD_LEN))
		return -1;

	cipher_digits = pkg_malloc(payload.len);
	plain_digits = pkg_malloc(payload.len);
	if (!cipher_digits || !plain_digits ||
			chars_to_digits(&payload, alnum62_idx, cipher_digits) < 0 ||
			ff1_crypt(cipher_digits, payload.len, TH_FF1_RADIX,
				plain_digits, 1) < 0)
		goto done;

	if (marker == TH_FF1_MARK_NATIVE) {
		callid->s = pkg_malloc(payload.len);
		if (!callid->s)
			goto done;
		digits_to_chars(plain_digits, payload.len, alnum62, callid->s);
		callid->len = payload.len;
	} else if (marker == TH_FF1_MARK_WORD) {
		if (decode_rank62(plain_digits, payload.len, callid) < 0)
			goto done;
		if (callid->len > TH_CALLID_MAX_PLAIN_LEN)
			goto done;
	} else {
		goto done;
	}
	rc = 0;

done:
	if (cipher_digits) pkg_free(cipher_digits);
	if (plain_digits) pkg_free(plain_digits);
	if (rc < 0 && callid->s) {
		pkg_free(callid->s);
		callid->s = NULL;
		callid->len = 0;
	}
	return rc;
}
