/*
 * Unit tests for media_security SDP feature classification.
 *
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
#include <stdio.h>
#include <string.h>

#define F_ICE        (1U << 0)
#define F_CANDIDATE  (1U << 1)
#define F_SRFLX      (1U << 2)
#define F_RELAY      (1U << 3)
#define F_DTLS_SRTP  (1U << 4)
#define F_SDES       (1U << 5)
#define F_RTCP_MUX   (1U << 6)
#define F_SECURE_RTP (1U << 7)
#define F_SDES_SRTP  (1U << 8)
#define F_DTLS_OR_SDES (1U << 9)

#define FP_SHA256 \
	"AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:" \
	"AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
#define FP_LINE "a=fingerprint:sha-256 " FP_SHA256 "\r\n"

unsigned int media_security_test_classify(const char *text);
unsigned int media_security_test_inspect_msg(const char *text);

static unsigned int inspect_invite(const char *ctype, const char *body)
{
	static char buf[8192];

	snprintf(buf, sizeof(buf),
		"INVITE sip:bob@example.org SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.0.2.4:5060;branch=z9hG4bKms1\r\n"
		"From: Alice <sip:alice@example.org>;tag=1\r\n"
		"To: Bob <sip:bob@example.org>\r\n"
		"CSeq: 1 INVITE\r\n"
		"Call-ID: media-security-test\r\n"
		"Max-Forwards: 70\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %d\r\n"
		"\r\n"
		"%s", ctype, (int)strlen(body), body);

	return media_security_test_inspect_msg(buf);
}

static void test_webrtc_dtls(void)
{
	const char *sdp =
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"a=ice-ufrag:abcd\r\n"
		"a=ice-pwd:defghijklmnopqrstuvwxyz1234\r\n"
		"a=candidate:1 1 UDP 1 10.0.0.1 10000 typ host\r\n"
		"a=candidate:2 1 UDP 1 203.0.113.1 20000 typ srflx\r\n"
		"a=candidate:3 1 UDP 1 198.51.100.1 30000 typ relay\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"a=rtcp-mux\r\n";
	unsigned int f = media_security_test_classify(sdp);

	ok((f & F_ICE) != 0, "media-security-dtls-ice");
	ok((f & F_CANDIDATE) != 0, "media-security-dtls-candidate");
	ok((f & F_SRFLX) != 0, "media-security-dtls-srflx");
	ok((f & F_RELAY) != 0, "media-security-dtls-relay");
	ok((f & F_DTLS_SRTP) != 0, "media-security-dtls-srtp");
	ok((f & F_RTCP_MUX) != 0, "media-security-dtls-rtcp-mux");
	ok((f & F_SECURE_RTP) != 0, "media-security-dtls-secure-rtp");
	ok((f & F_SDES) == 0, "media-security-dtls-no-sdes");
}

static void test_dtls_requires_full_tuple(void)
{
	unsigned int f;

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 RTP/SAVP 0\r\n"
		FP_LINE
		"a=setup:actpass\r\n");
	ok((f & F_SECURE_RTP) != 0, "media-security-savp-is-secure");
	ok((f & F_DTLS_SRTP) == 0,
		"media-security-fingerprint-on-savp-is-not-dtls-srtp");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		FP_LINE);
	ok((f & F_DTLS_SRTP) == 0,
		"media-security-dtls-missing-setup");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"a=setup:actpass\r\n");
	ok((f & F_DTLS_SRTP) == 0,
		"media-security-dtls-missing-fingerprint");
}

static void test_mixed_media_and_line_boundaries(void)
{
	unsigned int f;

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"m=video 9 RTP/AVP 96\r\n"
		FP_LINE
		"a=setup:actpass\r\n");
	ok((f & F_DTLS_SRTP) == 0,
		"media-security-mixed-media-not-dtls-secure");
	ok((f & F_SECURE_RTP) == 0,
		"media-security-mixed-media-not-fully-secure");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 RTP/AVP 0\r\n"
		"a=x-note:this text contains a=candidate: and typ relay\r\n"
		"a=x-note:UDP/TLS/RTP/SAVPF\r\n");
	ok((f & F_CANDIDATE) == 0,
		"media-security-ignore-candidate-substring-in-other-attribute");
	ok((f & F_RELAY) == 0,
		"media-security-ignore-relay-substring-in-other-attribute");
	ok((f & F_SECURE_RTP) == 0,
		"media-security-ignore-secure-profile-substring-outside-media-line");
}

static void test_per_media_policy_and_datachannel(void)
{
	unsigned int f;

	f = media_security_test_classify(
		"v=0\r\n"
		"a=ice-ufrag:sessionUfrag\r\n"
		"a=ice-pwd:sessionPassword0123456789\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"a=rtcp-mux\r\n"
		"m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
		"a=rtcp-mux\r\n"
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
	ok((f & F_ICE) != 0,
		"media-security-session-ice-inherited-by-rtp-media");
	ok((f & F_DTLS_SRTP) != 0,
		"media-security-session-dtls-attrs-inherited-by-rtp-media");
	ok((f & F_RTCP_MUX) != 0,
		"media-security-rtcp-mux-on-every-rtp-media");
	ok((f & F_SECURE_RTP) != 0,
		"media-security-datachannel-not-counted-as-insecure-rtp");

	f = media_security_test_classify(
		"v=0\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"a=rtcp-mux\r\n"
		"m=video 9 UDP/TLS/RTP/SAVPF 96\r\n");
	ok((f & F_RTCP_MUX) == 0,
		"media-security-one-missing-rtcp-mux-fails-whole-rtp-policy");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=video 9 UDP/TLS/RTP/SAVPF 96\r\n");
	ok((f & F_DTLS_SRTP) == 0,
		"media-security-media-level-dtls-attrs-do-not-leak-to-next-media");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"a=ice-ufrag:audioUfrag\r\n"
		"a=ice-pwd:audioPassword0123456789\r\n"
		"m=video 9 UDP/TLS/RTP/SAVPF 96\r\n");
	ok((f & F_ICE) == 0,
		"media-security-media-level-ice-does-not-leak-to-next-media");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 0 RTP/AVP 0\r\n"
		"m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"a=rtcp-mux\r\n");
	ok((f & F_DTLS_SRTP) != 0,
		"media-security-disabled-port-zero-media-is-ignored");
	ok((f & F_SECURE_RTP) != 0,
		"media-security-disabled-insecure-media-does-not-poison-policy");
}

static void test_malformed_security_attributes_do_not_satisfy_policy(void)
{
	unsigned int f;

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"a=ice-ufrag:abc\r\n"
		"a=ice-pwd:short\r\n"
		"a=fingerprint:\r\n"
		"a=setup:\r\n"
		"a=rtcp-mux\r\n"
		"a=candidate:1 typ relay\r\n");
	ok((f & F_ICE) == 0,
		"media-security-reject-short-ice-credentials");
	ok((f & F_DTLS_SRTP) == 0,
		"media-security-reject-empty-dtls-attributes");
	ok((f & F_RELAY) == 0,
		"media-security-reject-malformed-relay-candidate");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"a=ice-ufrag:abcd\r\n"
		"a=ice-pwd:abcdefghijklmnopqrstuv\r\n"
		FP_LINE
		"a=setup:invalid\r\n");
	ok((f & F_ICE) != 0,
		"media-security-accept-minimum-shaped-ice-credentials");
	ok((f & F_DTLS_SRTP) == 0,
		"media-security-reject-invalid-setup-role");
}

static void test_sdes_and_partial_ice(void)
{
	unsigned int f;

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 10000 RTP/SAVP 0\r\n"
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc\r\n");
	ok((f & F_SDES) != 0, "media-security-sdes-detected");
	ok((f & F_SECURE_RTP) != 0, "media-security-sdes-secure-transport");
	ok((f & F_DTLS_SRTP) == 0, "media-security-sdes-not-dtls");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 10000 RTP/AVP 0\r\n"
		"a=ice-ufrag:abc\r\n");
	ok((f & F_ICE) == 0, "media-security-ice-requires-ufrag-and-pwd");
}

#define WEBRTC_SDP \
	"v=0\r\n" \
	"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" \
	"a=ice-ufrag:abcd\r\n" \
	"a=ice-pwd:defghijklmnopqrstuvwxyz1234\r\n" \
	FP_LINE \
	"a=setup:actpass\r\n" \
	"a=rtcp-mux\r\n"

#define PLAIN_SDP \
	"v=0\r\n" \
	"m=audio 10000 RTP/AVP 0\r\n"

static void test_media_line_classification_fails_closed(void)
{
	unsigned int f;

	f = media_security_test_classify(
		"v=0\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"m=video 5000 rtp/avp 96\r\n");
	ok((f & F_SECURE_RTP) == 0 && (f & F_DTLS_SRTP) == 0,
		"media-security-lowercase-plain-rtp-profile-not-ignored");

	f = media_security_test_classify(
		"v=0\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=audio 9 udp/tls/rtp/savpf 111\r\n");
	ok((f & F_DTLS_SRTP) != 0,
		"media-security-dtls-profile-matched-case-insensitively");

	f = media_security_test_classify(
		"v=0\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"m=video 5000 udp 96\r\n");
	ok((f & F_SECURE_RTP) == 0,
		"media-security-video-with-non-rtp-proto-counts-as-insecure");

	f = media_security_test_classify(
		"v=0\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"m=audio 5000\r\n");
	ok((f & F_SECURE_RTP) == 0,
		"media-security-audio-without-proto-counts-as-insecure");

	f = media_security_test_classify(
		"v=0\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"m=video 0 RTP/AVP 96\r\n"
		"a=bundle-only\r\n");
	ok((f & F_SECURE_RTP) == 0 && (f & F_DTLS_SRTP) == 0,
		"media-security-bundle-only-port-zero-media-is-active");

	f = media_security_test_classify(
		"v=0\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"m=image 0 udptl t38\r\n");
	ok((f & F_DTLS_SRTP) != 0,
		"media-security-rejected-non-av-media-ignored");
}

static void test_candidates_scoped_to_active_media(void)
{
	unsigned int f;

	f = media_security_test_classify(
		"v=0\r\n"
		"a=candidate:3 1 UDP 1 198.51.100.1 30000 typ relay\r\n"
		"m=audio 10000 RTP/AVP 0\r\n");
	ok((f & (F_CANDIDATE | F_RELAY)) == 0,
		"media-security-session-level-relay-candidate-ignored");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 10000 RTP/AVP 0\r\n"
		"m=video 0 RTP/AVP 96\r\n"
		"a=candidate:3 1 UDP 1 198.51.100.1 30000 typ relay\r\n");
	ok((f & F_RELAY) == 0,
		"media-security-relay-candidate-in-rejected-media-ignored");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
		"a=candidate:3 1 UDP 1 198.51.100.1 30000 TYP RELAY\r\n");
	ok((f & F_RELAY) != 0,
		"media-security-relay-candidate-type-case-insensitive");
}

static unsigned int dtls_with_fingerprint(const char *fp_line)
{
	static char sdp[1024];

	snprintf(sdp, sizeof(sdp),
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"%s\r\n"
		"a=setup:actpass\r\n", fp_line);
	return media_security_test_classify(sdp) & F_DTLS_SRTP;
}

static void test_fingerprint_validation(void)
{
	ok(dtls_with_fingerprint("a=fingerprint:sha-256 " FP_SHA256) != 0,
		"media-security-fingerprint-sha256-valid");
	ok(dtls_with_fingerprint("a=fingerprint:SHA-256 " FP_SHA256) != 0,
		"media-security-fingerprint-hash-name-case-insensitive");
	ok(dtls_with_fingerprint("a=fingerprint:sha-256 " FP_SHA256 " ") != 0,
		"media-security-fingerprint-trailing-space-tolerated");
	ok(dtls_with_fingerprint("a=fingerprint:sha-1 "
		"AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01") != 0,
		"media-security-fingerprint-sha1-valid");
	ok(dtls_with_fingerprint("a=fingerprint:sha-256 AA:BB") == 0,
		"media-security-fingerprint-too-short-rejected");
	ok(dtls_with_fingerprint("a=fingerprint:sha-256 " FP_SHA256 ":00") == 0,
		"media-security-fingerprint-too-long-rejected");
	ok(dtls_with_fingerprint("a=fingerprint:sha-256 "
		"ZZ:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:"
		"AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89") == 0,
		"media-security-fingerprint-non-hex-rejected");
	ok(dtls_with_fingerprint("a=fingerprint:sha-256 "
		"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
		"ABCDEF0123456789ABCDEF0123456789") == 0,
		"media-security-fingerprint-missing-colons-rejected");
	ok(dtls_with_fingerprint("a=fingerprint:md5 "
		"AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89") == 0,
		"media-security-fingerprint-md5-rejected");
	ok(dtls_with_fingerprint("a=fingerprint:foo " FP_SHA256) == 0,
		"media-security-fingerprint-unknown-hash-rejected");
	ok(dtls_with_fingerprint("a=fingerprint:sha-256") == 0,
		"media-security-fingerprint-missing-value-rejected");
}

static unsigned int ice_with(const char *ufrag, const char *pwd)
{
	static char sdp[1024];

	snprintf(sdp, sizeof(sdp),
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		"a=ice-ufrag:%s\r\n"
		"a=ice-pwd:%s\r\n", ufrag, pwd);
	return media_security_test_classify(sdp) & F_ICE;
}

static void test_ice_credential_and_setup_validation(void)
{
	char long_pwd[300];
	unsigned int f;

	ok(ice_with("ab+/", "abcdefghijklmnopqrst+/") != 0,
		"media-security-ice-chars-plus-slash-accepted");
	ok(ice_with("ab;d", "abcdefghijklmnopqrstuv") == 0,
		"media-security-ice-ufrag-invalid-char-rejected");
	ok(ice_with("abcd", "abcdefghijklmnopqrstu\"") == 0,
		"media-security-ice-pwd-invalid-char-rejected");

	memset(long_pwd, 'a', 257);
	long_pwd[257] = '\0';
	ok(ice_with("abcd", long_pwd) == 0,
		"media-security-ice-pwd-over-256-chars-rejected");
	long_pwd[256] = '\0';
	ok(ice_with("abcd", long_pwd) != 0,
		"media-security-ice-pwd-256-chars-accepted");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		FP_LINE
		"a=setup:ACTPASS\r\n");
	ok((f & F_DTLS_SRTP) != 0,
		"media-security-setup-role-case-insensitive");
}

static unsigned int sdes_with(const char *proto, const char *crypto_line)
{
	static char sdp[1024];

	snprintf(sdp, sizeof(sdp),
		"v=0\r\n"
		"m=audio 10000 %s 0\r\n"
		"%s\r\n", proto, crypto_line);
	return media_security_test_classify(sdp);
}

#define SDES_KEY "inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"

static void test_crypto_validation(void)
{
	unsigned int f;

	f = sdes_with("RTP/SAVP",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 " SDES_KEY "|2^20|1:32");
	ok((f & F_SDES) && (f & F_SDES_SRTP),
		"media-security-crypto-valid");
	f = sdes_with("RTP/SAVP", "a=crypto:");
	ok((f & (F_SDES | F_SDES_SRTP)) == 0,
		"media-security-crypto-empty-rejected");
	f = sdes_with("RTP/SAVP", "a=crypto:1 AES_CM_128_HMAC_SHA1_80");
	ok((f & F_SDES_SRTP) == 0,
		"media-security-crypto-missing-key-rejected");
	f = sdes_with("RTP/SAVP", "a=crypto:x AES_CM_128_HMAC_SHA1_80 "
		SDES_KEY);
	ok((f & F_SDES_SRTP) == 0,
		"media-security-crypto-non-numeric-tag-rejected");
	f = sdes_with("RTP/SAVP", "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:");
	ok((f & F_SDES_SRTP) == 0,
		"media-security-crypto-empty-inline-key-rejected");
	f = sdes_with("UDP/TLS/RTP/SAVPF",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 " SDES_KEY);
	ok((f & F_SDES_SRTP) == 0,
		"media-security-crypto-on-dtls-profile-is-not-sdes-srtp");

	f = media_security_test_classify(
		"v=0\r\n"
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 " SDES_KEY "\r\n"
		"m=audio 10000 RTP/SAVP 0\r\n");
	ok((f & (F_SDES | F_SDES_SRTP)) == 0,
		"media-security-session-level-crypto-ignored");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=video 10000 RTP/SAVPF 96\r\n"
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 " SDES_KEY "\r\n");
	ok((f & F_DTLS_OR_SDES) != 0,
		"media-security-mixed-dtls-and-sdes-media-all-keyed");
	ok((f & (F_DTLS_SRTP | F_SDES_SRTP)) == 0,
		"media-security-mixed-dtls-and-sdes-media-neither-exclusive");

	f = media_security_test_classify(
		"v=0\r\n"
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
		FP_LINE
		"a=setup:actpass\r\n"
		"m=video 10000 RTP/SAVPF 96\r\n");
	ok((f & F_DTLS_OR_SDES) == 0,
		"media-security-unkeyed-savp-media-not-keyed");
}

static void test_all_sdp_body_parts_inspected(void)
{
	unsigned int f;

	f = inspect_invite("application/sdp", WEBRTC_SDP);
	ok((f & F_DTLS_SRTP) && (f & F_ICE) && (f & F_RTCP_MUX),
		"media-security-msg-single-sdp-part");

	f = inspect_invite("multipart/alternative;boundary=b1",
		"--b1\r\n"
		"Content-Type: application/sdp\r\n"
		"\r\n"
		WEBRTC_SDP
		"\r\n--b1\r\n"
		"Content-Type: application/sdp\r\n"
		"\r\n"
		PLAIN_SDP
		"\r\n--b1--\r\n");
	ok((f & F_DTLS_SRTP) == 0,
		"media-security-msg-insecure-second-sdp-alternative-not-masked");
	ok((f & F_SECURE_RTP) == 0,
		"media-security-msg-insecure-second-sdp-alternative-not-secure");

	f = inspect_invite("multipart/mixed;boundary=b1",
		"--b1\r\n"
		"Content-Type: application/sdp\r\n"
		"\r\n"
		WEBRTC_SDP
		"\r\n--b1\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"m=audio 10000 RTP/AVP 0\r\n"
		"\r\n--b1--\r\n");
	ok((f & F_DTLS_SRTP) != 0,
		"media-security-msg-non-sdp-parts-ignored");
}

void mod_tests(void)
{
	test_webrtc_dtls();
	test_dtls_requires_full_tuple();
	test_mixed_media_and_line_boundaries();
	test_per_media_policy_and_datachannel();
	test_malformed_security_attributes_do_not_satisfy_policy();
	test_sdes_and_partial_ice();
	test_all_sdp_body_parts_inspected();
	test_media_line_classification_fails_closed();
	test_candidates_scoped_to_active_media();
	test_fingerprint_validation();
	test_ice_credential_and_setup_validation();
	test_crypto_validation();
}
