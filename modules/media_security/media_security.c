/*
 * SDP media-security policy checks for OpenSIPS
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

#include <string.h>
#include <strings.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../statistics.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_body.h"
#include "../../parser/parse_content.h"
#include "../../evi/evi_modules.h"
#include "../../evi/evi_params.h"

#define E_MEDIA_SECURITY_VIOLATION "E_MEDIA_SECURITY_VIOLATION"
#define E_MEDIA_SECURITY_OK        "E_MEDIA_SECURITY_COMPLIANT"

struct media_features {
	int ice;
	int candidate;
	int srflx;
	int relay;
	int fingerprint;
	int setup;
	int dtls_srtp;
	int sdes;
	int rtcp_mux;
	int secure_rtp;
	int media_lines;
	int secure_media_lines;
	int dtls_media_lines;
	int ice_media_lines;
	int rtcp_mux_media_lines;
	int sdes_media_lines;
	int sdes_srtp;
	int keyed_media_lines;
	/* every RTP section is keyed by either DTLS-SRTP or SDES */
	int dtls_or_sdes_srtp;
};

static int require_ice = 1;
static int require_dtls_srtp = 1;
static int require_rtcp_mux = 1;
static int require_turn_relay = 0;
static int allow_sdes = 0;
static int emit_compliant = 0;

static stat_var *checks;
static stat_var *violations;
static stat_var *ice_sdps;
static stat_var *candidate_sdps;
static stat_var *srflx_sdps;
static stat_var *dtls_sdps;
static stat_var *relay_sdps;
static stat_var *sdes_sdps;
static stat_var *rtcp_mux_sdps;

static event_id_t violation_event = EVI_ERROR;
static event_id_t compliant_event = EVI_ERROR;
static str violation_event_name = str_init(E_MEDIA_SECURITY_VIOLATION);
static str compliant_event_name = str_init(E_MEDIA_SECURITY_OK);

static str p_reason = str_init("reason");
static str p_ice = str_init("ice");
static str p_candidate = str_init("candidate");
static str p_srflx = str_init("stun_srflx");
static str p_dtls_srtp = str_init("dtls_srtp");
static str p_rtcp_mux = str_init("rtcp_mux");
static str p_relay = str_init("relay_candidate");
static str p_sdes = str_init("sdes");

static int mod_init(void);
static int w_media_security_check(struct sip_msg *msg);
static int w_media_security_profile(struct sip_msg *msg, str *profile);
static int w_media_security_has(struct sip_msg *msg, str *feature);

static const cmd_export_t cmds[] = {
	{"media_security_check", (cmd_function)w_media_security_check,
		{{0, 0, 0}}, ALL_ROUTES},
	{"media_security_profile", (cmd_function)w_media_security_profile, {
		{CMD_PARAM_STR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
	{"media_security_has", (cmd_function)w_media_security_has, {
		{CMD_PARAM_STR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
	{0, 0, {{0, 0, 0}}, 0}
};

static const param_export_t params[] = {
	{"require_ice", INT_PARAM, &require_ice},
	{"require_dtls_srtp", INT_PARAM, &require_dtls_srtp},
	{"require_rtcp_mux", INT_PARAM, &require_rtcp_mux},
	{"require_turn_relay", INT_PARAM, &require_turn_relay},
	{"allow_sdes", INT_PARAM, &allow_sdes},
	{"emit_compliant", INT_PARAM, &emit_compliant},
	{0, 0, 0}
};

static const stat_export_t mod_stats[] = {
	{"checks", 0, &checks},
	{"violations", 0, &violations},
	{"ice_sdps", 0, &ice_sdps},
	{"ice_candidate_sdps", 0, &candidate_sdps},
	{"stun_srflx_sdps", 0, &srflx_sdps},
	{"dtls_srtp_sdps", 0, &dtls_sdps},
	{"turn_relay_sdps", 0, &relay_sdps},
	{"sdes_sdps", 0, &sdes_sdps},
	{"rtcp_mux_sdps", 0, &rtcp_mux_sdps},
	{0, 0, 0}
};

struct module_exports exports = {
	"media_security",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,
	0,
	cmds,
	0,
	params,
	mod_stats,
	0,
	0,
	0,
	0,
	0,
	mod_init,
	0,
	0,
	0,
	0
};

static const char *sdp_line_end(const char *p, const char *end)
{
	while (p < end && *p != '\r' && *p != '\n')
		p++;
	return p;
}

static int line_has_prefix(const char *line, int len, const char *prefix)
{
	int plen = strlen(prefix);
	return len >= plen && memcmp(line, prefix, plen) == 0;
}

static int line_equals(const char *line, int len, const char *value)
{
	int vlen = strlen(value);
	return len == vlen && memcmp(line, value, vlen) == 0;
}

static int token_eq_ci(const char *s, int len, const char *lit)
{
	int n = strlen(lit);

	return len == n && strncasecmp(s, lit, n) == 0;
}

static int candidate_has_type(const char *line, int len, const char *type)
{
	const char *p = line, *end = line + len;
	const char *tok;
	int tok_len, field = 0, saw_typ = 0;

	while (p < end) {
		while (p < end && (*p == ' ' || *p == '\t'))
			p++;
		tok = p;
		while (p < end && *p != ' ' && *p != '\t')
			p++;
		tok_len = (int)(p - tok);
		if (!tok_len)
			continue;
		field++;

		/*
		 * a=candidate:<foundation> component transport priority address
		 * port typ <candidate-type> [extensions...]
		 */
		if (field == 7) {
			/* ABNF literals are case-insensitive (RFC 5234) */
			if (!token_eq_ci(tok, tok_len, "typ"))
				return 0;
			saw_typ = 1;
			continue;
		}
		if (field == 8 && saw_typ)
			return token_eq_ci(tok, tok_len, type);
	}
	return 0;
}

static int is_ice_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '/';
}

/* ice-ufrag / ice-pwd values: min_len..256 ice-chars (RFC 8839) */
static int ice_attribute_valid(const char *line, int len,
	const char *prefix, int min_len)
{
	int plen = strlen(prefix), i, value_len;

	if (!line_has_prefix(line, len, prefix))
		return 0;
	value_len = len - plen;
	if (value_len < min_len || value_len > 256)
		return 0;
	for (i = plen; i < len; i++)
		if (!is_ice_char(line[i]))
			return 0;
	return 1;
}

static int is_hex_digit(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F');
}

/*
 * a=fingerprint:<hash-func> <fingerprint> (RFC 8122). The hash name is
 * matched case-insensitively; MD2/MD5 and unknown hash functions are not
 * accepted, and the fingerprint must be colon-separated hex byte pairs of
 * exactly the digest length of the hash function.
 */
static int fingerprint_attribute_valid(const char *line, int len)
{
	static const struct {
		const char *name;
		int bytes;
	} hashes[] = {
		{"sha-1", 20},
		{"sha-224", 28},
		{"sha-256", 32},
		{"sha-384", 48},
		{"sha-512", 64},
		{NULL, 0}
	};
	const char *prefix = "a=fingerprint:";
	const char *p, *end = line + len, *tok;
	int i, bytes = 0;

	if (!line_has_prefix(line, len, prefix))
		return 0;
	p = line + strlen(prefix);

	tok = p;
	while (p < end && *p != ' ' && *p != '\t')
		p++;
	for (i = 0; hashes[i].name; i++)
		if (token_eq_ci(tok, (int)(p - tok), hashes[i].name)) {
			bytes = hashes[i].bytes;
			break;
		}
	if (!bytes)
		return 0;

	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	/* trailing whitespace is tolerated */
	while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
		end--;

	if (end - p != bytes * 3 - 1)
		return 0;
	for (i = 0; i < bytes; i++, p += 3) {
		if (!is_hex_digit(p[0]) || !is_hex_digit(p[1]))
			return 0;
		if (i < bytes - 1 && p[2] != ':')
			return 0;
	}
	return 1;
}

/*
 * a=crypto:<tag> <crypto-suite> <key-params> (RFC 4568), where tag is
 * 1*9DIGIT and at least the first key-param uses the "inline:" method.
 */
static int crypto_attribute_valid(const char *line, int len)
{
	const char *prefix = "a=crypto:";
	const char *p, *end = line + len, *tok;

	if (!line_has_prefix(line, len, prefix))
		return 0;
	p = line + strlen(prefix);

	tok = p;
	while (p < end && *p >= '0' && *p <= '9')
		p++;
	if (p == tok || p - tok > 9 || p == end || (*p != ' ' && *p != '\t'))
		return 0;

	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	tok = p;
	while (p < end && *p != ' ' && *p != '\t')
		p++;
	if (p == tok)
		return 0;

	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	if (end - p <= 7 || strncasecmp(p, "inline:", 7) != 0)
		return 0;
	p += 7;
	return p < end && *p != ' ' && *p != '\t' && *p != '|' && *p != ';';
}

static int setup_attribute_valid(const char *line, int len)
{
	const char *prefix = "a=setup:";
	const char *value;
	int plen = strlen(prefix), vlen;

	if (!line_has_prefix(line, len, prefix))
		return 0;
	value = line + plen;
	vlen = len - plen;
	return token_eq_ci(value, vlen, "active") ||
		token_eq_ci(value, vlen, "passive") ||
		token_eq_ci(value, vlen, "actpass") ||
		token_eq_ci(value, vlen, "holdconn");
}


static int token_contains_ci(const char *s, int len, const char *needle)
{
	int nlen = strlen(needle), i;

	if (!s || !needle || nlen <= 0 || len < nlen)
		return 0;
	for (i = 0; i <= len - nlen; i++)
		if (!strncasecmp(s + i, needle, nlen))
			return 1;
	return 0;
}

static int media_port_disabled(const char *s, int len)
{
	return len > 0 && s[0] == '0' && (len == 1 || s[1] == '/');
}

struct media_section_features {
	int present;
	int port_zero;
	int bundle_only;
	int rtp;
	int secure;
	int dtls;
	int ice;
	int fingerprint;
	int setup;
	int rtcp_mux;
	int sdes;
	int candidate;
	int srflx;
	int relay;
};

/*
 * Parse "m=<media> <port> <proto> ...". The classification is fail-closed:
 * protocol tokens are matched case-insensitively (as many endpoints do), and
 * audio/video sections are always subject to the RTP policy, even with a
 * missing or non-RTP transport token, so they cannot be smuggled past it.
 */
static void media_proto_flags(const char *line, int len,
	struct media_section_features *m)
{
	const char *p = line, *end = line + len;
	const char *tok;
	int field = 0, tok_len;

	if (!line_has_prefix(line, len, "m="))
		return;
	p += 2;

	while (p < end) {
		while (p < end && (*p == ' ' || *p == '\t'))
			p++;
		tok = p;
		while (p < end && *p != ' ' && *p != '\t')
			p++;
		tok_len = (int)(p - tok);
		if (!tok_len)
			continue;
		field++;

		if (field == 1) {
			m->rtp = token_eq_ci(tok, tok_len, "audio") ||
				token_eq_ci(tok, tok_len, "video");
			continue;
		}
		if (field == 2) {
			m->port_zero = media_port_disabled(tok, tok_len);
			continue;
		}

		/* field 3: the transport protocol */
		if (token_contains_ci(tok, tok_len, "RTP/"))
			m->rtp = 1;

		if (token_eq_ci(tok, tok_len, "RTP/SAVP") ||
			token_eq_ci(tok, tok_len, "RTP/SAVPF")) {
			m->secure = 1;
		} else if (token_eq_ci(tok, tok_len, "UDP/TLS/RTP/SAVP") ||
			token_eq_ci(tok, tok_len, "UDP/TLS/RTP/SAVPF")) {
			m->secure = 1;
			m->dtls = 1;
		}
		return;
	}
}

static void finalize_media_section(struct media_features *f,
	const struct media_section_features *m, int session_ice,
	int session_fingerprint, int session_setup)
{
	int effective_ice, effective_fingerprint, effective_setup;
	int dtls_keyed, sdes_keyed;

	/*
	 * Port 0 rejects/disables a stream, except for BUNDLE "bundle-only"
	 * sections (RFC 8843), which are negotiated inside the bundle.
	 */
	if (!m->present || (m->port_zero && !m->bundle_only))
		return;

	/* ICE candidates of any active section (incl. data channels) count */
	f->candidate |= m->candidate;
	f->srflx |= m->srflx;
	f->relay |= m->relay;
	f->sdes |= m->sdes;

	if (!m->rtp)
		return;

	f->media_lines++;
	effective_ice = session_ice | m->ice;
	effective_fingerprint = session_fingerprint || m->fingerprint;
	effective_setup = session_setup || m->setup;

	if (effective_ice == 3)
		f->ice_media_lines++;
	if (m->secure)
		f->secure_media_lines++;
	dtls_keyed = m->dtls && effective_fingerprint && effective_setup;
	/* SDES keying applies to RTP/SAVP(F), not to the DTLS-SRTP profiles */
	sdes_keyed = m->sdes && m->secure && !m->dtls;

	if (dtls_keyed)
		f->dtls_media_lines++;
	if (m->rtcp_mux)
		f->rtcp_mux_media_lines++;
	if (sdes_keyed)
		f->sdes_media_lines++;
	if (dtls_keyed || sdes_keyed)
		f->keyed_media_lines++;
}


static int str_eq_ci(const str *s, const char *lit)
{
	int i, len;

	if (!s || !s->s || !lit)
		return 0;
	len = strlen(lit);
	if (s->len != len)
		return 0;
	for (i = 0; i < len; i++) {
		char a = s->s[i], b = lit[i];
		if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
		if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
		if (a != b)
			return 0;
	}
	return 1;
}

static int classify_sdp_body(const str *body, struct media_features *f)
{
	const char *p, *end, *le;
	int len;
	int session_ice = 0, session_fingerprint = 0, session_setup = 0;
	struct media_section_features media;

	if (!body || !body->s || body->len <= 0 || !f)
		return -1;

	memset(f, 0, sizeof(*f));
	memset(&media, 0, sizeof(media));
	p = body->s;
	end = body->s + body->len;

	while (p < end) {
		le = sdp_line_end(p, end);
		len = (int)(le - p);

		if (line_has_prefix(p, len, "m=")) {
			finalize_media_section(f, &media, session_ice,
				session_fingerprint, session_setup);
			memset(&media, 0, sizeof(media));
			media.present = 1;
			media_proto_flags(p, len, &media);
		} else if (line_equals(p, len, "a=bundle-only")) {
			if (media.present)
				media.bundle_only = 1;
		} else if (line_has_prefix(p, len, "a=candidate:")) {
			/* candidates are media-level only (RFC 8839) */
			if (media.present) {
				media.candidate = 1;
				if (candidate_has_type(p, len, "srflx"))
					media.srflx = 1;
				if (candidate_has_type(p, len, "relay"))
					media.relay = 1;
			}
		} else if (ice_attribute_valid(p, len, "a=ice-ufrag:", 4)) {
			if (media.present)
				media.ice |= 1;
			else
				session_ice |= 1;
		} else if (ice_attribute_valid(p, len, "a=ice-pwd:", 22)) {
			if (media.present)
				media.ice |= 2;
			else
				session_ice |= 2;
		} else if (fingerprint_attribute_valid(p, len)) {
			f->fingerprint = 1;
			if (media.present)
				media.fingerprint = 1;
			else
				session_fingerprint = 1;
		} else if (setup_attribute_valid(p, len)) {
			f->setup = 1;
			if (media.present)
				media.setup = 1;
			else
				session_setup = 1;
		} else if (line_equals(p, len, "a=rtcp-mux")) {
			if (media.present)
				media.rtcp_mux = 1;
		} else if (crypto_attribute_valid(p, len)) {
			/* a=crypto is media-level only (RFC 4568) */
			if (media.present)
				media.sdes = 1;
		}

		p = le;
		while (p < end && (*p == '\r' || *p == '\n'))
			p++;
	}

	finalize_media_section(f, &media, session_ice,
		session_fingerprint, session_setup);

	f->ice = f->media_lines > 0 &&
		f->ice_media_lines == f->media_lines;
	f->secure_rtp = f->media_lines > 0 &&
		f->secure_media_lines == f->media_lines;
	f->dtls_srtp = f->media_lines > 0 &&
		f->dtls_media_lines == f->media_lines;
	f->rtcp_mux = f->media_lines > 0 &&
		f->rtcp_mux_media_lines == f->media_lines;
	f->sdes_srtp = f->media_lines > 0 &&
		f->sdes_media_lines == f->media_lines;
	f->dtls_or_sdes_srtp = f->media_lines > 0 &&
		f->keyed_media_lines == f->media_lines;

	return 0;
}

/*
 * A feature is reported for the message only if every SDP body part has it,
 * so that a compliant first part cannot mask a non-compliant later one.
 */
static void merge_features(struct media_features *dst,
	const struct media_features *src)
{
	dst->ice &= src->ice;
	dst->candidate &= src->candidate;
	dst->srflx &= src->srflx;
	dst->relay &= src->relay;
	dst->fingerprint &= src->fingerprint;
	dst->setup &= src->setup;
	dst->dtls_srtp &= src->dtls_srtp;
	dst->sdes &= src->sdes;
	dst->rtcp_mux &= src->rtcp_mux;
	dst->secure_rtp &= src->secure_rtp;
	dst->sdes_srtp &= src->sdes_srtp;
	dst->dtls_or_sdes_srtp &= src->dtls_or_sdes_srtp;
}

static int inspect_sdp(struct sip_msg *msg, struct media_features *f)
{
	struct body_part *part;
	struct media_features pf;
	int parts = 0;

	if (parse_sip_body(msg) < 0 || !msg->body)
		return -1;

	/* check every SDP part, e.g. all alternatives of multipart/alternative */
	for (part = &msg->body->first; part; part = part->next) {
		if (!is_body_part_received(part) ||
			part->mime != ((TYPE_APPLICATION << 16) + SUBTYPE_SDP))
			continue;
		if (classify_sdp_body(&part->body, parts ? &pf : f) < 0)
			return -1;
		if (parts)
			merge_features(f, &pf);
		parts++;
	}

	return parts ? 0 : -1;
}

static void account_features(const struct media_features *f)
{
	if (f->ice) update_stat(ice_sdps, 1);
	if (f->candidate) update_stat(candidate_sdps, 1);
	if (f->srflx) update_stat(srflx_sdps, 1);
	if (f->dtls_srtp) update_stat(dtls_sdps, 1);
	if (f->relay) update_stat(relay_sdps, 1);
	if (f->sdes) update_stat(sdes_sdps, 1);
	if (f->rtcp_mux) update_stat(rtcp_mux_sdps, 1);
}

static void raise_policy_event(event_id_t event, const struct media_features *f,
	str *reason)
{
	evi_params_p ep;
	int ice = f->ice, candidate = f->candidate, srflx = f->srflx;
	int dtls = f->dtls_srtp, mux = f->rtcp_mux;
	int relay = f->relay, sdes = f->sdes;

	if (event == EVI_ERROR || !evi_probe_event(event))
		return;
	ep = evi_get_params();
	if (!ep)
		return;
	if ((reason && evi_param_add_str(ep, &p_reason, reason) < 0) ||
		evi_param_add_int(ep, &p_ice, &ice) < 0 ||
		evi_param_add_int(ep, &p_candidate, &candidate) < 0 ||
		evi_param_add_int(ep, &p_srflx, &srflx) < 0 ||
		evi_param_add_int(ep, &p_dtls_srtp, &dtls) < 0 ||
		evi_param_add_int(ep, &p_rtcp_mux, &mux) < 0 ||
		evi_param_add_int(ep, &p_relay, &relay) < 0 ||
		evi_param_add_int(ep, &p_sdes, &sdes) < 0) {
		evi_free_params(ep);
		return;
	}
	if (evi_raise_event(event, ep) < 0)
		LM_ERR("failed to raise media security event\n");
}

static int enforce(struct sip_msg *msg, int need_ice, int need_dtls,
	int need_mux, int need_relay, int accept_sdes)
{
	struct media_features f;
	static str r_no_sdp = str_init("no-sdp");
	static str r_ice = str_init("ice-required");
	static str r_dtls = str_init("dtls-srtp-required");
	static str r_mux = str_init("rtcp-mux-required");
	static str r_relay = str_init("turn-relay-candidate-required");
	str *reason = NULL;

	update_stat(checks, 1);
	if (inspect_sdp(msg, &f) < 0) {
		memset(&f, 0, sizeof(f));
		reason = &r_no_sdp;
		goto failed;
	}
	account_features(&f);

	if (need_ice && !f.ice)
		reason = &r_ice;
	else if (need_dtls && !f.dtls_srtp &&
		!(accept_sdes && f.dtls_or_sdes_srtp))
		reason = &r_dtls;
	else if (need_mux && !f.rtcp_mux)
		reason = &r_mux;
	else if (need_relay && !f.relay)
		reason = &r_relay;

	if (!reason) {
		if (emit_compliant)
			raise_policy_event(compliant_event, &f, NULL);
		return 1;
	}

failed:
	update_stat(violations, 1);
	raise_policy_event(violation_event, &f, reason);
	return -1;
}

static int w_media_security_check(struct sip_msg *msg)
{
	return enforce(msg, require_ice, require_dtls_srtp, require_rtcp_mux,
		require_turn_relay, allow_sdes);
}

static int w_media_security_profile(struct sip_msg *msg, str *profile)
{
	if (str_eq_ci(profile, "webrtc"))
		return enforce(msg, 1, 1, 1, 0, 0);
	if (str_eq_ci(profile, "webrtc-turn"))
		return enforce(msg, 1, 1, 1, 1, 0);
	if (str_eq_ci(profile, "sdes"))
		return enforce(msg, 0, 1, 0, 0, 1);
	if (str_eq_ci(profile, "secure"))
		return enforce(msg, 0, 1, 0, 0, allow_sdes);

	LM_ERR("unknown media security profile '%.*s'\n", profile->len, profile->s);
	return -1;
}

static int w_media_security_has(struct sip_msg *msg, str *feature)
{
	struct media_features f;

	if (inspect_sdp(msg, &f) < 0)
		return -1;
	if (str_eq_ci(feature, "ice")) return f.ice ? 1 : -1;
	if (str_eq_ci(feature, "candidate")) return f.candidate ? 1 : -1;
	if (str_eq_ci(feature, "srflx")) return f.srflx ? 1 : -1;
	if (str_eq_ci(feature, "relay")) return f.relay ? 1 : -1;
	if (str_eq_ci(feature, "dtls-srtp")) return f.dtls_srtp ? 1 : -1;
	if (str_eq_ci(feature, "sdes")) return f.sdes ? 1 : -1;
	if (str_eq_ci(feature, "rtcp-mux")) return f.rtcp_mux ? 1 : -1;
	if (str_eq_ci(feature, "srtp")) return f.secure_rtp ? 1 : -1;

	LM_ERR("unknown media security feature '%.*s'\n",
		feature->len, feature->s);
	return -1;
}

#ifdef UNIT_TESTS
#define MEDIA_SECURITY_TEST_ICE        (1U << 0)
#define MEDIA_SECURITY_TEST_CANDIDATE  (1U << 1)
#define MEDIA_SECURITY_TEST_SRFLX      (1U << 2)
#define MEDIA_SECURITY_TEST_RELAY      (1U << 3)
#define MEDIA_SECURITY_TEST_DTLS_SRTP  (1U << 4)
#define MEDIA_SECURITY_TEST_SDES       (1U << 5)
#define MEDIA_SECURITY_TEST_RTCP_MUX   (1U << 6)
#define MEDIA_SECURITY_TEST_SECURE_RTP (1U << 7)
#define MEDIA_SECURITY_TEST_SDES_SRTP  (1U << 8)
#define MEDIA_SECURITY_TEST_DTLS_OR_SDES (1U << 9)

static unsigned int media_security_test_flags(const struct media_features *fp)
{
	struct media_features f = *fp;
	unsigned int flags = 0;

	if (f.ice) flags |= MEDIA_SECURITY_TEST_ICE;
	if (f.candidate) flags |= MEDIA_SECURITY_TEST_CANDIDATE;
	if (f.srflx) flags |= MEDIA_SECURITY_TEST_SRFLX;
	if (f.relay) flags |= MEDIA_SECURITY_TEST_RELAY;
	if (f.dtls_srtp) flags |= MEDIA_SECURITY_TEST_DTLS_SRTP;
	if (f.sdes) flags |= MEDIA_SECURITY_TEST_SDES;
	if (f.rtcp_mux) flags |= MEDIA_SECURITY_TEST_RTCP_MUX;
	if (f.secure_rtp) flags |= MEDIA_SECURITY_TEST_SECURE_RTP;
	if (f.sdes_srtp) flags |= MEDIA_SECURITY_TEST_SDES_SRTP;
	if (f.dtls_or_sdes_srtp) flags |= MEDIA_SECURITY_TEST_DTLS_OR_SDES;
	return flags;
}

unsigned int media_security_test_classify(const char *text)
{
	str body = STR_NULL;
	struct media_features f;

	if (!text)
		return 0;
	body.s = (char *)text;
	body.len = strlen(text);
	if (classify_sdp_body(&body, &f) < 0)
		return 0;

	return media_security_test_flags(&f);
}

/* parse a full SIP message and inspect all of its SDP body parts */
unsigned int media_security_test_inspect_msg(const char *text)
{
	static char buf[8192];
	struct sip_msg msg;
	struct media_features f;
	unsigned int flags = 0;
	int len;

	if (!text || (len = strlen(text)) >= (int)sizeof(buf))
		return 0;
	memcpy(buf, text, len + 1);

	memset(&msg, 0, sizeof(msg));
	msg.buf = buf;
	msg.len = len;
	if (parse_msg(buf, len, &msg) != 0) {
		LM_ERR("failed to parse test SIP message\n");
		goto out;
	}
	if (inspect_sdp(&msg, &f) == 0)
		flags = media_security_test_flags(&f);
out:
	free_sip_msg(&msg);
	return flags;
}
#endif

static int mod_init(void)
{
	violation_event = evi_publish_event(violation_event_name);
	compliant_event = evi_publish_event(compliant_event_name);
	if (violation_event == EVI_ERROR || compliant_event == EVI_ERROR) {
		LM_ERR("failed to publish media security events\n");
		return -1;
	}
	return 0;
}
