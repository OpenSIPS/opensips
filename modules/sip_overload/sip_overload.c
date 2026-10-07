/*
 * RFC 7339 / RFC 7415 SIP overload control
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../locking.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_via.h"
#include "../../timer.h"
#include "../../ip_addr.h"
#include "../../statistics.h"
#include "../../msg_translator.h"
#include "../../evi/evi_modules.h"
#include "../../evi/evi_params.h"

#define OC_DEFAULT_VALIDITY_MS 500
#define OC_KEY_MAX 128
#define OC_SEQ_MAX 32
#define OC_ADV_MAX 160
#define OC_REPLY_MAX 192
#define OC_RATE_TAU_STEPS 4

enum oc_algorithm {
	OC_ALGO_LOSS = 0,
	OC_ALGO_RATE = 1
};

struct oc_seq {
	unsigned long long major;
	unsigned int minor;
};

struct oc_peer {
	unsigned short key_len;
	char key[OC_KEY_MAX];
	enum oc_algorithm algo;
	unsigned int value;
	unsigned int validity_ms;
	struct oc_seq seq;
	utime_t expires_us;
	utime_t next_allowed_us;
	struct oc_peer *next;
};

struct oc_local_feedback {
	int enabled;
	enum oc_algorithm algo;
	unsigned int value;
	unsigned int validity_ms;
	struct oc_seq seq;
};

static char *advertise_algorithms = "loss,rate";
static int advertise = 1;
static int max_peers = 4096;

static gen_lock_t *oc_lock;
static struct oc_peer **oc_peers;
static unsigned int *oc_peer_count;
static struct oc_local_feedback *local_feedback;

static stat_var *st_feedback_updates;
static stat_var *st_feedback_stale;
static stat_var *st_feedback_malformed;
static stat_var *st_requests_allowed;
static stat_var *st_requests_throttled;
static stat_var *st_feedback_expired;
static stat_var *st_peer_states;
static stat_var *st_peer_limit_drops;
static stat_var *st_server_updates;

static event_id_t ev_update = EVI_ERROR;
static event_id_t ev_throttle = EVI_ERROR;
static str ev_update_name = str_init("E_SIP_OVERLOAD_UPDATE");
static str ev_throttle_name = str_init("E_SIP_OVERLOAD_THROTTLE");
static str p_peer = str_init("peer");
static str p_algo = str_init("algorithm");
static str p_value = str_init("value");
static str p_validity = str_init("validity_ms");

static char oc_advertise_buf[OC_ADV_MAX];

static int mod_init(void);
static void mod_destroy(void);
static int oc_via_params_provider(struct sip_msg *msg, int context, str *out);
static int w_oc_update(struct sip_msg *msg);
static int w_oc_update_peer(struct sip_msg *msg, str *peer);
static int w_oc_check(struct sip_msg *msg, str *peer);
static int w_oc_set_local(struct sip_msg *msg, str *algo, int *value, int *validity);
static int w_oc_clear_local(struct sip_msg *msg);

static const cmd_export_t cmds[] = {
	{"oc_update", (cmd_function)w_oc_update, {{0,0,0}}, ONREPLY_ROUTE},
	{"oc_update_peer", (cmd_function)w_oc_update_peer,
		{{CMD_PARAM_STR,0,0},{0,0,0}}, ONREPLY_ROUTE},
	{"oc_check", (cmd_function)w_oc_check,
		{{CMD_PARAM_STR,0,0},{0,0,0}}, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"oc_set_local", (cmd_function)w_oc_set_local, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT,0,0},
		{0,0,0}}, ALL_ROUTES},
	{"oc_clear_local", (cmd_function)w_oc_clear_local, {{0,0,0}}, ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static const param_export_t params[] = {
	{"advertise_algorithms", STR_PARAM, &advertise_algorithms},
	{"advertise", INT_PARAM, &advertise},
	{"max_peers", INT_PARAM, &max_peers},
	{0,0,0}
};

static const stat_export_t stats[] = {
	{"feedback_updates", STAT_NO_RESET, &st_feedback_updates},
	{"feedback_stale", STAT_NO_RESET, &st_feedback_stale},
	{"feedback_malformed", STAT_NO_RESET, &st_feedback_malformed},
	{"requests_allowed", STAT_NO_RESET, &st_requests_allowed},
	{"requests_throttled", STAT_NO_RESET, &st_requests_throttled},
	{"feedback_expired", STAT_NO_RESET, &st_feedback_expired},
	{"peer_states", STAT_NO_RESET, &st_peer_states},
	{"peer_limit_drops", STAT_NO_RESET, &st_peer_limit_drops},
	{"server_updates", STAT_NO_RESET, &st_server_updates},
	{0,0,0}
};

struct module_exports exports = {
	"sip_overload",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,
	0,
	cmds,
	0,
	params,
	stats,
	0,
	0,
	0,
	0,
	0,
	mod_init,
	0,
	mod_destroy,
	0,
	0
};

/*
 * Microsecond monotonic clock. The core get_uticks() only advances in
 * UTIMER_TICK (100 ms) steps, which is far too coarse for rate control.
 */
static utime_t oc_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return get_uticks();
	return (utime_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int str_eq_ci(const str *s, const char *lit)
{
	int i, l;
	const char *p;
	if (!s || !s->s || !lit)
		return 0;
	p = s->s;
	l = s->len;
	if (l >= 2 && p[0] == '"' && p[l-1] == '"') {
		p++;
		l -= 2;
	}
	if ((int)strlen(lit) != l)
		return 0;
	for (i = 0; i < l; i++) {
		char a = p[i], b = lit[i];
		if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
		if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
		if (a != b)
			return 0;
	}
	return 1;
}

static int parse_uint(const str *s, unsigned int *out)
{
	unsigned long v = 0;
	int i;
	if (!s || !s->s || s->len <= 0)
		return -1;
	for (i = 0; i < s->len; i++) {
		if (s->s[i] < '0' || s->s[i] > '9')
			return -1;
		v = v * 10 + (unsigned long)(s->s[i] - '0');
		if (v > 0xffffffffUL)
			return -1;
	}
	*out = (unsigned int)v;
	return 0;
}

static int parse_seq(const str *s, struct oc_seq *seq)
{
	unsigned long long major = 0;
	unsigned int minor = 0;
	int i, dot = -1, minor_digits = 0;
	if (!s || !s->s || s->len < 3)
		return -1;
	for (i = 0; i < s->len; i++) {
		if (s->s[i] == '.') {
			if (dot >= 0 || i == 0 || i == s->len - 1)
				return -1;
			dot = i;
			continue;
		}
		if (s->s[i] < '0' || s->s[i] > '9')
			return -1;
		if (dot < 0) {
			major = major * 10ULL + (unsigned long long)(s->s[i] - '0');
		} else {
			if (++minor_digits > 5)
				return -1;
			minor = minor * 10U + (unsigned int)(s->s[i] - '0');
		}
	}
	if (dot < 0 || dot > 12 || minor_digits <= 0)
		return -1;
	seq->major = major;
	seq->minor = minor;
	return 0;
}

static int seq_cmp(const struct oc_seq *a, const struct oc_seq *b)
{
	if (a->major < b->major) return -1;
	if (a->major > b->major) return 1;
	if (a->minor < b->minor) return -1;
	if (a->minor > b->minor) return 1;
	return 0;
}

static struct via_param *find_via_param(struct via_body *via, const char *name)
{
	struct via_param *p;
	int nlen = strlen(name);
	if (!via)
		return NULL;
	for (p = via->param_lst; p; p = p->next)
		if (p->name.len == nlen && strncasecmp(p->name.s, name, nlen) == 0)
			return p;
	return NULL;
}

static struct oc_peer *find_peer_locked(const str *key)
{
	struct oc_peer *p;
	if (!key || !key->s || key->len <= 0 || key->len >= OC_KEY_MAX)
		return NULL;
	for (p = *oc_peers; p; p = p->next)
		if (p->key_len == key->len && memcmp(p->key, key->s, key->len) == 0)
			return p;
	return NULL;
}

static void purge_expired_peers_locked(utime_t now)
{
	struct oc_peer *p, *prev = NULL, *next;

	if (!oc_peers || !oc_peer_count)
		return;

	for (p = *oc_peers; p; p = next) {
		next = p->next;
		if (!p->validity_ms || now >= p->expires_us) {
			if (prev)
				prev->next = next;
			else
				*oc_peers = next;
			shm_free(p);
			if (*oc_peer_count)
				(*oc_peer_count)--;
			update_stat(st_peer_states, -1);
			continue;
		}
		prev = p;
	}
}

static struct oc_peer *get_peer_locked(const str *key, utime_t now)
{
	struct oc_peer *p = find_peer_locked(key);

	if (p)
		return p;

	if (*oc_peer_count >= (unsigned int)max_peers)
		purge_expired_peers_locked(now);
	if (*oc_peer_count >= (unsigned int)max_peers)
		return NULL;

	p = shm_malloc(sizeof(*p));
	if (!p)
		return NULL;
	memset(p, 0, sizeof(*p));
	p->key_len = key->len;
	memcpy(p->key, key->s, key->len);
	p->next = *oc_peers;
	*oc_peers = p;
	(*oc_peer_count)++;
	update_stat(st_peer_states, 1);
	return p;
}

static void raise_oc_event(event_id_t event, const str *peer,
	enum oc_algorithm algo, unsigned int value, unsigned int validity)
{
	evi_params_p ep;
	str algo_s = algo == OC_ALGO_RATE ? str_init("rate") : str_init("loss");
	int ivalue = (int)value, ivalidity = (int)validity;
	if (event == EVI_ERROR || !evi_probe_event(event))
		return;
	ep = evi_get_params();
	if (!ep)
		return;
	if (evi_param_add_str(ep, &p_peer, peer) < 0 ||
		evi_param_add_str(ep, &p_algo, &algo_s) < 0 ||
		evi_param_add_int(ep, &p_value, &ivalue) < 0 ||
		evi_param_add_int(ep, &p_validity, &ivalidity) < 0) {
		evi_free_params(ep);
		return;
	}
	if (evi_raise_event(event, ep) < 0)
		LM_ERR("failed to raise overload-control event\n");
}

static int source_peer(struct sip_msg *msg, str *peer, char *buf, int size)
{
	const char *ip;
	int len;
	if (!msg)
		return -1;
	ip = ip_addr2a(&msg->rcv.src_ip);
	if (!ip)
		return -1;
	len = snprintf(buf, size, "%s:%u", ip, msg->rcv.src_port);
	if (len <= 0 || len >= size)
		return -1;
	peer->s = buf;
	peer->len = len;
	return 0;
}

static int update_from_via(struct sip_msg *msg, const str *peer)
{
	struct via_param *p_oc, *p_algo, *p_validity, *p_seq;
	struct oc_peer *state;
	enum oc_algorithm algo;
	struct oc_seq seq;
	unsigned int value, validity = OC_DEFAULT_VALIDITY_MS;
	utime_t now;
	int cmp;

	if (!msg || !peer || peer->len <= 0)
		return -1;
	if (parse_headers(msg, HDR_VIA_F, 0) < 0 || !msg->via1)
		goto malformed;

	p_oc = find_via_param(msg->via1, "oc");
	p_algo = find_via_param(msg->via1, "oc-algo");
	p_validity = find_via_param(msg->via1, "oc-validity");
	p_seq = find_via_param(msg->via1, "oc-seq");

	/* No feedback means the downstream server did not update our OC state. */
	if (!p_oc)
		return 1;
	if (!p_oc->value.s || parse_uint(&p_oc->value, &value) < 0 || !p_seq ||
		parse_seq(&p_seq->value, &seq) < 0)
		goto malformed;

	if (p_algo && str_eq_ci(&p_algo->value, "rate"))
		algo = OC_ALGO_RATE;
	else if (!p_algo || str_eq_ci(&p_algo->value, "loss"))
		algo = OC_ALGO_LOSS;
	else
		goto malformed;

	if (p_validity && parse_uint(&p_validity->value, &validity) < 0)
		goto malformed;
	if (algo == OC_ALGO_LOSS && value > 100)
		goto malformed;

	now = oc_now_us();
	lock_get(oc_lock);
	state = get_peer_locked(peer, now);
	if (!state) {
		int at_limit = oc_peer_count &&
			*oc_peer_count >= (unsigned int)max_peers;
		lock_release(oc_lock);
		if (at_limit)
			update_stat(st_peer_limit_drops, 1);
		return -1;
	}

	if (state->seq.major || state->seq.minor) {
		cmp = seq_cmp(&seq, &state->seq);
		if (cmp <= 0) {
			lock_release(oc_lock);
			update_stat(st_feedback_stale, 1);
			return 1;
		}
	}

	state->algo = algo;
	state->value = value;
	state->validity_ms = validity;
	state->seq = seq;
	state->next_allowed_us = now;
	state->expires_us = validity ? now + (utime_t)validity * 1000 : now;
	lock_release(oc_lock);

	update_stat(st_feedback_updates, 1);
	raise_oc_event(ev_update, peer, algo, value, validity);
	return 1;

malformed:
	update_stat(st_feedback_malformed, 1);
	return -1;
}

static int w_oc_update(struct sip_msg *msg)
{
	char buf[OC_KEY_MAX];
	str peer;
	if (source_peer(msg, &peer, buf, sizeof(buf)) < 0)
		return -1;
	return update_from_via(msg, &peer);
}

static int w_oc_update_peer(struct sip_msg *msg, str *peer)
{
	if (!peer || !peer->s || peer->len <= 0 || peer->len >= OC_KEY_MAX)
		return -1;
	return update_from_via(msg, peer);
}

static int w_oc_check(struct sip_msg *msg, str *peer)
{
	struct oc_peer *state;
	enum oc_algorithm algo;
	unsigned int value, validity;
	utime_t now, step;
	int allow = 1;

	if (!peer || !peer->s || peer->len <= 0 || peer->len >= OC_KEY_MAX)
		return -1;
	now = oc_now_us();

	lock_get(oc_lock);
	state = find_peer_locked(peer);
	if (!state) {
		lock_release(oc_lock);
		update_stat(st_requests_allowed, 1);
		return 1;
	}

	if (!state->validity_ms || now >= state->expires_us) {
		if (state->validity_ms && now >= state->expires_us)
			update_stat(st_feedback_expired, 1);
		state->validity_ms = 0;
		lock_release(oc_lock);
		update_stat(st_requests_allowed, 1);
		return 1;
	}

	algo = state->algo;
	value = state->value;
	validity = state->validity_ms;

	if (algo == OC_ALGO_RATE) {
		/*
		 * RFC 7415 default leaky bucket, T = 1/oc and
		 * TAU = 4*T; next_allowed_us holds the bucket's theoretical
		 * arrival time (LCT + X).
		 */
		if (value == 0) {
			allow = 0;
		} else {
			step = 1000000ULL / value;
			if (!step) step = 1;
			if (state->next_allowed_us > now &&
					state->next_allowed_us - now > OC_RATE_TAU_STEPS * step) {
				allow = 0;
			} else {
				if (state->next_allowed_us < now)
					state->next_allowed_us = now;
				state->next_allowed_us += step;
			}
		}
	} else {
		if (value >= 100)
			allow = 0;
		else if (value > 0 && ((unsigned int)(rand() % 100) + 1) <= value)
			allow = 0;
	}
	lock_release(oc_lock);

	if (allow) {
		update_stat(st_requests_allowed, 1);
		return 1;
	}

	update_stat(st_requests_throttled, 1);
	raise_oc_event(ev_throttle, peer, algo, value, validity);
	return -1;
}

static void next_local_seq_locked(struct oc_seq *seq)
{
	unsigned long long sec = (unsigned long long)time(NULL);
	if (local_feedback->seq.major < sec) {
		seq->major = sec;
		seq->minor = 0;
	} else {
		*seq = local_feedback->seq;
		seq->minor++;
		if (seq->minor > 99999) {
			seq->major++;
			seq->minor = 0;
		}
	}
}

static int parse_algo_name(const str *algo, enum oc_algorithm *out)
{
	if (str_eq_ci(algo, "loss")) {
		*out = OC_ALGO_LOSS;
		return 0;
	}
	if (str_eq_ci(algo, "rate")) {
		*out = OC_ALGO_RATE;
		return 0;
	}
	return -1;
}

static int w_oc_set_local(struct sip_msg *msg, str *algo_s, int *value_p, int *validity_p)
{
	enum oc_algorithm algo;
	struct oc_seq seq;
	unsigned int value, validity;

	if (!value_p || !validity_p || *value_p < 0 || *validity_p < 0 ||
		parse_algo_name(algo_s, &algo) < 0)
		return -1;
	value = (unsigned int)*value_p;
	validity = (unsigned int)*validity_p;
	if (algo == OC_ALGO_LOSS && value > 100)
		return -1;

	lock_get(oc_lock);
	next_local_seq_locked(&seq);
	local_feedback->enabled = 1;
	local_feedback->algo = algo;
	local_feedback->value = value;
	local_feedback->validity_ms = validity;
	local_feedback->seq = seq;
	lock_release(oc_lock);
	update_stat(st_server_updates, 1);
	return 1;
}

static int w_oc_clear_local(struct sip_msg *msg)
{
	struct oc_seq seq;
	lock_get(oc_lock);
	next_local_seq_locked(&seq);
	local_feedback->enabled = 1;
	local_feedback->value = 0;
	local_feedback->validity_ms = 0;
	local_feedback->seq = seq;
	lock_release(oc_lock);
	update_stat(st_server_updates, 1);
	return 1;
}

static int advertised_algo_list_valid(const char *value)
{
	const unsigned char *p;
	int token_len = 0;

	if (!value || !*value)
		return 0;

	for (p = (const unsigned char *)value; ; p++) {
		if (*p == ',' || *p == '\0') {
			if (!token_len)
				return 0;
			token_len = 0;
			if (*p == '\0')
				break;
			continue;
		}
		if (!((*p >= 'A' && *p <= 'Z') ||
			  (*p >= 'a' && *p <= 'z') ||
			  (*p >= '0' && *p <= '9')))
			return 0;
		token_len++;
	}
	return 1;
}

static int algo_list_has(const str *value, const char *algo)
{
	int start, end, alen;

	if (!value || !value->s || !algo)
		return 0;
	alen = strlen(algo);
	start = 0;
	end = value->len;
	if (end >= 2 && value->s[0] == '"' && value->s[end - 1] == '"') {
		start++;
		end--;
	}

	while (start < end) {
		int tok_start, tok_end, j;

		while (start < end &&
				(value->s[start] == ' ' || value->s[start] == '\t' ||
				 value->s[start] == ','))
			start++;
		tok_start = start;
		while (start < end && value->s[start] != ',')
			start++;
		tok_end = start;
		while (tok_end > tok_start &&
				(value->s[tok_end - 1] == ' ' || value->s[tok_end - 1] == '\t'))
			tok_end--;

		if (tok_end - tok_start == alen) {
			for (j = 0; j < alen; j++) {
				char a = value->s[tok_start + j], b = algo[j];
				if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
				if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
				if (a != b)
					break;
			}
			if (j == alen)
				return 1;
		}
	}
	return 0;
}

static int request_supports_oc(struct sip_msg *msg)
{
	if (!msg)
		return 0;
	if (parse_headers(msg, HDR_VIA_F, 0) < 0 || !msg->via1)
		return 0;
	return find_via_param(msg->via1, "oc") != NULL;
}

static int request_supports_algo(struct sip_msg *msg, enum oc_algorithm algo)
{
	struct via_param *p_algo;

	if (!request_supports_oc(msg))
		return 0;

	p_algo = find_via_param(msg->via1, "oc-algo");
	if (!p_algo)
		return algo == OC_ALGO_LOSS;

	return algo_list_has(&p_algo->value,
		algo == OC_ALGO_RATE ? "rate" : "loss");
}

static int oc_via_params_provider(struct sip_msg *msg, int context, str *out)
{
	static char reply_buf[OC_REPLY_MAX];
	struct oc_local_feedback snap;
	enum oc_algorithm selected_algo;
	unsigned int selected_value, selected_validity;
	const char *algo;
	int len;

	out->s = NULL;
	out->len = 0;

	if (context == VIA_PARAM_CTX_REQUEST) {
		if (!advertise || !oc_advertise_buf[0])
			return 0;
		out->s = oc_advertise_buf;
		out->len = strlen(oc_advertise_buf);
		return 1;
	}

	if (context != VIA_PARAM_CTX_REPLY || !msg || !request_supports_oc(msg))
		return 0;

	lock_get(oc_lock);
	snap = *local_feedback;
	lock_release(oc_lock);
	if (!snap.enabled)
		return 0;

	selected_algo = snap.algo;
	selected_value = snap.value;
	selected_validity = snap.validity_ms;

	/*
	 * A server must choose an algorithm advertised by the client. Every
	 * RFC 7339 client supports loss. If local policy is rate-based but the
	 * neighbor did not advertise rate, acknowledge overload-control support
	 * using the mandatory loss algorithm without imposing an incompatible
	 * reduction value.
	 */
	if (!request_supports_algo(msg, selected_algo)) {
		selected_algo = OC_ALGO_LOSS;
		selected_value = 0;
		selected_validity = 0;
	}

	algo = selected_algo == OC_ALGO_RATE ? "rate" : "loss";
	len = snprintf(reply_buf, sizeof(reply_buf),
		";oc=%u;oc-algo=\"%s\";oc-validity=%u;oc-seq=%llu.%05u",
		selected_value, algo, selected_validity,
		snap.seq.major, snap.seq.minor);
	if (len <= 0 || len >= (int)sizeof(reply_buf))
		return -1;
	out->s = reply_buf;
	out->len = len;
	return 1;
}

#ifdef UNIT_TESTS
int sip_overload_test_parse_uint(const char *text, unsigned int *out)
{
	str value = STR_NULL;

	if (!text)
		return -1;
	value.s = (char *)text;
	value.len = strlen(text);
	return parse_uint(&value, out);
}

int sip_overload_test_parse_seq(const char *text,
	unsigned long long *major, unsigned int *minor)
{
	str value = STR_NULL;
	struct oc_seq seq;
	int rc;

	if (!text || !major || !minor)
		return -1;
	value.s = (char *)text;
	value.len = strlen(text);
	rc = parse_seq(&value, &seq);
	if (rc < 0)
		return rc;
	*major = seq.major;
	*minor = seq.minor;
	return 0;
}

int sip_overload_test_seq_cmp(const char *left, const char *right)
{
	str a_s = STR_NULL, b_s = STR_NULL;
	struct oc_seq a, b;

	if (!left || !right)
		return 99;
	a_s.s = (char *)left;
	a_s.len = strlen(left);
	b_s.s = (char *)right;
	b_s.len = strlen(right);
	if (parse_seq(&a_s, &a) < 0 || parse_seq(&b_s, &b) < 0)
		return 99;
	return seq_cmp(&a, &b);
}

int sip_overload_test_advertised_algo_list_valid(const char *list)
{
	return advertised_algo_list_valid(list);
}

int sip_overload_test_algo_list_has(const char *list, const char *algo)
{
	str value = STR_NULL;

	if (!list || !algo)
		return 0;
	value.s = (char *)list;
	value.len = strlen(list);
	return algo_list_has(&value, algo);
}
#endif

static int mod_init(void)
{
	str advertised;
	int len;

	if (!advertise_algorithms || !*advertise_algorithms) {
		LM_ERR("advertise_algorithms cannot be empty\n");
		return -1;
	}
	if (!advertised_algo_list_valid(advertise_algorithms)) {
		LM_ERR("advertise_algorithms must be a comma-separated list of "
			"non-empty ASCII alphanumeric tokens\n");
		return -1;
	}
	if (max_peers <= 0) {
		LM_ERR("max_peers must be greater than zero\n");
		return -1;
	}


	advertised.s = advertise_algorithms;
	advertised.len = strlen(advertise_algorithms);
	if (advertise && !algo_list_has(&advertised, "loss")) {
		LM_ERR("RFC 7339 clients must advertise the mandatory 'loss' algorithm\n");
		return -1;
	}

	len = snprintf(oc_advertise_buf, sizeof(oc_advertise_buf),
		";oc;oc-algo=\"%s\"", advertise_algorithms);
	if (len <= 0 || len >= (int)sizeof(oc_advertise_buf)) {
		LM_ERR("advertise_algorithms is too long\n");
		return -1;
	}

	oc_lock = lock_alloc();
	if (!oc_lock) {
		LM_ERR("failed to allocate overload-control lock\n");
		return -1;
	}
	if (!lock_init(oc_lock)) {
		LM_ERR("failed to initialize overload-control lock\n");
		lock_dealloc(oc_lock);
		oc_lock = NULL;
		return -1;
	}

	oc_peers = shm_malloc(sizeof(*oc_peers));
	if (!oc_peers) {
		LM_ERR("no shared memory for overload-control peer state\n");
		goto error;
	}
	*oc_peers = NULL;

	oc_peer_count = shm_malloc(sizeof(*oc_peer_count));
	if (!oc_peer_count) {
		LM_ERR("no shared memory for overload-control peer count\n");
		goto error;
	}
	*oc_peer_count = 0;

	local_feedback = shm_malloc(sizeof(*local_feedback));
	if (!local_feedback) {
		LM_ERR("no shared memory for overload-control local state\n");
		goto error;
	}
	memset(local_feedback, 0, sizeof(*local_feedback));

	/*
	 * Loading the module means this server supports RFC 7339. Even when
	 * not overloaded, capable upstream clients receive oc=0 so support can
	 * be negotiated without inventing overload state.
	 */
	local_feedback->enabled = 1;
	local_feedback->algo = OC_ALGO_LOSS;
	local_feedback->value = 0;
	local_feedback->validity_ms = 0;
	local_feedback->seq.major = (unsigned long long)time(NULL);
	local_feedback->seq.minor = 0;

	ev_update = evi_publish_event(ev_update_name);
	ev_throttle = evi_publish_event(ev_throttle_name);
	if (ev_update == EVI_ERROR || ev_throttle == EVI_ERROR) {
		LM_ERR("failed to publish overload-control events\n");
		goto error;
	}

	if (register_via_param_provider(oc_via_params_provider) < 0) {
		LM_ERR("failed to register overload-control Via parameter provider\n");
		goto error;
	}

	return 0;

error:
	if (local_feedback) {
		shm_free(local_feedback);
		local_feedback = NULL;
	}
	if (oc_peer_count) {
		shm_free(oc_peer_count);
		oc_peer_count = NULL;
	}
	if (oc_peers) {
		shm_free(oc_peers);
		oc_peers = NULL;
	}
	if (oc_lock) {
		lock_destroy(oc_lock);
		lock_dealloc(oc_lock);
		oc_lock = NULL;
	}
	return -1;
}

static void mod_destroy(void)
{
	struct oc_peer *p, *next;

	if (oc_lock)
		lock_get(oc_lock);
	if (oc_peers) {
		for (p = *oc_peers; p; p = next) {
			next = p->next;
			shm_free(p);
		}
		shm_free(oc_peers);
		oc_peers = NULL;
	}
	if (oc_peer_count) {
		shm_free(oc_peer_count);
		oc_peer_count = NULL;
	}
	if (local_feedback) {
		shm_free(local_feedback);
		local_feedback = NULL;
	}
	if (oc_lock) {
		lock_release(oc_lock);
		lock_destroy(oc_lock);
		lock_dealloc(oc_lock);
		oc_lock = NULL;
	}
}
