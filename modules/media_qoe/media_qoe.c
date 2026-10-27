/*
 * Media quality reporting for OpenSIPS
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../statistics.h"
#include "../../locking.h"
#include "../../mem/shm_mem.h"
#include "../../evi/evi_modules.h"
#include "../../evi/evi_params.h"

#define E_QOE_UPDATE_NAME   "E_MEDIA_QOE_UPDATE"
#define E_QOE_BAD_NAME      "E_MEDIA_QOE_DEGRADED"
#define E_QOE_FINAL_NAME    "E_MEDIA_QOE_FINAL"

#define QOE_HAVE_MOS        (1U << 0)
#define QOE_HAVE_JITTER     (1U << 1)
#define QOE_HAVE_PACKETLOSS (1U << 2)
#define QOE_HAVE_ROUNDTRIP  (1U << 3)

struct qoe_snapshot {
	unsigned long mos;
	unsigned long jitter;
	unsigned long packetloss;
	unsigned long roundtrip;
	unsigned int available_mask;
};

static int mod_init(void);
static void mod_destroy(void);
static int w_qoe_report(struct sip_msg *msg, str *callid, str *mos,
	str *jitter, str *packetloss, str *roundtrip);
static int w_qoe_final(struct sip_msg *msg, str *callid, str *mos,
	str *jitter, str *packetloss, str *roundtrip);

/* RTPengine's MOS values are represented in tenths: 35 means MOS 3.5. */
static int min_mos = 35;
/* Negative thresholds disable the respective degradation check. */
static int max_jitter = -1;
static int max_packetloss = -1;
static int max_roundtrip = -1;
static int emit_updates = 1;

static stat_var *reports;
static stat_var *invalid_reports;
static stat_var *incomplete_reports;
static stat_var *degraded_reports;
static stat_var *final_reports;
static struct qoe_snapshot *last_values;
static gen_lock_t *last_values_lock;

static event_id_t ev_update = EVI_ERROR;
static event_id_t ev_bad = EVI_ERROR;
static event_id_t ev_final = EVI_ERROR;

static str ev_update_name = str_init(E_QOE_UPDATE_NAME);
static str ev_bad_name = str_init(E_QOE_BAD_NAME);
static str ev_final_name = str_init(E_QOE_FINAL_NAME);

static str p_callid = str_init("callid");
static str p_mos = str_init("mos");
static str p_jitter = str_init("jitter");
static str p_packetloss = str_init("packetloss");
static str p_roundtrip = str_init("roundtrip");
static str p_reason = str_init("reason");

static const cmd_export_t cmds[] = {
	{"media_qoe_report", (cmd_function)w_qoe_report, {
		{CMD_PARAM_STR, 0, 0}, {CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
	{"media_qoe_final", (cmd_function)w_qoe_final, {
		{CMD_PARAM_STR, 0, 0}, {CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
	{0, 0, {{0, 0, 0}}, 0}
};

static const param_export_t params[] = {
	{"min_mos", INT_PARAM, &min_mos},
	{"max_jitter", INT_PARAM, &max_jitter},
	{"max_packetloss", INT_PARAM, &max_packetloss},
	{"max_roundtrip", INT_PARAM, &max_roundtrip},
	{"emit_updates", INT_PARAM, &emit_updates},
	{0, 0, 0}
};

static unsigned long stat_last_mos(void *unused)
{
	unsigned long v = 0;
	if (!last_values || !last_values_lock)
		return 0;
	lock_get(last_values_lock);
	v = last_values->mos;
	lock_release(last_values_lock);
	return v;
}

static unsigned long stat_last_jitter(void *unused)
{
	unsigned long v = 0;
	if (!last_values || !last_values_lock)
		return 0;
	lock_get(last_values_lock);
	v = last_values->jitter;
	lock_release(last_values_lock);
	return v;
}

static unsigned long stat_last_packetloss(void *unused)
{
	unsigned long v = 0;
	if (!last_values || !last_values_lock)
		return 0;
	lock_get(last_values_lock);
	v = last_values->packetloss;
	lock_release(last_values_lock);
	return v;
}

static unsigned long stat_last_roundtrip(void *unused)
{
	unsigned long v = 0;
	if (!last_values || !last_values_lock)
		return 0;
	lock_get(last_values_lock);
	v = last_values->roundtrip;
	lock_release(last_values_lock);
	return v;
}

static unsigned long stat_last_available_mask(void *unused)
{
	unsigned long v = 0;
	(void)unused;
	if (!last_values || !last_values_lock)
		return 0;
	lock_get(last_values_lock);
	v = last_values->available_mask;
	lock_release(last_values_lock);
	return v;
}

static const stat_export_t mod_stats[] = {
	{"reports", 0, &reports},
	{"invalid_reports", 0, &invalid_reports},
	{"incomplete_reports", 0, &incomplete_reports},
	{"degraded_reports", 0, &degraded_reports},
	{"final_reports", 0, &final_reports},
	{"last_mos", STAT_IS_FUNC, (stat_var **)stat_last_mos},
	{"last_jitter", STAT_IS_FUNC, (stat_var **)stat_last_jitter},
	{"last_packetloss", STAT_IS_FUNC, (stat_var **)stat_last_packetloss},
	{"last_roundtrip", STAT_IS_FUNC, (stat_var **)stat_last_roundtrip},
	{"last_available_mask", STAT_IS_FUNC, (stat_var **)stat_last_available_mask},
	{0, 0, 0}
};

struct module_exports exports = {
	"media_qoe",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	NULL,
	NULL,
	cmds,
	NULL,
	params,
	mod_stats,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	mod_init,
	0,
	mod_destroy,
	0,
	0
};

static int str_to_metric(const str *s, long *out)
{
	char buf[64], *end;
	long v;

	if (!out)
		return -1;
	*out = -1;

	/* RTPengine may legitimately expose NULL for unavailable RTCP-derived
	 * statistics. Treat empty/null values as unavailable, not malformed.
	 * A NULL variable printed inside a string parameter (e.g.
	 * "$rtpstat(MOS-average)") is rendered by the core as "<null>". */
	if (!s || !s->s || s->len <= 0)
		return 0;
	if ((s->len == 4 && strncasecmp(s->s, "null", 4) == 0) ||
		(s->len == 6 && strncasecmp(s->s, "<null>", 6) == 0) ||
		(s->len == 3 && strncasecmp(s->s, "n/a", 3) == 0))
		return 0;
	if (s->len >= (int)sizeof(buf))
		return -1;
	/* strtol() would silently accept leading blanks and a sign */
	if (s->s[0] < '0' || s->s[0] > '9')
		return -1;

	memcpy(buf, s->s, s->len);
	buf[s->len] = '\0';
	errno = 0;
	v = strtol(buf, &end, 10);
	if (errno || end == buf || *end != '\0' || v < 0)
		return -1;

	*out = v;
	return 1;
}

static int qoe_metrics_in_range(long mos, long jitter, long packetloss,
	long roundtrip)
{
	if (mos < -1 || jitter < -1 || packetloss < -1 || roundtrip < -1)
		return 0;
	if (mos > 50 || packetloss > 100)
		return 0;
	return 1;
}

static void update_last_values(long mos, long jitter, long packetloss, long roundtrip)
{
	unsigned int mask = 0;

	if (!last_values || !last_values_lock)
		return;
	lock_get(last_values_lock);
	last_values->mos = mos >= 0 ? (unsigned long)mos : 0;
	last_values->jitter = jitter >= 0 ? (unsigned long)jitter : 0;
	last_values->packetloss = packetloss >= 0 ? (unsigned long)packetloss : 0;
	last_values->roundtrip = roundtrip >= 0 ? (unsigned long)roundtrip : 0;
	if (mos >= 0) mask |= QOE_HAVE_MOS;
	if (jitter >= 0) mask |= QOE_HAVE_JITTER;
	if (packetloss >= 0) mask |= QOE_HAVE_PACKETLOSS;
	if (roundtrip >= 0) mask |= QOE_HAVE_ROUNDTRIP;
	last_values->available_mask = mask;
	lock_release(last_values_lock);
}

static int qoe_reason(long mos, long jitter, long packetloss, long roundtrip,
	str *reason)
{
	static str mos_reason = str_init("mos");
	static str jitter_reason = str_init("jitter");
	static str loss_reason = str_init("packetloss");
	static str rtt_reason = str_init("roundtrip");

	if (min_mos >= 0 && mos >= 0 && mos < min_mos) {
		*reason = mos_reason;
		return 1;
	}
	if (max_jitter >= 0 && jitter >= 0 && jitter > max_jitter) {
		*reason = jitter_reason;
		return 1;
	}
	if (max_packetloss >= 0 && packetloss >= 0 && packetloss > max_packetloss) {
		*reason = loss_reason;
		return 1;
	}
	if (max_roundtrip >= 0 && roundtrip >= 0 && roundtrip > max_roundtrip) {
		*reason = rtt_reason;
		return 1;
	}
	return 0;
}

static int raise_qoe_event(event_id_t event, str *callid, str *mos,
	str *jitter, str *packetloss, str *roundtrip, str *reason)
{
	evi_params_p p;

	if (event == EVI_ERROR || !evi_probe_event(event))
		return 0;
	p = evi_get_params();
	if (!p)
		return -1;
	if (evi_param_add_str(p, &p_callid, callid) < 0 ||
		evi_param_add_str(p, &p_mos, mos) < 0 ||
		evi_param_add_str(p, &p_jitter, jitter) < 0 ||
		evi_param_add_str(p, &p_packetloss, packetloss) < 0 ||
		evi_param_add_str(p, &p_roundtrip, roundtrip) < 0 ||
		(reason && evi_param_add_str(p, &p_reason, reason) < 0)) {
		evi_free_params(p);
		return -1;
	}
	if (evi_raise_event(event, p) < 0) {
		LM_ERR("failed to raise media QoE event\n");
		return -1;
	}
	return 0;
}

static int qoe_process(str *callid, str *mos_s, str *jitter_s,
	str *packetloss_s, str *roundtrip_s, int final)
{
	static str unavailable = str_init("null");
	long mos, jitter, packetloss, roundtrip;
	str reason = STR_NULL;
	str *mos_event = mos_s, *jitter_event = jitter_s;
	str *packetloss_event = packetloss_s, *roundtrip_event = roundtrip_s;
	int degraded;
	int mos_rc, jitter_rc, packetloss_rc, roundtrip_rc;
	int incomplete = 0;

	if (!callid || !callid->s || callid->len <= 0) {
		LM_ERR("media QoE report requires a non-empty Call-ID\n");
		update_stat(invalid_reports, 1);
		return -1;
	}

	mos_rc = str_to_metric(mos_s, &mos);
	jitter_rc = str_to_metric(jitter_s, &jitter);
	packetloss_rc = str_to_metric(packetloss_s, &packetloss);
	roundtrip_rc = str_to_metric(roundtrip_s, &roundtrip);

	if (mos_rc < 0 || jitter_rc < 0 || packetloss_rc < 0 ||
		roundtrip_rc < 0 ||
		!qoe_metrics_in_range(mos, jitter, packetloss, roundtrip)) {
		LM_ERR("invalid media QoE sample; expected non-negative RTPengine "
			"integers, MOS 0..50 and packet loss 0..100 percent\n");
		update_stat(invalid_reports, 1);
		return -1;
	}

	if (!mos_rc) {
		incomplete = 1;
		mos_event = &unavailable;
	}
	if (!jitter_rc) {
		incomplete = 1;
		jitter_event = &unavailable;
	}
	if (!packetloss_rc) {
		incomplete = 1;
		packetloss_event = &unavailable;
	}
	if (!roundtrip_rc) {
		incomplete = 1;
		roundtrip_event = &unavailable;
	}

	update_stat(reports, 1);
	if (incomplete)
		update_stat(incomplete_reports, 1);
	if (final)
		update_stat(final_reports, 1);
	update_last_values(mos, jitter, packetloss, roundtrip);

	degraded = qoe_reason(mos, jitter, packetloss, roundtrip, &reason);
	if (degraded) {
		update_stat(degraded_reports, 1);
		raise_qoe_event(ev_bad, callid, mos_event, jitter_event,
			packetloss_event, roundtrip_event, &reason);
	}
	if (emit_updates && !final)
		raise_qoe_event(ev_update, callid, mos_event, jitter_event,
			packetloss_event, roundtrip_event, degraded ? &reason : NULL);
	if (final)
		raise_qoe_event(ev_final, callid, mos_event, jitter_event,
			packetloss_event, roundtrip_event, degraded ? &reason : NULL);

	return degraded ? 2 : 1;
}

static int w_qoe_report(struct sip_msg *msg, str *callid, str *mos,
	str *jitter, str *packetloss, str *roundtrip)
{
	return qoe_process(callid, mos, jitter, packetloss, roundtrip, 0);
}

static int w_qoe_final(struct sip_msg *msg, str *callid, str *mos,
	str *jitter, str *packetloss, str *roundtrip)
{
	return qoe_process(callid, mos, jitter, packetloss, roundtrip, 1);
}

#ifdef UNIT_TESTS
int media_qoe_test_sample_valid(long mos, long jitter, long packetloss,
	long roundtrip)
{
	return qoe_metrics_in_range(mos, jitter, packetloss, roundtrip);
}

int media_qoe_test_parse_metric(const char *text, long *out)
{
	str value = STR_NULL;

	if (text) {
		value.s = (char *)text;
		value.len = strlen(text);
	}
	return str_to_metric(text ? &value : NULL, out);
}

int media_qoe_test_reason(long mos, long jitter, long packetloss,
	long roundtrip, int test_min_mos, int test_max_jitter,
	int test_max_packetloss, int test_max_roundtrip)
{
	int old_min_mos = min_mos;
	int old_max_jitter = max_jitter;
	int old_max_packetloss = max_packetloss;
	int old_max_roundtrip = max_roundtrip;
	str reason = STR_NULL;
	int rc;

	min_mos = test_min_mos;
	max_jitter = test_max_jitter;
	max_packetloss = test_max_packetloss;
	max_roundtrip = test_max_roundtrip;

	rc = qoe_reason(mos, jitter, packetloss, roundtrip, &reason);

	min_mos = old_min_mos;
	max_jitter = old_max_jitter;
	max_packetloss = old_max_packetloss;
	max_roundtrip = old_max_roundtrip;

	if (!rc)
		return 0;
	if (reason.len == 3 && !memcmp(reason.s, "mos", 3))
		return 1;
	if (reason.len == 6 && !memcmp(reason.s, "jitter", 6))
		return 2;
	if (reason.len == 10 && !memcmp(reason.s, "packetloss", 10))
		return 3;
	if (reason.len == 9 && !memcmp(reason.s, "roundtrip", 9))
		return 4;
	return -1;
}
#endif

static int mod_init(void)
{
	if (min_mos > 50) {
		LM_ERR("min_mos must use RTPengine MOS units (0..50), or a negative value to disable\n");
		return -1;
	}
	if (max_packetloss > 100) {
		LM_ERR("max_packetloss must be 0..100 percent, or a negative value to disable\n");
		return -1;
	}

	last_values = shm_malloc(sizeof(*last_values));
	if (!last_values) {
		LM_ERR("no shared memory for media QoE snapshot\n");
		return -1;
	}
	memset(last_values, 0, sizeof(*last_values));

	last_values_lock = lock_alloc();
	if (!last_values_lock || !lock_init(last_values_lock)) {
		LM_ERR("failed to initialize media QoE snapshot lock\n");
		if (last_values_lock)
			lock_dealloc(last_values_lock);
		last_values_lock = NULL;
		shm_free(last_values);
		last_values = NULL;
		return -1;
	}

	ev_update = evi_publish_event(ev_update_name);
	ev_bad = evi_publish_event(ev_bad_name);
	ev_final = evi_publish_event(ev_final_name);
	if (ev_update == EVI_ERROR || ev_bad == EVI_ERROR || ev_final == EVI_ERROR) {
		LM_ERR("failed to publish media QoE events\n");
		mod_destroy();
		return -1;
	}
	return 0;
}

static void mod_destroy(void)
{
	if (last_values_lock) {
		lock_destroy(last_values_lock);
		lock_dealloc(last_values_lock);
		last_values_lock = NULL;
	}
	if (last_values) {
		shm_free(last_values);
		last_values = NULL;
	}
}
