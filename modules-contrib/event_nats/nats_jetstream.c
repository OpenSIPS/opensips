/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

/*
 * nats_jetstream.c — JetStream Management MI Commands
 *
 * Implements MI commands for managing JetStream streams, consumers,
 * messages, and querying account info. All commands use the shared
 * connection pool from modules-contrib/nats via nats_pool_get_js().
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <nats/nats.h>

#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../mi/mi.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_validate.h"
#include "nats_jetstream.h"

/* Named JetStream API error codes (jsErrCode), replacing the raw literals
 * that were scattered through the MI handlers below.  Values are from the
 * NATS server API error registry. */
#define JS_ERR_STREAM_NOT_FOUND     10059  /* JSStreamNotFoundErr */
#define JS_ERR_CONSUMER_NOT_FOUND   10014  /* JSConsumerNotFoundErr */
#define JS_ERR_MSG_NOT_FOUND        10037  /* JSNoMessageFoundErr */

/* Helper: get JetStream context, return MI error if unavailable */
static jsCtx *get_js(void)
{
	jsCtx *js = nats_pool_get_js();
	if (!js)
		LM_ERR("JetStream context not available\n");
	return js;
}

/* Helper: parse retention string to enum */
static jsRetentionPolicy parse_retention(const char *s, int len)
{
	if (len == 8 && strncasecmp(s, "interest", 8) == 0)
		return js_InterestPolicy;
	if (len == 9 && strncasecmp(s, "workqueue", 9) == 0)
		return js_WorkQueuePolicy;
	return js_LimitsPolicy; /* default */
}

/* Helper: parse storage string to enum */
static jsStorageType parse_storage(const char *s, int len)
{
	if (len == 6 && strncasecmp(s, "memory", 6) == 0)
		return js_MemoryStorage;
	return js_FileStorage; /* default */
}

/* Cluster replication ceiling. JetStream supports R=1..5. */
#define NATS_MAX_REPLICAS      5
/* MaxAge is stored in nanoseconds as int64; cap input seconds to avoid overflow. */
#define NATS_MAX_AGE_SECONDS   (10LL * 365 * 24 * 60 * 60)  /* 10 years */
/* Hard cap for user-facing subject listing. Must match subj_ptrs capacity below. */
#define NATS_STREAM_SUBJECT_CAP 32

/* Validate a NATS identifier (stream or consumer name): single token, no
 * dots/wildcards/path chars/whitespace/control.  Thin wrapper over the shared
 * modules-contrib/nats validator. */
static int valid_nats_name(const char *s, int len)
{
	return nats_validate(s, len, NATS_VALIDATE_STREAM_NAME);
}

/* Validate a NATS subscribe-filter subject: dots and wildcards ('*','>')
 * allowed; control/whitespace/empty rejected.  Thin wrapper. */
static int valid_nats_subject(const char *s, int len)
{
	return nats_validate(s, len, NATS_VALIDATE_FILTER_SUBJECT);
}

/* ── nats_account_info ──────────────────────────────────────── */

mi_response_t *mi_nats_account_info(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsAccountInfo *ai = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj, *api_obj, *limits_obj;

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = nats_dl.js_GetAccountInfo(&ai, js, NULL, &jerr);
	if (s != NATS_OK || !ai) {
		LM_ERR("js_GetAccountInfo failed: %s (jerr=%d)\n",
			nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("GetAccountInfo failed"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) goto cleanup;

	if (add_mi_number(resp_obj, MI_SSTR("memory"), (double)ai->Memory) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("storage"), (double)ai->Store) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("streams"), (double)ai->Streams) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("consumers"), (double)ai->Consumers) < 0)
		goto error;

	/* API stats */
	api_obj = add_mi_object(resp_obj, MI_SSTR("api"));
	if (!api_obj) goto error;
	if (add_mi_number(api_obj, MI_SSTR("total"), (double)ai->API.Total) < 0)
		goto error;
	if (add_mi_number(api_obj, MI_SSTR("errors"), (double)ai->API.Errors) < 0)
		goto error;

	/* Limits */
	limits_obj = add_mi_object(resp_obj, MI_SSTR("limits"));
	if (!limits_obj) goto error;
	if (add_mi_number(limits_obj, MI_SSTR("max_memory"),
			(double)ai->Limits.MaxMemory) < 0)
		goto error;
	if (add_mi_number(limits_obj, MI_SSTR("max_storage"),
			(double)ai->Limits.MaxStore) < 0)
		goto error;
	if (add_mi_number(limits_obj, MI_SSTR("max_streams"),
			(double)ai->Limits.MaxStreams) < 0)
		goto error;
	if (add_mi_number(limits_obj, MI_SSTR("max_consumers"),
			(double)ai->Limits.MaxConsumers) < 0)
		goto error;

	nats_dl.jsAccountInfo_Destroy(ai);
	return resp;

error:
	free_mi_response(resp);
cleanup:
	if (ai) nats_dl.jsAccountInfo_Destroy(ai);
	return NULL;
}

/* The read-only observability handlers were removed: cachedb_nats
 * owns the stream list/info MI commands (richer variants with
 * filter/pagination/format support), and defining the same global
 * handler symbols in two co-loaded modules was an ODR hazard.
 * Only the mutating admin handlers remain here. */

/* ── nats_stream_create ─────────────────────────────────────── */

mi_response_t *mi_nats_stream_create(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsStreamInfo *si = NULL;
	jsStreamConfig cfg;
	jsErrCode jerr;
	natsStatus s;
	char *name, *subjects_str;
	int name_len, subjects_len;
	char name_buf[256], subj_buf[1024];
	int replicas_int = 0;
	char *retention_str = NULL, *storage_str = NULL;
	int retention_len = 0, storage_len = 0;

	if (try_get_mi_string_param(params, "name", &name, &name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'name' parameter"));
	if (try_get_mi_string_param(params, "subjects",
			&subjects_str, &subjects_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'subjects' parameter"));

	if (name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("name too long"));
	if (valid_nats_name(name, name_len) < 0)
		return init_mi_error(400,
			MI_SSTR("invalid stream name (empty, wildcard, dot, or control char)"));
	memcpy(name_buf, name, name_len);
	name_buf[name_len] = '\0';

	if (subjects_len >= (int)sizeof(subj_buf))
		return init_mi_error(400, MI_SSTR("subjects too long"));
	memcpy(subj_buf, subjects_str, subjects_len);
	subj_buf[subjects_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	nats_dl.jsStreamConfig_Init(&cfg);
	cfg.Name = name_buf;

	/* Parse comma-separated subjects. Silent truncation on more than
	 * NATS_STREAM_SUBJECT_CAP tokens would be a data-loss bug, so we
	 * reject instead. Each token is validated individually. */
	const char *subj_ptrs[NATS_STREAM_SUBJECT_CAP];
	int subj_count = 0;
	{
		char *p = subj_buf, *tok_start;
		while (*p) {
			while (*p == ' ' || *p == ',') p++;
			if (!*p) break;
			if (subj_count >= NATS_STREAM_SUBJECT_CAP)
				return init_mi_error(400,
					MI_SSTR("too many subjects (max 32)"));
			tok_start = p;
			while (*p && *p != ',') p++;
			if (valid_nats_subject(tok_start, (int)(p - tok_start)) < 0)
				return init_mi_error(400,
					MI_SSTR("invalid subject token (whitespace or control char)"));
			subj_ptrs[subj_count++] = tok_start;
			if (*p == ',') *p++ = '\0';
		}
	}
	if (subj_count == 0)
		return init_mi_error(400, MI_SSTR("subjects cannot be empty"));
	cfg.Subjects = subj_ptrs;
	cfg.SubjectsLen = subj_count;

	/* Optional params */
	if (try_get_mi_int_param(params, "replicas", &replicas_int) == 0) {
		if (replicas_int < 1 || replicas_int > NATS_MAX_REPLICAS)
			return init_mi_error(400,
				MI_SSTR("replicas must be between 1 and 5"));
		cfg.Replicas = replicas_int;
	}
	if (try_get_mi_string_param(params, "retention",
			&retention_str, &retention_len) == 0)
		cfg.Retention = parse_retention(retention_str, retention_len);
	if (try_get_mi_string_param(params, "storage",
			&storage_str, &storage_len) == 0)
		cfg.Storage = parse_storage(storage_str, storage_len);

	/* Optional numeric params. Values are int on the wire; -1 is the NATS
	 * sentinel for "unlimited" on msgs/bytes but not age. max_age in seconds
	 * is bounded to avoid int64 overflow when multiplied by 1e9 ns. */
	{
		int val;
		if (try_get_mi_int_param(params, "max_msgs", &val) == 0) {
			if (val < -1)
				return init_mi_error(400,
					MI_SSTR("max_msgs must be >= -1"));
			cfg.MaxMsgs = (int64_t)val;
		}
		if (try_get_mi_int_param(params, "max_bytes", &val) == 0) {
			if (val < -1)
				return init_mi_error(400,
					MI_SSTR("max_bytes must be >= -1"));
			cfg.MaxBytes = (int64_t)val;
		}
		if (try_get_mi_int_param(params, "max_age", &val) == 0) {
			if (val < 0 || (int64_t)val > NATS_MAX_AGE_SECONDS)
				return init_mi_error(400,
					MI_SSTR("max_age seconds out of range (0..10y)"));
			cfg.MaxAge = (int64_t)val * 1000000000LL; /* seconds → nanoseconds */
		}
	}

	s = nats_dl.js_AddStream(&si, js, &cfg, NULL, &jerr);
	if (s != NATS_OK) {
		LM_ERR("nats_dl.js_AddStream(%s) failed: %s (jerr=%d)\n",
			name_buf, nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("AddStream failed"));
	}

	mi_response_t *resp;
	mi_item_t *resp_obj;
	resp = init_mi_result_object(&resp_obj);
	if (!resp) { nats_dl.jsStreamInfo_Destroy(si); return NULL; }

	if (add_mi_string(resp_obj, MI_SSTR("status"),
			MI_SSTR("created")) < 0 ||
		add_mi_string(resp_obj, MI_SSTR("name"),
			name_buf, strlen(name_buf)) < 0) {
		free_mi_response(resp);
		nats_dl.jsStreamInfo_Destroy(si);
		return NULL;
	}

	nats_dl.jsStreamInfo_Destroy(si);
	return resp;
}

/* ── nats_stream_delete ─────────────────────────────────────── */

mi_response_t *mi_nats_stream_delete(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name;
	int stream_name_len;
	char name_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	if (valid_nats_name(stream_name, stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid stream name"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = nats_dl.js_DeleteStream(js, name_buf, NULL, &jerr);
	if (s != NATS_OK) {
		if (jerr == JS_ERR_STREAM_NOT_FOUND)
			return init_mi_error(404, MI_SSTR("stream not found"));
		LM_ERR("nats_dl.js_DeleteStream(%s) failed: %s (jerr=%d)\n",
			name_buf, nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("DeleteStream failed"));
	}

	return init_mi_result_ok();
}

/* ── nats_stream_purge ──────────────────────────────────────── */

mi_response_t *mi_nats_stream_purge(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name;
	int stream_name_len;
	char name_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	if (valid_nats_name(stream_name, stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid stream name"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = nats_dl.js_PurgeStream(js, name_buf, NULL, &jerr);
	if (s != NATS_OK) {
		if (jerr == JS_ERR_STREAM_NOT_FOUND)
			return init_mi_error(404, MI_SSTR("stream not found"));
		LM_ERR("nats_dl.js_PurgeStream(%s) failed: %s (jerr=%d)\n",
			name_buf, nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("PurgeStream failed"));
	}

	return init_mi_result_ok();
}

/* ── nats_consumer_list ─────────────────────────────────────── */

mi_response_t *mi_nats_consumer_list(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsConsumerInfoList *list = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj, *arr, *item;
	char *stream_name;
	int stream_name_len;
	char name_buf[256];
	int i;

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	if (valid_nats_name(stream_name, stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid stream name"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	/* Verify stream exists first (js_Consumers returns NATS_NOT_FOUND
	 * for both missing streams and empty consumer lists) */
	{
		jsStreamInfo *_si = NULL;
		jsErrCode _je;
		natsStatus _ss = nats_dl.js_GetStreamInfo(&_si, js, name_buf, NULL, &_je);
		if (_si) nats_dl.jsStreamInfo_Destroy(_si);
		if (_ss != NATS_OK)
			return init_mi_error(404, MI_SSTR("stream not found"));
	}

	s = nats_dl.js_Consumers(&list, js, name_buf, NULL, &jerr);
	if (s != NATS_OK || !list) {
		/* Stream exists but has no consumers — return empty list */
		if (s == NATS_NOT_FOUND || (list && list->Count == 0)) {
			mi_response_t *r;
			mi_item_t *ro;
			r = init_mi_result_object(&ro);
			if (!r) return NULL;
			if (add_mi_number(ro, MI_SSTR("count"), 0) < 0 ||
				!add_mi_array(ro, MI_SSTR("consumers"))) {
				free_mi_response(r);
				return NULL;
			}
			if (list) nats_dl.jsConsumerInfoList_Destroy(list);
			return r;
		}
		LM_ERR("nats_dl.js_Consumers(%s) failed: %s (jerr=%d)\n",
			name_buf, nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("Consumers list failed"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) goto cleanup;

	if (add_mi_number(resp_obj, MI_SSTR("count"), (double)list->Count) < 0)
		goto error;

	arr = add_mi_array(resp_obj, MI_SSTR("consumers"));
	if (!arr) goto error;

	for (i = 0; i < list->Count; i++) {
		jsConsumerInfo *ci = list->List[i];
		if (!ci) continue;

		item = add_mi_object(arr, NULL, 0);
		if (!item) goto error;

		if (ci->Name &&
			add_mi_string(item, MI_SSTR("name"),
				ci->Name, strlen(ci->Name)) < 0)
			goto error;
		if (add_mi_number(item, MI_SSTR("num_pending"),
				(double)ci->NumPending) < 0)
			goto error;
		if (add_mi_number(item, MI_SSTR("num_ack_pending"),
				(double)ci->NumAckPending) < 0)
			goto error;
	}

	nats_dl.jsConsumerInfoList_Destroy(list);
	return resp;

error:
	free_mi_response(resp);
cleanup:
	if (list) nats_dl.jsConsumerInfoList_Destroy(list);
	return NULL;
}

/* ── nats_consumer_info ─────────────────────────────────────── */

mi_response_t *mi_nats_consumer_info(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsConsumerInfo *ci = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj, *cfg_obj, *del_obj, *ack_obj;
	char *stream_name, *consumer_name;
	int stream_name_len, consumer_name_len;
	char stream_buf[256], consumer_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	if (try_get_mi_string_param(params, "consumer",
			&consumer_name, &consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'consumer' parameter"));

	if (stream_name_len >= (int)sizeof(stream_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	if (valid_nats_name(stream_name, stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid stream name"));
	memcpy(stream_buf, stream_name, stream_name_len);
	stream_buf[stream_name_len] = '\0';

	if (consumer_name_len >= (int)sizeof(consumer_buf))
		return init_mi_error(400, MI_SSTR("consumer name too long"));
	if (valid_nats_name(consumer_name, consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid consumer name"));
	memcpy(consumer_buf, consumer_name, consumer_name_len);
	consumer_buf[consumer_name_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = nats_dl.js_GetConsumerInfo(&ci, js, stream_buf, consumer_buf, NULL, &jerr);
	if (s != NATS_OK || !ci) {
		if (jerr == JS_ERR_CONSUMER_NOT_FOUND || jerr == JS_ERR_STREAM_NOT_FOUND)
			return init_mi_error(404, MI_SSTR("consumer not found"));
		LM_ERR("nats_dl.js_GetConsumerInfo(%s/%s) failed: %s (jerr=%d)\n",
			stream_buf, consumer_buf, nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("GetConsumerInfo failed"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) goto cleanup;

	if (ci->Stream &&
		add_mi_string(resp_obj, MI_SSTR("stream"),
			ci->Stream, strlen(ci->Stream)) < 0)
		goto error;
	if (ci->Name &&
		add_mi_string(resp_obj, MI_SSTR("name"),
			ci->Name, strlen(ci->Name)) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("num_pending"),
			(double)ci->NumPending) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("num_ack_pending"),
			(double)ci->NumAckPending) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("num_redelivered"),
			(double)ci->NumRedelivered) < 0)
		goto error;
	if (add_mi_number(resp_obj, MI_SSTR("num_waiting"),
			(double)ci->NumWaiting) < 0)
		goto error;

	/* Config subset */
	if (ci->Config) {
		cfg_obj = add_mi_object(resp_obj, MI_SSTR("config"));
		if (!cfg_obj) goto error;
		{
			const char *dp;
			switch (ci->Config->DeliverPolicy) {
			case js_DeliverAll:       dp = "all"; break;
			case js_DeliverLast:      dp = "last"; break;
			case js_DeliverNew:       dp = "new"; break;
			case js_DeliverByStartSequence: dp = "by_start_sequence"; break;
			case js_DeliverByStartTime:     dp = "by_start_time"; break;
			case js_DeliverLastPerSubject:   dp = "last_per_subject"; break;
			default: dp = "unknown";
			}
			if (add_mi_string(cfg_obj, MI_SSTR("deliver_policy"),
					dp, strlen(dp)) < 0)
				goto error;
		}
		{
			const char *ap;
			switch (ci->Config->AckPolicy) {
			case js_AckExplicit: ap = "explicit"; break;
			case js_AckNone:     ap = "none"; break;
			case js_AckAll:      ap = "all"; break;
			default: ap = "unknown";
			}
			if (add_mi_string(cfg_obj, MI_SSTR("ack_policy"),
					ap, strlen(ap)) < 0)
				goto error;
		}
	}

	/* Delivered / AckFloor */
	del_obj = add_mi_object(resp_obj, MI_SSTR("delivered"));
	if (!del_obj) goto error;
	if (add_mi_number(del_obj, MI_SSTR("consumer"),
			(double)ci->Delivered.Consumer) < 0)
		goto error;
	if (add_mi_number(del_obj, MI_SSTR("stream"),
			(double)ci->Delivered.Stream) < 0)
		goto error;

	ack_obj = add_mi_object(resp_obj, MI_SSTR("ack_floor"));
	if (!ack_obj) goto error;
	if (add_mi_number(ack_obj, MI_SSTR("consumer"),
			(double)ci->AckFloor.Consumer) < 0)
		goto error;
	if (add_mi_number(ack_obj, MI_SSTR("stream"),
			(double)ci->AckFloor.Stream) < 0)
		goto error;

	nats_dl.jsConsumerInfo_Destroy(ci);
	return resp;

error:
	free_mi_response(resp);
cleanup:
	if (ci) nats_dl.jsConsumerInfo_Destroy(ci);
	return NULL;
}

/* ── nats_consumer_create ───────────────────────────────────── */

mi_response_t *mi_nats_consumer_create(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsConsumerInfo *ci = NULL;
	jsConsumerConfig cfg;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name, *consumer_name;
	int stream_name_len, consumer_name_len;
	char stream_buf[256], consumer_buf[256];
	char *filter_subject = NULL;
	int filter_subject_len = 0;
	char filter_buf[512];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	if (try_get_mi_string_param(params, "name",
			&consumer_name, &consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'name' parameter"));

	if (stream_name_len >= (int)sizeof(stream_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	if (valid_nats_name(stream_name, stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid stream name"));
	memcpy(stream_buf, stream_name, stream_name_len);
	stream_buf[stream_name_len] = '\0';

	if (consumer_name_len >= (int)sizeof(consumer_buf))
		return init_mi_error(400, MI_SSTR("consumer name too long"));
	if (valid_nats_name(consumer_name, consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid consumer name"));
	memcpy(consumer_buf, consumer_name, consumer_name_len);
	consumer_buf[consumer_name_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	nats_dl.jsConsumerConfig_Init(&cfg);
	cfg.Durable = consumer_buf;
	cfg.Name = consumer_buf;

	/* Optional filter_subject */
	if (try_get_mi_string_param(params, "filter_subject",
			&filter_subject, &filter_subject_len) == 0) {
		if (filter_subject_len >= (int)sizeof(filter_buf))
			return init_mi_error(400, MI_SSTR("filter_subject too long"));
		if (valid_nats_subject(filter_subject, filter_subject_len) < 0)
			return init_mi_error(400,
				MI_SSTR("invalid filter_subject (whitespace or control char)"));
		memcpy(filter_buf, filter_subject, filter_subject_len);
		filter_buf[filter_subject_len] = '\0';
		cfg.FilterSubject = filter_buf;
	}

	/* Optional deliver_policy */
	{
		char *dp_str = NULL;
		int dp_len = 0;
		if (try_get_mi_string_param(params, "deliver_policy",
				&dp_str, &dp_len) == 0) {
			if (dp_len == 3 && strncasecmp(dp_str, "all", 3) == 0)
				cfg.DeliverPolicy = js_DeliverAll;
			else if (dp_len == 4 && strncasecmp(dp_str, "last", 4) == 0)
				cfg.DeliverPolicy = js_DeliverLast;
			else if (dp_len == 3 && strncasecmp(dp_str, "new", 3) == 0)
				cfg.DeliverPolicy = js_DeliverNew;
			else if (dp_len == 16 && strncasecmp(dp_str, "last_per_subject", 16) == 0)
				cfg.DeliverPolicy = js_DeliverLastPerSubject;
		}
	}

	/* Optional ack_policy */
	{
		char *ap_str = NULL;
		int ap_len = 0;
		if (try_get_mi_string_param(params, "ack_policy",
				&ap_str, &ap_len) == 0) {
			if (ap_len == 8 && strncasecmp(ap_str, "explicit", 8) == 0)
				cfg.AckPolicy = js_AckExplicit;
			else if (ap_len == 4 && strncasecmp(ap_str, "none", 4) == 0)
				cfg.AckPolicy = js_AckNone;
			else if (ap_len == 3 && strncasecmp(ap_str, "all", 3) == 0)
				cfg.AckPolicy = js_AckAll;
		}
	}

	s = nats_dl.js_AddConsumer(&ci, js, stream_buf, &cfg, NULL, &jerr);
	if (s != NATS_OK) {
		LM_ERR("nats_dl.js_AddConsumer(%s/%s) failed: %s (jerr=%d)\n",
			stream_buf, consumer_buf, nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("AddConsumer failed"));
	}

	mi_response_t *resp;
	mi_item_t *resp_obj;
	resp = init_mi_result_object(&resp_obj);
	if (!resp) { nats_dl.jsConsumerInfo_Destroy(ci); return NULL; }

	if (add_mi_string(resp_obj, MI_SSTR("status"),
			MI_SSTR("created")) < 0 ||
		add_mi_string(resp_obj, MI_SSTR("name"),
			consumer_buf, strlen(consumer_buf)) < 0) {
		free_mi_response(resp);
		nats_dl.jsConsumerInfo_Destroy(ci);
		return NULL;
	}

	nats_dl.jsConsumerInfo_Destroy(ci);
	return resp;
}

/* ── nats_consumer_delete ───────────────────────────────────── */

mi_response_t *mi_nats_consumer_delete(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name, *consumer_name;
	int stream_name_len, consumer_name_len;
	char stream_buf[256], consumer_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	if (try_get_mi_string_param(params, "consumer",
			&consumer_name, &consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'consumer' parameter"));

	if (stream_name_len >= (int)sizeof(stream_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	if (valid_nats_name(stream_name, stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid stream name"));
	memcpy(stream_buf, stream_name, stream_name_len);
	stream_buf[stream_name_len] = '\0';

	if (consumer_name_len >= (int)sizeof(consumer_buf))
		return init_mi_error(400, MI_SSTR("consumer name too long"));
	if (valid_nats_name(consumer_name, consumer_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid consumer name"));
	memcpy(consumer_buf, consumer_name, consumer_name_len);
	consumer_buf[consumer_name_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = nats_dl.js_DeleteConsumer(js, stream_buf, consumer_buf, NULL, &jerr);
	if (s != NATS_OK) {
		if (jerr == JS_ERR_CONSUMER_NOT_FOUND || jerr == JS_ERR_STREAM_NOT_FOUND)
			return init_mi_error(404, MI_SSTR("consumer not found"));
		LM_ERR("nats_dl.js_DeleteConsumer(%s/%s) failed: %s (jerr=%d)\n",
			stream_buf, consumer_buf, nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("DeleteConsumer failed"));
	}

	return init_mi_result_ok();
}

/* Parse the "seq" MI param as a full 64-bit stream sequence.  JetStream
 * sequences are uint64; try_get_mi_int_param would cap them at INT_MAX and
 * wrap a larger value.  Accept a JSON string ("5000000000") parsed with
 * strtoull for the full range, and keep the JSON-number int path for
 * back-compat (values <= INT_MAX).  Returns 0 with *out set (>=1), -1 if the
 * param is missing, -2 if present but not a positive integer. */
static int mi_get_seq_u64(const mi_params_t *params, uint64_t *out)
{
	char *s = NULL;
	int   slen = 0;

	if (try_get_mi_string_param((mi_params_t *)params, "seq", &s, &slen) == 0
			&& slen > 0) {
		char buf[24], *endp;
		unsigned long long v;
		if (slen >= (int)sizeof(buf))
			return -2;
		memcpy(buf, s, slen);
		buf[slen] = '\0';
		/* digits only: strtoull() takes a sign and leading blanks, and
		 * "-1" -- which is also what an MI integer -1 arrives as -- would
		 * come out as the largest sequence there is */
		if (buf[0] < '0' || buf[0] > '9')
			return -2;
		errno = 0;
		v = strtoull(buf, &endp, 10);
		if (endp == buf || *endp != '\0' || errno == ERANGE || v == 0)
			return -2;
		*out = (uint64_t)v;
		return 0;
	}
	{
		int si;
		if (try_get_mi_int_param((mi_params_t *)params, "seq", &si) < 0)
			return -1;
		if (si <= 0)
			return -2;
		*out = (uint64_t)si;
		return 0;
	}
}

/* ── nats_msg_get ───────────────────────────────────────────── */

mi_response_t *mi_nats_msg_get(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	natsMsg *msg = NULL;
	jsErrCode jerr;
	natsStatus s;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	char *stream_name;
	int stream_name_len;
	uint64_t seq;
	int seq_rc;
	char name_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	seq_rc = mi_get_seq_u64(params, &seq);
	if (seq_rc == -1)
		return init_mi_error(400, MI_SSTR("missing 'seq' parameter"));
	if (seq_rc == -2)
		return init_mi_error(400, MI_SSTR("seq must be a positive integer"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	if (valid_nats_name(stream_name, stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid stream name"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = nats_dl.js_GetMsg(&msg, js, name_buf, seq, NULL, &jerr);
	if (s != NATS_OK || !msg) {
		if (jerr == JS_ERR_MSG_NOT_FOUND || jerr == JS_ERR_STREAM_NOT_FOUND)
			return init_mi_error(404, MI_SSTR("message not found"));
		LM_ERR("nats_dl.js_GetMsg(%s, %llu) failed: %s (jerr=%d)\n",
			name_buf, (unsigned long long)seq,
			nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(404, MI_SSTR("message not found"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp) { nats_dl.natsMsg_Destroy(msg); return NULL; }

	{
		const char *subj = nats_dl.natsMsg_GetSubject(msg);
		if (subj && add_mi_string(resp_obj, MI_SSTR("subject"),
				subj, strlen(subj)) < 0)
			goto error;
	}
	{
		const char *data = nats_dl.natsMsg_GetData(msg);
		int data_len = nats_dl.natsMsg_GetDataLength(msg);
		if (data && add_mi_string(resp_obj, MI_SSTR("data"),
				data, data_len) < 0)
			goto error;
	}
	if (add_mi_number(resp_obj, MI_SSTR("sequence"), (double)seq) < 0)
		goto error;

	nats_dl.natsMsg_Destroy(msg);
	return resp;

error:
	free_mi_response(resp);
	nats_dl.natsMsg_Destroy(msg);
	return NULL;
}

/* ── nats_msg_delete ────────────────────────────────────────── */

mi_response_t *mi_nats_msg_delete(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	jsCtx *js;
	jsErrCode jerr;
	natsStatus s;
	char *stream_name;
	int stream_name_len;
	uint64_t seq;
	int seq_rc;
	char name_buf[256];

	if (try_get_mi_string_param(params, "stream",
			&stream_name, &stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("missing 'stream' parameter"));
	seq_rc = mi_get_seq_u64(params, &seq);
	if (seq_rc == -1)
		return init_mi_error(400, MI_SSTR("missing 'seq' parameter"));
	if (seq_rc == -2)
		return init_mi_error(400, MI_SSTR("seq must be a positive integer"));

	if (stream_name_len >= (int)sizeof(name_buf))
		return init_mi_error(400, MI_SSTR("stream name too long"));
	if (valid_nats_name(stream_name, stream_name_len) < 0)
		return init_mi_error(400, MI_SSTR("invalid stream name"));
	memcpy(name_buf, stream_name, stream_name_len);
	name_buf[stream_name_len] = '\0';

	js = get_js();
	if (!js)
		return init_mi_error(500, MI_SSTR("JetStream not available"));

	s = nats_dl.js_DeleteMsg(js, name_buf, seq, NULL, &jerr);
	if (s != NATS_OK) {
		if (jerr == JS_ERR_MSG_NOT_FOUND || jerr == JS_ERR_STREAM_NOT_FOUND)
			return init_mi_error(404, MI_SSTR("message not found"));
		LM_ERR("nats_dl.js_DeleteMsg(%s, %llu) failed: %s (jerr=%d)\n",
			name_buf, (unsigned long long)seq,
			nats_dl.natsStatus_GetText(s), (int)jerr);
		return init_mi_error(500, MI_SSTR("DeleteMsg failed"));
	}

	return init_mi_result_ok();
}
