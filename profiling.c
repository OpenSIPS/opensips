/*
 * Profiling hooks for external instrumentation
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

#include "profiling.h"
#include "dprint.h"
#include "evi/evi_modules.h"
#include "evi/evi_params.h"
#include "parser/msg_parser.h"
#include "pt.h"
#include <string.h>
#include <time.h>

profiling_handlers_t *profiling_handlers;

typedef struct profiling_event_handle {
	event_id_t id;
	evi_params_p params;
	evi_param_p timestamp_p;
	evi_param_p session_p;
	evi_param_p verb_p;
	evi_param_p name_p;
	evi_param_p type_p;
	evi_param_p depth_p;
	evi_param_p file_p;
	evi_param_p line_p;
	evi_param_p status_p;
} profiling_event_handle_t;

static str ev_name_script = str_init("E_PROFILING_SCRIPT");
static str ev_name_proc = str_init("E_PROFILING_PROC");
static str ev_param_timestamp = str_init("timestamp");
static str ev_param_session = str_init("session");
static str ev_param_verb = str_init("verb");
static str ev_param_name = str_init("name");
static str ev_param_type = str_init("type");
static str ev_param_depth = str_init("depth");
static str ev_param_file = str_init("file");
static str ev_param_line = str_init("line");
static str ev_param_status = str_init("status");

static profiling_event_handle_t profiling_events[2];

static int profiling_data_type_to_idx(int data_type)
{
	switch (data_type) {
	case PROFILING_DATA_TYPE_SCRIPT:
		return 0;
	case PROFILING_DATA_TYPE_PROC:
		return 1;
	default:
		return -1;
	}
}

static int init_profiling_event(profiling_event_handle_t *ev, str *ev_name)
{
	ev->id = evi_publish_event(*ev_name);
	if (ev->id == EVI_ERROR) {
		LM_ERR("cannot register '%.*s' event\n", ev_name->len, ev_name->s);
		return -1;
	}

	ev->params = evi_get_params();
	if (!ev->params) {
		LM_ERR("cannot create params for '%.*s'\n", ev_name->len, ev_name->s);
		return -1;
	}
	ev->params->flags &= ~EVI_FREE_LIST;

	ev->timestamp_p = evi_param_create(ev->params, &ev_param_timestamp);
	ev->session_p = evi_param_create(ev->params, &ev_param_session);
	ev->verb_p = evi_param_create(ev->params, &ev_param_verb);
	ev->name_p = evi_param_create(ev->params, &ev_param_name);
	ev->type_p = evi_param_create(ev->params, &ev_param_type);
	ev->depth_p = evi_param_create(ev->params, &ev_param_depth);
	ev->file_p = evi_param_create(ev->params, &ev_param_file);
	ev->line_p = evi_param_create(ev->params, &ev_param_line);
	ev->status_p = evi_param_create(ev->params, &ev_param_status);
	if (!ev->timestamp_p || !ev->session_p || !ev->verb_p || !ev->name_p ||
		!ev->type_p || !ev->depth_p ||
		!ev->file_p || !ev->line_p || !ev->status_p) {
		LM_ERR("cannot create params for '%.*s'\n", ev_name->len, ev_name->s);
		return -1;
	}

	return 0;
}

static inline void profiling_raise_event(int data_type, char *verb,
	const char *name, int type, int depth, const char *file, int line,
	int status, void *payload)
{
	int idx;
	profiling_event_handle_t *ev;
	int timestamp;
	int session = 0;
	struct sip_msg *msg;
	str verb_s, name_s, file_s;

	idx = profiling_data_type_to_idx(data_type);
	if (idx < 0)
		return;

	ev = &profiling_events[idx];
	if (ev->id == EVI_ERROR || !ev->params)
		return;

	if (!evi_probe_event(ev->id))
		return;

	if (!name)
		name = "<root>";
	if (!verb)
		verb = "";

	verb_s.s = verb;
	verb_s.len = strlen(verb);
	timestamp = (int)time(NULL);
	switch (data_type) {
	case PROFILING_DATA_TYPE_SCRIPT:
		msg = (struct sip_msg *)payload;
		if (msg && msg != FAKED_REPLY)
			session = (int)msg->id;
		break;
	case PROFILING_DATA_TYPE_PROC:
		session = my_pid();
		break;
	}
	name_s.s = (char *)name;
	name_s.len = strlen(name);
	if (file) {
		file_s.s = (char *)file;
		file_s.len = strlen(file);
	}

	if (evi_param_set_int(ev->timestamp_p, &timestamp) < 0 ||
		evi_param_set_int(ev->session_p, &session) < 0 ||
		evi_param_set_str(ev->verb_p, &verb_s) < 0 ||
		evi_param_set_str(ev->name_p, &name_s) < 0 ||
		evi_param_set_int(ev->type_p, &type) < 0 ||
		evi_param_set_int(ev->depth_p, &depth) < 0 ) {
		LM_ERR("cannot populate profiling event params 1\n");
		return;
	}

	if (file &&
		(evi_param_set_str(ev->file_p, &file_s) < 0 ||
		evi_param_set_int(ev->line_p, &line) < 0 )) {
		LM_ERR("cannot populate profiling event params 2\n");
		return;
	}

	if (status>=0 &&
		(evi_param_set_int(ev->status_p, &status) < 0)) {
		LM_ERR("cannot populate profiling event params 3\n");
		return;
	}

	if (evi_raise_event(ev->id, ev->params) < 0)
		LM_ERR("cannot raise profiling event\n");
}

static void profiling_event_on_start(int data_type, const char *name,
	int subtype, int depth, void *payload)
{
	profiling_raise_event(data_type, "start", name, subtype, depth, NULL, 0,
		-1, payload);
}

static void profiling_event_on_end(int data_type, const char *name,
	int subtype, int depth, int status, void *payload)
{
	profiling_raise_event(data_type, "end", name, subtype, depth, NULL, 0,
		status, payload);
}

static void profiling_event_on_enter(int data_type, const char *name,
	int subtype, int depth, const char *file, int line, void *payload)
{
	profiling_raise_event(data_type, "enter", name, subtype, depth, file,
		line, -1, payload);
}

static void profiling_event_on_exit(int data_type, const char *name,
	int subtype, int depth, const char *file, int line, int status,
	void *payload)
{
	profiling_raise_event(data_type, "exit", name, subtype, depth, file, line,
		status, payload);
}

static profiling_handlers_t profiling_event_handler = {
	.name = "event",
	.accepted_data_types = PROFILING_DATA_TYPE_SCRIPT |
		PROFILING_DATA_TYPE_PROC,
	.next = NULL,
	.on_start = profiling_event_on_start,
	.on_end = profiling_event_on_end,
	.on_enter = profiling_event_on_enter,
	.on_exit = profiling_event_on_exit,
	.get_ctx = NULL,
	.set_ctx = NULL,
};

int init_profiling(void)
{
	memset(profiling_events, 0, sizeof(profiling_events));
	profiling_events[0].id = EVI_ERROR;
	profiling_events[1].id = EVI_ERROR;

	if (init_profiling_event(&profiling_events[0], &ev_name_script) < 0)
		return -1;
	if (init_profiling_event(&profiling_events[1], &ev_name_proc) < 0)
		return -1;

	if (register_profiling_handler(&profiling_event_handler) < 0) {
		LM_ERR("failed to register profiling event handler\n");
		return -1;
	}

	return 0;
}

int register_profiling_handler(profiling_handlers_t *handlers)
{
	profiling_handlers_t *it;

	if (!handlers)
		return -1;

	for (it = profiling_handlers; it; it = it->next) {
		if (it == handlers)
			return 0;
	}

	handlers->next = profiling_handlers;
	profiling_handlers = handlers;
	return 0;
}

void unregister_profiling_handler(profiling_handlers_t *handlers)
{
	profiling_handlers_t **it;

	for (it = &profiling_handlers; *it; it = &(*it)->next) {
		if (*it == handlers) {
			*it = handlers->next;
			handlers->next = NULL;
			return;
		}
	}
}
