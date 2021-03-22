/*
 * This file is part of OpenSIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * ---------
 */

#include <stdlib.h>

#include "../../globals.h"
#include "../../sr_module.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../lib/list.h"
#include "../httpd/httpd_load.h"

/* module functions */
static int mod_init();
int prom_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket);
static ssize_t prom_flush_data(void *cls, uint64_t pos, char *buf,
		size_t max);

enum prom_group_mode {
	PROM_GROUP_MODE_NONE=0,
	PROM_GROUP_MODE_NAME=1,
	PROM_GROUP_MODE_LABEL=2,
	PROM_GROUP_MODE_INVALID
};

int prom_grp_mode = PROM_GROUP_MODE_NONE;
str prom_http_root = str_init("metrics");
str prom_prefix = str_init("opensips");
str prom_grp_prefix = str_init("");
str prom_delimiter = str_init("_");
str prom_grp_label = str_init("group");
httpd_api_t prom_httpd_api;

static int prom_stats_param( modparam_t type, void* val);

/* module parameters */
static param_export_t mi_params[] = {
	{"root",        STR_PARAM, &prom_http_root.s},
	{"prefix",      STR_PARAM, &prom_prefix.s},
	{"delimiter",   STR_PARAM, &prom_delimiter.s},
	{"group_prefix",STR_PARAM, &prom_grp_prefix.s},
	{"group_label", STR_PARAM, &prom_grp_label.s},
	{"group_mode",  INT_PARAM, &prom_grp_mode},
	{"statistics",  STR_PARAM|USE_FUNC_PARAM, &prom_stats_param},
	{0,0,0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "httpd", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/* module exports */
struct module_exports exports = {
	"prometheus",				/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	&deps,						/* OpenSIPS module dependencies */
	NULL,						/* exported functions */
	NULL,						/* exported async functions */
	mi_params,					/* exported parameters */
	NULL,						/* exported statistics */
	NULL,						/* exported MI functions */
	NULL,						/* exported PV */
	NULL,						/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	(response_function) 0,		/* response handling function */
	(destroy_function)  0,		/* destroy function */
	NULL,						/* per-child init function */
	NULL						/* reload confirm function */
};

static OSIPS_LIST_HEAD(prom_stats);
static OSIPS_LIST_HEAD(prom_stat_mods);

struct prom_stat {
	str name;
	struct list_head list;
	union {
		module_stats *mod;
		stat_var **stat; /* shm pointer to the stat */
	};
	char name_s[0];
};

static int mod_init(void)
{
	struct list_head *it;
	struct prom_stat *s;

	prom_http_root.len = strlen(prom_http_root.s);
	prom_prefix.len = strlen(prom_prefix.s);
	prom_delimiter.len = strlen(prom_delimiter.s);
	prom_grp_prefix.len = strlen(prom_grp_prefix.s);
	prom_grp_label.len = strlen(prom_grp_label.s);

	if (prom_grp_mode < PROM_GROUP_MODE_NONE || prom_grp_mode >= PROM_GROUP_MODE_INVALID) {
		LM_ERR("invalid group mode %d\n", prom_grp_mode);
		return -1;
	}

	/* Load httpd api */
	if(load_httpd_api(&prom_httpd_api)<0) {
		LM_ERR("Failed to load httpd api\n");
		return -1;
	}

	/* try to resolve as many stats as possible now */
	list_for_each(it, &prom_stats) {
		s = list_entry(it, struct prom_stat, list);
		s->stat = shm_malloc(sizeof *s->stat);
		if (!s->stat) {
			LM_ERR("oom for stat!\n");
			return -1;
		}
		*s->stat = get_stat(&s->name);
		/* if we don't find it now, don't panic, we might find it later */
	}

	/* Load httpd hooks */
	prom_httpd_api.register_httpdcb(exports.name, &prom_http_root,
				&prom_answer_to_connection,
				&prom_flush_data,
				HTTPD_TEXT_PLAIN_PROMETHEUS_TYPE,
				NULL);

	return 0;
}


static ssize_t prom_flush_data(void *cls, uint64_t pos, char *buf,
																	size_t max)
{
	/* if no content for the response, just inform httpd */
	return -1;
}

#define MI_HTTP_OK_CODE				200
#define MI_HTTP_METHOD_ERR_CODE		405
#define MI_HTTP_INTERNAL_ERR_CODE	500

static inline int prom_push_stat(stat_var *stat, str *page, int max_len)
{
	str v;
	str *m = get_stat_module_name(stat);
	v.s = int2str(get_stat_val(stat), &v.len);
	int grp_len = 0;
	int name_len = prom_prefix.len + prom_delimiter.len + stat->name.len;

	switch (prom_grp_mode) {
	case PROM_GROUP_MODE_NONE:
		break;
	case PROM_GROUP_MODE_NAME:
		name_len += prom_grp_prefix.len + m->len + prom_delimiter.len;
		break;
	case PROM_GROUP_MODE_LABEL:
		grp_len = 1 /* '{' */ + prom_grp_label.len + 2 /* '="' */ +
			prom_grp_prefix.len +  m->len + 2 /* '"}' */;
		break;
	}
	if (page->len +
			7 /* '# TYPE ' */ +
			name_len +
			9 /* ' counter\n' */ +
			name_len +
			grp_len +
			1 /* ' ' */ +
			v.len +
			1 /* '\n' */ >= max_len)
		return -1;
	memcpy(page->s + page->len, "# TYPE ", 7);
	page->len += 7;
	memcpy(page->s + page->len, prom_prefix.s, prom_prefix.len);
	page->len += prom_prefix.len;
	memcpy(page->s + page->len, prom_delimiter.s, prom_delimiter.len);
	page->len += prom_delimiter.len;

	if (prom_grp_mode == PROM_GROUP_MODE_NAME) {
		memcpy(page->s + page->len, prom_grp_prefix.s, prom_grp_prefix.len);
		page->len += prom_grp_prefix.len;
		memcpy(page->s + page->len, m->s, m->len);
		page->len += m->len;
		memcpy(page->s + page->len, prom_delimiter.s, prom_delimiter.len);
		page->len += prom_delimiter.len;
	}

	memcpy(page->s + page->len, stat->name.s, stat->name.len);
	page->len += stat->name.len;

	if (stat->flags & (STAT_IS_FUNC|STAT_NO_RESET)) {
		memcpy(page->s + page->len, " gauge\n", 7);
		page->len += 7;
	} else {
		memcpy(page->s + page->len, " counter\n", 9);
		page->len += 9;
	}
	memcpy(page->s + page->len, prom_prefix.s, prom_prefix.len);
	page->len += prom_prefix.len;
	memcpy(page->s + page->len, prom_delimiter.s, prom_delimiter.len);
	page->len += prom_delimiter.len;

	if (prom_grp_mode == PROM_GROUP_MODE_NAME) {
		memcpy(page->s + page->len, prom_grp_prefix.s, prom_grp_prefix.len);
		page->len += prom_grp_prefix.len;
		memcpy(page->s + page->len, m->s, m->len);
		page->len += m->len;
		memcpy(page->s + page->len, prom_delimiter.s, prom_delimiter.len);
		page->len += prom_delimiter.len;
	}

	memcpy(page->s + page->len, stat->name.s, stat->name.len);
	page->len += stat->name.len;

	if (prom_grp_mode == PROM_GROUP_MODE_LABEL) {
		memcpy(page->s + page->len, "{", 1);
		page->len += 1;
		memcpy(page->s + page->len, prom_grp_label.s, prom_grp_label.len);
		page->len += prom_grp_label.len;

		memcpy(page->s + page->len, "=\"", 2);
		page->len += 2;

		memcpy(page->s + page->len, prom_grp_prefix.s, prom_grp_prefix.len);
		page->len += prom_grp_prefix.len;

		memcpy(page->s + page->len, m->s, m->len);
		page->len += m->len;

		memcpy(page->s + page->len, "\"} ", 3);
		page->len += 3;
	} else {
		memcpy(page->s + page->len, " ", 1);
		page->len += 1;
	}

	memcpy(page->s + page->len, v.s, v.len);
	page->len += v.len;
	memcpy(page->s + page->len, "\n", 1);
	page->len += 1;
	return 0;
}

#define PROM_PUSH_STAT(_s) \
	do { \
		if (prom_push_stat(_s, page, buffer->len) < 0) { \
			LM_ERR("out of memory for stats\n"); \
			return MI_HTTP_INTERNAL_ERR_CODE; \
		} \
	} while(0)

int prom_answer_to_connection (void *cls, void *connection,
	const char *url, const char *method,
	const char *version, const char *upload_data,
	size_t upload_data_size, void **con_cls,
	str *buffer, str *page, union sockaddr_union* cl_socket)
{
	struct list_head *it;
	struct prom_stat *s;
	stat_var *stat;

	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
			"version=%s, upload_data[%d]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			(int)upload_data_size, upload_data, *con_cls);

	page->s = NULL;
	page->len = 0;

	if (strncmp(method, "GET", 3)) {
		LM_ERR("unexpected http method [%s]\n", method);

		return MI_HTTP_METHOD_ERR_CODE;
	}

	page->s = buffer->s;
	page->len = 0;

	list_for_each(it, &prom_stat_mods) {
		s = list_entry(it, struct prom_stat, list);
		if (!s->mod) {
			s->mod = get_stat_module(&s->name);
			if (!s->mod) {
				LM_DBG("stat module %.*s not found\n", s->name.len, s->name.s);
				continue;
			}
		}
		/* TODO: should we lock here? */
		for (stat = s->mod->head; stat; stat = stat->lnext)
			PROM_PUSH_STAT(stat);
	}

	list_for_each(it, &prom_stats) {
		s = list_entry(it, struct prom_stat, list);
		if (*s->stat == NULL) {
			/* try to find the stat now */
			stat = get_stat(&s->name);
			if (!stat)
				continue;
			*s->stat = stat;
		}
		PROM_PUSH_STAT(*s->stat);
	}
	if (page->len + 1 >= buffer->len) {
		LM_ERR("out of memory for stats\n");
		return MI_HTTP_INTERNAL_ERR_CODE;
	}
	memcpy(page->s + page->len, "\n", 1);
	page->len++;

	return MI_HTTP_OK_CODE;
}
#undef PROM_PUSH_STAT

static int prom_stats_param( modparam_t type, void* val)
{
	str stats;
	str name;
	init_str(&stats, val);
	struct prom_stat *s;
	struct list_head *head;

	trim_leading(&stats);
	while (stats.len > 0) {
		name = stats;
		while (stats.len > 0 && !is_ws(*stats.s)) {
			stats.s++;
			stats.len--;
		}
		name.len = stats.s - name.s;
		trim_leading(&stats);

		if (name.s[name.len - 1] == ':') {
			name.len--;
			head = &prom_stat_mods;
			LM_INFO("Adding statistics module %.*s\n", name.len, name.s);
		} else {
			head = &prom_stats;
			LM_INFO("Adding statistic %.*s\n", name.len, name.s);
		}

		s = pkg_malloc(sizeof *s + name.len);
		if (!s) {
			LM_ERR("oom!\n");
			return -1;
		}
		s->name.len = name.len;
		s->name.s = s->name_s;
		memcpy(s->name.s, name.s, name.len);
		list_add(&s->list, head);
	}
	return 0;
}
