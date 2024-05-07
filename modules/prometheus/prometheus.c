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
#include "../../pt.h"
#include "../../re.h"
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

int prom_all_stats = 0;
int prom_grp_mode = PROM_GROUP_MODE_NONE;
str prom_http_root = str_init("metrics");
str prom_prefix = str_init("opensips");
str prom_grp_prefix = str_init("");
str prom_delimiter = str_init("_");
str prom_grp_label = str_init("group");
httpd_api_t prom_httpd_api;
str prometheus_script_route = {NULL, 0};
struct script_route_ref *prometheus_route_ref = NULL;
char* prometheus_avp_param = NULL;
unsigned short prometheus_avp_type = 0;
int prometheus_avp_name = -1;

static int prom_stats_param( modparam_t type, void* val);
static int prom_labels_param( modparam_t type, void* val);

/* module parameters */
static const param_export_t mi_params[] = {
	{"root",        STR_PARAM, &prom_http_root.s},
	{"prefix",      STR_PARAM, &prom_prefix.s},
	{"delimiter",   STR_PARAM, &prom_delimiter.s},
	{"group_prefix",STR_PARAM, &prom_grp_prefix.s},
	{"group_label", STR_PARAM, &prom_grp_label.s},
	{"group_mode",  INT_PARAM, &prom_grp_mode},
	{"statistics",  STR_PARAM|USE_FUNC_PARAM, &prom_stats_param},
	{"labels",      STR_PARAM|USE_FUNC_PARAM, &prom_labels_param},
	{"script_route", STR_PARAM, &prometheus_script_route}, 
	{"script_route_avp_result", STR_PARAM, &prometheus_avp_param}, 
	{0,0,0}
};

static const dep_export_t deps = {
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
static OSIPS_LIST_HEAD(prom_labels);

struct prom_stat {
	str name;
	struct list_head list;
	union {
		module_stats *mod;
		stat_var **stat; /* shm pointer to the stat */
	};
	char name_s[0];
};

struct prom_label {
	str module;
	struct list_head list;
	struct subst_expr *subst;
	char _buf[0];
};

static int mod_init(void)
{
	struct list_head *it;
	struct prom_stat *s;
	str avp_s;
	pv_spec_t avp_spec;

	prom_http_root.len = strlen(prom_http_root.s);
	prom_prefix.len = strlen(prom_prefix.s);
	prom_delimiter.len = strlen(prom_delimiter.s);
	prom_grp_prefix.len = strlen(prom_grp_prefix.s);
	prom_grp_label.len = strlen(prom_grp_label.s);

	if (prometheus_script_route.s) {
		prometheus_script_route.len = strlen(prometheus_script_route.s);

		prometheus_route_ref = ref_script_route_by_name(prometheus_script_route.s,
					sroutes->request, RT_NO , REQUEST_ROUTE, 0);
		if ( !ref_script_route_is_valid(prometheus_route_ref) ) {
			LM_ERR("Prometheus route <%s> not defined!\n", prometheus_script_route.s);
			return -1;
		}

		if (prometheus_avp_param && *prometheus_avp_param) {
			avp_s.s = prometheus_avp_param;
			avp_s.len = strlen(avp_s.s);
			if (pv_parse_spec(&avp_s, &avp_spec)==0
					|| avp_spec.type!=PVT_AVP) {
				LM_ERR("malformed or non AVP %s AVP definition\n", prometheus_avp_param);
				return -1;
			}

			if(pv_get_avp_name(0, &avp_spec.pvp, &prometheus_avp_name, &prometheus_avp_type)!=0)
			{
				LM_ERR("[%s]- invalid AVP definition\n", prometheus_avp_param);
				return -1;
			}
		} else {
			LM_ERR("Prometheus route <%s> defined but no AVP result set!\n", prometheus_script_route.s);
			return -1;
		}
	}	

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

struct prom_labels_stat {
	str labels;
	str *free_buf;
	stat_var *stat;
	struct list_head list;
};

struct prom_grp {
	group_stats *grp;
	struct list_head list;
	struct list_head stats;
};

struct prom_labels_grp {
	str name;
	struct list_head list;
	struct list_head stats;
	char _buf[0];
};

static void prom_groups_add(struct list_head *groups, group_stats *grp)
{
	struct prom_grp *pgrp = pkg_malloc(sizeof *pgrp);
	if (!pgrp)
		return;
	pgrp->grp = grp;
	list_add(&pgrp->list, groups);
}

static int prom_groups_exists(struct list_head *groups, group_stats *grp)
{
	struct list_head *it;
	list_for_each(it, groups)
		if (grp == list_entry(it, struct prom_grp, list)->grp)
			return 1;
	return 0;
}

static void prom_groups_free(struct list_head *groups,
		struct list_head *label_groups)
{
	struct list_head *it, *safe;
	struct list_head *it_stat, *safe_stat;
	struct prom_labels_grp *grp;
	struct prom_labels_stat *stat;

	list_for_each_safe(it, safe, groups)
		pkg_free(list_entry(it, struct prom_grp, list));
	list_for_each_safe(it, safe, label_groups) {
		grp = list_entry(it, struct prom_labels_grp, list);
		list_for_each_safe(it_stat, safe_stat, &grp->stats) {
			stat = list_entry(it_stat, struct prom_labels_stat, list);
			if (stat->free_buf->s)
				pkg_free(stat->free_buf->s);
			pkg_free(stat->free_buf);
			pkg_free(stat);
		}
		pkg_free(grp);
	}
}


#define MI_HTTP_OK_CODE				200
#define MI_HTTP_METHOD_ERR_CODE		405
#define MI_HTTP_INTERNAL_ERR_CODE	500

static void fill_stats_name(str *stat_name, str *page)
{
	/*
	 * the stat's name must adhere to the following regex:
	 * '[a-zA-Z_:][a-zA-Z0-9_:]*'
	 * Source: https://prometheus.io/docs/concepts/data_model/
	 *
	 * Replace all characters that are not allowed with '_'
	 */

	char *s, *e, *p = page->s + page->len;
	e = stat_name->s + stat_name->len;
	for (s = stat_name->s; s < e; s++) {
		if ((*s >= 'a' && *s <= 'z') ||
			(*s >= 'A' && *s <= 'Z') ||
			(*s >= '0' && *s <= '9') ||
			*s == '_' || *s == ':') {
			*p++ = *s;
		} else {
			*p++ = '_';
		}
	}
	page->len += stat_name->len;
}

static inline int prom_print_stat(stat_var *stat, str *stat_name,
		str *labels, str *page, int max_len, int *skip_type)
{
	str v, id;
	str *m = get_stat_module_name(stat);
	int label_len = 0, label_idx = 0;
	int name_len, type_len;
	str prefix = prom_prefix;

	if (stat->flags & STAT_HIDDEN)
		return 0;

	v.s = int2str(get_stat_val(stat), &v.len);

	/* if the first char of the stat is a number, and we have no prefix, we
	 * force the '_' to preserve the stat's grammar */
	if (prom_prefix.len == 0 && prom_delimiter.len == 0 &&
			prom_grp_mode == PROM_GROUP_MODE_NONE &&
			stat_name->s[0] >= '0' && stat_name->s[0] <= '9') {
		prefix.s = "_";
		prefix.len = 1;
	}
	name_len = prefix.len + prom_delimiter.len + stat_name->len;
	if (labels) {
		label_len = labels->len + 1;
		label_idx++;
	}

	switch (prom_grp_mode) {
	case PROM_GROUP_MODE_NONE:
		break;
	case PROM_GROUP_MODE_NAME:
		name_len += prom_grp_prefix.len + m->len + prom_delimiter.len;
		break;
	case PROM_GROUP_MODE_LABEL:
		label_len += prom_grp_label.len + 2 /* '="' */ +
			prom_grp_prefix.len +  m->len + 1 /* '"' */;
		label_idx++;
		break;
	}
	if (stat->flags & STAT_HAS_GROUP) {
		/* dump the id in the group */
		label_len += 4 /* 'id="' */ + INT2STR_MAX_LEN + 1 /* '"' */;
		label_idx++;
	}

	if (stat->flags & STAT_PER_PROC) {
		/* dump the pid in the group */
		label_len += 5 /* 'pid="' */ + INT2STR_MAX_LEN + 1 /* '"' */;
		label_idx++;
		label_len += 6 /* 'desc="' */ + MAX_PT_DESC + 1 /* '"' */;
		label_idx++;
	}

	type_len = ((!skip_type || *skip_type == 0)? \
			7 /* '# TYPE ' */ +
			name_len +
			9 /* ' counter\n' */ : 0);
	if (label_idx)
		label_len += 2 /* '{' and '}' */ + label_idx - 1 /* ',' */;

	if (page->len +
			type_len +
			name_len +
			label_len +
			1 /* ' ' */ +
			v.len +
			1 /* '\n' */ >= max_len)
		return -1;
	if (type_len) {
		memcpy(page->s + page->len, "# TYPE ", 7);
		page->len += 7;
		memcpy(page->s + page->len, prefix.s, prefix.len);
		page->len += prefix.len;
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

		fill_stats_name(stat_name, page);

		if (stat->flags & (STAT_IS_FUNC|STAT_NO_RESET)) {
			memcpy(page->s + page->len, " gauge\n", 7);
			page->len += 7;
		} else {
			memcpy(page->s + page->len, " counter\n", 9);
			page->len += 9;
		}
		/* we've written the first type - don't print it from now on */
		if (skip_type)
			*skip_type = 1;
	}
	memcpy(page->s + page->len, prefix.s, prefix.len);
	page->len += prefix.len;
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

	fill_stats_name(stat_name, page);
	label_idx = 0;

	if (label_len) {
		memcpy(page->s + page->len, "{", 1);
		page->len += 1;

		if (labels) {
			memcpy(page->s + page->len, labels->s, labels->len);
			page->len += labels->len;
			label_idx++;
		}

		if (prom_grp_mode == PROM_GROUP_MODE_LABEL) {
			if (label_idx) {
				memcpy(page->s + page->len, ",", 1);
				page->len += 1;
			}
			memcpy(page->s + page->len, prom_grp_label.s, prom_grp_label.len);
			page->len += prom_grp_label.len;

			memcpy(page->s + page->len, "=\"", 2);
			page->len += 2;

			memcpy(page->s + page->len, prom_grp_prefix.s, prom_grp_prefix.len);
			page->len += prom_grp_prefix.len;

			memcpy(page->s + page->len, m->s, m->len);
			page->len += m->len;

			memcpy(page->s + page->len, "\"", 1);
			page->len += 1;
			label_idx++;
		}

		if (stat->flags & STAT_HAS_GROUP) {
			if (label_idx) {
				memcpy(page->s + page->len, ",", 1);
				page->len += 1;
			}
			memcpy(page->s + page->len, "id=\"", 4);
			page->len += 4;
			id.s = int2str((unsigned long)stat->context, &id.len);

			memcpy(page->s + page->len, id.s, id.len);
			page->len += id.len;

			memcpy(page->s + page->len, "\"", 1);
			page->len += 1;
			label_idx++;
		}

		if (stat->flags & STAT_PER_PROC) {
			if (label_idx) {
				memcpy(page->s + page->len, ",", 1);
				page->len += 1;
			}
			memcpy(page->s + page->len, "pid=\"", 5);
			page->len += 5;
			id.s = int2str(pt[(unsigned long)stat->context].pid, &id.len);

			memcpy(page->s + page->len, id.s, id.len);
			page->len += id.len;
			label_idx++;

			memcpy(page->s + page->len, "\",desc=\"", 8);
			page->len += 8;
			init_str(&id, pt[(unsigned long)stat->context].desc);
			memcpy(page->s + page->len, id.s, id.len);
			page->len += id.len;
			memcpy(page->s + page->len, "\"", 1);
			page->len += 1;
			label_idx++;
		}


		memcpy(page->s + page->len, "}", 1);
		page->len += 1;
	}

	memcpy(page->s + page->len, " ", 1);
	page->len += 1;

	memcpy(page->s + page->len, v.s, v.len);
	page->len += v.len;
	memcpy(page->s + page->len, "\n", 1);
	page->len += 1;
	return 0;
}

static struct prom_labels_grp *prom_labels_grp_get(str *name, struct list_head *groups)
{
	struct prom_labels_grp *grp;
	struct list_head *it;
	list_for_each(it, groups) {
		grp = list_entry(it, struct prom_labels_grp, list);
		if (str_match(&grp->name, name))
			return grp;
	}
	grp = pkg_malloc(sizeof (*grp) + name->len);
	if (!grp) {
		LM_ERR("oom for new labels group\n");
		return NULL;
	}
	grp->name.s = grp->_buf;
	memcpy(grp->name.s, name->s, name->len);
	grp->name.len = name->len;
	INIT_LIST_HEAD(&grp->stats);
	list_add(&grp->list, groups);
	return grp;
}

static int prom_push_stat_labels(stat_var *stat, struct list_head *groups)
{
	str input, name, labels;
	str *result;
	struct list_head *it;
	struct prom_label *label = NULL;
	str *mod;
	int match_no;
	struct prom_labels_stat *grp_stat;
	struct prom_labels_grp *grp;

	if (list_empty(&prom_labels))
		return -1;

	mod = get_stat_module_name(stat);

	/* unknown module */
	if (!mod)
		return -1;
	/* check to see if there are any labels regex defined for this group */
	list_for_each(it, &prom_labels) {
		label = list_entry(it, struct prom_label, list);
		if (str_match(&label->module, mod)) {
			/* try to get the labels */
			if (pkg_nt_str_dup(&input, &stat->name) < 0)
				return -1;
			result = subst_str(input.s, NULL, label->subst, &match_no);
			if (!result)
				goto next;
			name.s = result->s;
			labels.s = q_memchr(result->s, ':', result->len);
			if (labels.s == NULL)
				goto free_result;

			name.len = labels.s - name.s;
			if (name.len <= 0)
				goto free_result;
			labels.s++;
			labels.len = result->len - name.len - 1;
			if (labels.len <= 0)
				goto free_result;

			grp = prom_labels_grp_get(&name, groups);
			if (!grp)
				goto free_result;

			grp_stat = pkg_malloc(sizeof *grp_stat);
			if (!grp_stat)
				goto free_result;
			grp_stat->labels = labels;
			grp_stat->free_buf = result;
			grp_stat->stat = stat;
			list_add(&grp_stat->list, &grp->stats);
			pkg_free(input.s);
			return 0;
free_result:
			pkg_free(result);
next:
			pkg_free(input.s);
		}
	}
	return -1;
}

static inline int prom_push_stat(stat_var *stat, str *page, int max_len,
		struct list_head *groups, struct list_head *label_groups)
{
	int s, skip_type = 0;
	group_stats *grp = NULL;

	/* first, check if the stat is part of a stats group */
	if ((stat->flags & STAT_HAS_GROUP) && (grp = get_stat_group(stat)) != NULL) {
		/* if the group was already dumped, we don't need to do anything
		 * since the variable has already been printed */
		if (prom_groups_exists(groups, grp))
			return 0;
		/* print all stats in the group - the first one prints the type */
		for (s = 0; s < grp->no; s++)
			if (prom_print_stat(grp->vars[s],
					&grp->name, NULL, page, max_len, &skip_type) < 0)
				return -1;
		prom_groups_add(groups, grp); /* add the group, to make sure
										 vars are not double printed */
		return 0;
	} else if (prom_push_stat_labels(stat, label_groups) < 0) {
		return prom_print_stat(stat, &stat->name, NULL, page, max_len, 0);
	} else {
		return 0;
	}
}

#define PROM_PUSH_STAT(_s, _m) \
	do { \
		if (prom_push_stat(_s, page, buffer->len, &groups, &label_groups) < 0) { \
			if (_m) \
				stats_mod_unlock(_m); \
			LM_ERR("out of memory for stats\n"); \
			prom_groups_free(&groups, &label_groups); \
			return MI_HTTP_INTERNAL_ERR_CODE; \
		} \
	} while(0)

int process_extra_prometheus_entry(cJSON *obj,str *page, int max_len)
{
	cJSON *header,*values,*value, *name, *counter;
	str val, cval;
	int c;

	if (!obj)
		return -1;

	if (obj->type != cJSON_Object) {
		LM_ERR("Expecting a JSON object in the array but got %d \n",obj->type);
		return -1;
	}

	header = cJSON_GetObjectItem(obj, "header");
	values = cJSON_GetObjectItem(obj, "values");

	if (!header || header->type != cJSON_String) {
		LM_ERR("Invalid header provided \n");
		return -1;
	}

	if (!values || values->type != cJSON_Array) {
		LM_ERR("Invalid values provided \n");
		return -1;
	}

	val.s = header->valuestring;
	val.len = strlen(val.s);

	if (!val.len) {
		LM_ERR("No header content provided \n");
		return -1;
	}

	if (page->len + val.len + 1 >= max_len) {
		LM_ERR("No more HTTP buffer space, have %d, need extra %d into max %d\n",page->len,val.len + 1,max_len);
		return -1;
	}

	memcpy(page->s + page->len,val.s,val.len);
	page->len += val.len;	

	memcpy(page->s + page->len, "\n", 1);
	page->len += 1;

	value = values->child;
	while (value) {
		if (value->type != cJSON_Object) {
			LM_ERR("Expected value object and found type %d\n",value->type);
			goto next_value;
		}

		name = cJSON_GetObjectItem(value, "name");
		if (!name || name->type != cJSON_String) {
			LM_ERR("Stat name not found \n");
			goto next_value;
		}

		counter = cJSON_GetObjectItem(value, "value");
		if (!counter || counter->type != cJSON_Number) {
			LM_ERR("Stat name not found \n");
			goto next_value;
		}

		val.s = name->valuestring; 
		val.len = strlen(val.s);

		c = counter->valueint;
		cval.s = int2str(c,&cval.len);

		if (page->len + val.len + cval.len + 2 /* blank & \n */ >= max_len) {
			LM_ERR("No more HTTP buffer space, have %d, need extra %d into max %d\n",page->len,val.len + cval.len + 2,max_len);
			return -1;
		}

		memcpy(page->s + page->len,val.s,val.len);
		page->len += val.len;	

		memcpy(page->s + page->len, " ", 1);
		page->len += 1;

		memcpy(page->s + page->len,cval.s,cval.len);
		page->len += cval.len;	

		memcpy(page->s + page->len, "\n", 1);
		page->len += 1;
next_value:
		value = value->next;
	}

	return 0;
}

int process_extra_prometheus(char *extra, int len,str *page, int max_len)
{
	cJSON *j_obj=NULL,*arr;

	if (!extra || len <= 0) {
		return -1;
	}

	j_obj = cJSON_Parse(extra);
	if (j_obj == NULL) {
		LM_ERR("Failed to parse JSON obj \n");
		return -1;
	}

	if (j_obj->type != cJSON_Array) {
		LM_ERR("Main JSON object expecting an array \n");
		goto error;
	}

	arr = j_obj->child;
	while (arr) {
		if (process_extra_prometheus_entry(arr,page,max_len) < 0) {
			LM_ERR("Failed to process JSON entry \n");
			goto error;
		}

		arr=arr->next;
	}
error:
	cJSON_Delete(j_obj);

	return 0;
}


int prom_answer_to_connection (void *cls, void *connection,
	const char *url, const char *method,
	const char *version, const char *upload_data,
	size_t upload_data_size, void **con_cls,
	str *buffer, str *page, union sockaddr_union* cl_socket)
{
	struct list_head groups;
	struct list_head label_groups;
	struct list_head *it, *grp;
	struct prom_stat *s;
	struct prom_labels_grp *lgrp;
	struct prom_labels_stat *lstat;
	module_stats *mod;
	stat_var *stat;
	int skip_type;
	struct sip_msg *route_msg = NULL;
	int_str val;

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
	INIT_LIST_HEAD(&groups);
	INIT_LIST_HEAD(&label_groups);

	if (prom_all_stats) {
		mod = 0;
		while ((mod = module_stats_iterate(mod)) != NULL) {
			stats_mod_lock(mod);
			for (stat = mod->head; stat; stat = stat->lnext)
				PROM_PUSH_STAT(stat, mod);
			stats_mod_unlock(mod);
		}
		goto end;
	}

	list_for_each(it, &prom_stat_mods) {
		s = list_entry(it, struct prom_stat, list);
		if (!s->mod) {
			s->mod = get_stat_module(&s->name);
			if (!s->mod) {
				LM_DBG("stat module %.*s not found\n", s->name.len, s->name.s);
				continue;
			}
		}
		stats_mod_lock(s->mod);
		for (stat = s->mod->head; stat; stat = stat->lnext)
			PROM_PUSH_STAT(stat, s->mod);
		stats_mod_unlock(s->mod);
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
		PROM_PUSH_STAT(*s->stat, NULL);
	}
end:
	list_for_each(grp, &label_groups) {
		lgrp = list_entry(grp, struct prom_labels_grp, list);
		skip_type = 0;
		list_for_each(it, &lgrp->stats) {
			lstat = list_entry(it, struct prom_labels_stat, list);
			if (prom_print_stat(lstat->stat, &lgrp->name, &lstat->labels,
					page, buffer->len, &skip_type) < 0) {
				prom_groups_free(&groups, &label_groups);
				return MI_HTTP_INTERNAL_ERR_CODE;
			}
		}
	}

	if (ref_script_route_is_valid(prometheus_route_ref)) {
		/* get a dummy msg for our route */	
		route_msg = get_dummy_sip_msg();
		if (!route_msg) {
			LM_ERR("Failed to get dummy msg for prometheus route \n");
			goto final;
		}

		/* set request route type */
		set_route_type( REQUEST_ROUTE );

		/* run given hep route */
		run_top_route( sroutes->request[prometheus_route_ref->idx], route_msg);

		memset(&val, 0, sizeof(int_str));
		if (prometheus_avp_name>=0 && 
		search_first_avp(prometheus_avp_type, prometheus_avp_name, &val, 0) &&
	       	val.s.len > 0) {
			if (process_extra_prometheus(val.s.s,val.s.len,page,buffer->len) < 0) {
				LM_ERR("Failed to add custom prometheus stats \n");
			}
		}


		/* free possible loaded avps */
		reset_avps();

		release_dummy_sip_msg(route_msg);
	}

final:

	if (page->len + 1 >= buffer->len) {
		LM_ERR("out of memory for stats\n");
		prom_groups_free(&groups, &label_groups);
		return MI_HTTP_INTERNAL_ERR_CODE;
	}
	memcpy(page->s + page->len, "\n", 1);
	page->len++;

	prom_groups_free(&groups, &label_groups);
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

	if (prom_all_stats) {
		LM_DBG("Already adding all statistics\n");
		return 0;
	}

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
		} else if (str_match_nt(&name, "all")) {
			prom_all_stats = 1;
			LM_INFO("Adding all statistics\n");
			return 0;
		} else {
			head = &prom_stats;
			LM_INFO("Adding statistic %.*s\n", name.len, name.s);
		}

		s = pkg_malloc(sizeof *s + name.len);
		if (!s) {
			LM_ERR("oom!\n");
			return -1;
		}
		memset(s, 0, sizeof *s);
		s->name.len = name.len;
		s->name.s = s->name_s;
		memcpy(s->name.s, name.s, name.len);
		list_add(&s->list, head);
	}
	return 0;
}

static int prom_labels_param(modparam_t type, void* val)
{
	str module;
	str regex;
	struct prom_label *label;
	init_str(&regex, val);

	trim_leading(&regex);
	module = regex;
	while (regex.len > 0 && *regex.s != ':') {
		regex.s++;
		regex.len--;
	}
	module.len = regex.s - module.s;
	if (module.len == 0) {
		LM_ERR("no type regexined!\n");
		return -1;
	}
	regex.s++;
	regex.len--;
	trim_leading(&regex);
	if (regex.len <= 0) {
		LM_ERR("no regex regexined!\n");
		return -1;
	}
	label = pkg_malloc(sizeof(*label) + module.len);
	if (!label) {
		LM_ERR("oom for label!\n");
		return -1;
	}
	memset(label, 0, sizeof *label);
	label->module.s = label->_buf;
	memcpy(label->module.s, module.s, module.len);
	label->module.len = module.len;

	label->subst = subst_parser(&regex);
	if (!label->subst) {
		pkg_free(label);
		LM_ERR("could not parse substitution [%.*s]\n",
				regex.len, regex.s);
		return -1;
	}
	list_add_tail(&label->list, &prom_labels);

	return 0;
}
