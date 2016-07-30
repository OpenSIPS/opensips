/*
 * Copyright (C) 2007 1&1 Internet AG
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */


#include <string.h>

#include "../../sr_module.h"
#include "../../parser/parse_uri.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../mem/mem.h"
#include "../../usr_avp.h"
#include "../../locking.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../db/db.h"

#include "dt.h"
#include "db.h"




#define MAXNUMBERLEN 31


typedef struct _avp_check
{
	int avp_flags;
	int_str avp_name;
} avp_check_t;


struct check_blacklist_fs_t {
  struct dt_node_t *dt_root;
};


static str db_url       = {NULL, 0};
static str db_table     = str_init("userblacklist");
static int use_domain   = 0;

/* ---- fixup functions: */
static int check_blacklist_fixup(void** param, int param_no);
static int check_user_blacklist_fixup(void** param, int param_no);

/* ---- exported commands: */
static int check_user_blacklist(struct sip_msg *msg, char* str1, char* str2, char* str3, char* str4);
static int check_blacklist(struct sip_msg *msg, struct check_blacklist_fs_t *arg1);

/* ---- module init functions: */
static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

/* --- fifo functions */
struct mi_root * mi_reload_blacklist(struct mi_root* cmd, void* param);  /* usage: opensipsctl fifo reload_blacklist */


static cmd_export_t cmds[]={
	{ "check_user_blacklist", (cmd_function)check_user_blacklist, 2, check_user_blacklist_fixup, 0, REQUEST_ROUTE | FAILURE_ROUTE },
	{ "check_user_blacklist", (cmd_function)check_user_blacklist, 3, check_user_blacklist_fixup, 0, REQUEST_ROUTE | FAILURE_ROUTE },
	{ "check_user_blacklist", (cmd_function)check_user_blacklist, 4, check_user_blacklist_fixup, 0, REQUEST_ROUTE | FAILURE_ROUTE },
	{ "check_blacklist", (cmd_function)check_blacklist, 1, check_blacklist_fixup, 0, REQUEST_ROUTE | FAILURE_ROUTE },
	{ 0, 0, 0, 0, 0, 0}
};


static param_export_t params[] = {
	{ "db_url",          STR_PARAM, &db_url.s },
	{ "db_table",        STR_PARAM, &db_table.s },
	{ "use_domain",      INT_PARAM, &use_domain },
	{ 0, 0, 0}
};


/* Exported MI functions */
static mi_export_t mi_cmds[] = {
	{ "reload_blacklist", 0, mi_reload_blacklist, MI_NO_INPUT_FLAG, 0, 0 },
	{ 0, 0, 0, 0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"userblacklist",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	NULL,
	params,
	0,
	mi_cmds,
	0,
	0,
	mod_init,
	0,
	mod_destroy,
	child_init
};


struct source_t {
	struct source_t *next;
	/** prefixes to be used are stored in this table */
	char *table;
	/** d-tree structure: will be built from data in database */
	struct dt_node_t *dt_root;
};


struct source_list_t {
  struct source_t *head;
};


static gen_lock_t *lock = NULL;
static struct source_list_t *sources = NULL;
static struct dt_node_t *dt_root;


static int check_user_blacklist_fixup(void** param, int param_no)
{
	pv_elem_t *model=NULL;
	str s;

	/* convert to str */
	s.s = (char*)*param;
	s.len = strlen(s.s);

	if (param_no > 0 && param_no <= 4) {
		if(s.len == 0 && param_no != 4) {
			LM_ERR("no parameter %d\n", param_no);
			return E_UNSPEC;
		}

		if(pv_parse_format(&s, &model) < 0 || !model) {
			LM_ERR("wrong format [%.*s] for parameter %d\n", s.len, s.s, param_no);
			return E_UNSPEC;
		}

		if(!model->spec.getf) {
			if(param_no == 1) {
				if(str2int(&s, (unsigned int*)&model->spec.pvp.pvn.u.isname.name.n) != 0) {
					LM_ERR("wrong value [%.*s] for parameter %d\n", s.len, s.s, param_no);
					return E_UNSPEC;
				}
			} else {
				if(param_no == 2 || param_no == 3) {
					LM_ERR("wrong value [%.*s] for parameter %d\n", s.len, s.s, param_no);
					return E_UNSPEC;
				} else {
					// only a string
					return 0;
				}
			}
		}
		*param = (void*)model;
	} else {
		LM_ERR("wrong number of parameters\n");
	}

	return 0;
}


static int check_user_blacklist(struct sip_msg *msg, char* str1, char* str2, char* str3, char* str4)
{
	str user = { .len = 0, .s = NULL };
	str domain = { .len = 0, .s = NULL};
	str table = { .len = 0, .s = NULL};
	str number = { .len = 0, .s = NULL};

	char whitelist;
	char *src;
    char *dst;
	char req_number[MAXNUMBERLEN+1];

	/* user */
	if(((pv_elem_p)str1)->spec.getf) {
		if(pv_printf_s(msg, (pv_elem_p)str1, &user) != 0) {
			LM_ERR("cannot print user pseudo-variable\n");
			return -1;
		}
	}
	/* domain */
	if(((pv_elem_p)str2)->spec.getf) {
		if(pv_printf_s(msg, (pv_elem_p)str2, &domain) != 0) {
			LM_ERR("cannot print domain pseudo-variable\n");
			return -1;
		}
	}
	/* source number */
	if(str3 != NULL && ((pv_elem_p)str3)->spec.getf) {
		if(pv_printf_s(msg, (pv_elem_p)str3, &number) != 0) {
			LM_ERR("cannot print number pseudo-variable\n");
			return -1;
		}
	}
	/* table name */
	if(str4 != NULL && strlen(str4) > 0) {
		/* string */
		table.s=str4;
		table.len=strlen(str4);
	} else {
		/* use default table name */
		table.len=db_table.len;
		table.s=db_table.s;
	}

	if (msg->first_line.type != SIP_REQUEST) {
		LM_ERR("SIP msg is not a request\n");
		return -1;
	}

	if(number.s == NULL) {
		/* use R-URI */
		if ((parse_sip_msg_uri(msg) < 0) || (!msg->parsed_uri.user.s) || (msg->parsed_uri.user.len > MAXNUMBERLEN)) {
			LM_ERR("cannot parse msg URI\n");
			return -1;
		}
		strncpy(req_number, msg->parsed_uri.user.s, msg->parsed_uri.user.len);
		req_number[msg->parsed_uri.user.len] = '\0';
	} else {
		if (number.len > MAXNUMBERLEN) {
			LM_ERR("number to long\n");
			return -1;
		}
		strncpy(req_number, number.s, number.len);
		req_number[number.len] = '\0';
	}

	LM_DBG("check entry %s for user %.*s on domain %.*s in table %.*s\n", req_number,
		user.len, user.s, domain.len, domain.s, table.len, table.s);
	if (db_build_userbl_tree(&user, &domain, &table, dt_root, use_domain) < 0) {
		LM_ERR("cannot build d-tree\n");
		return -1;
	}

	src = dst = req_number;
	/* Skip over non-digits.  */
	while (*src) {
        if (isdigit(*src))
            *dst++ = *src++;
        else
            src++;
	}
    *dst = '\0';

	if (dt_longest_match(dt_root, req_number, &whitelist) >= 0) {
		if (whitelist) {
			/* LM_ERR("whitelisted"); */
			return 1; /* found, but is whitelisted */
		}
	} else {
		/* LM_ERR("not found"); */
		return 1; /* not found is ok */
	}

	LM_DBG("entry %s is blacklisted\n", req_number);
	return -1;
}


/**
 * Finds d-tree root for given table.
 * \return pointer to d-tree root on success, NULL otherwise
 */
static struct dt_node_t *table2dt(const char *table)
{
	struct source_t *src = sources->head;
	while (src) {
		if (strcmp(table, src->table) == 0) return src->dt_root;
		src = src->next;
	}

	LM_ERR("invalid table '%s'.\n", table);
	return NULL;
}


/**
 * Adds a new table to the list, if the table is
 * already present, nothing will be done.
 * \return zero on success, negative on errors
 */
static int add_source(const char *table)
{
	/* check if the table is already present */
	struct source_t *src = sources->head;
	while (src) {
		if (strcmp(table, src->table) == 0) return 0;
		src = src->next;
	}

	src = shm_malloc(sizeof(struct source_t));
	if (!src) {
		LM_ERR("out of shared memory.\n");
		return -1;
	}
	memset(src, 0, sizeof(struct source_t));

	src->next = sources->head;
	sources->head = src;

	src->table = shm_malloc(strlen(table)+1);
	if (!src->table) {
		LM_ERR("out of shared memory.\n");
		shm_free(src);
		return -1;
	}
	strcpy(src->table, table);
	LM_DBG("add table %s", table);

	return dt_init(&(src->dt_root));
}


static int check_blacklist_fixup(void **arg, int arg_no)
{
	char *table = (char *)(*arg);
	struct dt_node_t *node = NULL;
	if (arg_no != 1) {
		LM_ERR("wrong number of parameters\n");
		return -1;
	}

	if (!table) {
		LM_ERR("no table name\n");
		return -1;
	}
	/* try to add the table */
	if (add_source(table) != 0) {
		LM_ERR("could not add table");
		return -1;
	}

	/* get the node that belongs to the table */
	node = table2dt(table);
	if (!node) {
		LM_ERR("invalid table '%s'\n", table);
		return -1;
	}

	struct check_blacklist_fs_t *new_arg = (struct check_blacklist_fs_t*)pkg_malloc(sizeof(struct check_blacklist_fs_t));
	if (!new_arg) {
		LM_ERR("out of private memory\n");
		return -1;
	}
	memset(new_arg, 0, sizeof(struct check_blacklist_fs_t));
	new_arg->dt_root = node;
	*arg=(void*)new_arg;

	return 0;
}


static int check_blacklist(struct sip_msg *msg, struct check_blacklist_fs_t *arg1)
{
	char whitelist;
	char *src;
    char *dst;
	char req_number[MAXNUMBERLEN+1];

	if (msg->first_line.type != SIP_REQUEST) {
		LM_ERR("SIP msg is not a request\n");
		return -1;
	}

	if (parse_sip_msg_uri(msg) < 0) {
		LM_ERR("cannot parse msg URI\n");
		return -1;
	}

	if ((parse_sip_msg_uri(msg) < 0) || (!msg->parsed_uri.user.s) || (msg->parsed_uri.user.len > MAXNUMBERLEN)) {
		LM_ERR("cannot parse msg URI\n");
		return -1;
	}
	strncpy(req_number, msg->parsed_uri.user.s, msg->parsed_uri.user.len);
	req_number[msg->parsed_uri.user.len] = '\0';


	src = dst = req_number;
	/* Skip over non-digits.  */
	while (*src) {
        if (isdigit(*src))
            *dst++ = *src++;
        else
            src++;
	}
    *dst = '\0';

	LM_DBG("check entry %s\n", req_number);
	if (dt_longest_match(arg1->dt_root, req_number, &whitelist) >= 0) {
		if (whitelist) {
			/* LM_DBG("whitelisted"); */
			return 1; /* found, but is whitelisted */
		}
	}
	else {
		/* LM_ERR("not found"); */
		return 1; /* not found is ok */
	}

	LM_DBG("entry %s is blacklisted\n", req_number);
	return -1;
}


/**
 * Fills the d-tree for all configured and prepared sources.
 * \return 0 on success, -1 otherwise
 */
static int reload_sources(void)
{
	int result = 0;
	str tmp;

	/* critical section start: avoids dirty reads when updating d-tree */
	lock_get(lock);

	struct source_t *src = sources->head;
	while (src) {
		tmp.s = src->table;
		tmp.len = strlen(src->table);
		int n = db_reload_source(&tmp, src->dt_root);
		if (n < 0) {
			LM_ERR("cannot reload source from '%.*s'\n", tmp.len, tmp.s);
			result = -1;
			break;
		}
		LM_INFO("got %d entries from '%.*s'\n", n, tmp.len, tmp.s);
		src = src->next;
	}

	/* critical section end */
	lock_release(lock);

	return result;
}


static int init_source_list(void)
{
	sources = shm_malloc(sizeof(struct source_list_t));
	if (!sources) {
		LM_ERR("out of private memory\n");
		return -1;
	}
	sources->head = NULL;
	return 0;
}


static void destroy_source_list(void)
{
	if (sources) {
		while (sources->head) {
			struct source_t *src = sources->head;
			sources->head = src->next;

			if (src->table) shm_free(src->table);
			dt_destroy(&(src->dt_root));
			shm_free(src);
		}

		shm_free(sources);
		sources = NULL;
	}
}


static int init_shmlock(void)
{
	lock = lock_alloc();
	if (!lock) {
		LM_CRIT("cannot allocate memory for lock.\n");
		return -1;
	}
	if (lock_init(lock) == 0) {
		LM_CRIT("cannot initialize lock.\n");
		return -1;
	}

	return 0;
}


static void destroy_shmlock(void)
{
	if (lock) {
		lock_destroy(lock);
		lock_dealloc((void *)lock);
		lock = NULL;
	}
}


struct mi_root * mi_reload_blacklist(struct mi_root* cmd, void* param)
{
	struct mi_root * tmp = NULL;

	if(reload_sources() == 0) {
		tmp = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	} else {
		tmp = init_mi_tree( 500, "cannot reload blacklist", 21);
	}

	return tmp;
}


static int mod_init(void)
{
	LM_INFO("initializing ...\n");
	init_db_url( db_url , 0 /*cannot be null*/);
	db_table.len = strlen(db_table.s);

	if (db_bind(&db_url) != 0) return -1;
	if (init_shmlock() != 0) return -1;
	if (init_source_list() != 0) return -1;
	LM_INFO("finished initializing\n");

	return 0;
}


static int child_init(int rank)
{
	if (db_init(&db_url, &db_table) != 0) return -1;
	if (dt_init(&dt_root) != 0) return -1;
	/* because we've added new sources during the fixup */
	if (reload_sources() != 0) return -1;

	return 0;
}


static void mod_destroy(void)
{
	destroy_source_list();
	destroy_shmlock();
	db_destroy();
	dt_destroy(&dt_root);
}
