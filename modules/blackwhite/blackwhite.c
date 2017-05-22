/*
 * $Id$
 *
 * BLACKWHITE module
 *
 * Copyright (C) 2016 sa
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <string.h>
#include "../../sr_module.h"

#include "address.h"
#include "mi.h"
#include "funcs.h"

#include "../../mem/mem.h"
#include "../../db/db.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../str.h"
#include "../../resolve.h"
#include "../../ut.h"


str db_url    = {NULL, 0};
str db_table  = str_init("blackwhite");
str uname_col = str_init("username");
str ip_col    = str_init("ip");
str mask_col  = str_init("mask");
str bw_col    = str_init("flag");


static db_con_t* db_handle = 0;
static db_func_t bw_dbf;


static int mod_init(void);
static void mod_exit(void);
static int child_init(int rank);
static int mi_bw_child_init();

static int blackwhite(struct sip_msg* msg);
int reload_bw_data(void);


/* Exported functions */
static cmd_export_t cmds[] = {
	{"blackwhite" , (cmd_function) blackwhite, 0,
		0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

/* Exported parameters */
static param_export_t params[] = {
	{"db_url",             STR_PARAM, &db_url.s          },
	{"db_table",           STR_PARAM, &db_table.s        },
	{"uname_col",          STR_PARAM, &uname_col.s       },
	{"ip_col",             STR_PARAM, &ip_col.s          },
	{"mask_col",           STR_PARAM, &mask_col.s        },
	{"bw_col",             STR_PARAM, &bw_col.s          },
	{0, 0, 0}
};

/* Exported MI functions */
static mi_export_t mi_cmds[] = {
	{ MI_BW_RELOAD,       0, mi_bw_reload,        MI_NO_INPUT_FLAG,  0,  mi_bw_child_init },
	{ MI_BW_DUMP,         0, mi_bw_dump,          MI_NO_INPUT_FLAG,  0,  0 },
	{ 0, 0, 0, 0, 0, 0}
};

/* Module dependencies */
static dep_export_t deps = {
	{
		{ MOD_TYPE_SQLDB,   NULL,     DEP_ABORT },
		{ MOD_TYPE_NULL,    NULL,     0 },
	},
	{
	},
};

/* Module interface */
struct module_exports exports = {
	"blackwhite",
	MOD_TYPE_DEFAULT,  /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,   /* dlopen flags */
	&deps,             /* OpenSIPS module dependencies */
	cmds,              /* Exported functions */
	0,                 /* exported async functions */
	params,            /* Exported parameters */
	0,                 /* exported statistics */
	mi_cmds,           /* exported MI functions */
	0,                 /* exported pseudo-variables */
	0,                 /* extra processes */
	mod_init,          /* module initialization function */
	0,                 /* response function */
	mod_exit,          /* destroy function */
	child_init         /* child initialization function */
};



/*
 * module initialization function 
 */
static int mod_init(void)
{
	LM_DBG("Black And White initializing...\n");

	init_db_url(db_url , 0 /*can't be null*/);
	db_table.len  = strlen(db_table.s);
	uname_col.len = strlen(uname_col.s);
	ip_col.len    = strlen(ip_col.s);
	mask_col.len  = strlen(mask_col.s);
	bw_col.len    = strlen(bw_col.s);

	bw_data1 = shm_malloc(sizeof(struct bw_data));
	bw_data2 = shm_malloc(sizeof(struct bw_data));
	/* data ptr in shm */
	cur_data = shm_malloc(sizeof(struct bw_data*));
	*cur_data = NULL;

	if (bw_data1 == NULL || bw_data2 == NULL)
	{
		LM_ERR("failed to allocate memory\n");
		return -1;
	}

	bw_data1->addrs = NULL; bw_data1->data_n = 0;
	bw_data2->addrs = NULL; bw_data2->data_n = 0;

	if (reload_bw_data() != 0) {
		LM_ERR("failed to initialize the blackwhite module\n");
		return -1;
	}

	return 0;
}


static int child_init(int rank)
{
	return 0;
}


static int mi_bw_child_init(void)
{
    return 0;
}


/* 
 * destroy function 
 */
static void mod_exit(void) 
{
	free_data(bw_data1->addrs, &bw_data1->data_n);
	free_data(bw_data2->addrs, &bw_data2->data_n);

	bw_data1->addrs = NULL;
	bw_data2->addrs = NULL;
	shm_free(bw_data1);
	shm_free(bw_data2);
	bw_data1 = bw_data2 = NULL;
	cur_data = NULL;
}


/*
 * return:
 *  1 - block
 * -2 - pass
 * -3 - no id
 */
static int blackwhite(struct sip_msg* msg)
{
	struct sip_uri *from_uri;

	from_uri = parse_from_uri(msg);

	if (from_uri == NULL) {
                LM_ERR("failed to parse From body\n");
                return -1;
        }

        if (is_printable(L_DBG))
	{
		struct in_addr in;
		str str_ip;

		in.s_addr = msg->rcv.src_ip.u.addr32[0];
		str_ip.s = inet_ntoa(in);

		if (!str_ip.s) {
			LM_ERR("error at inet_ntoa\n");
			return -1;
		}

		str_ip.len = strlen(str_ip.s);

		LM_DBG("Looking for From: %.*s IP: %.*s\n", from_uri->user.len, from_uri->user.s, str_ip.len, str_ip.s);
	}

	return blackwhite_(&from_uri->user, &msg->rcv.src_ip, (*cur_data)->addrs, (*cur_data)->data_n);
}


/*
 * Get count for alloc bw_data array
 */
static size_t count_distinct(db_res_t *res)
{
	size_t n = 0;
	int i, is_str = 0;
	str cur = {NULL, 0}, tmp;

	db_row_t* row;
	db_val_t* val;

	row = RES_ROWS(res);

	/* find first not null */
	for (i = 0; i < RES_ROW_N(res); ++i)
	{
		val = ROW_VALUES(row + i);

		if (VAL_NULL(val))
			continue;

		if (VAL_TYPE(val) == DB_STRING)
		{
			tmp.s = (char*)VAL_STRING(val);
			tmp.len = strlen(VAL_STRING(val));

			cur = tmp;
		}
		else if (VAL_TYPE(val) == DB_STR)
		{
			cur = VAL_STR(val);
			is_str = 1;
		}
		else
		{
			LM_ERR("username col is not string\n");
			return 0;
		}

		++n;
		break;
	}

	/* count distinct */
	if (is_str)
		for (++i; i < RES_ROW_N(res); ++i)
		{
			val = ROW_VALUES(row + i);

			if (str_cmp(&cur, &VAL_STR(val)))
			{
				cur = VAL_STR(val);
				++n;
			}
		}
	else
		for (++i; i < RES_ROW_N(res); ++i)
		{
			val = ROW_VALUES(row + i);

			tmp.s = (char*)VAL_STRING(val);
			tmp.len = strlen(VAL_STRING(val));

			if (str_cmp(&cur, &tmp))
			{
				cur = tmp;
				++n;
			}
		}

	LM_DBG("blackwhite found %lu unique usernames\n", n);
	return n;
}


static void bw_data_fill(db_res_t *res, struct address *addrs, size_t *new_n)
{
	db_row_t* row;
	db_val_t* val;

	int i, mask, black;
	struct ip_addr *ip_addr;
	struct net *subnet;
	str username, str_src_ip;

	row = RES_ROWS(res);

	for (i = 0; i < RES_ROW_N(res); ++i) {

		val = ROW_VALUES(row + i);
		if ((VAL_TYPE(val) != DB_STRING && VAL_TYPE(val) != DB_STR) ||
				VAL_NULL(val)) {
			LM_ERR("invalid username column type/value on row %d, skipping..\n", i);
			continue;
		}
		if ((VAL_TYPE(val + 1) != DB_STRING && VAL_TYPE(val + 1) != DB_STR) ||
				VAL_NULL(val + 1)) {
			LM_ERR("invalid IP column type/value on row %d, skipping..\n", i);
			continue;
		}
		if (VAL_TYPE(val + 2) != DB_INT || VAL_NULL(val + 2) ||
					VAL_INT(val + 2) < 0 || VAL_INT(val + 2) > 32) {
			LM_ERR("invalid mask column type/value on row %d, skipping..\n", i);
			continue;
		}
		if (VAL_TYPE(val + 3) != DB_INT || VAL_NULL(val + 3)) {
			LM_ERR("invalid flag column type/value on row %d, skipping..\n", i);
			continue;
		}

		/* username string */
		if (VAL_TYPE(val) == DB_STRING) {
			username.s = (char*)VAL_STRING(val);
			username.len = strlen(username.s);
		} else {
			username = VAL_STR(val);
		}
		if (username.len==0) {
			LM_ERR("empty username field in blackwhite table, ignoring entry"
					" number %d\n", i);
			continue;
		}

		/* IP string */
		if (VAL_TYPE(val+1)==DB_STRING) {
			str_src_ip.s = (char*)VAL_STRING(val+1);
			str_src_ip.len = strlen(str_src_ip.s);
		} else {
			str_src_ip = VAL_STR(val+1);
		}
		if (str_src_ip.len==0) {
			LM_ERR("empty ip field in blackwhite table, ignoring entry"
					" number %d\n", i);
			continue;
		}

		ip_addr = str2ip(&str_src_ip);

		if (!ip_addr) {
			LM_ERR("invalid ip field in blackwhite table, ignoring entry "
					" number %d\n", i);
			continue;
		}

		mask = (unsigned int) VAL_INT(val + 2);

		subnet = mk_net_bitlen(ip_addr, mask);

		if (subnet == NULL) {
			LM_ERR("blackwhite can't allocate memory (subnet)\n");
			break;
		}

		black = VAL_INT(val+3);

		if (data_append(&username, subnet, black, addrs, new_n)) {
			pkg_free(subnet);
			break;
		}

		LM_DBG("Tuple <%.*s, %.*s/%d, %s> inserted\n",
			username.len, username.s, str_src_ip.len, str_src_ip.s, mask, (black ? "white" : "black"));

		pkg_free(subnet);
	}
	LM_INFO("blackwhite %lu usernames accepted\n", *new_n);
}


static int read_bw_data(struct address **addrs, size_t *new_n)
{
	size_t dist_n;

	db_key_t cols[4];
	db_res_t* res = NULL;

	cols[0] = &uname_col;
	cols[1] = &ip_col;
	cols[2] = &mask_col;
	cols[3] = &bw_col;

	if (!db_url.s) {
		LM_INFO("db_url parameter of blackwhite module not set, "
			"disabling blackwhite\n");
		return 0;
	}

	if (db_bind_mod(&db_url, &bw_dbf) < 0) {
		LM_ERR("load a database support module\n");
		return -1;
	}

	if (!DB_CAPABILITY(bw_dbf, DB_CAP_QUERY)) {
		LM_ERR("database module does not implement 'query' function\n");
		return -1;
	}

	db_handle = bw_dbf.init(&db_url);

	if (!db_handle) {
		LM_ERR("unable to connect database\n");
		return -1;
	}

	if (bw_dbf.use_table(db_handle, &db_table) < 0) {
		LM_ERR("failed to use blackwhite table\n");
		goto error;
	}

	/* order by user name for count_distinct() */
	if (bw_dbf.query(db_handle, NULL, 0, NULL, cols, 0, 4, cols[0], &res) < 0) {
		LM_ERR("failed to query database\n");
		goto error;
	}

	if (RES_ROW_N(res) == 0) {
		LM_WARN("table blackwhite empty\n");
		goto error;
	}

	LM_DBG("number of rows in blackwhite table: %d\n", RES_ROW_N(res));

	if (RES_COL_N(res) != 4) {
		LM_ERR("too many columns\n");
		goto error;
	}

	dist_n = count_distinct(res);

	if (dist_n == 0) {
		LM_ERR("no distinct usernames\n");
		goto error;
	}

	*addrs = shm_malloc(sizeof(struct address) * dist_n);

	if (*addrs == NULL) {
		LM_ERR("blackwhite can't allocate memory\n");
		goto error;
	}

	memset(*addrs, 0, sizeof(struct address) * dist_n);

	bw_data_fill(res, *addrs, new_n);

	bw_dbf.free_result(db_handle, res);
	bw_dbf.close(db_handle);
	db_handle = 0;

	LM_DBG("blackwhite table readed successfully.\n");

	return 0;
error:
	if (*addrs) free_data(*addrs, new_n);
	if (res) bw_dbf.free_result(db_handle, res);
	bw_dbf.close(db_handle);
	db_handle = 0;
	return -1;
}


/*
 * Reload blackwhite table to memory and when done, make new array
 * current one.
 */

int reload_bw_data(void)
{
	struct bw_data *new_data = NULL;

	if (*cur_data == bw_data1)
		new_data = bw_data2;
	else
		new_data = bw_data1;

	free_data(new_data->addrs, &new_data->data_n);

	if (read_bw_data(&new_data->addrs, &new_data->data_n) != 0)
		return -1;

	/* sort and search should be done by one compare function */
	qsort(new_data->addrs, new_data->data_n, sizeof(struct address), cmpstringp);

	*cur_data = new_data;

	return 0;
}
