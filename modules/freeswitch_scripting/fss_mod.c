/*
 * Script and MI utilities for custom FreeSWITCH interactions
 *
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "../../sr_module.h"
#include "../../str.h"
#include "../../lib/url.h"
#include "../../ipc.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../mi/mi.h"

#include "../freeswitch/fs_api.h"
#include "fss_ipc.h"
#include "fss_evs.h"
#include "fss_db.h"

str fss_mod_tag = str_init("freeswitch_scripting");

str fss_table      = str_init("freeswitch");
str fss_col_user   = str_init("username");
str fss_col_pass   = str_init("password");
str fss_col_ip     = str_init("ip");
str fss_col_port   = str_init("port");
str fss_col_events = str_init("events_csv");

static int mod_init(void);
static void mod_destroy(void);

static int fs_esl(struct sip_msg *msg, char *cmd, char *url, char *out_pv);
static int fixup_fs_esl(void **param, int param_no);

static int fs_sub_add_url(modparam_t type, void *string);

struct mi_root *mi_fs_subscribe(struct mi_root *cmd, void *_);
struct mi_root *mi_fs_unsubscribe(struct mi_root *cmd, void *_);
struct mi_root *mi_fs_list(struct mi_root *cmd, void *_);
struct mi_root *mi_fs_reload(struct mi_root *cmd, void *_);

static cmd_export_t cmds[] = {
	{ "freeswitch_esl", (cmd_function)fs_esl, 2, fixup_fs_esl, 0, ALL_ROUTES },
	{ "freeswitch_esl", (cmd_function)fs_esl, 3, fixup_fs_esl, 0, ALL_ROUTES },
	{ NULL, NULL, 0, NULL, NULL, 0 }
};

static param_export_t mod_params[] = {
	{ "db_url",                 STR_PARAM,                       &db_url.s },
	{ "db_table",               STR_PARAM,                    &fss_table.s },
	{ "db_col_username",        STR_PARAM,                 &fss_col_user.s },
	{ "db_col_password",        STR_PARAM,                 &fss_col_pass.s },
	{ "db_col_ip",              STR_PARAM,                   &fss_col_ip.s },
	{ "db_col_port",            STR_PARAM,                 &fss_col_port.s },
	{ "db_col_events",          STR_PARAM,               &fss_col_events.s },
	{ "fs_subscribe",           STR_PARAM|USE_FUNC_PARAM,   fs_sub_add_url },
	{ 0, 0, 0 }
};

static mi_export_t mi_cmds[] = {
	{ "fs_subscribe",       0, mi_fs_subscribe,   0,  0,              0 },
	{ "fs_unsubscribe",     0, mi_fs_unsubscribe, 0,  0,              0 },
	{ "fs_list",            0, mi_fs_list,        0,  0,              0 },
	{ "fs_reload",          0, mi_fs_reload,      0,  0, fss_db_connect },
	{ 0, 0, 0, 0, 0, 0 }
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "freeswitch", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url",           get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"freeswitch_scripting",     /* module's name */
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	&deps,            /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	NULL,             /* exported async functions */
	mod_params,       /* param exports */
	NULL,             /* exported statistics */
	mi_cmds,          /* exported MI functions */
	NULL,             /* exported pseudo-variables */
	NULL,             /* exported transformations */
	NULL,             /* extra processes */
	mod_init,         /* module initialization function */
	NULL,             /* reply processing function */
	mod_destroy,      /* destroy function */
	NULL              /* per-child init function */
};

/* temporarily dup the URL modparams in shm until mod_init() runs */
struct list_head startup_fs_subs = LIST_HEAD_INIT(startup_fs_subs);
static int fs_sub_add_url(modparam_t type, void *string)
{
	struct str_dlist *strl;
	str url = {string, strlen(string)};

	strl = shm_malloc(sizeof *strl);
	if (!strl) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(strl, 0, sizeof *strl);

	if (shm_nt_str_dup(&strl->s, &url) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	list_add_tail(&strl->list, &startup_fs_subs);

	return 0;
}

static int mod_init(void)
{
	fss_table.len = strlen(fss_table.s);

	if (fss_init() != 0) {
		LM_ERR("failed to init runtime environment\n");
		return -1;
	}

	if (fss_ipc_init() != 0) {
		LM_ERR("failed to init IPC\n");
		return -1;
	}

	if (fss_evi_init() != 0) {
		LM_ERR("failed to init script events\n");
		return -1;
	}

	if (fss_db_init() != 0)
		LM_ERR("failed to init DB support, running without it\n");

	if (subscribe_to_fs_urls(&startup_fs_subs) != 0)
		LM_ERR("ignored one or more broken FS URL modparams (or oom!)\n");

	free_shm_str_dlist(&startup_fs_subs);

	return 0;
}

static void mod_destroy(void)
{
	fss_db_close();
}

static int fixup_fs_esl(void **param, int param_no)
{
	switch (param_no) {
	case 1:
	case 2:
		return fixup_spve(param);
	case 3:
		return fixup_pvar(param);
	default:
		LM_BUG("freeswitch_esl() called with > 3 params!\n");
		return -1;
	}
}

static int fs_esl(struct sip_msg *msg, char *cmd_gp, char *url_gp,
                  char *reply_pvs)
{
	fs_evs *sock;
	pv_value_t reply_val;
	str url, cmd, reply;
	int ret = 1;

	if (fixup_get_svalue(msg, (gparam_p)cmd_gp, &cmd) != 0) {
		LM_ERR("failed to print cmd parameter!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)url_gp, &url) != 0) {
		LM_ERR("failed to print url parameter!\n");
		return -1;
	}

	sock = fs_api.get_evs_by_url(&url);
	if (!sock) {
		LM_ERR("failed to get a socket for FS URL %.*s\n", url.len, url.s);
		return -1;
	}

	LM_DBG("running '%.*s' on %s:%d\n", cmd.len, cmd.s,
	       sock->host.s, sock->port);

	if (fs_api.fs_esl(sock, &cmd, &reply) != 0) {
		LM_ERR("failed to run freeswitch_esl cmd '%*s.' on %s:%d\n",
		       cmd.len, cmd.s, sock->host.s, sock->port);
		ret = -1;
		goto out;
	}

	LM_DBG("success, output is: '%.*s'\n", reply.len, reply.s);

	if (reply_pvs) {
		reply_val.flags = PV_VAL_STR;
		reply_val.rs = reply;

		if (pv_set_value(msg, (pv_spec_p)reply_pvs, 0, &reply_val) != 0) {
			LM_ERR("failed to set output pvar!\n");
			ret = -1;
		}
	}

out:
	if (reply.s)
		shm_free(reply.s);
	fs_api.put_evs(sock);
	return ret;
}

/* fs_subscribe 10.0.0.10 DTMF HEARTBEAT CHANNEL_STATE FOO ... */
struct mi_root *mi_fs_subscribe(struct mi_root *cmd_tree, void *_)
{
	struct mi_node *param, *event;
	struct mi_root *reply;
	struct str_list *evlist = NULL, *li, **last = &evlist;
	fs_evs *sock;
	str *url;

	param = cmd_tree->node.kids;
	if (!param || ZSTR(param->value))
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));

	url = &param->value;
	sock = fs_api.get_evs_by_url(url);
	if (!sock) {
		LM_ERR("failed to get a socket for FS URL %.*s\n", url->len, url->s);
		return init_mi_tree(500, MI_SSTR(MI_INTERNAL_ERR));
	}

	lock_start_write(db_reload_lk);

	if (find_evs(sock) != 0) {
		if (add_evs(sock) != 0) {
			lock_stop_write(db_reload_lk);
			fs_api.put_evs(sock);
			LM_ERR("failed to ref socket\n");
			return init_mi_tree(501, MI_SSTR(MI_INTERNAL_ERR));
		}
	} else {
		/* we're already referencing this socket */
		fs_api.put_evs(sock);
	}

	LM_DBG("found socket %s:%d for URL '%.*s'\n", sock->host.s, sock->port,
	       url->len, url->s);

	for (event = param->next; event; event = event->next) {
		if (ZSTR(event->value) || add_to_fss_sockets(sock, &event->value) <= 0)
			continue;

		li = pkg_malloc(sizeof *li);
		if (!li) {
			LM_ERR("oom\n");
			reply = init_mi_tree(502, MI_SSTR(MI_INTERNAL_ERR));
			goto out_free;
		}
		memset(li, 0, sizeof *li);

		li->s = event->value;
		*last = li;
		last = &li->next;

		LM_DBG("queued up sub for %.*s\n", li->s.len, li->s.s);
	}

	if (fs_api.evs_sub(sock, &fss_mod_tag, evlist, ipc_hdl_rcv_event) != 0) {
		LM_ERR("failed to subscribe for one or more events on %s:%d\n",
		       sock->host.s, sock->port);
		fs_api.evs_unsub(sock, &fss_mod_tag, evlist);
		reply = init_mi_tree(503, MI_SSTR(MI_INTERNAL_ERR));
		goto out_free;
	}

	reply = init_mi_tree(200, MI_SSTR(MI_OK));

out_free:
	lock_stop_write(db_reload_lk);

	_free_str_list(evlist, osips_pkg_free, NULL);
	return reply;
}

/* fs_unsubscribe 10.0.0.10 DTMF HEARTBEAT CHANNEL_STATE FOO ... */
struct mi_root *mi_fs_unsubscribe(struct mi_root *cmd_tree, void *_)
{
	struct mi_node *param, *event;
	struct mi_root *reply;
	struct str_list *evlist = NULL, *li, **last = &evlist;
	fs_evs *sock;
	str *url;
	int rc, do_unref = 0;

	param = cmd_tree->node.kids;
	if (!param || ZSTR(param->value))
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));

	url = &param->value;
	sock = fs_api.get_evs_by_url(url);
	if (!sock) {
		LM_ERR("failed to get a socket for FS URL %.*s\n", url->len, url->s);
		return init_mi_tree(500, MI_SSTR(MI_INTERNAL_ERR));
	}

	lock_start_write(db_reload_lk);

	if (find_evs(sock) != 0) {
		lock_stop_write(db_reload_lk);
		LM_DBG("we're not even referencing this socket: %s:%d\n",
		       sock->host.s, sock->port);
		fs_api.put_evs(sock);
		return init_mi_tree(200, MI_SSTR(MI_OK));
	}

	/* we're already referencing this socket */
	fs_api.put_evs(sock);

	LM_DBG("found socket %s:%d for URL '%.*s'\n", sock->host.s, sock->port,
	       url->len, url->s);

	for (event = param->next; event; event = event->next) {
		if (ZSTR(event->value))
			continue;

		rc = del_from_fss_sockets(sock, &event->value);
		if (rc < 0)
			continue;

		if (rc == 1)
			do_unref = 1;

		li = pkg_malloc(sizeof *li);
		if (!li) {
			LM_ERR("oom\n");
			reply = init_mi_tree(501, MI_SSTR(MI_INTERNAL_ERR));
			goto out_free;
		}
		memset(li, 0, sizeof *li);

		li->s = event->value;
		*last = li;
		last = &li->next;

		LM_DBG("queued up unsub for %.*s\n", li->s.len, li->s.s);
	}

	fs_api.evs_unsub(sock, &fss_mod_tag, evlist);
	reply = init_mi_tree(200, MI_SSTR(MI_OK));

out_free:
	lock_stop_write(db_reload_lk);

	_free_str_list(evlist, osips_pkg_free, NULL);
	if (do_unref) {
		LM_DBG("unreffing sock %s:%d\n", sock->host.s, sock->port);
		fs_api.put_evs(sock);
	}
	return reply;
}

struct mi_root *mi_fs_list(struct mi_root *cmd, void *_param)
{
	struct list_head *_;
	struct fs_evs_list *sock_list;
	struct mi_root *rpl_tree;
	struct mi_node *node, *_node, *rpl;
	struct mi_attr *attr;
	struct str_list *event;

	rpl_tree = init_mi_tree(200, MI_SSTR(MI_OK));
	if (!rpl_tree) {
		LM_ERR("oom\n");
		return NULL;
	}

	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	lock_start_read(db_reload_lk);

	list_for_each(_, fss_sockets) {
		sock_list = list_entry(_, struct fs_evs_list, list);

		node = add_mi_node_child(rpl, 0, "socket", 6, NULL, 0);
		if (!node)
			goto out_err;

		attr = addf_mi_attr(node, 0, "if", 2, "%s:%d",
		                    sock_list->sock->host.s, sock_list->sock->port);
		if (!attr)
			goto out_err;

		node = add_mi_node_child(node, MI_IS_ARRAY, "events", 6, NULL, 0);
		if (!node)
			goto out_err;

		for (event = sock_list->events; event; event = event->next) {
			_node = add_mi_node_child(node, 0, "event", 5, NULL, 0);
			if (!_node)
				goto out_err;

			if (!add_mi_node_child(_node, 0, "name", 4,
			                       event->s.s, event->s.len))
				goto out_err;
		}
	}

	lock_stop_read(db_reload_lk);
	return rpl_tree;

out_err:
	lock_stop_read(db_reload_lk);
	LM_ERR("failed to list FS sockets\n");
	free_mi_tree(rpl_tree);
	return NULL;
}

struct mi_root *mi_fs_reload(struct mi_root *cmd, void *param)
{
	if (!have_db())
		return NULL;

	if (fss_db_reload() != 0) {
		LM_ERR("failed to reload DB data, keeping old data set\n");
		return init_mi_tree(500, MI_SSTR(MI_INTERNAL_ERR));
	}

	return init_mi_tree(200, MI_SSTR(MI_OK));
}
