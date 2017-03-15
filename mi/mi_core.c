/*
 * Copyright (C) 2006 Voice Sistem SRL
 * Copyright (C) 2011-2013 OpenSIPS Solutions
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
 *
 * history:
 * ---------
 *  2006-09-08  first version (bogdan)
 */


/*!
 * \file
 * \brief MI :: Core
 * \ingroup mi
 */



#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>

#include "../dprint.h"
#include "../globals.h"
#include "../ut.h"
#include "../pt.h"
#include "../net/net_tcp.h"
#include "../mem/mem.h"
#include "../cachedb/cachedb.h"
#include "../evi/event_interface.h"
#include "mi.h"
#include "mi_trace.h"


static str    up_since_ctime;

static int init_mi_uptime(void)
{
	char *p;

	p = ctime(&startup_time);
	up_since_ctime.len = strlen(p)-1;
	up_since_ctime.s = (char*)pkg_malloc(up_since_ctime.len);
	if (up_since_ctime.s==0) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memcpy(up_since_ctime.s, p , up_since_ctime.len);
	return 0;
}


static struct mi_root *mi_uptime(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;
	time_t now;
	char   *p;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	time(&now);
	p = ctime(&now);
	node = add_mi_node_child( rpl, MI_DUP_VALUE, MI_SSTR("Now"),
		p, strlen(p)-1);
	if (node==0)
		goto error;

	node = add_mi_node_child( rpl, 0, MI_SSTR("Up since"),
		up_since_ctime.s, up_since_ctime.len);
	if (node==0)
		goto error;

	node = addf_mi_node_child( rpl, 0, MI_SSTR("Up time"),
		"%lu [sec]", (unsigned long)difftime(now, startup_time) );
	if (node==0)
		goto error;

	return rpl_tree;
error:
	LM_ERR("failed to add node\n");
	free_mi_tree(rpl_tree);
	return 0;
}



static struct mi_root *mi_version(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	node = add_mi_node_child( rpl, 0, MI_SSTR("Server"), SERVER_HDR+8,
		SERVER_HDR_LEN-8);
	if (node==0) {
		LM_ERR("failed to add node\n");
		free_mi_tree(rpl_tree);
		return 0;
	}

	return rpl_tree;
}



static struct mi_root *mi_pwd(struct mi_root *cmd, void *param)
{
	static int max_len = 0;
	static char *cwd_buf = 0;
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;

	if (cwd_buf==NULL) {
		max_len = pathmax();
		cwd_buf = pkg_malloc(max_len);
		if (cwd_buf==NULL) {
			LM_ERR("no more pkg mem\n");
			return 0;
		}
	}

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	if (getcwd(cwd_buf, max_len)==0) {
		LM_ERR("getcwd failed = %s\n",strerror(errno));
		goto error;
	}

	node = add_mi_node_child( rpl, 0, MI_SSTR("WD"), cwd_buf,strlen(cwd_buf));
	if (node==0) {
		LM_ERR("failed to add node\n");
		goto error;
	}

	return rpl_tree;
error:
	free_mi_tree(rpl_tree);
	return 0;
}



static struct mi_root *mi_arg(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;
	int n;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	for ( n=0; n<my_argc ; n++ ) {
		node = add_mi_node_child(rpl, 0, 0, 0, my_argv[n], strlen(my_argv[n]));
		if (node==0) {
			LM_ERR("failed to add node\n");
			free_mi_tree(rpl_tree);
			return 0;
		}
	}

	return rpl_tree;
}



static struct mi_root *mi_which(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_cmd  *cmds;
	struct mi_node *rpl;
	struct mi_node *node;
	int size;
	int i;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	get_mi_cmds( &cmds, &size);
	for ( i=0 ; i<size ; i++ ) {
		node = add_mi_node_child( rpl, 0, 0, 0, cmds[i].name.s,
			cmds[i].name.len);
		if (node==0) {
			LM_ERR("failed to add node\n");
			free_mi_tree(rpl_tree);
			return 0;
		}
	}

	return rpl_tree;
}



static struct mi_root *mi_ps(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;
	struct mi_attr *attr;
	char *p;
	int len;
	int i;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	for ( i=0 ; i<counted_processes ; i++ ) {
		node = add_mi_node_child(rpl, 0, MI_SSTR("Process"), 0, 0 );
		if (node==0)
			goto error;

		p = int2str((unsigned long)i, &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("ID"), p, len);
		if (attr==0)
			goto error;

		p = int2str((unsigned long)pt[i].pid, &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("PID"), p, len);
		if (attr==0)
			goto error;

		attr = add_mi_attr( node, 0, MI_SSTR("Type"),
			pt[i].desc, strlen(pt[i].desc));
		if (attr==0)
			goto error;
	}

	return rpl_tree;
error:
	LM_ERR("failed to add node\n");
	free_mi_tree(rpl_tree);
	return 0;
}



static struct mi_root *mi_kill(struct mi_root *cmd, void *param)
{
	kill(0, SIGTERM);

	return 0;
}



static struct mi_root *mi_log_level(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node;
	char *p;
	int len;
	int new_level, i;
	pid_t pid = 0;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;

	node = cmd->node.kids;
	if (node!=NULL) {
		if (str2sint( &node->value, &new_level) < 0)
			goto out_bad_param;

		node = node->next;
		if (node && str2sint( &node->value, &pid) < 0)
			goto out_bad_param;

	/* if called without arguments, print the table and exit */
	} else {
		rpl_tree->node.flags |= MI_IS_ARRAY;

		for (i = 0; i < counted_processes; i++) {
			node = add_mi_node_child(&rpl_tree->node, 0, MI_SSTR("Process"), 0, 0);
			if (node==0)
				goto out;

			p = int2str((unsigned long)pt[i].pid, &len);
			if (!add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("PID"), p, len))
				goto out;

			p = sint2str((unsigned long)pt[i].log_level, &len);
			if (!add_mi_attr( node, MI_DUP_VALUE, MI_SSTR("Log level"), p,len))
				goto out;

			if (!add_mi_attr( node, 0, MI_SSTR("Type"), pt[i].desc,
							  strlen(pt[i].desc)))
				goto out;
		}

		return rpl_tree;
	}

	p = sint2str((long)new_level, &len);
	if (pid)
		node = add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE,
			MI_SSTR("New log level"), p, len);
	else
		node = add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE,
			MI_SSTR("New global log level"), p, len);

	if (node==0)
		goto out;

	if (pid) {
		/* convert pid to OpenSIPS id */
		i = id_of_pid(pid);
		if (i == -1)
			goto out_bad_param;

		__set_proc_default_log_level(i, new_level);
		__set_proc_log_level(i, new_level);
	} else
		set_global_log_level(new_level);

	return rpl_tree;

out_bad_param:
	free_mi_tree(rpl_tree);
	return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM));

out:
	free_mi_tree(rpl_tree);
	return NULL;
}


static struct mi_root *mi_cachestore(struct mi_root *cmd, void *param)
{
	str mc_system;
	str attr;
	str value;
	unsigned int expires = 0;
	struct mi_node* node= NULL;
	str expires_str;

	if(cmd == NULL)
	{
		LM_ERR("NULL command\n");
		return init_mi_tree(404, MI_SSTR("NULL command"));
	}

	node = cmd->node.kids;
	if(node == NULL)
		return init_mi_tree(404, MI_SSTR("Too few arguments"));

	mc_system = node->value;
	if(mc_system.s == NULL || mc_system.len== 0)
	{
		LM_ERR( "empty memory cache system parameter\n");
		return init_mi_tree(404, MI_SSTR("Empty memory cache id"));
	}

	node = node->next;
	if(node == NULL)
		return init_mi_tree(404, MI_SSTR("Too few arguments"));

	attr = node->value;
	if(attr.s == NULL || attr.len== 0)
	{
		LM_ERR( "empty attribute name parameter\n");
		return init_mi_tree(404, MI_SSTR("Empty attribute name"));
	}

	node = node->next;
	if(node == NULL)
		return init_mi_tree(404, MI_SSTR("Too few arguments"));

	value = node->value;
	if(value.s == NULL || value.len== 0)
	{
		LM_ERR( "empty value parameter\n");
		return init_mi_tree(404, MI_SSTR("Empty value argument"));
	}

	/* expires parameter is not compulsory */
	node = node->next;
	if(node!= NULL)
	{
		expires_str = node->value;
		if(expires_str.s == NULL || expires_str.len == 0)
		{
			LM_ERR( "empty expires parameter\n");
			return init_mi_tree(404, MI_SSTR("Empty expires argument"));
		}
		if(str2int(&expires_str, &expires)< 0)
		{
			LM_ERR("wrong format for expires argument- needed int\n");
			return init_mi_tree(404,
				MI_SSTR("Bad format for expires argument"));
		}

		node = node->next;
		if(node!= NULL)
			return init_mi_tree(404, MI_SSTR("Too many parameters"));
	}

	if(cachedb_store(&mc_system, &attr, &value,expires)< 0)
	{
		LM_ERR("cachedb_store command failed\n");
		return init_mi_tree(500, MI_SSTR("Cache store command failed"));
	}

	return init_mi_tree(200, MI_SSTR(MI_OK));
}


static struct mi_root *mi_cachefetch(struct mi_root *cmd, void *param)
{
	str mc_system;
	str attr;
	str value;
	struct mi_node* node= NULL;
	struct mi_root *rpl_tree= NULL;
	int ret;

	if(cmd == NULL)
	{
		LM_ERR("NULL command\n");
		return init_mi_tree(404, MI_SSTR("NULL command"));
	}

	node = cmd->node.kids;
	if(node == NULL)
		return init_mi_tree(404, MI_SSTR("Too few arguments"));

	mc_system = node->value;
	if(mc_system.s == NULL || mc_system.len== 0)
	{
		LM_ERR( "empty memory cache system parameter\n");
		return init_mi_tree(404, MI_SSTR("Empty memory cache id"));
	}

	node = node->next;
	if(node == NULL)
		return init_mi_tree(404, MI_SSTR("Too few arguments"));

	attr = node->value;
	if(attr.s == NULL || attr.len== 0)
	{
		LM_ERR( "empty attribute name parameter\n");
		return init_mi_tree(404,MI_SSTR( "Empty attribute name"));
	}

	node = node->next;
	if(node != NULL)
		return init_mi_tree(404, MI_SSTR("Too many arguments"));

	ret = cachedb_fetch(&mc_system, &attr, &value);
	if(ret== -1)
	{
		LM_ERR("cachedb_fetch command failed\n");
		return init_mi_tree(500, MI_SSTR("Cache fetch command failed"));
	}

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
	{
		if(value.s)
			pkg_free(value.s);
		return 0;
	}

	if(ret == -2 || value.s == 0 || value.len == 0)
	{
		add_mi_node_child( &rpl_tree->node, 0, 0, 0,
			MI_SSTR("Value not found") );
		goto done;
	}

	addf_mi_node_child( &rpl_tree->node, 0, 0, 0, "%.*s = [%.*s]", attr.len,
			attr.s, value.len, value.s);

	pkg_free(value.s);

done:
	return rpl_tree;
}


static struct mi_root *mi_cacheremove(struct mi_root *cmd, void *param)
{
	str mc_system;
	str attr;
	struct mi_node* node= NULL;

	if(cmd == NULL)
	{
		LM_ERR("NULL command\n");
		return init_mi_tree(404, MI_SSTR("NULL command"));
	}

	node = cmd->node.kids;
	if(node == NULL)
		return init_mi_tree(404, MI_SSTR("Too few arguments"));

	mc_system = node->value;
	if(mc_system.s == NULL || mc_system.len== 0)
	{
		LM_ERR( "empty memory cache system parameter\n");
		return init_mi_tree(404, MI_SSTR("Empty memory cache id"));
	}

	node = node->next;
	if(node == NULL)
		return init_mi_tree(404, MI_SSTR("Too few arguments"));

	attr = node->value;
	if(attr.s == NULL || attr.len== 0)
	{
		LM_ERR( "empty attribute name parameter\n");
		return init_mi_tree(404, MI_SSTR("Empty attribute name"));
	}

	node = node->next;
	if(node != NULL)
		return init_mi_tree(404, MI_SSTR("Too many parameters"));

	if(cachedb_remove(&mc_system, &attr)< 0)
	{
		LM_ERR("cachedb_remove command failed\n");
		return init_mi_tree(500, MI_SSTR("Cache remove command failed"));
	}

	return init_mi_tree(200, MI_SSTR(MI_OK));
}



static mi_export_t mi_core_cmds[] = {
	{ "uptime", "prints various time information about OpenSIPS - "
		"when it started to run, for how long it runs",
		mi_uptime,     MI_NO_INPUT_FLAG,  0,  init_mi_uptime },
	{ "version", "prints the version string of a runningOpenSIPS",
		mi_version,    MI_NO_INPUT_FLAG,  0,  0 },
	{ "pwd", "prints the working directory of OpenSIPS",
		mi_pwd,        MI_NO_INPUT_FLAG,  0,  0 },
	{ "arg", "returns the full list of arguments used at startup",
		mi_arg,        MI_NO_INPUT_FLAG,  0,  0 },
	{ "which", "lists all avaialbe MI commands",
		mi_which,      MI_NO_INPUT_FLAG,  0,  0 },
	{ "ps", "lists all processes used by OpenSIPS",
		mi_ps,         MI_NO_INPUT_FLAG,  0,  0 },
	{ "kill", "terminates OpenSIPS",
		mi_kill,       MI_NO_INPUT_FLAG,  0,  0 },
	{ "log_level", "gets/sets the per process or global log level in OpenSIPS",
		mi_log_level,                 0,  0,  0 },
#if defined(QM_MALLOC) && defined(DBG_MALLOC)
	{ "shm_check", "complete scan of the shared memory pool "
		"(if any error is found, OpenSIPS will abort!)",
		mi_shm_check, MI_NO_INPUT_FLAG, 0,  0 },
#endif
	{ "cache_store", "stores in a cache system a string value",
		mi_cachestore,                0,  0,  0 },
	{ "cache_fetch", "queries for a cache stored value",
		mi_cachefetch,                0,  0,  0 },
	{ "cache_remove", "removes a record from the cache system",
		mi_cacheremove,               0,  0,  0 },
	{ "event_subscribe", "subscribes an event to the Event Interface",
		mi_event_subscribe,           0,  0,  0 },
	{ "events_list", "lists all the events advertised through the "
		"Event Interface",
		mi_events_list,MI_NO_INPUT_FLAG,  0,  0 },
	{ "subscribers_list", "lists all the Event Interface subscribers; "
		"Params: [ event [ subscriber ]]",
		mi_subscribers_list,          0,  0,  0 },
	{ "list_tcp_conns", "list all ongoing TCP based connections",
		mi_tcp_list_conns,MI_NO_INPUT_FLAG,0, 0 },
	{ "help", "prints information about MI commands usage",
		mi_help,                      0,  0,  0 },
	{ 0, 0, 0, 0, 0, 0}
};



int init_mi_core(void)
{
	if (register_mi_mod( "core", mi_core_cmds)<0) {
		LM_ERR("unable to register core MI cmds\n");
		return -1;
	}

	try_load_trace_api();

	return 0;
}
