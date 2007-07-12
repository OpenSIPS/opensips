/*
 * $Id$
 *
 * Copyright (C) 2006 Voice Sistem SRL
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2006-09-08  first version (bogdan)
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
#include "../mem/mem.h"
#include "mi.h"


#define MAX_CTIME_LEN 24

static time_t up_since;
static char *up_since_ctime;

static int init_mi_uptime()
{
	time(&up_since);
	up_since_ctime = (char*)pkg_malloc(MAX_CTIME_LEN+1);
	if (up_since_ctime==0) {
		LOG(L_ERR,"ERROR:mi:init_mi_uptime: no more pkg mem\n");
		return -1;
	}
	sprintf( up_since_ctime, "%s" , ctime(&up_since));
	return 0;
}


static struct mi_root *mi_uptime(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;
	time_t now;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	time(&now);
	node = add_mi_node_child( rpl, MI_DUP_VALUE, "Now", 3, ctime(&now),
		MAX_CTIME_LEN);
	if (node==0)
		goto error;

	node = add_mi_node_child( rpl, 0, "Up since", 8, up_since_ctime,
		MAX_CTIME_LEN);
	if (node==0)
		goto error;

	node = addf_mi_node_child( rpl, 0, "Up time", 7, "%lu [sec]",
		(unsigned long)difftime(now, up_since) );
	if (node==0)
		goto error;

	return rpl_tree;
error:
	LOG(L_ERR,"ERROR:mi_uptime: failed to add node\n");
	free_mi_tree(rpl_tree);
	return 0;
}



static struct mi_root *mi_version(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	node = add_mi_node_child( rpl, 0, "Server", 6, SERVER_HDR+8,
		SERVER_HDR_LEN-8);
	if (node==0) {
		LOG(L_ERR,"ERROR:mi_version: failed to add node\n");
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
			LOG(L_ERR, "ERROR:mi_pwd: no more pkg mem\n");
			return 0;
		}
	}

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	if (getcwd(cwd_buf, max_len)==0) {
		LOG(L_ERR,"ERROR:mi_pwd: getcwd failed = %s\n",strerror(errno));
		goto error;
	}

	node = add_mi_node_child( rpl, 0, "WD", 2, cwd_buf,strlen(cwd_buf));
	if (node==0) {
		LOG(L_ERR,"ERROR:mi_pwd: failed to add node\n");
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

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	for ( n=0; n<my_argc ; n++ ) {
		node = add_mi_node_child(rpl, 0, 0, 0, my_argv[n], strlen(my_argv[n]));
		if (node==0) {
			LOG(L_ERR,"ERROR:mi_arg: failed to add node\n");
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

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	get_mi_cmds( &cmds, &size);
	for ( i=0 ; i<size ; i++ ) {
		node = add_mi_node_child( rpl, 0, 0, 0, cmds[i].name.s,
			cmds[i].name.len);
		if (node==0) {
			LOG(L_ERR,"ERROR:mi_which: failed to add node\n");
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

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	for ( i=0 ; i<process_count() ; i++ ) {
		node = add_mi_node_child(rpl, 0, "Process", 7, 0, 0 );
		if (node==0)
			goto error;

		p = int2str((unsigned long)i, &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "ID", 2, p, len);
		if (attr==0)
			goto error;

		p = int2str((unsigned long)pt[i].pid, &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "PID", 3, p, len);
		if (attr==0)
			goto error;

		attr = add_mi_attr( node, 0, "Type", 4,
			pt[i].desc, strlen(pt[i].desc));
		if (attr==0)
			goto error;
	}

	return rpl_tree;
error:
	LOG(L_ERR,"ERROR:mi_ps: failed to add node\n");
	free_mi_tree(rpl_tree);
	return 0;
}



static struct mi_root *mi_kill(struct mi_root *cmd, void *param)
{
	kill(0, SIGTERM);

	return 0;
}



static struct mi_root *mi_debug(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node;
	char *p;
	int len;
	int new_debug;

#ifdef CHANGEABLE_DEBUG_LEVEL
	node = cmd->node.kids;
	if (node!=NULL) {
		if (str2sint( &node->value, &new_debug) < 0)
			return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
	} else
		new_debug = *debug;
#else
		new_debug = debug;
#endif

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;

	p = sint2str((long)new_debug, &len);
	node = add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE, "DEBUG", 5,
		p, len);
	if (node==0) {
		free_mi_tree(rpl_tree);
		return 0;
	}

#ifdef CHANGEABLE_DEBUG_LEVEL
	*debug = new_debug;
#endif

	return rpl_tree;
}



static mi_export_t mi_core_cmds[] = {
	{ "uptime",   mi_uptime,   MI_NO_INPUT_FLAG,  0,  init_mi_uptime },
	{ "version",  mi_version,  MI_NO_INPUT_FLAG,  0,  0 },
	{ "pwd",      mi_pwd,      MI_NO_INPUT_FLAG,  0,  0 },
	{ "arg",      mi_arg,      MI_NO_INPUT_FLAG,  0,  0 },
	{ "which",    mi_which,    MI_NO_INPUT_FLAG,  0,  0 },
	{ "ps",       mi_ps,       MI_NO_INPUT_FLAG,  0,  0 },
	{ "kill",     mi_kill,     MI_NO_INPUT_FLAG,  0,  0 },
	{ "debug",    mi_debug,                   0,  0,  0 },
	{ 0, 0, 0, 0, 0}
};



int init_mi_core()
{
	if (register_mi_mod( "core", mi_core_cmds)<0) {
		LOG(L_ERR, "ERROR:mi: unable to register core MI cmds\n");
		return -1;
	}

	return 0;
}
