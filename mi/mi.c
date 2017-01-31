/*
 * Copyright (C) 2006 Voice Sistem SRL
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
 * History:
 * ---------
 *  2006-09-08  first version (bogdan)
 */

/*!
 * \file
 * \brief MI :: Attributes
 * \ingroup mi
 */

/*!
 * \defgroup mi OpenSIPS Management Interface
 *
 * The OpenSIPS management interface (MI) is a plugin architecture with a few different
 * handlers that gives access to the management interface over various transports.
 *
 * The OpenSIPS core and modules register commands to the interface at runtime.
 * Look into the various module documentation files for information of these
 * commands.
 *
 */

#include <string.h>

#include "../dprint.h"
#include "../mem/mem.h"
#include "../mem/shm_mem.h"
#include "mi.h"
#include "mi_trace.h"

static struct mi_cmd*  mi_cmds = 0;
static int mi_cmds_no = 0;

mi_flush_f *crt_flush_fnct = NULL;
void *crt_flush_param = NULL;


static inline int get_mi_id( char *name, int len)
{
	int n;
	int i;

	for( n=0,i=0 ; i<len ; n+=name[i] ,i++ );
	return n;
}


static inline struct mi_cmd* lookup_mi_cmd_id(int id,char *name, int len)
{
	int i;

	for( i=0 ; i<mi_cmds_no ; i++ ) {
		if ( id==mi_cmds[i].id && len==mi_cmds[i].name.len &&
		memcmp(mi_cmds[i].name.s,name,len)==0 )
			return &mi_cmds[i];
	}

	return 0;
}


int register_mi_mod( char *mod_name, mi_export_t *mis)
{
	int ret;
	int i;

	if (mis==0)
		return 0;

	for ( i=0 ; mis[i].name ; i++ ) {
		ret = register_mi_cmd( mis[i].cmd, mis[i].name, mis[i].help,
				mis[i].param, mis[i].init_f, mis[i].flags, mod_name);
		if (ret!=0) {
			LM_ERR("failed to register cmd <%s> for module %s\n",
					mis[i].name,mod_name);
		}
	}

	return 0;
}


int init_mi_child(void)
{
	int i;

	for ( i=0 ; i<mi_cmds_no ; i++ ) {
		if ( mi_cmds[i].init_f && mi_cmds[i].init_f()!=0 ) {
			LM_ERR("failed to init <%.*s>\n",
					mi_cmds[i].name.len,mi_cmds[i].name.s);
			return -1;
		}
	}
	return 0;
}



int register_mi_cmd( mi_cmd_f f, char *name, char *help, void *param,
									mi_child_init_f in, unsigned int flags, char* mod_name)
{
	struct mi_cmd *cmds;
	int id;
	int len;

	if (f==0 || name==0) {
		LM_ERR("invalid params f=%p, name=%s\n", f, name);
		return -1;
	}

	if (flags&MI_NO_INPUT_FLAG && flags&MI_ASYNC_RPL_FLAG) {
		LM_ERR("invalids flags for <%s> - "
			"async functions must take input\n",name);
	}

	len = strlen(name);
	id = get_mi_id(name,len);

	if (lookup_mi_cmd_id( id, name, len)) {
		LM_ERR("command <%.*s> already registered\n", len, name);
		return -1;
	}

	cmds = (struct mi_cmd*)pkg_realloc( mi_cmds,
			(mi_cmds_no+1)*sizeof(struct mi_cmd) );
	if (cmds==0) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	mi_cmds = cmds;
	mi_cmds_no++;

	cmds = &cmds[mi_cmds_no-1];

	cmds->f = f;
	cmds->init_f = in;
	cmds->flags = flags;
	cmds->name.s = name;
	cmds->name.len = len;
	cmds->module.s = mod_name;
	cmds->module.len = strlen(mod_name);
	cmds->help.s = help;
	cmds->help.len = help ? strlen(help) : 0;
	cmds->id = id;
	cmds->param = param;

	/**
	 * FIXME we should check if trace_api is loaded not to lose unnecessary space
	 * but some mi commands might have been already registered before loading the api
	 * an example is the statistics mi commands
	 */
	cmds->trace_mask = shm_malloc(sizeof(volatile unsigned char));
	if ( !cmds->trace_mask ) {
		LM_ERR("no more shm mem!\n");
		return -1;
	}

	/* by default all commands are traced */
	*cmds->trace_mask = (~(volatile unsigned char)0);

	return 0;
}



struct mi_cmd* lookup_mi_cmd( char *name, int len)
{
	int id;

	id = get_mi_id(name,len);
	return lookup_mi_cmd_id( id, name, len);
}


void get_mi_cmds( struct mi_cmd** cmds, int *size)
{
	*cmds = mi_cmds;
	*size = mi_cmds_no;
}

#define MI_HELP_STR "help mi_cmd - " \
	"returns information about 'mi_cmd'"
#define MI_UNKNOWN_CMD "unknown MI command"
#define MI_NO_HELP "not available for this command"
#define MI_MODULE_STR "by \"%.*s\" module"

struct mi_root *mi_help(struct mi_root *root, void *param)
{
	struct mi_root *rpl_tree = 0;
	struct mi_node *node;
	struct mi_node *rpl;
	struct mi_cmd *cmd;

	if (!root) {
		LM_ERR("invalid MI command\n");
		return 0;
	}
	node = root->node.kids;
	if (!node || !node->value.len || !node->value.s) {
		rpl_tree = init_mi_tree(200, MI_SSTR(MI_OK));
		if (!rpl_tree) {
			LM_ERR("cannot init mi tree\n");
			return 0;
		}
		rpl = &rpl_tree->node;
		if (!add_mi_node_child(rpl, 0, "Usage", 5, MI_SSTR(MI_HELP_STR))) {
			LM_ERR("cannot add new child\n");
			goto error;
		}
	} else {
		/* search the command */
		cmd = lookup_mi_cmd(node->value.s, node->value.len);
		if (!cmd)
			return init_mi_tree(404, MI_SSTR(MI_UNKNOWN_CMD));
		rpl_tree = init_mi_tree(200, MI_SSTR(MI_OK));
		if (!rpl_tree) {
			LM_ERR("cannot init mi tree\n");
			return 0;
		}
		rpl = &rpl_tree->node;
		if (!addf_mi_node_child(rpl, 0, "Help", 4, "%s", cmd->help.s ?
					cmd->help.s : MI_NO_HELP)) {
			LM_ERR("cannot add new child\n");
			goto error;
		}
		if (cmd->module.len && cmd->module.s &&
				!add_mi_node_child(rpl, 0, "Exported by", 11,
					cmd->module.s, cmd->module.len)) {
			LM_ERR("cannot add new child\n");
			goto error;
		}
	}

	return rpl_tree;

error:
	if (rpl_tree)
		free_mi_tree(rpl_tree);
	return 0;
}
