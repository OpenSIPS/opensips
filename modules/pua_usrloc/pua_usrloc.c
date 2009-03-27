/*
 * $Id$
 *
 * pua_usrloc module - usrloc pua module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 * History:
 * --------
 *  2006-11-29  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>
#include <sys/stat.h>

#include "../../mi/mi.h" // ibc
#include "../../script_cb.h"
#include "../../sr_module.h"
#include "../../parser/parse_expires.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../mem/mem.h"
#include "../../locking.h"
#include "../../pt.h"
#include "../usrloc/ul_mod.h"
#include "../usrloc/usrloc.h"
#include "../usrloc/ul_callback.h"
#include "../pua/pua_bind.h"
#include "pua_usrloc.h"

MODULE_VERSION

#define BL_MAX_LINE 400


/** parameters */

str default_domain= {NULL, 0};
int pua_ul_publish= 0;
pua_api_t pua;
str pres_prefix= {0, 0};
str presence_server= {0, 0};
char *blfile = NULL;
regex_t *blregex = NULL;
gen_lock_t *bl_lock;

/* Structure containing pointers to usrloc functions */
usrloc_api_t ul;


/** module functions */

static int mod_init(void);
static int child_init(int);
static void destroy(void);

static int load_bl(int);
static int pua_check_bl(struct sip_msg* _msg, char* _s1, char* _s2);
static int it_list_fixup(void** param, int param_no);

static struct mi_root* mi_bl_reload(struct mi_root* cmd, void* param);
int pua_set_publish(struct sip_msg* msg , char* s1, char* s2);


static cmd_export_t cmds[]=
{
	{"pua_set_publish", (cmd_function)pua_set_publish, 0, 0, 0, REQUEST_ROUTE},
	{"pua_check_bl", (cmd_function)pua_check_bl, 1, it_list_fixup, 0,
	 REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[]={
	{"default_domain",	 STR_PARAM, &default_domain.s	},
	{"entity_prefix",	 STR_PARAM, &pres_prefix.s		},
	{"presence_server",	 STR_PARAM, &presence_server.s	},
	{"blacklist_file",	 STR_PARAM, &blfile				},
	{0,							 0,			0			}
};

static mi_export_t mi_cmds[]={
	{ "pua_usrloc_bl_reload",   mi_bl_reload,   MI_NO_INPUT_FLAG, 0, 0 },
	{ 0, 0, 0, 0, 0}
};

struct module_exports exports= {
	"pua_usrloc",				/* module name */
	DEFAULT_DLFLAGS,            /* dlopen flags */
	cmds,						/* exported functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,					/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	(response_function) 0,		/* response handling function */
	destroy,					/* destroy function */
	child_init                  /* per-child init function */
};


/**
 * init module function
 */
static int mod_init(void)
{
	bind_usrloc_t bind_usrloc;
	bind_pua_t bind_pua;

	LM_INFO("initializing module...\n");

	if(default_domain.s == NULL )
	{	
		LM_ERR("default domain parameter not set\n");
		return -1;
	}
	default_domain.len= strlen(default_domain.s);
	
	if(pres_prefix.s == NULL )
	{	
		LM_DBG("No pres_prefix configured\n");
	}
	else
		pres_prefix.len= strlen(pres_prefix.s);
	
	if(presence_server.s)
	{
		presence_server.len= strlen(presence_server.s);
	}

	bind_usrloc = (bind_usrloc_t)find_export("ul_bind_usrloc", 1, 0);
	if (!bind_usrloc)
	{
		LM_ERR("Can't bind usrloc\n");
		return -1;
	}
	if (bind_usrloc(&ul) < 0)
	{
		LM_ERR("Can't bind usrloc\n");
		return -1;
	}
	if(ul.register_ulcb == NULL)
	{
		LM_ERR("Could not import ul_register_ulcb\n");
		return -1;
	}

	if(ul.register_ulcb(UL_CONTACT_INSERT, ul_publish, 0)< 0)
	{
		LM_ERR("can not register callback for"
				" insert\n");
		return -1;
	}
	if(ul.register_ulcb(UL_CONTACT_EXPIRE, ul_publish, 0)< 0)
	{
		LM_ERR("can not register callback for"
				" expire\n");
		return -1;
	}
	
	if(ul.register_ulcb(UL_CONTACT_UPDATE, ul_publish, 0)< 0)
	{
		LM_ERR("can not register callback for update\n");
		return -1;
	}
	
	if(ul.register_ulcb(UL_CONTACT_DELETE, ul_publish, 0)< 0)
	{
		LM_ERR("can not register callback for delete\n");
		return -1;
	}
	
	bind_pua= (bind_pua_t)find_export("bind_pua", 1,0);
	if (!bind_pua)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}
	
	if (bind_pua(&pua) < 0)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}
	if(pua.send_publish == NULL)
	{
		LM_ERR("Could not import send_publish\n");
		return -1;
	}
	pua_send_publish= pua.send_publish;

	if(pua.send_subscribe == NULL)
	{
		LM_ERR("Could not import send_subscribe\n");
		return -1;
	}
	pua_send_subscribe= pua.send_subscribe;
	
	/* register post-script pua_unset_publish unset function */
	if(register_script_cb(pua_unset_publish, POST_SCRIPT_CB|REQ_TYPE_CB, 0)<0)
	{
		LM_ERR("failed to register POST request callback\n");
		return -1;
	}

	// If blacklist file parameter is set load and parse it.
	if(blfile!=NULL)
	{
		// Create the bl_lock and init it.
		bl_lock = lock_alloc();
		if(bl_lock == NULL)
		{
			LM_ERR("cannot allocate the bl_lock\n");
			return E_OUT_OF_MEM;
		}
		if(lock_init(bl_lock) == NULL)
		{
			LM_ERR("cannot init the bl_lock\n");
			lock_dealloc(bl_lock);
			return -1;
		}
		
		// Load the blacklist regex.
		LM_NOTICE("loading blacklist regex...\n");
		if (load_bl(0))
		{
			LM_ERR("failed to load blacklist\n");
			return -1;
		}
	}

	return 0;
}

static int child_init(int rank)
{
	LM_DBG("child [%d]  pid [%d]\n", rank, getpid());
	return 0;
}	

static void destroy(void)
{	
	LM_DBG("destroying module...\n");

	if(blregex)
		shm_free(blregex);

	return;
}

// Convert the blfile content into a regular expresion and store it in blregex.
static int load_bl(int reload)
{
	FILE *f = NULL;
	struct stat file_status;
	char line[BL_MAX_LINE], *pattern;

	f = fopen(blfile, "r");
	if(f==NULL)
	{
		LM_ERR("can't open blacklist file [%s]\n", blfile);
		return -1;
	}

	// Get the file size.
	if(stat(blfile, &file_status) != 0)
	{
		LM_ERR("can't stat blacklist file [%s]\n", blfile);
		fclose(f);
		return -1;
	}
	
	// pattern size = blfile size + '(' + ')' + '\0'.
	if ((pattern = malloc(sizeof(char)*(file_status.st_size+3))) == 0)
	{
		LM_ERR("no more memory to store pattern\n");
		fclose(f);
		return E_OUT_OF_MEM;
	}

	// Fill pattern with '\0'.
	memset(pattern, '\0', file_status.st_size+3);

	// Start pattern with '('.
	pattern[0] = '(';
	
	while (fgets(line, BL_MAX_LINE, f) != NULL)
	{
		// Ignore comments or empty lines.
		if (line[0]=='\n' || line[0]=='#' || line[0]==' ' || line[0]=='\t') {
			continue;
		}

		// Replace '\n' with '|' (except when it's the last char of file).
		if (line[strlen(line)-1] == '\n')
			line[strlen(line)-1]='|';

		// Append the line to pattern.
		memcpy(pattern+strlen(pattern), line, strlen(line));
	}
	fclose(f);
	
	// Delete last '|' if there is nothing else after it.
	if (pattern[strlen(pattern)-1] == '|')
		pattern[strlen(pattern)-1] = '\0';

	// End pattern with ')'.
	pattern[strlen(pattern)] = ')';
	
	LM_NOTICE("<PATTERN>%s</PATTERN>\n", pattern);
	
	// Get the lock.
	lock_get(bl_lock);

	// Init.
	if (reload == 0) {
		// Creating blregex object.
		if ((blregex=(regex_t*)shm_malloc(sizeof(regex_t)))==0)
		{
			LM_ERR("no more shm memory for blregex\n");
			lock_release(bl_lock);
			free(pattern);
			return E_OUT_OF_MEM;
		}
	}
	// Reload (from MI command).
	else {
		// FIXME: When running this, OpenSIPs fails (sometimes segmentation
		// fault, sometimes it doesn't reply to SIP requests...). Also, the
		// new compiled regcomp doesn't work.
		//   http://dev.sipdoc.net/issues/show/11
	}

	// Compile the regular expression.
	if (regcomp(blregex, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE|REG_NEWLINE))
	{
		LM_ERR("regcomp: bad pattern\n");
		shm_free(blregex);
		lock_release(bl_lock);
		free(pattern);
		return E_BAD_RE;
	}

	// Release the lock.
	lock_release(bl_lock);

	free(pattern);

	return 0;
}

// Return true if the argument matches blregex.
static int pua_check_bl(struct sip_msg *msg, char *key, char *foo)
{
	str s;
	int match=0;

	if(blregex==NULL) {
		LM_ERR("blregex is NULL, 'pua_usrloc_blacklist' parameter must be set for this function to work!\n");
		return -1;
	}

	if (pv_printf_s(msg, (pv_elem_t*)key, &s)<0) {
		LM_ERR("failed to print the format\n");
		return -1;
	}

	//LM_NOTICE("matching '%s' against blregex...\n", s.s);  // TODO: Poner DBG
	
	lock_get(bl_lock);
	// FIXME: Cuando da coredump al hacer el MI es justo aquí.
	match = regexec(blregex, s.s, 0, NULL, 0);
	lock_release(bl_lock);
	
	if (!match) {
		LM_NOTICE("%s matches blregex\n", s.s);  // TODO: Poner DBG
		return 1;
	}
	else {
		LM_NOTICE("%s doesn't match blregex\n", s.s);  // TODO: Poner DBG
		return -1;
	}
}

static int it_list_fixup(void** param, int param_no)
{
	pv_elem_t *model;
	str s;
	if(*param)
	{
		s.s = (char*)(*param); s.len = strlen(s.s);
		if(pv_parse_format(&s, &model)<0)
		{
			LM_ERR("wrong format[%s]\n",(char*)(*param));
			return E_UNSPEC;
		}
		*param = (void*)model;
	}
	return 0;
}

// MI functions.
static struct mi_root* mi_bl_reload(struct mi_root* cmd_tree, void* param)
{
	if(blfile!=NULL)
	{
		LM_NOTICE("reloading blacklist regex...\n");
		// Call load_bl() with parameter 1 (reload)
		if (load_bl(1))
		{
			LM_ERR("failed to load blacklist\n");
			return init_mi_tree(500, MI_INTERNAL_ERR_S, MI_INTERNAL_ERR_LEN);
		}
		return init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	}
	else
	{
		return init_mi_tree(403, "Feature not enabled", 19);
	}
}
