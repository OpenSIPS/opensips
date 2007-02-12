/* $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
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
 *  2003-03-10  switched to new module_exports format: updated find_export,
 *               find_export_param, find_module (andrei)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-03-19  Support for flags in find_export (janakj)
 *  2003-03-29  cleaning pkg_mallocs introduced (jiri)
 *  2003-04-24  module version checking introduced (jiri)
 *  2004-09-19  compile flags are checked too (andrei)
 *  2006-03-02  added find_cmd_export_t(), killed find_exportp() and
 *              find_module() (bogdan)
 *  2006-11-28  added module_loaded() (Jeffrey Magder - SOMA Networks)
 */


#include "sr_module.h"
#include "dprint.h"
#include "error.h"
#include "mem/mem.h"

#include <strings.h>
#include <stdlib.h>
#include <string.h>


struct sr_module* modules=0;

#ifdef STATIC_EXEC
	extern struct module_exports* exec_exports();
#endif
#ifdef STATIC_TM
	extern struct module_exports* tm_exports();
#endif

#ifdef STATIC_MAXFWD
	extern struct module_exports* maxfwd_exports();
#endif

#ifdef STATIC_AUTH
        extern struct module_exports* auth_exports();
#endif

#ifdef STATIC_RR
        extern struct module_exports* rr_exports();
#endif

#ifdef STATIC_USRLOC
        extern struct module_exports* usrloc_exports();
#endif

#ifdef STATIC_SL
        extern struct module_exports* sl_exports();
#endif


/* initializes statically built (compiled in) modules*/
int register_builtin_modules()
{
	int ret;

	ret=0;
#ifdef STATIC_TM
	ret=register_module(tm_exports,"built-in", 0); 
	if (ret<0) return ret;
#endif

#ifdef STATIC_EXEC
	ret=register_module(exec_exports,"built-in", 0); 
	if (ret<0) return ret;
#endif

#ifdef STATIC_MAXFWD
	ret=register_module(maxfwd_exports, "built-in", 0);
	if (ret<0) return ret;
#endif

#ifdef STATIC_AUTH
	ret=register_module(auth_exports, "built-in", 0); 
	if (ret<0) return ret;
#endif
	
#ifdef STATIC_RR
	ret=register_module(rr_exports, "built-in", 0);
	if (ret<0) return ret;
#endif
	
#ifdef STATIC_USRLOC
	ret=register_module(usrloc_exports, "built-in", 0);
	if (ret<0) return ret;
#endif

#ifdef STATIC_SL
	ret=register_module(sl_exports, "built-in", 0);
	if (ret<0) return ret;
#endif
	
	return ret;
}



/* registers a module,  register_f= module register  functions
 * returns <0 on error, 0 on success */
int register_module(struct module_exports* e, char* path, void* handle)
{
	int ret;
	struct sr_module* mod;
	
	ret=-1;

	/* add module to the list */
	if ((mod=pkg_malloc(sizeof(struct sr_module)))==0){
		LOG(L_ERR, "register_module: memory allocation failure\n");
		ret=E_OUT_OF_MEM;
		goto error;
	}
	memset(mod,0, sizeof(struct sr_module));
	mod->path=path;
	mod->handle=handle;
	mod->exports=e;
	mod->next=modules;
	modules=mod;

	/* register module pseudo-variables */
	if (e->items) {
		DBG("DEBUG: register_pv: %s\n", e->name);
		if (register_items_mod(e->name, e->items)!=0) {
			LOG(L_ERR, "register_module: Error while registering "
				"pseudo-variables for module %s\n", e->name);
			pkg_free(mod);
			return -1;
		}
	}

	return 0;
error:
	return ret;
}

#ifndef DLSYM_PREFIX
/* define it to null */
#define DLSYM_PREFIX
#endif

static inline int version_control(void *handle, char *path)
{
	char **m_ver;
	char **m_flags;
	char* error;

	m_ver=(char **)dlsym(handle, DLSYM_PREFIX "module_version");
	if ((error=(char *)dlerror())!=0) {
		LOG(L_ERR, "ERROR: no version info in module <%s>: %s\n",
			path, error );
		return 0;
	}
	m_flags=(char **)dlsym(handle, DLSYM_PREFIX "module_flags");
	if ((error=(char *)dlerror())!=0) {
		LOG(L_ERR, "ERROR: no compile flags info in module <%s>: %s\n",
			path, error );
		return 0;
	}
	if (!m_ver || !(*m_ver)) {
		LOG(L_ERR, "ERROR: no version in module <%s>\n", path );
		return 0;
	}
	if (!m_flags || !(*m_flags)) {
		LOG(L_ERR, "ERROR: no compile flags in module <%s>\n", path );
		return 0;
	}
	
	if (strcmp(SER_FULL_VERSION, *m_ver)==0){
		if (strcmp(SER_COMPILE_FLAGS, *m_flags)==0)
			return 1;
		else {
			LOG(L_ERR, "ERROR: module compile flags mismatch for %s "
						" \ncore: %s \nmodule: %s\n",
						path, SER_COMPILE_FLAGS, *m_flags);
			return 0;
		}
	}
	LOG(L_ERR, "ERROR: module version mismatch for %s; "
		"core: %s; module: %s\n", path, SER_FULL_VERSION, *m_ver );
	return 0;
}

/* returns 0 on success , <0 on error */
int sr_load_module(char* path)
{
	void* handle;
	unsigned int moddlflags;
	char* error;
	struct module_exports* exp;
	struct sr_module* t;
	
	handle=dlopen(path, OPENSER_DLFLAGS); /* resolve all symbols now */
	if (handle==0){
		LOG(L_ERR, "ERROR: load_module: could not open module <%s>: %s\n",
					path, dlerror() );
		goto error;
	}
	
	for(t=modules;t; t=t->next){
		if (t->handle==handle){
			LOG(L_WARN, "WARNING: load_module: attempting to load the same"
						" module twice (%s)\n", path);
			goto skip;
		}
	}
	/* version control */
	if (!version_control(handle, path)) {
		exit(0);
	}
	exp = (struct module_exports*)dlsym(handle, DLSYM_PREFIX "exports");
	if ( (error =(char*)dlerror())!=0 ){
		LOG(L_ERR, "ERROR: load_module: %s\n", error);
		goto error1;
	}
	if(exp->dlflags!=DEFAULT_DLFLAGS && exp->dlflags!=OPENSER_DLFLAGS) {
		moddlflags = exp->dlflags;
		dlclose(handle);
		DBG("DEBUG:load_module:Reloading module %s with flags %d\n",
			 path, moddlflags);
		handle = dlopen(path, moddlflags);
		if (handle==0){
			LOG(L_ERR, "ERROR: load_module: could not open module <%s>: %s\n",
					path, dlerror() );
			goto error;
		}
		exp = (struct module_exports*)dlsym(handle, DLSYM_PREFIX "exports");
		if ( (error =(char*)dlerror())!=0 ){
			LOG(L_ERR, "ERROR: load_module: %s\n", error);
			goto error1;
		}
	}

	/* launch register */
	if (register_module(exp, path, handle)<0) goto error1;
	return 0;

error1:
	dlclose(handle);
error:
skip:
	return -1;
}



/* searches the module list and returns pointer to the "name" function or
 * 0 if not found 
 * flags parameter is OR value of all flags that must match
 */
cmd_function find_export(char* name, int param_no, int flags)
{
	cmd_export_t* cmd;

	cmd = find_cmd_export_t(name, param_no, flags);
	if (cmd==0)
		return 0;
	return cmd->function;
}



/* searches the module list and returns pointer to the "name" cmd_export_t
 * structure or 0 if not found 
 * flags parameter is OR value of all flags that must match
 */
cmd_export_t* find_cmd_export_t(char* name, int param_no, int flags)
{
	struct sr_module* t;
	cmd_export_t* cmd;

	for(t=modules;t;t=t->next){
		for(cmd=t->exports->cmds; cmd && cmd->name; cmd++){
			if((strcmp(name, cmd->name)==0)&&
			   (cmd->param_no==param_no) &&
			   ((cmd->flags & flags) == flags)
			  ){
				DBG("find_cmd_export_t: found <%s>(%d) in module %s [%s]\n",
					name, param_no, t->exports->name, t->path);
				return cmd;
			}
		}
	}
	DBG("find_cmd_export_t: <%s> not found \n", name);
	return 0;
}



/*
 * searches the module list and returns pointer to "name" function in module 
 * "mod" or 0 if not found
 * flags parameter is OR value of all flags that must match
 */
cmd_function find_mod_export(char* mod, char* name, int param_no, int flags)
{
	struct sr_module* t;
	cmd_export_t* cmd;

	for (t = modules; t; t = t->next) {
		if (strcmp(t->exports->name, mod) == 0) {
			for (cmd = t->exports->cmds;  cmd && cmd->name; cmd++) {
				if ((strcmp(name, cmd->name) == 0) &&
				    (cmd->param_no == param_no) &&
				    ((cmd->flags & flags) == flags)
				   ){
					DBG("find_mod_export: found <%s> in module %s [%s]\n",
					    name, t->exports->name, t->path);
					return cmd->function;
				}
			}
		}
	}

	DBG("find_mod_export: <%s> in module %s not found\n", name, mod);
	return 0;
}




void* find_param_export(char* mod, char* name, modparam_t type)
{
	struct sr_module* t;
	param_export_t* param;

	for(t = modules; t; t = t->next) {
		if (strcmp(mod, t->exports->name) == 0) {
			for(param=t->exports->params;param && param->name ; param++) {
				if ((strcmp(name, param->name) == 0) &&
				    (param->type == type)) {
					DBG("find_param_export: found <%s> in module %s [%s]\n",
					    name, t->exports->name, t->path);
					return param->param_pointer;
				}
			}
		}
	}
	DBG("find_param_export: parameter <%s> or module <%s> not found\n",
			name, mod);
	return 0;
}



void destroy_modules()
{
	struct sr_module* t, *foo;

	t=modules;
	while(t) {
		foo=t->next;
		if ((t->exports)&&(t->exports->destroy_f)) t->exports->destroy_f();
		pkg_free(t);
		t=foo;
	}
	modules=0;
}


/* recursive module child initialization; (recursion is used to
   process the module linear list in the same order in
   which modules are loaded in config file
*/

static int init_mod_child( struct sr_module* m, int rank, char *type )
{
	if (m) {
		/* iterate through the list; if error occurs,
		   propagate it up the stack */
		if (init_mod_child(m->next, rank, type)!=0)
			return -1;

		if (m->exports && m->exports->init_child_f) {
			DBG("DEBUG:init_mod_child: %s , rank=%d, module=%s\n", 
					type, rank, m->exports->name);
			if (m->exports->init_child_f(rank)<0) {
				LOG(L_ERR, "ERROR:init_mod_child: Error while initializing"
							" module %s, rank %d\n", m->exports->name,rank);
				return -1;
			} else {
				/* module correctly initialized */
				return 0;
			}
		}

		/* no init function -- proceed with success */
		return 0;
	} else {
		/* end of list */
		return 0;
	}
}


/*
 * per-child initialization
 */
int init_child(int rank)
{
	char* type;

	type = 0;

	switch(rank) {
	case PROC_MAIN:     type = "PROC_MAIN";     break;
	case PROC_TIMER:    type = "PROC_TIMER";    break;
	case PROC_TCP_MAIN: type = "PROC_TCP_MAIN"; break;
	case PROC_UNIXSOCK: type = "PROC_UNIXSOCK"; break;
	}

	if (!type) {
		if (rank>0)
			type = "CHILD";
		else
			type = "UNKNOWN";
	}

	return init_mod_child(modules, rank, type);
}



/* recursive module initialization; (recursion is used to
   process the module linear list in the same order in
   which modules are loaded in config file
*/

static int init_mod( struct sr_module* m )
{
	if (m) {
		/* iterate through the list; if error occurs,
		   propagate it up the stack
		 */
		if (init_mod(m->next)!=0) return -1;
		if (m->exports==0)
			return 0;
		if (m->exports->init_f) {
			DBG("DEBUG: init_mod: %s\n", m->exports->name);
			if (m->exports->init_f()!=0) {
				LOG(L_ERR, "init_mod(): Error while initializing"
					" module %s\n", m->exports->name);
				return -1;
			}
		}
		/* no init function -- proceed further */
#ifdef STATISTICS
		if (m->exports->stats) {
			DBG("DEBUG: register_stats: %s\n", m->exports->name);
			if (register_module_stats(m->exports->name,m->exports->stats)!=0) {
				LOG(L_ERR, "init_mod(): Error while registering "
					"statistics for module %s\n", m->exports->name);
				return -1;
			}
		}
#endif
		/* register MI functions */
		if (m->exports->mi_cmds) {
			DBG("DEBUG: register_mi: %s\n", m->exports->name);
			if (register_mi_mod(m->exports->name,m->exports->mi_cmds)!=0) {
				LOG(L_ERR, "init_mod(): Error while registering "
					"MI functions for module %s\n", m->exports->name);
			}
		}

		/* proceed with success */
		return 0;
	} else {
		/* end of list */
		return 0;
	}
}

/*
 * Initialize all loaded modules, the initialization
 * is done *AFTER* the configuration file is parsed
 */
int init_modules(void)
{
	return init_mod(modules);
}

/* Returns 1 if the module with name 'name' is loaded, and zero otherwise. */
int module_loaded(char *name) {

	struct sr_module *currentMod;

	for (currentMod=modules; currentMod; currentMod=currentMod->next) {
		if (strcasecmp(name,currentMod->exports->name)==0) {
			return 1;
		}

	}

	return 0;
}

