/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
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

/*!
 * \file
 * \brief modules/plug-in structures declarations
 */


#include "sr_module.h"
#include "dprint.h"
#include "error.h"
#include "mem/mem.h"
#include "pt.h"
#include "daemonize.h"

#include <strings.h>
#include <stdlib.h>
#include <string.h>


struct sr_module* modules=0;

#ifdef STATIC_EXEC
	extern struct module_exports exec_exports;
#endif
#ifdef STATIC_TM
	extern struct module_exports tm_exports;
#endif

#ifdef STATIC_MAXFWD
	extern struct module_exports maxfwd_exports;
#endif

#ifdef STATIC_AUTH
	extern struct module_exports auth_exports;
#endif

#ifdef STATIC_RR
	extern struct module_exports rr_exports;
#endif

#ifdef STATIC_USRLOC
	extern struct module_exports usrloc_exports;
#endif

#ifdef STATIC_SL
	extern struct module_exports sl_exports;
#endif


/* initializes statically built (compiled in) modules*/
int register_builtin_modules(void)
{
	int ret;

	ret=0;
#ifdef STATIC_TM
	ret=register_module(&tm_exports,"built-in", 0); 
	if (ret<0) return ret;
#endif

#ifdef STATIC_EXEC
	ret=register_module(&exec_exports,"built-in", 0); 
	if (ret<0) return ret;
#endif

#ifdef STATIC_MAXFWD
	ret=register_module(&maxfwd_exports, "built-in", 0);
	if (ret<0) return ret;
#endif

#ifdef STATIC_AUTH
	ret=register_module(&auth_exports, "built-in", 0); 
	if (ret<0) return ret;
#endif
	
#ifdef STATIC_RR
	ret=register_module(&rr_exports, "built-in", 0);
	if (ret<0) return ret;
#endif
	
#ifdef STATIC_USRLOC
	ret=register_module(&usrloc_exports, "built-in", 0);
	if (ret<0) return ret;
#endif

#ifdef STATIC_SL
	ret=register_module(&sl_exports, "built-in", 0);
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
		LM_ERR("no more pkg memory\n");
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
		LM_DBG("register_pv: %s\n", e->name);
		if (register_pvars_mod(e->name, e->items)!=0) {
			LM_ERR("failed to register pseudo-variables for module %s\n",
				e->name);
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

static inline int version_control(struct module_exports* exp, char *path)
{
	if ( !exp->version ) {
		LM_CRIT("BUG - version not defined in module <%s>\n", path );
		return 0;
	}
	if ( !exp->compile_flags ) {
		LM_CRIT("BUG - compile flags not defined in module <%s>\n", path );
		return 0;
	}

	if (strcmp(OPENSIPS_FULL_VERSION, exp->version)==0){
		if (strcmp(OPENSIPS_COMPILE_FLAGS, exp->compile_flags)==0)
			return 1;
		else {
			LM_ERR("module compile flags mismatch for %s "
				" \ncore: %s \nmodule: %s\n",
				exp->name, OPENSIPS_COMPILE_FLAGS, exp->compile_flags);
			return 0;
		}
	}
	LM_ERR("module version mismatch for %s; core: %s; module: %s\n",
		exp->name, OPENSIPS_FULL_VERSION, exp->version );
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

	/* load module */
	handle=dlopen(path, OPENSIPS_DLFLAGS); /* resolve all symbols now */
	if (handle==0){
		LM_ERR("could not open module <%s>: %s\n", path, dlerror() );
		goto error;
	}

	/* check for duplicates */
	for(t=modules;t; t=t->next){
		if (t->handle==handle){
			LM_WARN("attempting to load the same module twice (%s)\n", path);
			goto skip;
		}
	}

	/* import module interface */
	exp = (struct module_exports*)dlsym(handle, DLSYM_PREFIX "exports");
	if ( (error =(char*)dlerror())!=0 ){
		LM_ERR("load_module: %s\n", error);
		goto error1;
	}
	if(exp->dlflags!=DEFAULT_DLFLAGS && exp->dlflags!=OPENSIPS_DLFLAGS) {
		moddlflags = exp->dlflags;
		dlclose(handle);
		LM_DBG("reloading module %s with flags %d\n", path, moddlflags);
		handle = dlopen(path, moddlflags);
		if (handle==0){
			LM_ERR("could not open module <%s>: %s\n", path, dlerror() );
			goto error;
		}
		exp = (struct module_exports*)dlsym(handle, DLSYM_PREFIX "exports");
		if ( (error =(char*)dlerror())!=0 ){
			LM_ERR("failed to load module : %s\n", error);
			goto error1;
		}
	}

	/* version control */
	if (!version_control(exp, path)) {
		exit(0);
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
 * In order to find the module the name, flags parameter number and type and
 * the value of all flags in the config must match to the module export
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
				LM_DBG("found <%s>(%d) in module %s [%s]\n",
					name, param_no, t->exports->name, t->path);
				return cmd;
			}
		}
	}
	LM_DBG("<%s> not found \n", name);
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
					LM_DBG("found <%s> in module %s [%s]\n",
					    name, t->exports->name, t->path);
					return cmd->function;
				}
			}
		}
	}

	LM_DBG("<%s> in module %s not found\n", name, mod);
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
					LM_DBG("found <%s> in module %s [%s]\n",
						name, t->exports->name, t->path);
					return param->param_pointer;
				}
			}
		}
	}
	LM_DBG("parameter <%s> or module <%s> not found\n", name, mod);
	return 0;
}



void destroy_modules(void)
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
			LM_DBG("type=%s, rank=%d, module=%s\n", 
					type, rank, m->exports->name);
			if (m->exports->init_child_f(rank)<0) {
				LM_ERR("failed to initializing module %s, rank %d\n",
					m->exports->name,rank);
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
	case PROC_MODULE:   type = "PROC_MODULE";   break;
	case PROC_TCP_MAIN: type = "PROC_TCP_MAIN"; break;
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
			LM_DBG("initializing module %s\n", m->exports->name);
			if (m->exports->init_f()!=0) {
				LM_ERR("failed to initialize"
					" module %s\n", m->exports->name);
				return -1;
			}
		}
		/* no init function -- proceed further */
#ifdef STATISTICS
		if (m->exports->stats) {
			LM_DBG("registering stats for %s\n", m->exports->name);
			if (register_module_stats(m->exports->name,m->exports->stats)!=0) {
				LM_ERR("failed to registering "
					"statistics for module %s\n", m->exports->name);
				return -1;
			}
		}
#endif
		/* register MI functions */
		if (m->exports->mi_cmds) {
			LM_DBG("register MI for %s\n", m->exports->name);
			if (register_mi_mod(m->exports->name,m->exports->mi_cmds)!=0) {
				LM_ERR("failed to register MI functions for module %s\n",
					m->exports->name);
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
int module_loaded(char *name)
{
	struct sr_module *currentMod;

	for (currentMod=modules; currentMod; currentMod=currentMod->next) {
		if (strcasecmp(name,currentMod->exports->name)==0) {
			return 1;
		}

	}

	return 0;
}


/* Counts the additional the number of processes requested by modules */
int count_module_procs(void)
{
	struct sr_module *m;
	unsigned int cnt;
	unsigned int n;

	for( m=modules,cnt=0 ; m ; m=m->next) {
		if (m->exports->procs) {
			for( n=0 ; m->exports->procs[n].name ; n++)
				if (m->exports->procs[n].function)
					cnt += m->exports->procs[n].no;
		}
	}
	LM_DBG("modules require %d extra processes\n",cnt);
	return cnt;
}


int start_module_procs(void)
{
	struct sr_module *m;
	unsigned int n;
	unsigned int l;
	pid_t x;

	for( m=modules ; m ; m=m->next) {
		if (m->exports->procs==NULL)
			continue;
		for( n=0 ; m->exports->procs[n].name ; n++) {
			if ( !m->exports->procs[n].no || !m->exports->procs[n].function )
				continue;
			/* run pre-fork function */
			if (m->exports->procs[n].pre_fork_function)
				if (m->exports->procs[n].pre_fork_function()!=0) {
					LM_ERR("pre-fork function failed for process \"%s\" "
						"in module %s\n",
						m->exports->procs[n].name, m->exports->name);
					return -1;
				}
			/* fork the processes */
			for ( l=0; l<m->exports->procs[n].no ; l++) {
				LM_DBG("forking process \"%s\"/%d for module %s\n",
					m->exports->procs[n].name, l, m->exports->name);
				x = internal_fork(m->exports->procs[n].name);
				if (x<0) {
					LM_ERR("failed to fork process \"%s\"/%d for module %s\n",
						m->exports->procs[n].name, l, m->exports->name);
					return -1;
				} else if (x==0) {
					/* new process */
					/* initialize the process for the rest of the modules */
					if ( m->exports->procs[n].flags&PROC_FLAG_INITCHILD ) {
						if (init_child(PROC_MODULE) < 0) {
							LM_ERR("error in init_child for PROC_MODULE\n");
							if (send_status_code(-1) < 0)
								LM_ERR("failed to send status code\n");
							clean_write_pipeend();
							exit(-1);
						}

						if (send_status_code(0) < 0)
							LM_ERR("failed to send status code\n");
						clean_write_pipeend();
					} else
						clean_write_pipeend();

					/* run the function */
					m->exports->procs[n].function(l);
					/* we shouldn't get here */
					exit(0);
				}
			}
			/* run post-fork function */
			if (m->exports->procs[n].post_fork_function)
				if (m->exports->procs[n].post_fork_function()!=0) {
					LM_ERR("post-fork function failed for process \"%s\" "
						"in module %s\n",
						m->exports->procs[n].name, m->exports->name);
					return -1;
				}
		}
	}

	return 0;
}
