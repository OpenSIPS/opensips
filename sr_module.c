/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
#include "globals.h"
#include "mem/mem.h"
#include "pt.h"
#include "ut.h"
#include "daemonize.h"

#include <strings.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "net/api_proto.h"
#include "net/proto_udp/proto_udp_handler.h"
#include "net/proto_tcp/proto_tcp_handler.h"

#include "test/unit_tests.h"

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

#define MPATH_LEN	256
static const char *mpath;
static char mpath_buf[MPATH_LEN + 1];
static int  mpath_len;

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

	/* register module transformations */
	if (e->trans) {
		LM_DBG("register_trans: %s\n", e->name);
		if (register_trans_mod(e->name, e->trans) !=0) {
			LM_ERR("failed to register transformations for module %s\n",
				e->name);
			pkg_free(mod);
			return -1;
		}
	}

	/* register all module dependencies */
	if (e->deps) {
		ret = add_module_dependencies(mod);
		if (ret != 0) {
			LM_CRIT("failed to add module dependencies [%d]\n", ret);
			return ret;
		}
	}

	return 0;
error:
	return ret;
}


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

	if (exp->load_f && exp->load_f() < 0) {
		LM_ERR("could not initialize module %s\n", path);
		goto error1;
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

/* built-in modules with static exports */
struct static_modules {
	str name;
	struct module_exports *exp;
};

struct static_modules static_modules[] = {
	{ str_init(PROTO_PREFIX "udp"), &proto_udp_exports },
	{ str_init(PROTO_PREFIX "tcp"), &proto_tcp_exports },
};

static int load_static_module(char *path)
{
	int len = strlen(path);
	char *end = path + len;
	struct sr_module* t;
	unsigned int i;

	/* eliminate the .so, if found */
	if (len > 3 && strncmp(end - 3, ".so", 3)==0) {
		end -= 3;
		len -= 3;
	}
	/* we check whether the protocol is found within the static_modules */
	for (i = 0; i < (sizeof(static_modules)/sizeof(static_modules[0])); i++) {
		if (len >= static_modules[i].name.len &&
				/* the path ends in the module's name */
				memcmp(end - static_modules[i].name.len,
					static_modules[i].name.s, static_modules[i].name.len) == 0 &&
				/* check if the previous char is '/' or nothing */
				(len == static_modules[i].name.len || (*(end-len-1) == '/'))) {

			/* yey, found the module - check if it was loaded twice */
			for(t=modules;t; t=t->next){
				if (t->handle==static_modules[i].exp){
					LM_WARN("attempting to load the same module twice (%s)\n", path);
					return 0;
				}
			}

			/* version control */
			if (!version_control(static_modules[i].exp, path)) {
				exit(0);
			}

			/* launch register */
			if (register_module(static_modules[i].exp, path, static_modules[i].exp)<0)
				return -1;
			return 0;
		}
	}

	return -1;
}

void set_mpath(const char *new_mpath)
{
	int len = strlen(new_mpath);
	if (len >= MPATH_LEN) {
		LM_ERR("mpath %s too long!\n", new_mpath);
		return;
	}
	mpath = new_mpath;
	strcpy(mpath_buf, new_mpath);
	mpath_len = len;
	if (mpath_len == 0 || mpath_buf[mpath_len - 1] != '/') {
		mpath_buf[mpath_len] = '/';
		mpath_len++;
		mpath_buf[mpath_len] = '\0';
	}
}

/* returns 0 on success , <0 on error */
int load_module(char* name)
{
	int i_tmp;
	struct stat statf;

	/* if this is a static module, load it directly */
	if (load_static_module(name) == 0)
		return 0;

	if(*name!='/' && mpath!=NULL
		&& strlen(name)+mpath_len<MPATH_LEN)
	{
		strcpy(mpath_buf+mpath_len, name);
		if (stat(mpath_buf, &statf) == -1 || S_ISDIR(statf.st_mode)) {
			i_tmp = strlen(mpath_buf);
			if(strchr(name, '/')==NULL &&
				strncmp(mpath_buf+i_tmp-3, ".so", 3)==0)
			{
				if(i_tmp+strlen(name)<MPATH_LEN)
				{
					strcpy(mpath_buf+i_tmp-3, "/");
					strcpy(mpath_buf+i_tmp-2, name);
					if (stat(mpath_buf, &statf) == -1) {
						mpath_buf[mpath_len]='\0';
						LM_ERR("module '%s' not found in '%s'\n",
								name, mpath_buf);
						return -1;
					}
				} else {
					LM_ERR("failed to load module - path too long\n");
					return -1;
				}
			} else {
				LM_ERR("failed to load module - not found\n");
				return -1;
			}
		}
		LM_DBG("loading module %s\n", mpath_buf);
		if (sr_load_module(mpath_buf)!=0){
			LM_ERR("failed to load module\n");
			return -1;
		}
		mpath_buf[mpath_len]='\0';
	} else {
		LM_DBG("loading module %s\n", name);
		if (sr_load_module(name)!=0){
			LM_ERR("failed to load module\n");
			return -1;
		}
	}
	return 0;
}



/* searches the module list and returns pointer to the "name" function or
 * 0 if not found
 * flags parameter is OR value of all flags that must match
 */
cmd_function find_export(char* name, int flags)
{
	cmd_export_t* cmd;

	cmd = find_mod_cmd_export_t(name, flags);
	if (cmd==0)
		return 0;

	return cmd->function;
}



/* Searches the module list for the "name" cmd_export_t structure.
 */
cmd_export_t* find_mod_cmd_export_t(char* name, int flags)
{
	struct sr_module* t;
	cmd_export_t* cmd;

	for(t=modules;t;t=t->next){
		for(cmd=t->exports->cmds; cmd && cmd->name; cmd++){
			if((strcmp(name, cmd->name)==0)&&((cmd->flags & flags) == flags)){
				LM_DBG("found <%s> in module %s [%s]\n",
						name, t->exports->name, t->path);
				return cmd;
			}
		}
	}

	LM_DBG("<%s> not found \n", name);
	return 0;
}



/* Searches the module list for the "name" acmd_export_t structure.
 */
acmd_export_t* find_mod_acmd_export_t(char* name)
{
	struct sr_module* t;
	acmd_export_t* cmd;

	for(t=modules;t;t=t->next){
		for(cmd=t->exports->acmds; cmd && cmd->name; cmd++){
			if((strcmp(name, cmd->name)==0)){
				LM_DBG("found <%s> in module %s [%s]\n",
						name, t->exports->name, t->path);
				return cmd;
			}
		}
	}
	LM_DBG("async <%s> not found \n", name);
	return 0;
}

/*
 * searches the module list and returns pointer to "name" function in module
 * "mod" or 0 if not found
 * flags parameter is OR value of all flags that must match
 */
cmd_function find_mod_export(char* mod, char* name, int flags)
{
	struct sr_module* t;
	cmd_export_t* cmd;

	for (t = modules; t; t = t->next) {
		if (strcmp(t->exports->name, mod) == 0) {
			for (cmd = t->exports->cmds;  cmd && cmd->name; cmd++) {
				if ((strcmp(name, cmd->name) == 0) &&
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

	t = modules;
	while (t) {
		foo = t->next;
		if (t->init_done && t->exports && t->exports->destroy_f)
			t->exports->destroy_f();
		pkg_free(t);
		t = foo;
	}

	modules = NULL;
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

static int init_mod( struct sr_module* m, int skip_others)
{
	struct sr_module_dep *dep;

	if (m) {
		/* iterate through the list; if error occurs,
		   propagate it up the stack
		 */
		if (!skip_others && init_mod(m->next, 0) != 0)
			return -1;

		/* our module might have been already init'ed through dependencies! */
		if (m->init_done)
			return 0;

		if (!m->exports)
			return 0;

		/* make sure certain modules get loaded before this one */
		for (dep = m->sr_deps; dep; dep = dep->next) {
			if (!dep->mod->init_done)
				if (init_mod(dep->mod, 1) != 0)
					return -1;
		}

		if (m->exports->init_f) {
			LM_DBG("initializing module %s\n", m->exports->name);
			if (m->exports->init_f()!=0) {
				LM_ERR("failed to initialize module %s\n", m->exports->name);
				return -1;
			}
		}

		m->init_done = 1;

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
	struct sr_module *currentMod;
	int ret;

	if (testing_framework)
		init_unit_tests();

	/* pre-initialize all modules */
	for (currentMod=modules; currentMod; currentMod=currentMod->next) {
		if (currentMod->exports->preinit_f == NULL)
			continue;
		ret = currentMod->exports->preinit_f();
		if (ret < 0) {
			LM_ERR("could not pre-initialize module %s!\n",
					currentMod->exports->name);
			return ret;
		}
	}

	ret = init_mod(modules, 0);

	free_module_dependencies(modules);

	return ret;
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


void *get_mod_handle(const char *name)
{
	struct sr_module *mod;

	for (mod = modules; mod; mod = mod->next)
		if (!strcasecmp(name, mod->exports->name))
			return mod->handle;

	return NULL;
}


/* Counts the additional the number of processes requested by modules */
int count_module_procs(int flags)
{
	struct sr_module *m;
	unsigned int cnt;
	unsigned int n;

	for( m=modules,cnt=0 ; m ; m=m->next) {
		if (m->exports->procs==NULL)
			continue;
		for ( n=0 ; m->exports->procs[n].name ; n++) {
			if (!m->exports->procs[n].no || !m->exports->procs[n].function)
				continue;

			if (!flags || (m->exports->procs[n].flags & flags))
				cnt+=m->exports->procs[n].no;
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
	int x;

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
				x = internal_fork( m->exports->procs[n].name,
						((m->exports->procs[n].flags&PROC_FLAG_HAS_IPC) ?
						0 : OSS_PROC_NO_IPC)|OSS_PROC_IS_EXTRA, TYPE_MODULE );
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
							report_failure_status();
							exit(-1);
						}

						report_conditional_status( (!no_daemon_mode), 0);
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


int modules_validate_reload(void)
{
	struct sr_module *m;
	int ret = 1;

	for( m=modules ; m ; m=m->next) {
		if (m->exports->reload_ack_f==NULL)
			continue;
		if (!m->exports->reload_ack_f()) {
			LM_ERR("module <%s> did not validated the cfg file\n",
				m->exports->name);
			ret = 0;
		}
	}

	return ret;
}

