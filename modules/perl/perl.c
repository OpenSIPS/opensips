/*
 * Perl module for OpenSIPS
 *
 * Copyright (C) 2006 Collax GmbH
 *                    (Bastian Friedrich <bastian.friedrich@collax.com>)
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

#define DEFAULTMODULE "OpenSIPS"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../mi/mi.h"
#include "../rr/api.h"
#include "../sl/sl_api.h"

/* lock_ops.h defines union semun, perl does not need to redefine it */
#ifdef USE_SYSV_SEM
# define HAS_UNION_SEMUN
#endif

#include "perlfunc.h"
#include "perl.h"

/* #include "perlxsi.h" function is in here... */



/* Full path to the script including executed functions */
char *filename = NULL;

/* Path to an arbitrary directory where the OpenSIPS Perl modules are
 * installed */
char *modpath = NULL;

/* Reference to the running Perl interpreter instance */
PerlInterpreter *my_perl = NULL;

/** SIGNALING binds */
struct sig_binds sigb;

/*
 * Module destroy function prototype
 */
static void destroy(void);

/*
 * Module child-init function prototype
 */
static int child_init(int rank);

/*
 * Module initialization function prototype
 */
static int mod_init(void);


/*
 * Reload perl interpreter - reload perl script. Forward declaration.
 */
mi_response_t *perl_mi_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);



/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"perl_exec_simple", (cmd_function)perl_exec_simple, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE},
	{"perl_exec", (cmd_function)perl_exec, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"filename", STR_PARAM, &filename},
	{"modpath", STR_PARAM, &modpath},
	{ 0, 0, 0 }
};


/*
 * Exported MI functions
 */
static mi_export_t mi_cmds[] = {
	/* FIXME This does not yet work...
	{ "perl_reload", 0,0,0, {
		{perl_mi_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	*/
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "signaling", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/*
 * Module info
 */

#ifndef RTLD_NOW
/* for openbsd */
#define RTLD_NOW DL_LAZY
#endif

#ifndef RTLD_GLOBAL
/* Unsupported! */
#define RTLD_GLOBAL 0
#endif

/*
 * Module interface
 */
struct module_exports exports = {
	"perl",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	RTLD_NOW | RTLD_GLOBAL,
	0,          /* load function */
	&deps,      /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init, /* child initialization function */
	0           /* reload confirm function */
};


static int child_init(int rank)
{
	return 0;
}


EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);
EXTERN_C void boot_OpenSIPS(pTHX_ CV* cv);


/*
 * This is output by perl -MExtUtils::Embed -e xsinit
 * and complemented by the OpenSIPS bootstrapping
 */
EXTERN_C void xs_init(pTHX) {
        char *file = __FILE__;
        dXSUB_SYS;

        newXS("OpenSIPS::bootstrap", boot_OpenSIPS, file);

        newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}


/*
 * Initialize the perl interpreter.
 * This might later be used to reinit the module.
 */
PerlInterpreter *parser_init(void) {
	int argc = 0;
	char *argv[9];
	PerlInterpreter *new_perl = NULL;
	int modpathset = 0;

	new_perl = perl_alloc();

	if (!new_perl) {
		LM_ERR("could not allocate perl.\n");
		return NULL;
	}

	perl_construct(new_perl);

	argv[0] = ""; argc++; /* First param _needs_ to be empty */

	 /* Possible Include path extension by modparam */
	if (modpath && (strlen(modpath) > 0)) {
		modpathset = argc;
		LM_INFO("setting lib path: '%s'\n", modpath);
		argv[argc] = pkg_malloc(strlen(modpath)+20);
		sprintf(argv[argc], "-I%s", modpath);
		argc++;
	}

	argv[argc] = "-M"DEFAULTMODULE; argc++; /* Always "use" Opensips.pm */

	argv[argc] = filename; /* The script itself */
	argc++;

	if (perl_parse(new_perl, xs_init, argc, argv, NULL)) {
		LM_ERR("failed to load perl file \"%s\".\n", argv[argc-1]);
		if (modpathset) pkg_free(argv[modpathset]);
		return NULL;
	} else {
		LM_INFO("successfully loaded perl file \"%s\"\n", argv[argc-1]);
	}

	if (modpathset) pkg_free(argv[modpathset]);
	perl_run(new_perl);

	return new_perl;

}

/*
 *
 */
int unload_perl(PerlInterpreter *p) {
	perl_destruct(p);
	perl_free(p);

	return 0;
}


/*
 * reload function.
 * Reinitializes the interpreter. Works, but execution for _all_
 * children is difficult.
 */
int perl_reload(struct sip_msg *m, char *a, char *b) {

	PerlInterpreter *new_perl;

	new_perl = parser_init();

	if (new_perl) {
		unload_perl(my_perl);
		my_perl = new_perl;
#ifdef PERL_EXIT_DESTRUCT_END
		PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#else
#warning Perl 5.8.x should be used. Please upgrade.
#warning This binary will be unsupported.
		PL_exit_flags |= PERL_EXIT_EXPECTED;
#endif
		return 1;
	} else {
		return 0;
	}

}


/*
 * Reinit through fifo.
 * Currently does not seem to work :((
 */
mi_response_t *perl_mi_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (perl_reload(NULL, NULL, NULL)) {
		return init_mi_result_ok();
	} else {
		return init_mi_error(500, MI_SSTR("Perl reload failed"));
	}
}


/*
 * mod_init
 * Called by opensips at init time
 */
static int mod_init(void) {

	int ret = 0;
	static int argc = 1;
	static char *argv_name = "opensips";
	static char **argv = { &argv_name };

	LM_INFO("initializing...\n");

	if (!filename) {
		LM_ERR("insufficient module parameters. Module not loaded.\n");
		return -1;
	}

	/**
	 * We will need reply() from signaling
	 * module for sending replies
	 */

	/* load SIGNALING API */
	if(load_sig_api(&sigb)< 0) {
		LM_ERR("can't load signaling functions\n");
		return -1;
	}

	PERL_SYS_INIT3(&argc, &argv, &environ);

	if ((my_perl = parser_init())) {
		ret = 0;
#ifdef PERL_EXIT_DESTRUCT_END
		PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#else
		PL_exit_flags |= PERL_EXIT_EXPECTED;
#endif

	} else {
		ret = -1;
	}

	return ret;
}

/*
 * destroy
 * called by opensips at exit time
 */
static void destroy(void)
{
	if(my_perl==NULL)
		return;
	unload_perl(my_perl);
	PERL_SYS_TERM();
	my_perl = NULL;
}
