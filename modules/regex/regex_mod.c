/*
 * regex module - pcre operations
 *
 * Copyright (C) 2008 Iñaki Baz Castillo
 *
 * This file is part of OpenSIPS, a free SIP server.
 *
 * OpenSIPS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * OpenSIPS is distributed in the hope that it will be useful,
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
 *  2009-01-14  initial version (Iñaki Baz Castillo)
 */


/*!
 * \file
 * \brief REGEX :: Perl-compatible regular expressions using PCRE library
 * Copyright (C) 2008 Iñaki Baz Castillo
 * \ingroup regex
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pcre.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../pt.h"
#include "../../mem/shm_mem.h"
#include "../../str.h"
#include "../../locking.h"
#include "../../mod_fix.h"
#include "../../mi/mi.h"



#define START 0
#define RELOAD 1

#define FILE_MAX_LINE 500        /*!< Max line size in the file */
#define MAX_GROUPS 20            /*!< Max number of groups */
#define GROUP_MAX_SIZE 8192      /*!< Max size of a group */


/*
 * Locking variables
 */
gen_lock_t *reload_lock;


/*
 * Module exported parameter variables
 */
static char *file;
static int max_groups            = MAX_GROUPS;
static int group_max_size        = GROUP_MAX_SIZE;
static int pcre_caseless         = 0;
static int pcre_multiline        = 0;
static int pcre_dotall           = 0;
static int pcre_extended         = 0;


/*
 * Module internal parameter variables
 */
static pcre **pcres;
static pcre ***pcres_addr;
static int *num_pcres;
static int pcre_options = 0x00000000;


/*
 * Module core functions
 */
static int mod_init(void);
static void destroy(void);


/*
 * Module internal functions
 */
static int load_pcres(int);
static void free_shared_memory(void);


/*
 * Script functions
 */
static int w_pcre_match(struct sip_msg* _msg, str* string, str* _regex_s);
static int w_pcre_match_group(struct sip_msg* _msg, str* string, int* _num_pcre);


/*
 * MI functions
 */
mi_response_t *mi_pcres_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);


/*
 * Exported functions
 */
static cmd_export_t cmds[] =
{
	{"pcre_match", (cmd_function)w_pcre_match, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"pcre_match_group", (cmd_function)w_pcre_match_group, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"file",                STR_PARAM,  &file                },
	{"max_groups",          INT_PARAM,  &max_groups          },
	{"group_max_size",      INT_PARAM,  &group_max_size      },
	{"pcre_caseless",       INT_PARAM,  &pcre_caseless       },
	{"pcre_multiline",      INT_PARAM,  &pcre_multiline      },
	{"pcre_dotall",         INT_PARAM,  &pcre_dotall         },
	{"pcre_extended",       INT_PARAM,  &pcre_extended       },
	{0, 0, 0}
};


/*
 * Exported MI functions
 */
static mi_export_t mi_cmds[] = {
	{ "regex_reload", 0, 0, 0, {
		{mi_pcres_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

/*
 * Module interface
 */
struct module_exports exports = {
	"regex",                   /*!< module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,           /*!< dlopen flags */
	0,				           /*!< load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,                      /*!< exported functions */
	0,                         /*!< exported async functions */
	params,                    /*!< exported parameters */
	0,                         /*!< exported statistics */
	mi_cmds,                   /*!< exported MI functions */
	0,                         /*!< exported pseudo-variables */
	0,                         /*!< exported transformations */
	0,                         /*!< extra processes */
	0,                         /*!< module pre-initialization function */
	mod_init,                  /*!< module initialization function */
	(response_function) 0,     /*!< response handling function */
	destroy,                   /*!< destroy function */
	0,                         /*!< per-child init function */
	0                          /* reload confirm function */
};



/*! \brief
 * Init module function
 */
static int mod_init(void)
{

	LM_INFO("initializing module...\n");

	/* Group matching feature */
	if (file == NULL) {
		LM_NOTICE("'file' parameter is not set, group matching disabled\n");
	} else {
		/* Create and init the lock */
		reload_lock = lock_alloc();
		if (reload_lock == NULL) {
			LM_ERR("cannot allocate reload_lock\n");
			goto err;
		}
		if (lock_init(reload_lock) == NULL) {
			LM_ERR("cannot init the reload_lock\n");
			lock_dealloc(reload_lock);
			goto err;
		}

		/* PCRE options */
		if (pcre_caseless != 0) {
			LM_DBG("PCRE CASELESS enabled\n");
			pcre_options = pcre_options | PCRE_CASELESS;
		}
		if (pcre_multiline != 0) {
			LM_DBG("PCRE MULTILINE enabled\n");
			pcre_options = pcre_options | PCRE_MULTILINE;
		}
		if (pcre_dotall != 0) {
			LM_DBG("PCRE DOTALL enabled\n");
			pcre_options = pcre_options | PCRE_DOTALL;
		}
		if (pcre_extended != 0) {
			LM_DBG("PCRE EXTENDED enabled\n");
			pcre_options = pcre_options | PCRE_EXTENDED;
		}
		LM_DBG("PCRE options: %i\n", pcre_options);

		/* Pointer to pcres */
		if ((pcres_addr = shm_malloc(sizeof(pcre **))) == 0) {
			LM_ERR("no memory for pcres_addr\n");
			goto err;
		}

		/* Integer containing the number of pcres */
		if ((num_pcres = shm_malloc(sizeof(int))) == 0) {
			LM_ERR("no memory for num_pcres\n");
			goto err;
		}

		/* Load the pcres */
		LM_NOTICE("loading pcres...\n");
		if (load_pcres(START)) {
			LM_CRIT("failed to load pcres\n");
			goto err;
		}
	}

	return 0;

err:
	free_shared_memory();
	return -1;
}


static void destroy(void)
{
	free_shared_memory();
}


/*! \brief Convert the file content into regular expressions and store them in pcres */
static int load_pcres(int action)
{
	int i, j;
	int len, plen;
	FILE *f;
	char line[FILE_MAX_LINE];
	char **patterns = NULL;
	pcre *pcre_tmp = NULL;
	int pcre_size;
	int pcre_rc;
	const char *pcre_error;
	int pcre_erroffset;
	int num_pcres_tmp = 0;
	pcre **pcres_tmp = NULL;

	/* Get the lock */
	lock_get(reload_lock);

	if (!(f = fopen(file, "r"))) {
		LM_ERR("could not open file '%s'\n", file);
		goto err;
	}

	/* Array containing each pattern in the file */
	if ((patterns = pkg_malloc(sizeof(char*) * max_groups)) == 0) {
		LM_ERR("no more memory for patterns\n");
		fclose(f);
		goto err;
	}
	for (i=0; i<max_groups; i++) {
		patterns[i] = NULL;
	}
	for (i=0; i<max_groups; i++) {
		if ((patterns[i] = pkg_malloc(sizeof(char) * group_max_size)) == 0) {
			LM_ERR("no more memory for patterns[%d]\n", i);
			fclose(f);
			goto err;
		}
		memset(patterns[i], '\0', group_max_size);
	}

	/* Read the file and extract the patterns */
	memset(line, '\0', FILE_MAX_LINE);
	i = -1;
	while (fgets(line, FILE_MAX_LINE, f) != NULL) {

		/* Ignore comments and lines starting by space, tab, CR, LF */
		if(isspace(line[0]) || line[0]=='#') {
			memset(line, '\0', FILE_MAX_LINE);
			continue;
		}

		/* First group */
		if (i == -1 && line[0] != '[') {
			LM_ERR("first group must be initialized with [0] before any regular expression\n");
			fclose(f);
			goto err;
		}

		/* New group */
		if (line[0] == '[') {
			i++;
			/* Check if there are more patterns than the max value */
			if (i >= max_groups) {
				LM_ERR("max patterns exceeded\n");
				fclose(f);
				goto err;
			}
			/* Start the regular expression with '(' */
			patterns[i][0] = '(';
			memset(line, '\0', FILE_MAX_LINE);
			continue;
		}
		len = strlen(line);

		/* Check if the patter size is too big (aprox) */
		if (strlen(patterns[i]) + len >= group_max_size - 2) {
			LM_ERR("pattern max file exceeded\n");
			fclose(f);
			goto err;
		}
		if (len >= FILE_MAX_LINE - 1) {
			LM_ERR("cannot add group termination\n");
			fclose(f);
			goto err;
		}

		/* Append ')' at the end of the line */
		if (line[len - 1] == '\n') {
			line[len] = line[len - 1];
			line[len - 1] = ')';
		} else {
			/* This is the last char in the file and it's not \n */
			line[len] = ')';
		}
		len++;
		plen = strlen(patterns[i]);

		/* Append '(' at the beginning of the line */
		memcpy(patterns[i]+plen, "(", 1);
		plen++;

		/* Append the line to the current pattern */
		memcpy(patterns[i]+plen, line, len);

		memset(line, '\0', FILE_MAX_LINE);
	}
	num_pcres_tmp = i + 1;

	fclose(f);

	/* Fix the patterns */
	for (i=0; i < num_pcres_tmp; i++) {
		plen = strlen(patterns[i]);

		/* Convert empty groups in unmatcheable regular expression ^$ */
		if (plen == 1) {
			patterns[i][0] = '^';
			patterns[i][1] = '$';
			patterns[i][2] = '\0';
			continue;
		}

		/* Delete possible '\n' at the end of the pattern */
		if (patterns[i][plen-1] == '\n') {
			patterns[i][plen-1] = '\0';
			plen--;
		}

		/* Replace '\n' with '|' (except at the end of the pattern) */
		for (j=0; j < plen; j++) {
			if (patterns[i][j] == '\n' && j != plen-1) {
				patterns[i][j] = '|';
			}
		}

		/* Add ')' at the end of the pattern */
		patterns[i][plen] = ')';
	}

	/* Log the group patterns */
	LM_NOTICE("num groups = %d\n", num_pcres_tmp);
	for (i=0; i < num_pcres_tmp; i++) {
		LM_NOTICE("<group[%d]>%s</group[%d]> (size = %i)\n", i, patterns[i], i, (int)strlen(patterns[i]));
	}

	/* Temporal pointer of pcres */
	if ((pcres_tmp = pkg_malloc(sizeof(pcre *) * num_pcres_tmp)) == 0) {
		LM_ERR("no more memory for pcres_tmp\n");
		goto err;
	}
	for (i=0; i<num_pcres_tmp; i++) {
		pcres_tmp[i] = NULL;
	}

	/* Compile the patters */
	for (i=0; i<num_pcres_tmp; i++) {

		pcre_tmp = pcre_compile(patterns[i], pcre_options, &pcre_error, &pcre_erroffset, NULL);
		if (pcre_tmp == NULL) {
			LM_ERR("pcre_tmp compilation of '%s' failed at offset %d: %s\n", patterns[i], pcre_erroffset, pcre_error);
			goto err;
		}
		pcre_rc = pcre_fullinfo(pcre_tmp, NULL, PCRE_INFO_SIZE, &pcre_size);
		if (pcre_rc) {
			printf("pcre_fullinfo on compiled pattern[%i] yielded error: %d\n", i, pcre_rc);
			goto err;
		}

		if ((pcres_tmp[i] = pkg_malloc(pcre_size)) == 0) {
			LM_ERR("no more memory for pcres_tmp[%i]\n", i);
			goto err;
		}

		memcpy(pcres_tmp[i], pcre_tmp, pcre_size);
		pcre_free(pcre_tmp);
		pkg_free(patterns[i]);
	}

	/* Copy to shared memory */
	if (action == RELOAD) {
		for(i=0; i<*num_pcres; i++) {  /* Use the previous num_pcres value */
			if (pcres[i]) {
				shm_free(pcres[i]);
			}
		}
		shm_free(pcres);
	}
	if ((pcres = shm_malloc(sizeof(pcre *) * num_pcres_tmp)) == 0) {
		LM_ERR("no more memory for pcres\n");
		goto err;
	}
	for (i=0; i<num_pcres_tmp; i++) {
		pcres[i] = NULL;
	}
	for (i=0; i<num_pcres_tmp; i++) {
		pcre_rc = pcre_fullinfo(pcres_tmp[i], NULL, PCRE_INFO_SIZE, &pcre_size);
		if ((pcres[i] = shm_malloc(pcre_size)) == 0) {
			LM_ERR("no more memory for pcres[%i]\n", i);
			goto err;
		}
		memcpy(pcres[i], pcres_tmp[i], pcre_size);
	}
	*num_pcres = num_pcres_tmp;
	*pcres_addr = pcres;

	/* Free used memory */
	for (i=0; i<num_pcres_tmp; i++) {
		pkg_free(pcres_tmp[i]);
	}
	pkg_free(pcres_tmp);
	/* release the "non-existing" patterns */
	for (i = num_pcres_tmp; i < max_groups; i++)
		pkg_free(patterns[i]);
	pkg_free(patterns);
	lock_release(reload_lock);

	return 0;


err:
	if (patterns) {
		for(i=0; i<max_groups; i++) {
			if (patterns[i]) {
				pkg_free(patterns[i]);
			}
		}
		pkg_free(patterns);
	}
	if (pcres_tmp) {
		for (i=0; i<num_pcres_tmp; i++) {
			if (pcres_tmp[i]) {
				pkg_free(pcres_tmp[i]);
			}
		}
		pkg_free(pcres_tmp);
	}
	if (reload_lock) {
		lock_release(reload_lock);
	}
	if (action == START) {
		free_shared_memory();
	}
	return -1;
}


static void free_shared_memory(void)
{
	int i;

	if (pcres) {
		for(i=0; i<*num_pcres; i++) {
			if (pcres[i]) {
				shm_free(pcres[i]);
			}
		}
		shm_free(pcres);
	}

	if (num_pcres) {
		shm_free(num_pcres);
	}

	if (pcres_addr) {
		shm_free(pcres_addr);
	}

	if (reload_lock) {
		lock_destroy(reload_lock);
		lock_dealloc(reload_lock);
    }
}


/*
 * Script functions
 */

/*! \brief Return true if the argument matches the regular expression parameter */
static int w_pcre_match(struct sip_msg* _msg, str* string, str* _regex_s)
{
	pcre *pcre_re = NULL;
	int pcre_rc;
	const char *pcre_error;
	int pcre_erroffset;
	str regex;

	if (pkg_nt_str_dup(&regex, _regex_s) < 0)
		return -1;

	pcre_re = pcre_compile(regex.s, pcre_options, &pcre_error, &pcre_erroffset, NULL);
	if (pcre_re == NULL) {
		LM_ERR("pcre_re compilation of '%s' failed at offset %d: %s\n", regex.s, pcre_erroffset, pcre_error);
		pkg_free(regex.s);
		return -4;
	}

	pcre_rc = pcre_exec(
		pcre_re,                    /* the compiled pattern */
		NULL,                       /* no extra data - we didn't study the pattern */
		string->s,                   /* the matching string */
		(int)(string->len),          /* the length of the subject */
		0,                          /* start at offset 0 in the string */
		0,                          /* default options */
		NULL,                       /* output vector for substring information */
		0);                         /* number of elements in the output vector */

	/* Matching failed: handle error cases */
	if (pcre_rc < 0) {
		switch(pcre_rc) {
			case PCRE_ERROR_NOMATCH:
				LM_DBG("'%s' doesn't match '%s'\n", string->s, regex.s);
				break;
			default:
				LM_DBG("matching error '%d'\n", pcre_rc);
				break;
		}
		pcre_free(pcre_re);
		pkg_free(regex.s);
		return -1;
	}

	pcre_free(pcre_re);
	pkg_free(regex.s);
	LM_DBG("'%s' matches '%s'\n", string->s, regex.s);
	return 1;
}


/*! \brief Return true if the string argument matches the pattern group parameter */
static int w_pcre_match_group(struct sip_msg* _msg, str* string, int* _num_pcre)
{
	int num_pcre;
	int pcre_rc;

	/* Check if group matching feature is enabled */
	if (file == NULL) {
		LM_ERR("group matching is disabled\n");
		return -2;
	}

	if (!_num_pcre)
		num_pcre = 0;
	else
		num_pcre = *_num_pcre;

	if (num_pcre >= *num_pcres) {
		LM_ERR("invalid pcre index '%i', there are %i pcres\n", num_pcre, *num_pcres);
		return -4;
	}

	lock_get(reload_lock);

	pcre_rc = pcre_exec(
		(*pcres_addr)[num_pcre],    /* the compiled pattern */
		NULL,                       /* no extra data - we didn't study the pattern */
		string->s,                   /* the matching string */
		(int)(string->len),          /* the length of the subject */
		0,                          /* start at offset 0 in the string */
		0,                          /* default options */
		NULL,                       /* output vector for substring information */
		0);                         /* number of elements in the output vector */

	lock_release(reload_lock);

	/* Matching failed: handle error cases */
	if (pcre_rc < 0) {
		switch(pcre_rc) {
			case PCRE_ERROR_NOMATCH:
				LM_DBG("'%s' doesn't match pcres[%i]\n", string->s, num_pcre);
				break;
			default:
				LM_DBG("matching error '%d'\n", pcre_rc);
				break;
		}
		return -1;
	}
	else {
		LM_DBG("'%s' matches pcres[%i]\n", string->s, num_pcre);
		return 1;
	}

}


/*
 * MI functions
 */

/*! \brief Reload pcres by reading the file again */
mi_response_t *mi_pcres_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	/* Check if group matching feature is enabled */
	if (file == NULL) {
		LM_NOTICE("'file' parameter is not set, group matching disabled\n");
		return init_mi_error(403, MI_SSTR("Group matching not enabled"));
	}

	LM_NOTICE("reloading pcres...\n");
	if (load_pcres(RELOAD)) {
		LM_ERR("failed to reload pcres\n");
		return init_mi_error(500, MI_SSTR("Internal error"));
	}
	LM_NOTICE("reload success\n");
	return init_mi_result_ok();
}
