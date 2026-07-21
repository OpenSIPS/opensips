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
 *  2023-08-12  export pcres_match to MI (Fabien Aunay)
 *  2023-08-12  export pcres_match_group to MI (Fabien Aunay)
 *  2025-09-17  switch to libpcre2 (Steven Ayre)
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
#ifdef PCRE2_LIB
#define PCRE2_CODE_UNIT_WIDTH 8
#define PCRE2_ERR int
#include <pcre2.h>
#else
#define pcre2_code pcre
#define PCRE2_SIZE int
#define PCRE2_ERR const char *
#define PCRE2_CASELESS PCRE_CASELESS
#define PCRE2_MULTILINE PCRE_MULTILINE
#define PCRE2_DOTALL PCRE_DOTALL
#define PCRE2_EXTENDED PCRE_EXTENDED
#define PCRE2_NOTBOL PCRE_NOTBOL
#define PCRE2_UNSET ((PCRE2_SIZE)-1)
#define PCRE2_ERROR_NOMATCH PCRE_ERROR_NOMATCH
#define PCRE2_UCHAR unsigned char
#define PCRE2_SPTR char *
#define PCRE2_INFO_SIZE PCRE_INFO_SIZE
#define PCRE2_INFO_CAPTURECOUNT PCRE_INFO_CAPTURECOUNT
#define pcre2_pattern_info(subst_comp, flag, ret) \
	pcre_fullinfo(subst_comp, NULL, flag, ret)
#define pcre2_compile(pattern, _, flags, error, erroffset, ctx) \
	pcre_compile(pattern, flags, error, erroffset, NULL)
#define pcre2_code_free pcre_free
#define pcre2_get_error_message(error, error_str, error_str_len) \
	do { \
		int _len = strlen(error); \
		if (_len > error_str_len - 1) \
			_len = error_str_len - 1; \
		memcpy(error_str, error, _len); \
		error_str[_len] = '\0'; \
	} while (0)
#include <pcre.h>
#endif
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../pt.h"
#include "../../mem/shm_mem.h"
#include "../../str.h"
#include "../../locking.h"
#include "../../mod_fix.h"
#include "../../pvar.h"
#include "../../error.h"
#include "../../mi/mi.h"
#include "../../re.h"
#include "../../trim.h"
#include "../../ut.h"

#define START 0
#define RELOAD 1

#define FILE_MAX_LINE 500        /*!< Max line size in the file */
#define MAX_GROUPS 20            /*!< Max number of groups */
#define GROUP_MAX_SIZE 8192      /*!< Max size of a group */

#define ERROR_BUF_SIZE 100
#define MAX_REPLACE_WITH 100

enum tr_pcre_subtype {
	TR_PCRE_NONE = 0,
	TR_PCRE_SUBST
};

struct pcre_subst_expr {
	pcre2_code *re;
	str replacement;
	int replace_all;
	int n_escapes;
	int max_pmatch;
	int capture_count;
	struct replace_with replace[1];
};


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
static pcre2_code **pcres;
static pcre2_code ***pcres_addr;
static int *num_pcres;
static int pcre_options = 0x00000000;
static char *pcre_subst_tmp_buf;
static str pcre_subst_cached = {0, 0};
static str pcre_subst_out = {0, 0};
static struct pcre_subst_expr *pcre_subst_re;


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
static int fixup_check_pv_setf(void **param);
static int set_match_pvar(struct sip_msg *msg, pv_spec_t *match, str *value);
static void pcre_subst_expr_free(struct pcre_subst_expr *se);
static struct pcre_subst_expr *pcre_subst_parser(str *subst);
static int pcre_subst_apply(struct sip_msg *msg, str *input,
		struct pcre_subst_expr *se, str *out, int *out_len, int *count);


/*
 * Script functions
 */
static int w_pcre_match(struct sip_msg* _msg, str* string, str* _regex_s,
		pv_spec_t *match);
static int w_pcre_match_group(struct sip_msg* _msg, str* string, int* _num_pcre);

/*
 * Exported transformations
 */
static int tr_pcre_parse(str *in, trans_t *t);
static int tr_pcre_eval(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

static const trans_export_t trans[] = {
	{str_const_init("pcre"), tr_pcre_parse, tr_pcre_eval},
	{{0,0},0,0}
};


/*
 * MI functions
 */
mi_response_t *mi_pcres_reload(const mi_params_t *params, struct mi_handler *async_hdl);
mi_response_t *mi_pcres_match(const mi_params_t *params, struct mi_handler *async_hdl);
mi_response_t *mi_pcres_match_group(const mi_params_t *params, struct mi_handler *async_hdl);


/*
 * Exported functions
 */
static const cmd_export_t cmds[] =
{
	{"pcre_match", (cmd_function)w_pcre_match, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_pv_setf, 0}, {0,0,0}},
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
static const param_export_t params[] = {
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
static const mi_export_t mi_cmds[] = {
	{ "reload", "Causes regex module to re-read the content of the text file and re-compile the regular expressions", 0, 0, {
		{mi_pcres_reload, {0}},
		{EMPTY_MI_RECIPE}}, {"regex_reload", 0}
	},
	{ "match", "Matches the given string parameter against the regular expression pcre_regex", 0, 0, {
		{mi_pcres_match, {"string", "pcre_regex", 0}},
		{EMPTY_MI_RECIPE}}, {"regex_match", 0}
	},
	{ "match_group", "It uses the groups readed from the text file to match the given string parameter against the compiled regular expression in group number group", 0, 0, {
		{mi_pcres_match_group, {"string", "group", 0}},
		{EMPTY_MI_RECIPE}}, {"regex_match_group", 0}
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
	trans,                     /*!< exported transformations */
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
			pcre_options = pcre_options | PCRE2_CASELESS;
		}
		if (pcre_multiline != 0) {
			LM_DBG("PCRE MULTILINE enabled\n");
			pcre_options = pcre_options | PCRE2_MULTILINE;
		}
		if (pcre_dotall != 0) {
			LM_DBG("PCRE DOTALL enabled\n");
			pcre_options = pcre_options | PCRE2_DOTALL;
		}
		if (pcre_extended != 0) {
			LM_DBG("PCRE EXTENDED enabled\n");
			pcre_options = pcre_options | PCRE2_EXTENDED;
		}
		LM_DBG("PCRE options: %i\n", pcre_options);

		/* Pointer to pcres */
		if ((pcres_addr = shm_malloc(sizeof(pcre2_code **))) == 0) {
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
	if (pcre_subst_re) {
		pcre_subst_expr_free(pcre_subst_re);
		pcre_subst_re = NULL;
	}
	if (pcre_subst_tmp_buf) {
		pkg_free(pcre_subst_tmp_buf);
		pcre_subst_tmp_buf = NULL;
	}
	if (pcre_subst_cached.s) {
		pkg_free(pcre_subst_cached.s);
		pcre_subst_cached.s = NULL;
		pcre_subst_cached.len = 0;
	}
	if (pcre_subst_out.s) {
		pkg_free(pcre_subst_out.s);
		pcre_subst_out.s = NULL;
		pcre_subst_out.len = 0;
	}
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
	pcre2_code *pcre_tmp = NULL;
	size_t pcre_size;
	int pcre_rc;
	PCRE2_ERR pcre_error;
	PCRE2_UCHAR pcre_error_str[ERROR_BUF_SIZE];
	PCRE2_SIZE pcre_erroffset;
	int num_pcres_tmp = 0;
	pcre2_code **pcres_tmp = NULL;

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
				i--;
				LM_ERR("max_groups: %d exceeded\n",max_groups);
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
	if ((pcres_tmp = pkg_malloc(sizeof(pcre2_code *) * num_pcres_tmp)) == 0) {
		LM_ERR("no more memory for pcres_tmp\n");
		goto err;
	}
	for (i=0; i<num_pcres_tmp; i++) {
		pcres_tmp[i] = NULL;
	}

	/* Compile the patters */
	for (i=0; i<num_pcres_tmp; i++) {

		pcre_tmp = pcre2_compile((PCRE2_SPTR)patterns[i], PCRE2_ZERO_TERMINATED, pcre_options, &pcre_error, &pcre_erroffset, NULL);
		if (pcre_tmp == NULL) {
                	pcre2_get_error_message(pcre_error, pcre_error_str, sizeof(pcre_error_str));
			LM_ERR("pcre_tmp compilation of '%s' failed at offset %lu: %s\n", patterns[i], (unsigned long)pcre_erroffset, pcre_error_str);
			goto err;
		}
		pcre_rc = pcre2_pattern_info(pcre_tmp, PCRE2_INFO_SIZE, &pcre_size);
		if (pcre_rc) {
			printf("pcre2_pattern_info on compiled pattern[%i] yielded error: %d\n", i, pcre_rc);
			goto err;
		}

		if ((pcres_tmp[i] = pkg_malloc(pcre_size)) == 0) {
			LM_ERR("no more memory for pcres_tmp[%i]\n", i);
			goto err;
		}

		memcpy(pcres_tmp[i], pcre_tmp, pcre_size);
		pcre2_code_free(pcre_tmp);
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
	if ((pcres = shm_malloc(sizeof(pcre2_code *) * num_pcres_tmp)) == 0) {
		LM_ERR("no more memory for pcres\n");
		goto err;
	}
	for (i=0; i<num_pcres_tmp; i++) {
		pcres[i] = NULL;
	}
	for (i=0; i<num_pcres_tmp; i++) {
		pcre_rc = pcre2_pattern_info(pcres_tmp[i], PCRE2_INFO_SIZE, &pcre_size);
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

static int fixup_check_pv_setf(void **param)
{
	if (!pv_is_w(((pv_spec_t*)*param))) {
		LM_ERR("invalid output parameter: must be writable\n");
		return E_SCRIPT;
	}

	return 0;
}


static int set_match_pvar(struct sip_msg *msg, pv_spec_t *match, str *value)
{
	pv_value_t pv_val;

	if (!match)
		return 0;

	if (!value) {
		if (pv_set_value(msg, match, 0, NULL) != 0) {
			LM_ERR("failed to clear match pvar\n");
			return -1;
		}

		return 0;
	}

	memset(&pv_val, 0, sizeof(pv_val));
	pv_val.flags = PV_VAL_STR;
	pv_val.rs = *value;

	if (pv_set_value(msg, match, 0, &pv_val) != 0) {
		LM_ERR("failed to set match pvar\n");
		return -1;
	}

	return 0;
}


static void pcre_subst_expr_free(struct pcre_subst_expr *se)
{
	int i;

	if (!se)
		return;

	if (se->replacement.s)
		pkg_free(se->replacement.s);
	if (se->re)
		pcre2_code_free(se->re);
	for (i = 0; i < se->n_escapes; i++) {
		if (se->replace[i].type != REPLACE_SPEC)
			continue;
		if (se->replace[i].u.spec.pvp.pvi.type == PV_IDX_PVAR)
			pv_spec_free(se->replace[i].u.spec.pvp.pvi.u.dval);
		if ((se->replace[i].u.spec.pvp.pvv_flags & PV_PARAM_PVV_SHM) &&
				se->replace[i].u.spec.pvp.pvv.s)
			shm_free(se->replace[i].u.spec.pvp.pvv.s);
	}
	pkg_free(se);
}


static struct pcre_subst_expr *pcre_subst_parser(str *subst)
{
	char c;
	char *end;
	char *p;
	char *re;
	char *re_end = NULL;
	char *repl;
	char *repl_end;
	char saved = 0;
	int re_saved = 0;
	struct replace_with rw[MAX_REPLACE_WITH];
	int r;
	int rw_no;
	int replace_all = 0;
	int max_pmatch = 0;
	int pcre_flags = pcre_options;
	pcre2_code *pcre_re = NULL;
	struct pcre_subst_expr *se = NULL;
	PCRE2_ERR pcre_error;
	PCRE2_UCHAR pcre_error_str[ERROR_BUF_SIZE];
	PCRE2_SIZE pcre_erroffset;
#ifdef PCRE2_LIB
	uint32_t capture_count = 0;
#else
	int capture_count = 0;
#endif

	if (subst->len < 3) {
		LM_ERR("expression is too short: %.*s\n", subst->len, subst->s);
		goto error;
	}

	p = subst->s;
	end = subst->s + subst->len;

	c = *p;
	if (c == '\\') {
		LM_ERR("invalid separator char <%c> in %.*s\n",
				c, subst->len, subst->s);
		goto error;
	}
	p++;

	re = p;
	for (; p < end; p++) {
		if ((*p == c) && (*(p - 1) != '\\'))
			goto found_re;
	}
	LM_ERR("no separator found: %.*s\n", subst->len, subst->s);
	goto error;

found_re:
	re_end = p;
	if (end < p + 2) {
		LM_ERR("string too short\n");
		goto error;
	}

	repl = p + 1;
	if ((rw_no = parse_repl(rw, &p, end, &max_pmatch, WITH_SEP)) < 0)
		goto error;

	repl_end = p;
	p++;

	for (; p < end; p++) {
		switch (*p) {
		case 'i':
			pcre_flags |= PCRE2_CASELESS;
			break;
		case 's':
			pcre_flags |= PCRE2_DOTALL;
			break;
		case 'm':
			pcre_flags |= PCRE2_MULTILINE;
			break;
		case 'x':
			pcre_flags |= PCRE2_EXTENDED;
			break;
		case 'g':
			replace_all = 1;
			break;
		default:
			LM_ERR("unknown flag %c in %.*s\n", *p, subst->len, subst->s);
			goto error;
		}
	}

	saved = *re_end;
	*re_end = '\0';
	re_saved = 1;
	pcre_re = pcre2_compile((PCRE2_SPTR)re, PCRE2_ZERO_TERMINATED,
			pcre_flags, &pcre_error, &pcre_erroffset, NULL);
	*re_end = saved;
	re_saved = 0;
	if (pcre_re == NULL) {
		pcre2_get_error_message(pcre_error, pcre_error_str,
				sizeof(pcre_error_str));
		LM_ERR("pcre subst compilation of '%.*s' failed at offset %lu: %s\n",
				(int)(re_end - re), re, (unsigned long)pcre_erroffset,
				pcre_error_str);
		goto error;
	}

	if (pcre2_pattern_info(pcre_re, PCRE2_INFO_CAPTURECOUNT,
				&capture_count) != 0) {
		LM_ERR("failed to read pcre capture count\n");
		goto error;
	}

	if (max_pmatch > (int)capture_count) {
		LM_ERR("illegal access to the %i-th subexpr of the pcre subst expr\n",
				max_pmatch);
		goto error;
	}

	se = pkg_malloc(sizeof(*se) +
			((rw_no) ? (rw_no - 1) * sizeof(struct replace_with) : 0));
	if (!se) {
		LM_ERR("out of pkg memory (pcre subst expr)\n");
		goto error;
	}
	memset(se, 0, sizeof(*se));

	se->replacement.len = repl_end - repl;
	if (se->replacement.len > 0) {
		se->replacement.s = pkg_malloc(se->replacement.len);
		if (!se->replacement.s) {
			LM_ERR("out of pkg memory (replacement)\n");
			goto error;
		}
		memcpy(se->replacement.s, repl, se->replacement.len);
	}

	se->re = pcre_re;
	pcre_re = NULL;
	se->replace_all = replace_all;
	se->n_escapes = rw_no;
	se->max_pmatch = max_pmatch;
	se->capture_count = (int)capture_count;
	for (r = 0; r < rw_no; r++)
		se->replace[r] = rw[r];

	return se;

error:
	if (re_saved)
		*re_end = saved;
	if (se)
		pcre_subst_expr_free(se);
	if (pcre_re)
		pcre2_code_free(pcre_re);
	return NULL;
}


static int pcre_subst_append(str *out, int *out_len, const char *src, int len)
{
	if (len <= 0)
		return 0;

	if (pkg_str_extend(out, *out_len + len + 1) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	memcpy(out->s + *out_len, src, len);
	*out_len += len;
	out->s[*out_len] = '\0';
	return 0;
}


static int pcre_subst_append_replacement(struct sip_msg *msg, str *input,
		struct pcre_subst_expr *se, PCRE2_SIZE *ovector, int match_count,
		str *out, int *out_len)
{
	int r;
	int size;
	int nmatch;
	str *uri;
	pv_value_t sv;
	char *p;
	char *end;

	if (se->replacement.len == 0)
		return 0;

	p = se->replacement.s;
	end = p + se->replacement.len;

	for (r = 0; r < se->n_escapes; r++) {
		size = se->replacement.s + se->replace[r].offset - p;
		if (pcre_subst_append(out, out_len, p, size) < 0)
			return -1;
		p += size + se->replace[r].size;

		switch (se->replace[r].type) {
		case REPLACE_NMATCH:
			nmatch = se->replace[r].u.nmatch;
			if (nmatch < match_count &&
					ovector[2 * nmatch] != PCRE2_UNSET &&
					ovector[2 * nmatch + 1] != PCRE2_UNSET) {
				if (pcre_subst_append(out, out_len,
							input->s + ovector[2 * nmatch],
							(int)(ovector[2 * nmatch + 1] -
								ovector[2 * nmatch])) < 0)
					return -1;
			}
			break;
		case REPLACE_CHAR:
			if (pcre_subst_append(out, out_len, &se->replace[r].u.c, 1) < 0)
				return -1;
			break;
		case REPLACE_URI:
			if (msg == NULL || msg->first_line.type != SIP_REQUEST) {
				LM_CRIT("uri substitution attempt on no request message\n");
				break;
			}
			uri = (msg->new_uri.s) ? &msg->new_uri :
				&msg->first_line.u.request.uri;
			if (pcre_subst_append(out, out_len, uri->s, uri->len) < 0)
				return -1;
			break;
		case REPLACE_SPEC:
			if (msg == NULL) {
				LM_DBG("replace spec attempted on no message\n");
				break;
			}
			if (pv_get_spec_value(msg, &se->replace[r].u.spec, &sv) != 0 ||
					!(sv.flags & PV_VAL_STR)) {
				LM_CRIT("item substitution returned error\n");
				break;
			}
			if (pcre_subst_append(out, out_len, sv.rs.s, sv.rs.len) < 0)
				return -1;
			break;
		default:
			LM_CRIT("unknown replacement type %d\n", se->replace[r].type);
			break;
		}
	}

	return pcre_subst_append(out, out_len, p, end - p);
}


static int pcre_subst_apply(struct sip_msg *msg, str *input,
		struct pcre_subst_expr *se, str *out, int *out_len, int *count)
{
	int pcre_rc;
	int cnt = 0;
	int start_offset = 0;
	int last_offset = 0;
	int match_options = 0;
#ifndef PCRE2_LIB
	int nmatch = se->capture_count + 1;
#endif
#ifdef PCRE2_LIB
	pcre2_match_data *match_data = NULL;
	PCRE2_SIZE *ovector;
#else
	int *ovector = NULL;
#endif

	*out_len = 0;

#ifdef PCRE2_LIB
	match_data = pcre2_match_data_create_from_pattern(se->re, NULL);
	if (!match_data) {
		LM_ERR("failed to allocate pcre match data\n");
		goto error;
	}
#else
	ovector = pkg_malloc(sizeof(int) * 3 * nmatch);
	if (!ovector) {
		LM_ERR("failed to allocate pcre ovector\n");
		goto error;
	}
#endif

	do {
#ifdef PCRE2_LIB
		pcre_rc = pcre2_match(se->re, (PCRE2_SPTR)input->s,
				(PCRE2_SIZE)input->len, (PCRE2_SIZE)start_offset,
				match_options, match_data, NULL);
		ovector = pcre2_get_ovector_pointer(match_data);
#else
		pcre_rc = pcre_exec(se->re, NULL, input->s, input->len,
				start_offset, match_options, ovector, 3 * nmatch);
		if (pcre_rc == 0)
			pcre_rc = nmatch;
#endif
		if (pcre_rc == PCRE2_ERROR_NOMATCH)
			break;
		if (pcre_rc < 0) {
			LM_ERR("pcre subst matching error '%d'\n", pcre_rc);
			goto error;
		}
		if (ovector[0] == PCRE2_UNSET || ovector[1] == PCRE2_UNSET ||
				ovector[0] > ovector[1] ||
				ovector[1] > (PCRE2_SIZE)input->len) {
			LM_ERR("invalid pcre subst match offsets\n");
			goto error;
		}
		if (ovector[0] == ovector[1]) {
			LM_ERR("matched string is empty... invalid regexp?\n");
			goto error;
		}

		if (pcre_subst_append(out, out_len, input->s + last_offset,
					(int)ovector[0] - last_offset) < 0)
			goto error;
		if (pcre_subst_append_replacement(msg, input, se, ovector,
					pcre_rc, out, out_len) < 0)
			goto error;

		last_offset = (int)ovector[1];
		start_offset = last_offset;
		if (last_offset > 0 &&
				(input->s[last_offset - 1] == '\n' ||
				 input->s[last_offset - 1] == '\r'))
			match_options &= ~PCRE2_NOTBOL;
		else
			match_options |= PCRE2_NOTBOL;
		cnt++;
	} while (se->replace_all);

	if (cnt > 0 && pcre_subst_append(out, out_len,
				input->s + last_offset, input->len - last_offset) < 0)
		goto error;

	if (count)
		*count = cnt;
#ifdef PCRE2_LIB
	pcre2_match_data_free(match_data);
#else
	pkg_free(ovector);
#endif
	return 0;

error:
	if (count)
		*count = -1;
#ifdef PCRE2_LIB
	if (match_data)
		pcre2_match_data_free(match_data);
#else
	if (ovector)
		pkg_free(ovector);
#endif
	return -1;
}


#define pcre_tr_is_in_str(p, in) ((p) < (in)->s + (in)->len && *(p))

static int tr_pcre_parse(str *in, trans_t *t)
{
	char *p;
	str name;
	tr_param_t *tp = NULL;

	if (in == NULL || t == NULL)
		return -1;

	p = in->s;
	name.s = in->s;

	while (pcre_tr_is_in_str(p, in) &&
			*p != TR_PARAM_MARKER && *p != TR_RBRACKET)
		p++;
	if (*p == '\0') {
		LM_ERR("invalid transformation: %.*s\n", in->len, in->s);
		goto error;
	}

	name.len = p - name.s;
	trim(&name);

	if (name.len == 5 && strncasecmp(name.s, "subst", 5) == 0) {
		t->subtype = TR_PCRE_SUBST;
		if (*p != TR_PARAM_MARKER) {
			LM_ERR("invalid pcre subst transformation: %.*s\n",
					in->len, in->s);
			goto error;
		}
		p++;
		if (tr_parse_sparam(p, in, &tp, 1) == NULL)
			goto error;
		t->params = tp;
		return 0;
	}

	LM_ERR("unknown pcre transformation: %.*s/%.*s/%d\n", in->len, in->s,
			name.len, name.s, name.len);

error:
	if (tp)
		free_tr_param(tp);
	return -1;
}


static int tr_pcre_eval(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	pv_value_t v;
	str sv;
	str subst;
	char *buf;
	char *s;
	char *e;
	char *p;
	int match_no = 0;
	int out_len = 0;

	if (!val)
		return -1;

	if (val->flags & PV_VAL_NULL)
		return 0;

	if (!(val->flags & PV_VAL_STR) || val->rs.len <= 0)
		goto error;

	switch (subtype) {
	case TR_PCRE_SUBST:
		if (tp->type == TR_PARAM_STRING) {
			sv = tp->v.s;
		} else {
			if (pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v) != 0 ||
					(!(v.flags & PV_VAL_STR)) || v.rs.len <= 0) {
				LM_ERR("cannot get pcre subst value from spec\n");
				goto error;
			}
			sv = v.rs;
		}

		buf = pkg_realloc(pcre_subst_tmp_buf, sv.len + 1);
		if (!buf) {
			LM_ERR("not enough memory for pcre subst buffer %d [%.*s]\n",
					sv.len, sv.len, sv.s);
			goto error;
		}
		pcre_subst_tmp_buf = buf;

		subst.s = buf;
		subst.len = sv.len;
		for (s = sv.s, e = sv.s + sv.len, p = buf; s < e; s++, p++) {
			if (*s == '\\') {
				if (s + 1 >= e)
					break;
				if (*(s + 1) == TR_RBRACKET ||
						*(s + 1) == TR_LBRACKET) {
					s++;
					subst.len--;
				}
			}
			*p = *s;
		}
		*p = '\0';

		LM_INFO("Trying to apply pcre subst [%.*s] on : [%.*s]\n",
				subst.len, subst.s, val->rs.len, val->rs.s);

		if (pcre_subst_re == NULL || !pcre_subst_cached.s ||
				pcre_subst_cached.len != subst.len ||
				memcmp(pcre_subst_cached.s, subst.s, subst.len) != 0) {
			if (pcre_subst_re != NULL) {
				pcre_subst_expr_free(pcre_subst_re);
				pcre_subst_re = NULL;
			}

			pcre_subst_re = pcre_subst_parser(&subst);
			if (!pcre_subst_re) {
				LM_ERR("cannot compile pcre subst expression\n");
				goto error;
			}

			if (pkg_str_extend(&pcre_subst_cached, subst.len) != 0) {
				LM_ERR("oom\n");
				goto error;
			}
			memcpy(pcre_subst_cached.s, subst.s, subst.len);
			pcre_subst_cached.len = subst.len;
		}

		if (pcre_subst_apply(msg, &val->rs, pcre_subst_re,
					&pcre_subst_out, &out_len, &match_no) < 0) {
			LM_ERR("pcre subst failed\n");
			goto error;
		}
		if (match_no == 0) {
			LM_INFO("no match for pcre subst expression\n");
			break;
		}

		val->flags = PV_VAL_STR;
		val->rs.s = pcre_subst_out.s;
		val->rs.len = out_len;
		val->ri = 0;
		break;
	default:
		LM_BUG("unknown pcre transformation subtype [%d]\n", subtype);
		goto error;
	}

	return 0;

error:
	val->flags = PV_VAL_NULL;
	return -1;
}


/*! \brief Return true if the argument matches the regular expression parameter */
static int w_pcre_match(struct sip_msg* _msg, str* string, str* _regex_s,
		pv_spec_t *match)
{
	pcre2_code *pcre_re = NULL;
	int pcre_rc;
	PCRE2_ERR pcre_error;
	PCRE2_UCHAR pcre_error_str[ERROR_BUF_SIZE];
	PCRE2_SIZE pcre_erroffset;
#ifdef PCRE2_LIB
	pcre2_match_data *match_data;
	PCRE2_SIZE *ovector;
#else
	int ovector[3];
#endif
	str regex;
	str match_str;

	if (pkg_nt_str_dup(&regex, _regex_s) < 0)
		return -1;

	pcre_re = pcre2_compile((PCRE2_SPTR)regex.s, PCRE2_ZERO_TERMINATED, pcre_options, &pcre_error, &pcre_erroffset, NULL);
	if (pcre_re == NULL) {
                pcre2_get_error_message(pcre_error, pcre_error_str, sizeof(pcre_error_str));
		LM_ERR("pcre_re compilation of '%s' failed at offset %lu: %s\n", regex.s, (unsigned long)pcre_erroffset, pcre_error_str);
		pkg_free(regex.s);
		return -4;
	}

#ifndef PCRE2_LIB
	pcre_rc = pcre_exec(
			pcre_re, /* the compiled pattern */
			NULL, /* no extra data - we didn't study the pattern */
			string->s, /* the subject string */
			string->len, /* the length of the subject */
			0, /* start at offset 0 in the subject */
			0, /* default options */
			match ? ovector : NULL, /* output vector for substring information */
			match ? 3 : 0); /* number of elements in the output vector */
#else
	if (match)
		match_data = pcre2_match_data_create_from_pattern(pcre_re, NULL);
	else
		match_data = pcre2_match_data_create(0, NULL);
	if (!match_data) {
		LM_ERR("failed to allocate match data\n");
		pcre2_code_free(pcre_re);
		pkg_free(regex.s);
		return -1;
	}

	pcre_rc = pcre2_match(
		pcre_re,                    /* the compiled pattern */
		(PCRE2_SPTR)string->s,                  /* the matching string */
		(PCRE2_SIZE)(string->len),  /* the length of the subject */
		0,                          /* start at offset 0 in the string */
		0,                          /* default options */
		match_data,                 /* match data block */
		NULL);                      /* match context */
#endif

	/* Matching failed: handle error cases */
	if (pcre_rc < 0) {
		switch(pcre_rc) {
			case PCRE2_ERROR_NOMATCH:
				LM_DBG("'%s' doesn't match '%s'\n", string->s, regex.s);
				break;
			default:
				LM_DBG("matching error '%d'\n", pcre_rc);
				break;
		}
#ifdef PCRE2_LIB
		pcre2_match_data_free(match_data);
#endif
		pcre2_code_free(pcre_re);
		pkg_free(regex.s);
		if (set_match_pvar(_msg, match, NULL) < 0)
			return -1;
		return -1;
	}

	LM_DBG("'%s' matches '%s'\n", string->s, regex.s);

	if (match) {
#ifdef PCRE2_LIB
		ovector = pcre2_get_ovector_pointer(match_data);
#endif
		match_str.s = string->s + ovector[0];
		match_str.len = (int)(ovector[1] - ovector[0]);

		if (set_match_pvar(_msg, match, &match_str) < 0) {
#ifdef PCRE2_LIB
			pcre2_match_data_free(match_data);
#endif
			pcre2_code_free(pcre_re);
			pkg_free(regex.s);
			return -1;
		}
	}

#ifdef PCRE2_LIB
	pcre2_match_data_free(match_data);
#endif
	pcre2_code_free(pcre_re);
	pkg_free(regex.s);
	return 1;
}


/*! \brief Return true if the string argument matches the pattern group parameter */
static int w_pcre_match_group(struct sip_msg* _msg, str* string, int* _num_pcre)
{
	int num_pcre;
	int pcre_rc;
#ifdef PCRE2_LIB
	pcre2_match_data *match_data;
#endif

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

#ifndef PCRE2_LIB
	pcre_rc = pcre_exec(
			(*pcres_addr)[num_pcre], /* the compiled pattern */
			NULL, /* no extra data - we didn't study the pattern */
			string->s, /* the subject string */
			string->len, /* the length of the subject */
			0, /* start at offset 0 in the subject */
			0, /* default options */
			NULL, /* output vector for substring information */
			0); /* number of elements in the output vector */
#else
	match_data = pcre2_match_data_create(0, NULL); // no captures needed

	pcre_rc = pcre2_match(
		(*pcres_addr)[num_pcre],    /* the compiled pattern */
		(PCRE2_SPTR)string->s,                  /* the matching string */
		(PCRE2_SIZE)(string->len),  /* the length of the subject */
		0,                          /* start at offset 0 in the string */
		0,                          /* default options */
		match_data,                 /* match data block */
		0);                         /* match context */

	pcre2_match_data_free(match_data);
#endif

	lock_release(reload_lock);

	/* Matching failed: handle error cases */
	if (pcre_rc < 0) {
		switch(pcre_rc) {
			case PCRE2_ERROR_NOMATCH:
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
mi_response_t *mi_pcres_reload(const mi_params_t *params, struct mi_handler *async_hdl)
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


/*! \brief Matches the given string parameter against the regular expression pcre_regex */
mi_response_t *mi_pcres_match(const mi_params_t *params, struct mi_handler *async_hdl)
{
	str string, pcre_regex;
	int rc;

	if ( get_mi_string_param(params, "string", &string.s, &string.len ) < 0) {
		LM_DBG("mi_pcres_match string param error\n");
		return init_mi_param_error();
	}
	if ( get_mi_string_param(params, "pcre_regex", &pcre_regex.s, &pcre_regex.len) < 0) {
		LM_DBG("mi_pcres_match pcre_regex param error\n");
		return init_mi_param_error();
	}

	/* handle call back function result */
	rc = w_pcre_match(NULL, &string, &pcre_regex, NULL);
	LM_DBG("w_pcre_match: string<%s>, pcre_regex=<%s>, result:<%i>\n", string.s, pcre_regex.s, rc);

	switch(rc) {
		case -4:
			/* Compilation error */
			return init_mi_error(500, MI_SSTR("Error pcre_re compilation"));
			break;
		case -1:
			/* Not Match */
			return init_mi_result_string(MI_SSTR("Not Match"));
			break;
		case 1:
			/* Match */
			return init_mi_result_string(MI_SSTR("Match"));
			break;
		default:
			/* Any other case */
			return init_mi_error(500, MI_SSTR("Error"));
	}
}

/*! \brief It uses the groups readed from the text file to match the given string parameter against
 * the compiled regular expression in group number group
 */
mi_response_t *mi_pcres_match_group(const mi_params_t *params, struct mi_handler *async_hdl)
{
	str string, group;
	int _group;
	int rc;

	if ( get_mi_string_param(params, "string", &string.s, &string.len ) < 0) {
		LM_DBG("mi_pcres_match_group string param error\n");
		return init_mi_param_error();
	}
	if ( get_mi_string_param(params, "group", &group.s, &group.len) < 0) {
		LM_DBG("mi_pcres_match_group group param error\n");
		return init_mi_param_error();
	}

	/*
	 *	type casting MI Param -> int(group) function.
	 *	L.616 already test if group is an integer, if not, default 0 is set.
	 */
	_group = atoi(group.s);

	/* No possible negative index */
	if ( _group < 0 ) {
		return init_mi_error(500, MI_SSTR("Error invalid pcre index"));
	}

	/* handle call back function result */
	rc = w_pcre_match_group(NULL, &string, &_group);
	LM_DBG("w_pcre_match_group: string<%s>, _group=<%i>, result:<%i>\n", string.s, _group, rc);

	switch(rc) {
		case -4:
			/* Compilation error */
			return init_mi_error(500, MI_SSTR("Error invalid pcre index"));
			break;
		case -2:
			/* group is disabled */
			return init_mi_error(500, MI_SSTR("Error group matching is disabled"));
			break;
		case -1:
			/* Not Match */
			return init_mi_result_string(MI_SSTR("Not Match"));
			break;
		case 1:
			/* Match */
			return init_mi_result_string(MI_SSTR("Match"));
			break;
		default:
			/* Any other case */
			return init_mi_error(500, MI_SSTR("Error"));
	}
}
