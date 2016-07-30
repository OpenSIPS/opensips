/*
 * Diversion Header Field Support
 *
 * Copyright (C) 2004 FhG Fokus
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

#include <stdio.h>
#include <string.h>
#include "../../sr_module.h"
#include "../../error.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../data_lump.h"
#include "../../mod_fix.h"
#include "../../ut.h"




#define DIVERSION_HF "Diversion"
#define DIVERSION_HF_LEN (sizeof(DIVERSION_HF) - 1)

#define DIVERSION_PREFIX     DIVERSION_HF ": <"
#define DIVERSION_PREFIX_LEN (sizeof(DIVERSION_PREFIX) - 1)

#define DIVERSION_SUFFIX     ">;reason="
#define DIVERSION_SUFFIX_LEN (sizeof(DIVERSION_SUFFIX) - 1)

#define DIVERSION_COUNTER     ";counter="
#define DIVERSION_COUNTER_LEN (sizeof(DIVERSION_COUNTER) - 1)



str suffix = {"", 0};

int add_diversion(struct sip_msg* msg, char* _s1, char* _s2, char* _s3);

static int fixup_diversion_params(void **param, int param_no);

/*
 * Module initialization function prototype
 */
static int mod_init(void);


/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"add_diversion",    (cmd_function)add_diversion,    1, fixup_diversion_params,
		0, REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
        {"add_diversion",    (cmd_function)add_diversion,    2, fixup_diversion_params,
		0, REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"add_diversion",    (cmd_function)add_diversion,    3, fixup_diversion_params,
		0, REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"suffix", STR_PARAM, &suffix.s},
	{0, 0, 0}
};


/*
 * Module interface
 */
struct module_exports exports = {
	"diversion",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0           /* child initialization function */
};


static int mod_init(void)
{
	LM_INFO("initializing...\n");
	suffix.len = strlen(suffix.s);
	return 0;
}


static int fixup_diversion_params(void** param, int param_no)
{
	if (param_no == 1) {
		/* diversion reason */
		return fixup_str(param);
	} else if (param_no == 2) {
		/* diversion uri */
		return fixup_spve(param);
	} else {
		/* diversion counter */
		return fixup_uint(param);
	}
}


static inline int add_diversion_helper(struct sip_msg* msg, str* s)
{
	char *ptr;

	static struct lump* anchor = 0;
	static unsigned int msg_id = 0;

	if (msg_id != msg->id) {
		msg_id = msg->id;
		anchor = 0;
	}

	if (!msg->diversion && parse_headers(msg, HDR_DIVERSION_F, 0) == -1) {
		LM_ERR("header parsing failed\n");
		return -1;
	}

	if (msg->diversion) {
		     /* Insert just before the topmost Diversion header */
		ptr = msg->diversion->name.s;
	} else {
		     /* Insert at the end */
		ptr = msg->unparsed;
	}

	if (!anchor) {
		anchor = anchor_lump(msg, ptr - msg->buf, 0);
		if (!anchor) {
			LM_ERR("can't get anchor\n");
			return -2;
		}
	}

	if (!insert_new_lump_before(anchor, s->s, s->len, 0)) {
		LM_ERR("can't insert lump\n");
		return -3;
	}

	return 0;
}


int add_diversion(struct sip_msg* msg, char* _s1, char* _s2, char* _s3)
{
	str div_hf;
	char *at;
	str uri;
	str* reason;
	char *counter_s;
	int counter_len;

	reason = (str*)_s1;

	if (_s2 == NULL || fixup_get_svalue(msg, (gparam_p)_s2, &uri) != 0)
		uri = msg->first_line.u.request.uri;

	if (_s3) {
		counter_s = int2str((unsigned long)(void *)_s3, &counter_len);
	} else {
		counter_len = -1;
		counter_s = NULL;
	}

	div_hf.len = DIVERSION_PREFIX_LEN + uri.len + DIVERSION_SUFFIX_LEN + reason->len;
	if (counter_len != -1) {
	    div_hf.len += DIVERSION_COUNTER_LEN + counter_len;
	}
	div_hf.len += CRLF_LEN;
	div_hf.s = pkg_malloc(div_hf.len);
	if (!div_hf.s) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	at = div_hf.s;
	memcpy(at, DIVERSION_PREFIX, DIVERSION_PREFIX_LEN);
	at += DIVERSION_PREFIX_LEN;

	memcpy(at, uri.s, uri.len);
	at += uri.len;

	memcpy(at, DIVERSION_SUFFIX, DIVERSION_SUFFIX_LEN);
	at += DIVERSION_SUFFIX_LEN;

	memcpy(at, reason->s, reason->len);
	at += reason->len;

	if (counter_len != -1) {
		memcpy(at, DIVERSION_COUNTER, DIVERSION_COUNTER_LEN);
		at += DIVERSION_COUNTER_LEN;

		memcpy(at, counter_s, counter_len);
		at += counter_len;
	}

	memcpy(at, CRLF, CRLF_LEN);

	if (add_diversion_helper(msg, &div_hf) < 0) {
		pkg_free(div_hf.s);
		return -1;
	}

	return 1;
}
