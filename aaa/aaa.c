/*
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
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
 * History
 * --------
 * 2009-07-10    First version (Irina Stanescu)
 */

#include <string.h>
#include "aaa.h"
#include "../ut.h"

int aaa_parse_url(str* aaa_url, aaa_prot_config* aaa_config) {

	char* p;
	int len;

	if (!aaa_url || !aaa_config) {
		LM_ERR("null arguments\n");
		return -1;
	}

	p = q_memchr(aaa_url->s, ':', aaa_url->len);

	if (!p) {
		LM_ERR("invalid aaa url\n");
		return -1;
	}

	len = p - aaa_url->s;

	aaa_config->prot_name = (str*) pkg_malloc (sizeof(str));
	if (!aaa_config->prot_name) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	aaa_config->prot_name->s = (char*) pkg_malloc (len * sizeof(char));
	if (!aaa_config->prot_name->s) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	aaa_config->prot_name->len = len;
	aaa_config->rest = p + 1;

	strncpy(aaa_config->prot_name->s, aaa_url->s, len);

	return 0;
}


int aaa_prot_bind(str* aaa_url, aaa_prot* prot) {

	aaa_prot_config pc;
	char *module_name;
	aaa_bind_api_f bind_f;

	if (!aaa_url || !prot) {

		LM_ERR("null argument\n");
		return -1;
	}

	if (aaa_parse_url(aaa_url, &pc)) {
		LM_ERR("parse url error\n");
		return -1;
	}

	module_name = (char*) pkg_malloc(pc.prot_name->len + 4 + 1);

	if (!module_name) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	sprintf(module_name, "aaa_%.*s", pc.prot_name->len,pc.prot_name->s);

	bind_f = (aaa_bind_api_f) find_mod_export(module_name,
						"aaa_bind_api", 0);

	if (bind_f) {
		LM_DBG("using aaa bind api for %s\n", module_name);

		if (bind_f(prot)) {
			pkg_free(module_name);
			return -1;
		}
	} else {
		LM_ERR("<%s> has no bind api function\n", module_name);
		pkg_free(module_name);
		return -1;
	}

	pkg_free(module_name);
	return 0;
}
