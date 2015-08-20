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
 * -------
 * 2003-03-20  regex support in modparam (janakj)
 * 2004-03-12  extra flag USE_FUNC_PARAM added to modparam type -
 *             instead of copying the param value, a func is called (bogdan)
 */

/*!
 * \file
 * \brief Module parameter configuration
 */


#include "modparam.h"
#include "dprint.h"
#include "mem/mem.h"
#include "ut.h"
#include <sys/types.h>
#include <regex.h>
#include <string.h>

int set_mod_param_regex(char* regex, char* name, modparam_t type, void* val)
{
	struct sr_module* t;
	param_export_t* param;
	regex_t preg;
	int mod_found, param_found, len;
	char* reg;
	int n;

	len = strlen(regex);
	reg = pkg_malloc(len + 2 + 2 + 1);
	if (reg == 0) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}
	reg[0] = '^';
	reg[1] = '(';
	memcpy(reg + 2, regex, len);
	reg[len + 2] = ')';
	reg[len + 3] = '$';
	reg[len + 4] = '\0';

	if (regcomp(&preg, reg, REG_EXTENDED | REG_NOSUB | REG_ICASE)) {
		LM_ERR("failed to compile regular expression\n");
		pkg_free(reg);
		return -2;
	}

	mod_found = 0;

	for(t = modules; t; t = t->next) {
		if (regexec(&preg, t->exports->name, 0, 0, 0) == 0) {
			LM_DBG("%s matches module %s\n",regex, t->exports->name);
			mod_found = 1;
			param_found = 0;

			for(param=t->exports->params;param && param->name ; param++) {

				if (strcmp(name, param->name) == 0) {
					param_found = 1;

					if (PARAM_TYPE_MASK(param->type) == type) {
						LM_DBG("found <%s> in module %s [%s]\n",
							name, t->exports->name, t->path);

						if (param->type&USE_FUNC_PARAM) {
							n = ((param_func_t)(param->param_pointer))(type, val );
							if (n<0)
								return -4;
						} else {
							switch(type) {
								case STR_PARAM:
									*((char**)(param->param_pointer)) =
										strdup((char*)val);
									break;
								case INT_PARAM:
									*((int*)(param->param_pointer)) =
										(int)(long)val;
									break;
							}
						}

						/* register any module deps imposed by this parameter */
						if (add_modparam_dependencies(t, param) != 0) {
							LM_ERR("failed to add modparam dependencies!\n");
							return E_BUG;
						}

						break;
					}
				}
			}

			if (!param || !param->name) {
				if (param_found)
					LM_ERR("type mismatch for parameter <%s> in module <%s>\n",
					        name, t->exports->name);
				else
					LM_ERR("parameter <%s> not found in module <%s>\n",
						    name, t->exports->name);

				regfree(&preg);
				pkg_free(reg);
				return -3;
			}
		}
	}

	regfree(&preg);
	if (!mod_found) {
		LM_ERR("no module matching %s found\n", regex);
		pkg_free(reg);
		return -4;
	}

	pkg_free(reg);
	return 0;
}
