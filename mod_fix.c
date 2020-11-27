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
 */


#include <stdio.h>
#include <stdlib.h>

#include "mem/mem.h"
#include "str.h"
#include "ut.h"
#include "error.h"
#include "mod_fix.h"

static char *re_buff=NULL;
static int re_buff_len = 0;
int fixup_regcomp(regex_t **re, str *re_str, int dup_nt)
{
	char *regex;

	if (dup_nt) {
		if (re_str->len + 1 > re_buff_len) {
			re_buff = pkg_realloc(re_buff,re_str->len + 1);
			if (re_buff == NULL) {
				LM_ERR("No more pkg \n");
				return E_OUT_OF_MEM;
			}

			re_buff_len = re_str->len + 1;
		}

		memcpy(re_buff,re_str->s,re_str->len);
		re_buff[re_str->len] = 0;

		regex = re_buff;
	} else
		regex = re_str->s;

	if ((*re = pkg_malloc(sizeof **re)) == 0) {
		LM_ERR("no more pkg memory\n");
		return E_OUT_OF_MEM;
	}
	if (regcomp(*re, regex, (REG_EXTENDED|REG_ICASE|REG_NEWLINE))) {
		LM_ERR("bad re %s\n", regex);
		pkg_free(*re);
		return E_BAD_RE;
	}

	return 0;
}

static inline gparam_p alloc_gp(void)
{
	gparam_p gp;

	gp = pkg_malloc(sizeof *gp);
	if (!gp) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}
	memset(gp, 0, sizeof *gp);

	return gp;
}

int check_cmd(struct cmd_param *params, action_elem_t *elems)
{
	int i;
	struct cmd_param *param;
	pv_elem_t *pve;

	for (param=params, i=1; param->flags; param++, i++) {
		pve = NULL;

		if (elems[i].type == NOSUBTYPE || elems[i].type == NULLV_ST) {
			if (!(param->flags & CMD_PARAM_OPT)) {
				LM_BUG("Mandatory parameter missing\n");
				return -1;
			} else {
				continue;
			}
		}

		if (param->flags & CMD_PARAM_INT) {
			if (elems[i].type != NUMBER_ST && elems[i].type != SCRIPTVAR_ST) {
				LM_ERR("Param [%d] expected to be an integer or variable\n", i);
				return -1;
			}
		} else if (param->flags & CMD_PARAM_STR) {
			if (elems[i].type == STR_ST) {
				if (!(param->flags & CMD_PARAM_NO_EXPAND) &&
					pv_parse_format(&elems[i].u.s, &pve) < 0) {
					LM_ERR("Failed to parse formatted string in param "
						"[%d]\n",i);
					return -1;
				}

				if ((!(param->flags & CMD_PARAM_NO_EXPAND) &&
				    (pve->next || pve->spec.type != PVT_NONE)) &&
					(param->flags & CMD_PARAM_STATIC)) {
					LM_ERR("Param [%d] does not support formatted strings\n",i);
					return -1;
				}

				if (pve)
					pv_elem_free_all(pve);
			} else if (elems[i].type == SCRIPTVAR_ST) {
				if (param->flags & CMD_PARAM_STATIC) {
					LM_ERR("Param [%d] does not support variables\n",i);
					return -1;
				}
			} else {
				LM_ERR("Param [%d] expected to be a string or variable\n", i);
				return -1;
			}
		} else if (param->flags & CMD_PARAM_VAR) {
			if (elems[i].type != SCRIPTVAR_ST) {
				LM_ERR("Param [%d] expected to be a variable\n",i);
				return -1;
			}
		} else if (param->flags & CMD_PARAM_REGEX) {
			if (elems[i].type != STR_ST && elems[i].type != SCRIPTVAR_ST) {
				LM_ERR("Param [%d] expected to be an integer or variable\n", i);
				return -1;
			}
		}
	}

	return 0;
}

int fix_cmd(struct cmd_param *params, action_elem_t *elems)
{
	int i;
	struct cmd_param *param;
	gparam_p gp = NULL;
	int ret;
	pv_elem_t *pve;
	regex_t *re = NULL;
	void *h;

	for (param=params, i=1; param->flags; param++, i++) {
		pve = NULL;
		if ((elems[i].type == NOSUBTYPE) ||
			(elems[i].type == NULLV_ST)) {
			gp = NULL;
			if (param->flags & CMD_PARAM_OPT) {
				if (param->fixup && (param->flags & CMD_PARAM_FIX_NULL)) {
					h = NULL;
					if (param->fixup(&h) < 0) {
						LM_ERR("Fixup failed for param [%d]\n", i);
						ret = E_UNSPEC;
						goto error;
					}

					if (h != NULL) {
						if ((gp = alloc_gp()) == NULL)
							return E_OUT_OF_MEM;

						gp->type = GPARAM_TYPE_FIXUP;
						gp->pval = h;
					}
				}

				goto fill_elems;
			} else {
				LM_BUG("Mandatory parameter missing\n");
				ret = E_BUG;
				goto error;
			}
		}

		if ((gp = alloc_gp()) == NULL)
			return E_OUT_OF_MEM;

		if (param->flags & CMD_PARAM_INT) {

			if (elems[i].type == NUMBER_ST) {
				gp->v.ival = elems[i].u.number;
				gp->pval = &gp->v.ival;
				gp->type = GPARAM_TYPE_VAL;

				if (param->fixup) {
					h = gp->pval;
					if (param->fixup(&gp->pval) < 0) {
						LM_ERR("Fixup failed for param [%d]\n", i);
						ret = E_UNSPEC;
						goto error;
					}
					if (h!=gp->pval)
						gp->type = GPARAM_TYPE_FIXUP;
				}
			} else if (elems[i].type == SCRIPTVAR_ST) {
				gp->pval = elems[i].u.data;
				gp->type = GPARAM_TYPE_PVS;
			} else {
				LM_ERR("Param [%d] expected to be an integer "
					"or variable\n", i);
				return E_CFG;
			}

		} else if (param->flags & CMD_PARAM_STR) {

			if (elems[i].type == STR_ST) {
				if (!(param->flags & CMD_PARAM_NO_EXPAND) &&
					pv_parse_format(&elems[i].u.s, &pve) < 0) {
					LM_ERR("Failed to parse formatted string in param "
						"[%d]\n",i);
					ret = E_UNSPEC;
					goto error;
				}

				if ((param->flags & CMD_PARAM_NO_EXPAND) ||
				    (!pve->next && pve->spec.type == PVT_NONE)) {
					/* ignoring/no variables in the provided string */
					if (pve)
						pv_elem_free_all(pve);

					gp->v.sval = elems[i].u.s;
					gp->pval = &gp->v.sval;
					gp->type = GPARAM_TYPE_VAL;

					if (param->fixup) {
						h = gp->pval;
						if (param->fixup(&gp->pval) < 0) {
							LM_ERR("Fixup failed for param [%d]\n", i);
							ret = E_UNSPEC;
							goto error;
						}
						if (h!=gp->pval)
							gp->type = GPARAM_TYPE_FIXUP;
					}
				} else {
					if (param->flags & CMD_PARAM_STATIC) {
						LM_ERR("Param [%d] does not support formatted strings\n",i);
						return E_CFG;
					}

					gp->pval = pve;
					gp->type = GPARAM_TYPE_PVE;
				}
			} else if (elems[i].type == SCRIPTVAR_ST) {
				if (param->flags & CMD_PARAM_STATIC) {
					LM_ERR("Param [%d] does not support variables\n",i);
					return E_CFG;
				}

				gp->pval = elems[i].u.data;
				gp->type = GPARAM_TYPE_PVS;
			} else {
				LM_ERR("Param [%d] expected to be a string "
					"or variable\n", i);
				ret = E_CFG;
				goto error;
			}

		} else if (param->flags & CMD_PARAM_VAR) {

			if (elems[i].type != SCRIPTVAR_ST) {
				LM_ERR("Param [%d] expected to be a variable\n",i);
				ret = E_CFG;
				goto error;
			}

			gp->pval = elems[i].u.data;

			if (param->fixup && param->fixup(&gp->pval) < 0) {
				LM_ERR("Fixup failed for param [%d]\n", i);
				ret = E_UNSPEC;
				goto error;
			}

		} else if (param->flags & CMD_PARAM_REGEX) {

			if (elems[i].type == STR_ST) {
				ret = fixup_regcomp(&re, &elems[i].u.s, 0);
				if (ret < 0)
					return ret;

				gp->pval = re;
				gp->type = GPARAM_TYPE_VAL;

				if (param->fixup && param->fixup(&gp->pval) < 0) {
					LM_ERR("Fixup failed for param [%d]\n", i);
					ret = E_UNSPEC;
					goto error;
				}
			} else if (elems[i].type == SCRIPTVAR_ST) {
				gp->pval = elems[i].u.data;
				gp->type = GPARAM_TYPE_PVS;
			} else {
				LM_ERR("Param [%d] expected to be a string "
					"or variable\n", i);
				ret = E_CFG;
				goto error;
			}

		} else {
			LM_BUG("Bad command parameter type\n");
			ret = E_BUG;
			goto error;
		}

fill_elems:
		elems[i].u.data = (void*)gp;
	}

	return 0;
error:
	if (gp)
		pkg_free(gp);
	if (re)
		pkg_free(re);
	return ret;
}

int get_cmd_fixups(struct sip_msg* msg, struct cmd_param *params,
				action_elem_t *elems, void **cmdp, pv_value_t *tmp_vals)
{
	int i;
	struct cmd_param *param;
	gparam_p gp;
	regex_t *re = NULL;
	int ret;

	for (param=params, i=1; param->flags; param++, i++) {
		gp = (gparam_p)elems[i].u.data;
		if (!gp) {
			cmdp[i-1] = NULL;
			continue;
		}

		if (param->flags & CMD_PARAM_INT) {

			switch (gp->type) {
			case GPARAM_TYPE_VAL:
				tmp_vals[i].ri = *(int*)gp->pval;
				cmdp[i-1] = &tmp_vals[i].ri;
				break;
			case GPARAM_TYPE_FIXUP:
				cmdp[i-1] = gp->pval;
				break;
			case GPARAM_TYPE_PVS:
				if (pv_get_spec_value(msg, (pv_spec_t *)gp->pval,
					&tmp_vals[i]) != 0) {
					LM_ERR("Failed to get spec value in param [%d]\n", i);
					return E_UNSPEC;
				}
				if (tmp_vals[i].flags & PV_VAL_NULL ||
					!(tmp_vals[i].flags & PV_VAL_INT)) {
					LM_ERR("Variable in param [%d] is not an integer\n", i);
					return E_UNSPEC;
				}

				cmdp[i-1] = (void *)&tmp_vals[i].ri;

				/* run fixup as we now have the value of the variable */
				if (param->fixup && param->fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Fixup failed for param [%d]\n", i);
					return E_UNSPEC;
				}

				break;
			default:
				LM_BUG("Bad type for generic parameter\n");
				return E_BUG;
			}

		} else if (param->flags & CMD_PARAM_STR) {

			switch (gp->type) {
			case GPARAM_TYPE_VAL:
				tmp_vals[i].rs = *(str*)gp->pval;
				cmdp[i-1] = &tmp_vals[i].rs;
				break;
			case GPARAM_TYPE_FIXUP:
				cmdp[i-1] = gp->pval;
				break;
			case GPARAM_TYPE_PVE:
				if (pv_printf_s(msg, (pv_elem_t *)gp->pval,
					&tmp_vals[i].rs) != 0) {
					LM_ERR("Failed to print formatted string in param [%d]\n", i);
					return E_UNSPEC;
				}

				cmdp[i-1] = &tmp_vals[i].rs;

				if (param->fixup && param->fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Fixup failed for param [%d]\n", i);
					return E_UNSPEC;
				}

				break;
			case GPARAM_TYPE_PVS:
				if (pv_get_spec_value(msg, (pv_spec_t *)gp->pval,
					&tmp_vals[i]) != 0) {
					LM_ERR("Failed to get spec value in param [%d]\n", i);
					return E_UNSPEC;
				}
				if (tmp_vals[i].flags & PV_VAL_NULL ||
					!(tmp_vals[i].flags & PV_VAL_STR)) {
					LM_ERR("Variable in param [%d] is not a string\n", i);
					return E_UNSPEC;
				}

				cmdp[i-1] = &tmp_vals[i].rs;

				if (param->fixup && param->fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Fixup failed for param [%d]\n", i);
					return E_UNSPEC;
				}

				break;
			default:
				LM_BUG("Bad type for generic parameter\n");
				return E_BUG;
			}

		} else if (param->flags & CMD_PARAM_VAR) {

			cmdp[i-1] = gp->pval;

		} else if (param->flags & CMD_PARAM_REGEX) {

			switch (gp->type) {
			case GPARAM_TYPE_VAL:
				cmdp[i-1] = gp->pval;
				break;
			case GPARAM_TYPE_PVS:
				if (pv_get_spec_value(msg, (pv_spec_t *)gp->pval,
					&tmp_vals[i]) != 0) {
					LM_ERR("Failed to get spec value in param [%d]\n", i);
					return E_UNSPEC;
				}
				if (tmp_vals[i].flags & PV_VAL_NULL ||
					!(tmp_vals[i].flags & PV_VAL_STR)) {
					LM_ERR("Variable in param [%d] is not a string\n", i);
					return E_UNSPEC;
				}

				ret = fixup_regcomp(&re, &tmp_vals[i].rs, 1);
				if (ret < 0)
					return ret;
				cmdp[i-1] = re;

				if (param->fixup) {
					if (param->fixup(&cmdp[i-1]) < 0) {
						LM_ERR("Fixup failed for param [%d]\n", i);
						ret = E_UNSPEC;
					}

					regfree(re);
					pkg_free(re);

					if (ret < 0)
						return ret;
				}

				break;
			default:
				LM_BUG("Bad type for generic parameter\n");
				return E_BUG;
			}

		} else {
			LM_BUG("Bad command parameter type\n");
			return E_BUG;
		}
	}

	return 0;
}

int free_cmd_fixups(struct cmd_param *params, action_elem_t *elems, void **cmdp)
{
	int i;
	struct cmd_param *param;
	gparam_p gp;

	for (param=params, i=1; param->flags; param++, i++) {
		gp = (gparam_p)elems[i].u.data;
		if (!gp)
			continue;

		if (param->flags & CMD_PARAM_INT) {
			if (param->free_fixup && gp->type == GPARAM_TYPE_PVS)
				if (param->free_fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Failed to free fixup for param [%d]\n", i);
					return E_UNSPEC;
				}
		} else if (param->flags & CMD_PARAM_STR) {
			if (param->free_fixup && (gp->type == GPARAM_TYPE_PVS ||
				gp->type == GPARAM_TYPE_PVE))
				if (param->free_fixup(&cmdp[i-1]) < 0) {
					LM_ERR("Failed to free fixup for param [%d]\n", i);
					return E_UNSPEC;
				}
		} else if (param->flags & CMD_PARAM_REGEX) {
			if (gp->type == GPARAM_TYPE_PVS || gp->type == GPARAM_TYPE_PVE) {
				if (param->fixup) {
					if (param->free_fixup && param->free_fixup(&cmdp[i-1]) < 0) {
						LM_ERR("Failed to free fixup for param [%d]\n", i);
						return E_UNSPEC;
					}
				} else {
					regfree((regex_t*)cmdp[i-1]);
					pkg_free(cmdp[i-1]);
				}
			}
		} else if (param->flags & CMD_PARAM_VAR) {
			continue;
		} else {
			LM_BUG("Bad command parameter type\n");
			return E_BUG;
		}
	}

	return 0;
}
