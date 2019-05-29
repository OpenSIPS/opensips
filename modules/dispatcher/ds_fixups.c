/**
 * dispatcher module fixup functions
 *
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
 * Copyright (C) 2014 OpenSIPS Foundation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
*/


#include "ds_fixups.h"
#include "../../trim.h"

#define LIST_DELIM ','
#define FLAGS_DELIM 'M'

#define DS_TYPE_INT 0
#define DS_TYPE_PVS 1

extern ds_partition_t *default_partition;
extern ds_partition_t *partitions;

int fixup_ds_part(void **param)
{
	ds_partition_t *it;
	str *part = (str *)*param;

	if (!part) {
		*param = default_partition;
		return 0;
	}

	for (it = partitions; it; it = it->next)
		if (!str_strcmp(&it->name, part)) {
			*param = it;
			return 0;
		}

	LM_ERR("could not locate partition %.*s\n", part->len, part->s);
	*param = NULL;

	return -1;
}

/*
 * Expand a pvar into a list of ints
*/

int_list_t *set_list_from_pvs(struct sip_msg *msg, pv_spec_t *pvs, int_list_t *end)
{
	int_list_t *result = end, *new_el;
	pv_value_t value;

	if (pv_get_spec_value(msg, pvs, &value) != 0 || value.flags&PV_VAL_NULL
		|| (!(value.flags&PV_VAL_INT) && !(value.flags&PV_VAL_STR))) {

		LM_ERR("no valid PV value found (error in scripts)\n");
		return NULL;
	}

	if (value.flags & PV_VAL_INT) {
		/* Just one element */

		new_el = pkg_malloc(sizeof(int_list_t));
		if (new_el == NULL) {
			LM_ERR("no more shared memory\n");
			return NULL;
		}

		new_el->v.ival = value.ri;
		new_el->type = DS_TYPE_INT;
		new_el->next = end;

		return new_el;
	}

	str sval = value.rs;

	if (sval.s == NULL)
		goto wrong_value;

	char * delim;
	do{
		delim = q_memchr(sval.s, LIST_DELIM, sval.len);
		str s_num = {sval.s, delim ? delim - sval.s : sval.len};
		sval.len -= s_num.len + 1;
		sval.s = delim + 1;
		trim(&s_num);

		int u_num;
		if (s_num.len == 0 || str2sint(&s_num, &u_num) != 0)
			goto wrong_value;

		new_el = pkg_malloc(sizeof(int_list_t));
		if (new_el == NULL) {
			goto no_memory;
		}

		new_el->v.ival = u_num;
		new_el->type = DS_TYPE_INT;
		new_el->next = result;
		result = new_el;

	} while (delim);

	if (sval.len > 0)
		goto wrong_value;

return result;

no_memory:
	while(result != end) {
		if (result->type == DS_TYPE_PVS)
			pkg_free(result->v.pvs);
		int_list_t *aux = result;
		result = result->next;
		pkg_free(aux);
	}
	LM_ERR("no more private memory\n");
	return NULL;

wrong_value:
	while(result != end) {
		if (result->type == DS_TYPE_PVS)
			pkg_free(result->v.pvs);
		int_list_t *aux = result;
		result = result->next;
		pkg_free(aux);
	}
	LM_ERR("wrong var value <%.*s>\n", value.rs.len, value.rs.s);
	return NULL;

}

/*
 * Create an int list from a string. Eg ("1, 2, 4")
*/

int set_list_from_string(str input, int_list_t **result)
{
	str original_input = input;
	int_list_t *new_el=NULL;
	int flags=0;
	int uset;

	*result = NULL;
	if (input.s == NULL || input.len == 0)
		return 0;

	if (str2sint(&input, &uset) == 0) {
		/* Just one set in the list */
		*result = pkg_malloc(sizeof(int_list_t));
		if (*result == NULL)
			goto no_memory;
		(*result)->v.ival = uset;
		(*result)->type = DS_TYPE_INT;
		(*result)->next = NULL;
		return 0;
	}

	char * delim, *pvdelim, *flagsdelim=NULL;
	str flg_tok;

	unsigned int u_num=0;
	int def_val = -1;
	do{
		delim = q_memchr(input.s, LIST_DELIM, input.len);
		str s_tok = {input.s, delim ? delim - input.s : input.len};
		int full_tok_len = s_tok.len;

		trim(&s_tok);

		/* search if only max results */
		if (s_tok.s[0] >= '0' && s_tok.s[0] <= '9') {
			flags = 0;
			goto only_max_res;
		}

		/*search for flags flags/maxlist delimiter*/
		flagsdelim=q_memchr(s_tok.s, FLAGS_DELIM, s_tok.len);
		if (flagsdelim == NULL) {
			/* search for only flags */
			if ((s_tok.s[0] >= 'a' && s_tok.s[0] <= 'z') ||
					(s_tok.s[0] >= 'A' && s_tok.s[0] <= 'Z')) {
				flg_tok.s = s_tok.s;
				flg_tok.len=0;
				if ((flg_tok.s[flg_tok.len] >= 'a' && flg_tok.s[flg_tok.len] <= 'z') ||
							(flg_tok.s[flg_tok.len] >= 'A' && flg_tok.s[flg_tok.len] <= 'Z'))
					flg_tok.len=s_tok.len;
				goto only_flags00;
			}
		}
		/* if found parse the flags */
		if (flagsdelim != NULL) {
			flg_tok.s = s_tok.s;
			flg_tok.len = flagsdelim - s_tok.s;

only_flags00:
			/* update list token */
			s_tok.s += flg_tok.len +1;
			s_tok.len -= (flg_tok.len +1);

			new_el = pkg_malloc(sizeof(int_list_t));
			if (new_el == NULL)
				goto no_memory;

			memset(new_el, 0, sizeof(int_list_t));

			trim(&flg_tok);

			/* must fixup flags string value */
			if ((flags = fixup_flags(&flg_tok)) < 0) {
				LM_ERR("cannot fixup flags\n");
				return -1;
			}

			trim(&s_tok);

			/* default value for max results */
			def_val = 1000;
		}

only_max_res:
		if (s_tok.len == 0) {
			if (flags > 0) {
				goto only_flags01;
			} else
				goto wrong_value;
		}
		else if (s_tok.s[0] == PV_MARKER) {
			if (new_el == NULL) {
				new_el = pkg_malloc(sizeof(int_list_t));
				if (new_el == NULL)
					goto no_memory;
			}

			new_el->type = DS_TYPE_PVS;
			new_el->v.pvs = pkg_malloc(sizeof(pv_spec_t));
			if (new_el->v.pvs == NULL) {
				pkg_free(new_el);
				goto no_memory;
			}

			if ((pvdelim = pv_parse_spec(&s_tok, new_el->v.pvs)) == NULL) {
				pkg_free(new_el->v.pvs);
				pkg_free(new_el);
				goto wrong_value;
			}

			new_el->next = *result;
			*result = new_el;
			new_el = NULL;

			if (delim)
				if (delim != pvdelim)
					goto wrong_value;
				else {
					input.len -= delim - input.s + 1;
					input.s = delim + 1;
				}
			else {
				input.len -= pvdelim - input.s + 1;
				input.s = pvdelim;
			}
		}
		else if (str2int(&s_tok, &u_num) == 0) {
			/*
			 * don't alloc twice
			 * if both flags and max_results defined
			 * it is already allocated
			 *
			 */
			if (new_el == NULL) {
				new_el = pkg_malloc(sizeof(int_list_t));
				if (new_el == NULL)
					goto no_memory;
			}

only_flags01:
			new_el->v.ival = def_val > 0 ? def_val : u_num;
			new_el->type = DS_TYPE_INT;
			if (flags>0)
				new_el->flags = flags;
			new_el->next = *result;
			*result = new_el;
			new_el = NULL;

			input.len -= full_tok_len + 1;
			input.s = delim + 1;
		}
		else goto wrong_value;
	} while (delim);

	if (input.len > 0)
		goto wrong_value;

	return 0;

no_memory:
	while(*result) {
		if ((*result)->type == DS_TYPE_PVS)
			pkg_free((*result)->v.pvs);
		int_list_t *aux = *result;
		*result = (*result)->next;
		pkg_free(aux);
	}
	LM_ERR("no more shared memory\n");
	return -1;

wrong_value:
	while(*result) {
		if ((*result)->type == DS_TYPE_PVS)
			pkg_free((*result)->v.pvs);
		int_list_t *aux = *result;
		*result = (*result)->next;
		pkg_free(aux);
	}
	LM_ERR("wrong format for set/set list. Token <%.*s>\n", original_input.len, original_input.s);
	return -1;
}

/*
 * Fixup for flags
 */

int fixup_flags(str* param)
{
	int index, ret=0;

	for (index=0; index < param->len; index++) {
		switch (param->s[index]) {
			case ' ':
				break;
			case 'f':
			case 'F':
				ret |= DS_FAILOVER_ON;
				break;
			case 'u':
			case 'U':
				ret |= DS_HASH_USER_ONLY;
				break;
			case 'd':
			case 'D':
				ret |= DS_USE_DEFAULT;
				break;
			case 'a':
			case 'A':
				ret |= DS_APPEND_MODE;
				break;

			default:
				LM_ERR("Invalid flag: '%c'\n", param->s[index]);
				return -1;
		}
	}

	return ret;
}

int fixup_ds_flags(void** param)
{
	int index, ret=0;
	str *flags = (str *)*param;

	for (index=0; index < flags->len; index++) {
		switch (flags->s[index]) {
			case ' ':
				break;
			case 'f':
			case 'F':
				ret |= DS_FAILOVER_ON;
				break;
			case 'u':
			case 'U':
				ret |= DS_HASH_USER_ONLY;
				break;
			case 'd':
			case 'D':
				ret |= DS_USE_DEFAULT;
				break;
			case 'a':
			case 'A':
				ret |= DS_APPEND_MODE;
				break;

			default:
				LM_ERR("Invalid definition\n");
				return -1;
		}
	}

	*param = (void *)(long)ret;
	return 0;
}

/*
 * Free an expanded list (obtained with set_list_from_pvs)
 * Delete everything in the range [start, end).
 * Do not use this function to erase any other lists
*/

void free_int_list(int_list_t *start, int_list_t *end)
{
	int_list_t *aux;
	while (start != end) {
		aux = start;
		start = start->next;
		pkg_free(aux);
	}
}

/*
 * Search for value in int_list_t
*/

int in_int_list(int_list_t *list, int val)
{
    int_list_t *tmp;
    for (tmp=list;tmp!=NULL;tmp=tmp->next) {
        if (tmp->v.ival == val) // TODO: test!
            return 0;
    }
    return -1;
}


int fixup_ds_count_filter(void **param)
{
	str *s = (str *)*param;
	int i, code = 0;

	for (i = 0; i < s->len; i++) {
		switch (s->s[i]) {
		/* active */
		case 'a':
		case 'A':
		case '1':
			code |= DS_COUNT_ACTIVE;
			break;

		/* inactive */
		case 'i':
		case 'I':
		case '0':
			code |= DS_COUNT_INACTIVE;
			break;

		/* probing */
		case 'p':
		case 'P':
		case '2':
			code |= DS_COUNT_PROBING;
			break;
		}
	}

	*param = (void *)(long)code;
	return 0;
}


