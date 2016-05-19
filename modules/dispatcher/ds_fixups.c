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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * -------
 *  2014-07-08  initial version (Andrei Datcu)
*/


#include "ds_fixups.h"
#include "../../trim.h"

#define LIST_DELIM ','
#define FLAGS_DELIM 'M'

extern ds_partition_t *default_partition;
extern ds_partition_t *partitions;

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
		new_el->type = GPARAM_TYPE_INT;
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
		new_el->type = GPARAM_TYPE_INT;
		new_el->next = result;
		result = new_el;

	} while (delim);

	if (sval.len > 0)
		goto wrong_value;

return result;

no_memory:
	while(result != end) {
		if (result->type == GPARAM_TYPE_PVS)
			pkg_free(result->v.pvs);
		int_list_t *aux = result;
		result = result->next;
		pkg_free(aux);
	}
	LM_ERR("no more private memory\n");
	return NULL;

wrong_value:
	while(result != end) {
		if (result->type == GPARAM_TYPE_PVS)
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
		(*result)->type = GPARAM_TYPE_INT;
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

			new_el->type = GPARAM_TYPE_PVS;
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
			new_el->type = GPARAM_TYPE_INT;
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
		if ((*result)->type == GPARAM_TYPE_PVS)
			pkg_free((*result)->v.pvs);
		int_list_t *aux = *result;
		*result = (*result)->next;
		pkg_free(aux);
	}
	LM_ERR("no more shared memory\n");
	return -1;

wrong_value:
	while(*result) {
		if ((*result)->type == GPARAM_TYPE_PVS)
			pkg_free((*result)->v.pvs);
		int_list_t *aux = *result;
		*result = (*result)->next;
		pkg_free(aux);
	}
	LM_ERR("wrong format for set/set list. Token <%.*s>\n", original_input.len, original_input.s);
	return -1;
}

/*
 * Create a general partition from a string (variable or plain-text name)
*/

static int get_gpart(str *input, gpartition_t *partition)
{

	if (input->s == NULL) {
		partition->type = GPART_TYPE_POINTER;
		partition->v.p = default_partition;
		return 0;
	}

	if (input->s[0] == PV_MARKER) {

		partition->type = GPART_TYPE_PVS;
		partition->v.pvs = shm_malloc(sizeof(pv_spec_t));

		if (partition->v.pvs == NULL) {
			LM_ERR ("no more shared memory\n");
			return -1;
		}

		char *end;
		if ((end = pv_parse_spec(input, partition->v.pvs)) == NULL) {
			LM_ERR ("cannot parse variable\n");
			return -1;
		}
		if (end - input->s != input->len) {
			LM_ERR ("wrong format for partition\n");
			return -1;
		}

		return 0;
	}

	/* We have a static partition name */
	ds_partition_t *part_it = partitions;
	for (; part_it; part_it = part_it->next)
		if (str_strcmp(&part_it->name, input) == 0) {
			partition->type = GPART_TYPE_POINTER;
			partition->v.p = part_it;
			return 0;
		}
	LM_ERR ("partition <%.*s> not found\n", input->len, input->s);
	return -1;
}

/*
 * Fixup for a string like "partition_name:set1, set2
 * The set list may be missing"
*/

static int fixup_partition_sets_null(void **param)
{
	str s_param = {(char*)*param, strlen(*param)};
	str part_name = {NULL, 0};

	char *delim = q_memchr(s_param.s, DS_PARTITION_DELIM, s_param.len);

	if (delim) {
		part_name.s = s_param.s;
		part_name.len = delim - s_param.s;
		s_param.s = delim + 1;
		s_param.len -= part_name.len + 1;
		trim(&part_name);
	}

	trim(&s_param);

	ds_param_t *final_param = shm_malloc(sizeof (ds_param_t));

	if (final_param == NULL) {
		LM_CRIT ("no more shared memory!\n");
		return -1;
	}

	if (get_gpart(&part_name, &final_param->partition) != 0) {
		shm_free(final_param);
		return -1;
	}

	if ((set_list_from_string(s_param, &final_param->sets)) != 0){
		shm_free(final_param);
		return -1;
	}

	*param = (void*)final_param;
	return 0;
}

/*
 * Fixup for a string like "partition_name:set1, set2
 * The set list is mandatory"
*/

int fixup_partition_sets(void **param)
{
	if (fixup_partition_sets_null(param) != 0)
		return -1;

	if (((ds_param_t*)*param)->sets == NULL) {
		/* Null sets are not allowed */
		LM_ERR("A set must be specified!\n");
		return -1;
	}
	return 0;
}

/*
 * Fixup for a string like "partition_name:set_no"
 *
 * Only one set number is allowed and it must not be missing
*/

int fixup_partition_one_set(void **param)
{
	if (fixup_partition_sets(param) != 0)
		return -1;
	if (((ds_param_t*)*param)->sets->next != NULL) {
		LM_ERR("Only one set is accepted\n");
		return -1;
	}
	return 0;
}

/*
 * Fixup for partition_name.
 * Turns char* into gpartition_t (i.e. pvspec or partition_t*)
*/

int fixup_partition(void **param)
{
	gpartition_t *partition = shm_malloc (sizeof(gpartition_t));
	str input = {(char*)(*param), strlen((char*)(*param))};
	trim(&input);

	if (get_gpart(&input, partition) != 0) {
		shm_free(partition);
		return -1;
	}

	*param = (void*)partition;
	return 0;
}

/*
 * Get the actual partition from a gpartition_t
*/

int fixup_get_partition(struct sip_msg *msg, const gpartition_t *gpart,
		ds_partition_t **partition)
{
	if (gpart->type == GPART_TYPE_POINTER) {
		*partition = gpart->v.p;
		return 0;
	}

	pv_value_t value;

	if(pv_get_spec_value(msg, gpart->v.pvs, &value)!=0
		|| value.flags&PV_VAL_NULL || !(value.flags&PV_VAL_STR)) {
		LM_ERR("no valid PV value found (error in scripts)\n");
		return -1;
	}

	if (value.rs.len == 0) {
		*partition = default_partition;
		return 0;
	}

	ds_partition_t *part_it = partitions;

	for (; part_it; part_it = part_it->next)
		if (part_it->name.len == value.rs.len &&
			memcmp(part_it->name.s, value.rs.s, value.rs.len) == 0) {
			*partition = part_it;
			return 0;
		}

	*partition = NULL;
	return 0;
}

/*
 * Fixup for an int list
*/

int fixup_int_list(void **param)
{
	str input = {(char*)(*param), strlen((char*)(*param))};
	int_list_t *lst;
	if (set_list_from_string(input, &lst) != 0 || lst == NULL)
		return -1;
	*param = (void*)(lst);
	return 0;
}

/*
 * Fixup for flags
 */

int fixup_flags(str* param)
{

	#define PV_DELIM ')'
	#define FLAG_ERR(_flag_msg_)\
		do{\
			LM_ERR("Cannot set " #_flag_msg_  " flag\n");\
			return -1;\
		} while(0);

	int index, ret=0;

	for(index=0; index < param->len; index++) {
		switch (param->s[index]) {
			case ' ':
				break;
			case 'f':
			case 'F':
				if (ret & DS_FAILOVER_ON) {
					FLAG_ERR(failover (F));
				} else {
					ret |= DS_FAILOVER_ON;
				}

				break;
			case 'u':
			case 'U':
				if (ret & DS_HASH_USER_ONLY) {
					FLAG_ERR(hash user (U));
				} else {
					ret |= DS_HASH_USER_ONLY;
				}

				break;
			case 'd':
			case 'D':
				if (ret & DS_USE_DEFAULT) {
					FLAG_ERR(use default (D));
				} else {
					ret |= DS_USE_DEFAULT;
				}
				break;
			case 's':
			case 'S':
				if (ret & DS_FORCE_DST) {
					FLAG_ERR(force dst (S));
				} else {
					ret |= DS_FORCE_DST;
				}
				break;
			default :
				LM_ERR("Invalid definition\n");
				return -1;
		}
	}

	return ret;

	#undef FLAG_ERR
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
        if (tmp->type == GPARAM_TYPE_INT && tmp->v.ival == val)
            return 0;
    }
    return -1;
}

/*
 * Get a partition and a set from a general ds_param structure
*/

int fixup_get_partition_set(struct sip_msg *msg, const ds_param_t *param,
		ds_partition_t **partition, unsigned int *uset)
{
	if (fixup_get_partition(msg, &param->partition, partition) != 0)
		return -1;

	if (*partition == NULL) {
		LM_ERR("unknown partition\n");
		return -1;
	}

	if (param->sets->type == GPARAM_TYPE_INT) {
		*uset = param->sets->v.ival;
		return 0;
	}

	int_list_t *tmp = set_list_from_pvs(msg, param->sets->v.pvs, NULL);
	if (tmp == NULL || tmp->next != NULL) {
		LM_ERR("Wrong variable value for set\n");
		return -1;
	}
	*uset = tmp->v.ival;
	free_int_list(tmp, NULL);
	return 0;
}

/* Fixup function for ds_next_dst and ds_next_domain functions */
int ds_next_fixup(void **param, int param_no)
{
	if (param_no > 1) {
		LM_CRIT ("Too many parameters for ds_next_dst/ds_next_domain\n");
		return -1;
	}

	return fixup_partition(param);
}

/* Fixup function for ds_mark_dst command */
int ds_mark_fixup(void **param, int param_no)
{
	if (param_no == 1)
		return fixup_partition(param);
	else if (param_no == 2)
		return fixup_sgp(param);
	else
		return -1;
}

/* Fixup function for ds_is_in_list command */
int in_list_fixup(void** param, int param_no)
{
	if (param_no==1) {
		/* the ip to test */
		return fixup_sgp(param);
	} else if (param_no==2) {
		/* the port to test */
		if (*param==NULL) {
			return 0;
		} else if ( *((char*)*param)==0 ) {
			pkg_free(*param);
			*param = NULL;
			return 0;
		}
		return fixup_igp(param);
	} else if (param_no==3) {
		if (fixup_partition_sets_null(param) != 0)
			return -1;
		int_list_t *sets = ((ds_param_t*)*param)->sets;
		if (sets && sets->next) {
			LM_ERR("Only one set is accepted\n");
			return -1;
		}
		return 0;
	} else if (param_no==4) {
		/*  active only check ? */
		return fixup_sint(param);
	} else {
		LM_CRIT("bug - too many params (%d) in is_in_list()\n",param_no);
		return -1;
	}
}


/* Fixup function for ds_select_dst and ds_select_domain commands */
int ds_select_fixup(void** param, int param_no)
{
	if (param_no > 3) {
		LM_CRIT("Too many params for ds_select_*\n");
		return -1;
	}

	pv_elem_t* elem;
	str s;
	max_list_param_p maxlst = NULL;
	int rc = 0;

	switch (param_no) {
		case 1:
			return fixup_partition_sets(param);
		case 2:
			return fixup_int_list(param);
		case 3:
			s.s = *param;
			s.len = strlen(s.s);

			trim_spaces_lr(s);

			if (s.len == 0) {
				LM_ERR("3rd parameter (flags max_results) is empty\n");
				return -1;
			}

			if (pv_parse_format(&s, &elem)) {
				LM_ERR("wrong format [%s] for param no %d!\n",
						(char*)(*param), param_no);
			}

			maxlst = pkg_malloc(sizeof(max_list_param_t));
			if (maxlst == NULL) {
				LM_ERR("no mem\n");
				return -1;
			}

			if (elem->text.len > 0 && elem->spec.setf == NULL
					&& elem->next == NULL) {
				rc=fixup_int_list(param);

				maxlst->lst.list = *param;
				maxlst->type = MAX_LIST_TYPE_STR;
			} else {
				maxlst->lst.elem = elem;
				maxlst->type = MAX_LIST_TYPE_PV;
				rc = 0;
			}
			break;
	}

	*param = maxlst;

	return rc;
}

/* Fixup function for ds_count command */
int ds_count_fixup(void** param, int param_no)
{
	char *s;
	int i, code = 0;

	if (param_no > 3)
		return 0;

	s = (char *)*param;
	i = strlen(s);

	switch (param_no)
	{
		case 1:
			return fixup_partition_one_set(param);
		case 2:

		while (i--)
		{
			switch (s[i])
			{
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
		break;

		case 3:
			return fixup_igp(param);
	}

	s[0] = (char)code;
	s[1] = '\0';

	return 0;
}


