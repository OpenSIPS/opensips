/*
 * Copyright (C) 2007 Elena-Ramona Modroiu
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

#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../pvar.h"
#include "../../lib/hash.h"

#include "shvar.h"

static gen_hash_t *sh_vars;
int shv_hash_size = 64;


/*
 * Get lock
 */
static inline void lock_shvar(sh_var_t *shv)
{
	hash_lock(sh_vars, shv->hash_entry);
}


/*
 * Release lock
 */
static inline void unlock_shvar(sh_var_t *shv)
{
	hash_unlock(sh_vars, shv->hash_entry);
}


sh_var_t* add_shvar(const str *name)
{
	sh_var_t **shv_holder, *shv;
	unsigned int e;

	if (!sh_vars && init_shvars() != 0) {
		LM_ERR("failed to initialize shared vars\n");
		return NULL;
	}

	if (!name || !name->s)
		return NULL;

	e = hash_entry(sh_vars, *name);
	hash_lock(sh_vars, e);

	shv_holder = (sh_var_t **)hash_get(sh_vars, e, *name);
	if (*shv_holder) {
		hash_unlock(sh_vars, e);
		return *shv_holder;
	}

	shv = shm_malloc(sizeof *shv + name->len + 1);
	if (!shv) {
		LM_ERR("oom\n");
		hash_unlock(sh_vars, e);
		return NULL;
	}
	memset(shv, 0, sizeof *shv);

	shv->name.s = (char *)(shv + 1);
	str_cpy(&shv->name, name);
	shv->name.s[shv->name.len] = '\0';

	shv->hash_entry = e;

	*shv_holder = shv;
	hash_unlock(sh_vars, e);

	return shv;
}

/* call it with lock set */
static inline sh_var_t* set_shvar_value(sh_var_t* shv, int_str *value, int flags)
{
	if(value==NULL)
	{
		if(shv->v.flags&VAR_VAL_STR)
		{
			shm_free(shv->v.value.s.s);
			shv->v.flags &= ~VAR_VAL_STR;
		}
		memset(&shv->v.value, 0, sizeof(int_str));

		return shv;
	}

	if(flags&VAR_VAL_STR)
	{
		if(shv->v.flags&VAR_VAL_STR)
		{ /* old and new value is str */
			if(value->s.len>shv->v.value.s.len)
			{ /* not enough space to copy */
				shm_free(shv->v.value.s.s);
				memset(&shv->v.value, 0, sizeof(int_str));
				shv->v.value.s.s =
					(char*)shm_malloc((value->s.len+1)*sizeof(char));
				if(shv->v.value.s.s==0)
				{
					LM_ERR("out of shm\n");
					goto error;
				}
			}
		} else {
			memset(&shv->v.value, 0, sizeof(int_str));
			shv->v.value.s.s =
					(char*)shm_malloc((value->s.len+1)*sizeof(char));
			if(shv->v.value.s.s==0)
			{
				LM_ERR("out of shm!\n");
				goto error;
			}
			shv->v.flags |= VAR_VAL_STR;
		}
		strncpy(shv->v.value.s.s, value->s.s, value->s.len);
		shv->v.value.s.len = value->s.len;
		shv->v.value.s.s[value->s.len] = '\0';

	} else {
		if(shv->v.flags&VAR_VAL_STR)
		{
			shm_free(shv->v.value.s.s);
			shv->v.flags &= ~VAR_VAL_STR;
			memset(&shv->v.value, 0, sizeof(int_str));
		}
		shv->v.value.n = value->n;
	}

	return shv;
error:
	/* set the var to init value */
	memset(&shv->v.value, 0, sizeof(int_str));
	shv->v.flags &= ~VAR_VAL_STR;
	return NULL;
}


static inline sh_var_t* get_shvar_by_name(str *name)
{
	unsigned int e = hash_entry(sh_vars, *name);
	sh_var_t **shv;

	hash_lock(sh_vars, e);
	shv = (sh_var_t **)hash_find(sh_vars, e, *name);
	hash_unlock(sh_vars, e);

	return shv ? *shv : NULL;
}


int init_shvars(void)
{
	if (sh_vars)
		return 0;

	if (!(sh_vars = hash_init(shv_hash_size))) {
		LM_ERR("oom\n");
		return -1;
	}

	return 0;
}


static void destroy_shvars_shv(void *value)
{
	sh_var_t *shv = (sh_var_t *)value;

	if (shv->v.flags & VAR_VAL_STR) {
		shm_free(shv->v.value.s.s);
		shv->v.value.s.s = NULL;
	}

	shm_free(shv);
}


void destroy_shvars(void)
{
	hash_destroy(sh_vars, destroy_shvars_shv);
	sh_vars = NULL;
}


/********* PV functions *********/
int pv_parse_shvar_name(pv_spec_p sp, const str *in)
{
	pv_spec_p pv_inner;
	str _in;

	if(in==NULL || in->s==NULL || in->len==0 || sp==NULL)
		return -1;

	_in = *in;
	trim(&_in);
	in = &_in;

	if (in->s[0] == PV_MARKER) {
		/* variable as name -> dynamic name */
		pv_inner = pkg_malloc(sizeof *pv_inner);
		if (!pv_inner) {
			LM_ERR("oom\n");
			return -1;
		}

		if (!pv_parse_spec(in, pv_inner)) {
			LM_ERR("oom\n");
			pv_spec_free(pv_inner);
			return -1;
		}

		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void *)pv_inner;
		return 0;
	}

	sp->pvp.pvn.type = PV_NAME_INTSTR;

	sp->pvp.pvn.u.dname = (void*)add_shvar(in);
	if(sp->pvp.pvn.u.dname==NULL)
	{
		LM_ERR("cannot register shvar [%.*s]\n", in->len, in->s);
		return -1;
	}

	return 0;
}

static inline int get_shvar_from_pv_name(struct sip_msg *msg,
                              pv_name_t *pvn, sh_var_t **shv)
{
	pv_value_t val;
	str s;

	if (pvn->type == PV_NAME_PVAR) {
		if (pv_get_spec_value(msg, (pv_spec_p)pvn->u.dname, &val) != 0) {
			LM_ERR("failed to get $shv dynamic name\n");
			return -1;
		}

		if (val.flags & PV_VAL_NULL) {
			LM_ERR("scripting error - $shv(NULL) not allowed!\n");
			return -1;
		}

		if (!(val.flags & (PV_VAL_STR|PV_VAL_INT))) {
			LM_ERR("unnaceptable type for $shv dynamic name: %d\n", val.flags);
			return -1;
		}

		if (!(val.flags & PV_VAL_STR))
			s.s = sint2str(val.ri, &s.len);
		else
			s = val.rs;

		*shv = add_shvar(&s);
		if (!*shv) {
			LM_ERR("failed to get $shv(%.*s)\n", s.len, s.s);
			return -1;
		}
	} else {
		*shv = (sh_var_t *)pvn->u.dname;
	}

	return 0;
}

int pv_get_shvar(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	sh_var_t *shv;

	if (get_shvar_from_pv_name(msg, &param->pvn, &shv) != 0) {
		LM_ERR("failed to obtain shared var\n");
		return pv_get_null(msg, param, res);
	}

	lock_shvar(shv);
	if (shv->v.flags & VAR_VAL_STR) {
		if (shm_str_extend(&param->pvv, shv->v.value.s.len + 1) != 0) {
			LM_ERR("oom\n");
			unlock_shvar(shv);
			return pv_get_null(msg, param, res);
		}

		memcpy(param->pvv.s, shv->v.value.s.s, shv->v.value.s.len);
		param->pvv.len = shv->v.value.s.len;
		param->pvv.s[param->pvv.len] = '\0';

		unlock_shvar(shv);

		res->rs = param->pvv;
		res->flags = PV_VAL_STR;
		if (res->rs.len == 0)
			res->flags |= PV_VAL_EMPTY;
	} else {
		res->ri = shv->v.value.n;

		unlock_shvar(shv);

		res->rs.s = sint2str(res->ri, &res->rs.len);
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	}
	return 0;
}

int pv_set_shvar(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	sh_var_t *shv;
	int_str isv;
	int flags;

	if (get_shvar_from_pv_name(msg, &param->pvn, &shv) != 0) {
		LM_ERR("failed to obtain shared var\n");
		return -1;
	}

	lock_shvar(shv);
	if(val == NULL)
	{
		isv.n = 0;
		set_shvar_value(shv, &isv, 0);
		goto done;
	}
	flags = 0;
	if(val->flags&PV_TYPE_INT)
	{
		isv.n = val->ri;
	} else {
		isv.s = val->rs;
		flags |= VAR_VAL_STR;
	}
	if(set_shvar_value(shv, &isv, flags)==NULL)
	{
		LM_ERR("cannot set shvar [%.*s]\n", shv->name.len, shv->name.s);
		goto error;
	}
done:
	unlock_shvar(shv);
	return 0;
error:
	unlock_shvar(shv);
	return -1;
}

mi_response_t *mi_shvar_set(const mi_params_t *params, struct mi_handler *_)
{
	str sp;
	str name;
	int_str isv;
	int flags;
	sh_var_t *shv = NULL;

	if (get_mi_string_param(params, "name", &name.s, &name.len) < 0)
		return init_mi_param_error();

	if (!name.s || name.len < 0)
	{
		LM_ERR("bad shv name (ptr: %p, len: %d)\n", name.s, name.len);
		return init_mi_error( 500, MI_SSTR("bad shv name"));
	}

	if (get_mi_string_param(params, "type", &sp.s, &sp.len) < 0)
		return init_mi_param_error();
	if(sp.len<=0 || sp.s==NULL)
		return init_mi_error(500, MI_SSTR("type not found"));

	flags = 0;
	if(sp.s[0]=='s' || sp.s[0]=='S')
		flags = VAR_VAL_STR;

	if(flags == 0)
	{
		if (get_mi_int_param(params, "value", &isv.n) < 0)
			return init_mi_param_error();
	} else {
		if (get_mi_string_param(params, "value", &isv.s.s, &isv.s.len) < 0)
			return init_mi_param_error();
		if(isv.s.len<=0 || isv.s.s==NULL)
		{
			return init_mi_error(500, MI_SSTR("value not found"));
		}
	}

	shv = add_shvar(&name);
	if (!shv)
		return init_mi_error(500, MI_SSTR("Internal Server Error"));

	lock_shvar(shv);
	if(set_shvar_value(shv, &isv, flags)==NULL)
	{
		unlock_shvar(shv);
		LM_ERR("cannot set shv value\n");
		return init_mi_error( 500, MI_SSTR("cannot set shv value"));
	}

	unlock_shvar(shv);
	LM_DBG("$shv(%.*s) updated\n", name.len, name.s);
	return init_mi_result_ok();
}

int mi_print_var(sh_var_t *shv, mi_item_t *var_item, int do_locking)
{
	int ival;

	if (do_locking)
		lock_shvar(shv);

	if(shv->v.flags&VAR_VAL_STR)
	{
		if (add_mi_string(var_item, MI_SSTR("type"), MI_SSTR("string")) < 0) {
			if (do_locking)
				unlock_shvar(shv);
			return -1;
		}

		if (add_mi_string(var_item, MI_SSTR("value"),
			shv->v.value.s.s, shv->v.value.s.len) < 0) {
			if (do_locking)
				unlock_shvar(shv);
			return -1;
		}

		unlock_shvar(shv);
	} else {
		ival = shv->v.value.n;
		if (do_locking)
			unlock_shvar(shv);

		if (add_mi_string(var_item, MI_SSTR("type"), MI_SSTR("integer")) < 0)
			return -1;

		if (add_mi_number(var_item, MI_SSTR("value"), ival) < 0)
			return -1;
	}

	return 0;
}

struct mi_shvar_params {
	mi_item_t *var_arr;
	int rc;
};

static int mi_shvar_push_shv(void *param, str key, void *value)
{
	struct mi_shvar_params *params = (struct mi_shvar_params *)param;
	mi_item_t *var_item;
	sh_var_t *shv = (sh_var_t *)value;

	var_item = add_mi_object(params->var_arr, NULL, 0);
	if (!var_item) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_string(var_item, MI_SSTR("name"),
	        shv->name.s, shv->name.len) < 0) {
		params->rc = 1;
		return 1;
	}

	if (mi_print_var(shv, var_item, 0) != 0) {
		params->rc = 1;
		return 1;
	}

	return 0;
}

mi_response_t *mi_shvar_get(const mi_params_t *_, struct mi_handler *__)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	struct mi_shvar_params params = {0};

	resp = init_mi_result_array(&resp_obj);
	if (!resp)
		return NULL;

	params.var_arr = add_mi_array(resp_obj, MI_SSTR("VARs"));
	if (!params.var_arr)
		goto error;

	hash_for_each_locked(sh_vars, mi_shvar_push_shv, &params);
	if (params.rc != 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}

mi_response_t *mi_shvar_get_1(const mi_params_t *params, struct mi_handler *_)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *var_obj;
	str name;
	sh_var_t *shv = NULL;

	if (get_mi_string_param(params, "name", &name.s, &name.len) < 0)
		return init_mi_param_error();

	if (!name.s || name.len < 0) {
		LM_ERR("bad shv name\n");
		return init_mi_error( 500, MI_SSTR("bad shv name"));
	}

	shv = get_shvar_by_name(&name);
	if(shv==NULL)
		return init_mi_error(404, MI_SSTR("Not found"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	var_obj = add_mi_object(resp_obj, MI_SSTR("VAR"));
	if (!var_obj)
		goto error;

	if (mi_print_var(shv, var_obj, 0) < 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}

int param_set_xvar( modparam_t type, void* val, int mode)
{
	str s;
	char *p;
	int_str isv;
	int flags;
	int ival;
	script_var_t *sv;
	sh_var_t *shared_sv;

	s.s = (char*)val;
	if(s.s == NULL || s.s[0] == '\0')
		goto error;

	p = s.s;
	while(*p && *p!='=') p++;

	if(*p!='=')
		goto error;

	s.len = p - s.s;
	if(s.len == 0)
		goto error;
	p++;
	flags = 0;
	if(*p!='s' && *p!='S' && *p!='i' && *p!='I')
		goto error;

	if(*p=='s' || *p=='S')
		flags = VAR_VAL_STR;
	p++;
	if(*p!=':')
		goto error;
	p++;
	isv.s.s = p;
	isv.s.len = strlen(p);
	if(flags != VAR_VAL_STR) {
		if(str2sint(&isv.s, &ival)<0)
			goto error;
		isv.n = ival;
	}
	if(mode==0){
		sv = add_var(&s);
		if(sv==NULL)
			goto error;
		if(set_var_value(sv, &isv, flags)==NULL)
			goto error;
	}
	else {
		shared_sv = add_shvar(&s);
		if(shared_sv == NULL)
			goto error;
		if(set_shvar_value(shared_sv, &isv, flags) == NULL)
			goto error;
	}

	return 0;
error:
	LM_ERR("unable to set %s parameter [%s]\n",
			(mode == 0 ? "var" : "shv"), s.s);
	return -1;
}

int param_set_var( modparam_t type, void* val)
{
	return param_set_xvar(type, val, 0);
}

int param_set_shvar( modparam_t type, void* val)
{
	return param_set_xvar(type, val, 1);
}


/*** $time(name) PV class */

int pv_parse_time_name(pv_spec_p sp, const str *in)
{
	if(sp==NULL || in==NULL || in->len<=0)
		return -1;

	switch(in->len)
	{
		case 3:
			if(strncmp(in->s, "sec", 3)==0)
				sp->pvp.pvn.u.isname.name.n = 0;
			else if(strncmp(in->s, "min", 3)==0)
				sp->pvp.pvn.u.isname.name.n = 1;
			else if(strncmp(in->s, "mon", 3)==0)
				sp->pvp.pvn.u.isname.name.n = 4;
			else goto error;
		break;
		case 4:
			if(strncmp(in->s, "hour", 4)==0)
				sp->pvp.pvn.u.isname.name.n = 2;
			else if(strncmp(in->s, "mday", 4)==0)
				sp->pvp.pvn.u.isname.name.n = 3;
			else if(strncmp(in->s, "year", 4)==0)
				sp->pvp.pvn.u.isname.name.n = 5;
			else if(strncmp(in->s, "wday", 4)==0)
				sp->pvp.pvn.u.isname.name.n = 6;
			else if(strncmp(in->s, "yday", 4)==0)
				sp->pvp.pvn.u.isname.name.n = 7;
			else goto error;
		break;
		case 5:
			if(strncmp(in->s, "isdst", 5)==0)
				sp->pvp.pvn.u.isname.name.n = 8;
			else goto error;
		break;
		default:
			goto error;
	}
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	return 0;

error:
	LM_ERR("unknown PV time name %.*s\n", in->len, in->s);
	return -1;
}


int pv_get_time(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	static struct tm stored_ts;
	static time_t stored_t = 0;
	time_t t;

	if(msg==NULL || param==NULL)
		return -1;

	t = time(NULL);
	if (t!=stored_t) {
		stored_t = t;
		if (localtime_r(&t, &stored_ts) == NULL) {
			LM_ERR("unable to break time to attributes\n");
			return -1;
		}
	}

	switch(param->pvn.u.isname.name.n)
	{
		case 1:
			return pv_get_uintval(msg, param, res, (unsigned int)stored_ts.tm_min);
		case 2:
			return pv_get_uintval(msg, param, res, (unsigned int)stored_ts.tm_hour);
		case 3:
			return pv_get_uintval(msg, param, res, (unsigned int)stored_ts.tm_mday);
		case 4:
			return pv_get_uintval(msg, param, res,
					(unsigned int)(stored_ts.tm_mon+1));
		case 5:
			return pv_get_uintval(msg, param, res,
					(unsigned int)(stored_ts.tm_year+1900));
		case 6:
			return pv_get_uintval(msg, param, res,
					(unsigned int)(stored_ts.tm_wday+1));
		case 7:
			return pv_get_uintval(msg, param, res,
					(unsigned int)(stored_ts.tm_yday+1));
		case 8:
			return pv_get_sintval(msg, param, res, stored_ts.tm_isdst);
		default:
			return pv_get_uintval(msg, param, res, (unsigned int)stored_ts.tm_sec);
	}
}

