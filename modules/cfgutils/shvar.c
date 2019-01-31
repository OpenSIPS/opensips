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

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../pvar.h"

#include "shvar.h"

int shvar_locks_no=16;
gen_lock_set_t* shvar_locks=0;

static sh_var_t *sh_vars = 0;

/*
 * Initialize locks
 */
int shvar_init_locks(void)
{
	int i;
	i = shvar_locks_no;
	do {
		if ((( shvar_locks=lock_set_alloc(i))!=0)&&
				(lock_set_init(shvar_locks)!=0))
		{
			shvar_locks_no = i;
			LM_INFO("locks array size %d\n", shvar_locks_no);
			return 0;

		}
		if (shvar_locks){
			lock_set_dealloc(shvar_locks);
			shvar_locks=0;
		}
		i--;
		if(i==0)
		{
			LM_ERR("failed to allocate locks\n");
			return -1;
		}
	} while (1);
}

void shvar_unlock_locks(void)
{
	unsigned int i;

	if (shvar_locks==0)
		return;

	for (i=0;i<shvar_locks_no;i++) {
#ifdef GEN_LOCK_T_PREFERED
		lock_release(&shvar_locks->locks[i]);
#else
		shvar_release_idx(i);
#endif
	};
}


void shvar_destroy_locks(void)
{
	if (shvar_locks !=0){
		lock_set_destroy(shvar_locks);
		lock_set_dealloc(shvar_locks);
	}
}

#ifndef GEN_LOCK_T_PREFERED
void shvar_lock_idx(int idx)
{
	lock_set_get(shvar_locks, idx);
}

void shvar_release_idx(int idx)
{
	lock_set_release(shvar_locks, idx);
}
#endif

/*
 * Get lock
 */
void lock_shvar(sh_var_t *shv)
{
	if(shv==NULL)
		return;
#ifdef GEN_LOCK_T_PREFERED
	lock_get(shv->lock);
#else
	shvar_lock_idx(shv->lockidx);
#endif
}


/*
 * Release lock
 */
void unlock_shvar(sh_var_t *shv)
{
	if(shv==NULL)
		return;
#ifdef GEN_LOCK_T_PREFERED
	lock_release(shv->lock);
#else
	shvar_release_idx(shv->lockidx);
#endif
}


sh_var_t* add_shvar(str *name)
{
	sh_var_t *sit;

	if(!shvar_locks){
		if(shvar_init_locks()){
			LM_ERR("init shvars locks failed\n");
			return 0;
		}
	}

	if(name==0 || name->s==0 || name->len<=0)
		return 0;

	for(sit=sh_vars; sit; sit=sit->next)
	{
		if(sit->name.len==name->len
				&& strncmp(name->s, sit->name.s, name->len)==0)
			return sit;
	}
	sit = (sh_var_t*)shm_malloc(sizeof(sh_var_t));
	if(sit==0)
	{
		LM_ERR("out of shm\n");
		return 0;
	}
	memset(sit, 0, sizeof(sh_var_t));
	sit->name.s = (char*)shm_malloc((name->len+1)*sizeof(char));

	if(sit->name.s==0)
	{
		LM_ERR("out of shm!\n");
		shm_free(sit);
		return 0;
	}
	sit->name.len = name->len;
	strncpy(sit->name.s, name->s, name->len);
	sit->name.s[sit->name.len] = '\0';

	if(sh_vars!=0)
		sit->n = sh_vars->n + 1;
	else
		sit->n = 1;

#ifdef GEN_LOCK_T_PREFERED
	sit->lock = &shvar_locks->locks[sit->n%shvar_locks_no];
#else
	sit->lockidx = sit->n%shvar_locks_no;
#endif

	sit->next = sh_vars;

	sh_vars = sit;

	return sit;
}

/* call it with lock set */
sh_var_t* set_shvar_value(sh_var_t* shv, int_str *value, int flags)
{
	if(shv==NULL)
		return NULL;
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

sh_var_t* get_shvar_by_name(str *name)
{
	sh_var_t *it;

	if(name==0 || name->s==0 || name->len<=0)
		return 0;

	for(it=sh_vars; it; it=it->next)
	{
		if(it->name.len==name->len
				&& strncmp(name->s, it->name.s, name->len)==0)
			return it;
	}
	return 0;
}

void reset_shvars(void)
{
	sh_var_t *it;
	for(it=sh_vars; it; it=it->next)
	{
		if(it->v.flags&VAR_VAL_STR)
		{
			shm_free(it->v.value.s.s);
			it->v.flags &= ~VAR_VAL_STR;
		}
		memset(&it->v.value, 0, sizeof(int_str));
	}
}

void destroy_shvars(void)
{
	sh_var_t *it;
	sh_var_t *it0;

	it = sh_vars;
	while(it)
	{
		it0 = it;
		it = it->next;
		shm_free(it0->name.s);
		if(it0->v.flags&VAR_VAL_STR)
			shm_free(it0->v.value.s.s);
		shm_free(it0);
	}

	sh_vars = 0;
}


/********* PV functions *********/
int pv_parse_shvar_name(pv_spec_p sp, str *in)
{
	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = (void*)add_shvar(in);
	if(sp->pvp.pvn.u.dname==NULL)
	{
		LM_ERR("cannot register shvar [%.*s]\n", in->len, in->s);
		return -1;
	}

	return 0;
}

int pv_get_shvar(struct sip_msg *msg,  pv_param_t *param,
		pv_value_t *res)
{
	int len = 0;
	char *sval = NULL;
	sh_var_t *shv=NULL;

	if(msg==NULL || res==NULL)
		return -1;

	if(param==NULL || param->pvn.u.dname==0)
		return pv_get_null(msg, param, res);

	shv= (sh_var_t*)param->pvn.u.dname;

	lock_shvar(shv);
	if(shv->v.flags&VAR_VAL_STR)
	{
		if(param->pvv.s==NULL || param->pvv.len < shv->v.value.s.len)
		{
			if(param->pvv.s!=NULL)
				pkg_free(param->pvv.s);
			param->pvv.s = (char*)pkg_malloc(shv->v.value.s.len*sizeof(char));
			if(param->pvv.s==NULL)
			{
				unlock_shvar(shv);
				LM_ERR("no more pkg mem\n");
				return pv_get_null(msg, param, res);
			}
		}
		strncpy(param->pvv.s, shv->v.value.s.s, shv->v.value.s.len);
		param->pvv.len = shv->v.value.s.len;

		unlock_shvar(shv);

		res->rs = param->pvv;
		res->flags = PV_VAL_STR;
	} else {
		res->ri = shv->v.value.n;

		unlock_shvar(shv);

		sval = sint2str(res->ri, &len);
		res->rs.s = sval;
		res->rs.len = len;
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	}
	return 0;
}

int pv_set_shvar(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	int_str isv;
	int flags;

	if(param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(param->pvn.u.dname==0)
	{
		LM_ERR("error - cannot find shvar\n");
		goto error;
	}
	lock_shvar((sh_var_t*)param->pvn.u.dname);
	if(val == NULL)
	{
		isv.n = 0;
		set_shvar_value((sh_var_t*)param->pvn.u.dname, &isv, 0);
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
	if(set_shvar_value((sh_var_t*)param->pvn.u.dname, &isv, flags)==NULL)
	{
		LM_ERR("error - cannot set shvar [%.*s] \n",
				((sh_var_t*)param->pvn.u.dname)->name.len,
				((sh_var_t*)param->pvn.u.dname)->name.s);
		goto error;
	}
done:
	unlock_shvar((sh_var_t*)param->pvn.u.dname);
	return 0;
error:
	unlock_shvar((sh_var_t*)param->pvn.u.dname);
	return -1;
}

mi_response_t *mi_shvar_set(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str sp;
	str name;
	int_str isv;
	int flags;
	sh_var_t *shv = NULL;

	if (get_mi_string_param(params, "name", &name.s, &name.len) < 0)
		return init_mi_param_error();
	if(name.len<=0 || name.s==NULL)
	{
		LM_ERR("bad shv name\n");
		return init_mi_error( 500, MI_SSTR("bad shv name"));
	}

	shv = get_shvar_by_name(&name);
	if(shv==NULL)
		return init_mi_error(404, MI_SSTR("Not found"));

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

int mi_print_var(sh_var_t *shv, mi_item_t *var_item)
{
	int ival;

	lock_shvar(shv);
	if(shv->v.flags&VAR_VAL_STR)
	{
		if (add_mi_string(var_item, MI_SSTR("type"), MI_SSTR("string")) < 0) {
			unlock_shvar(shv);
			return -1;
		}

		if (add_mi_string(var_item, MI_SSTR("value"),
			shv->v.value.s.s, shv->v.value.s.len) < 0) {
			unlock_shvar(shv);
			return -1;
		}

		unlock_shvar(shv);
	} else {
		ival = shv->v.value.n;
		unlock_shvar(shv);
		if (add_mi_string(var_item, MI_SSTR("type"), MI_SSTR("integer")) < 0)
			return -1;

		if (add_mi_number(var_item, MI_SSTR("value"), ival) < 0)
			return -1;
	}

	return 0;
}

mi_response_t *mi_shvar_get(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *var_arr, *var_item;
	sh_var_t *shv = NULL;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;
	var_arr = add_mi_array(resp_obj, MI_SSTR("VARs"));
	if (!var_arr)
		goto error;

	for(shv=sh_vars; shv; shv=shv->next)
	{
		var_item = add_mi_object(var_arr, NULL, 0);
		if (!var_item)
			goto error;

		if (add_mi_string(var_item, MI_SSTR("name"),
			shv->name.s, shv->name.len) < 0)
			goto error;

		if (mi_print_var(shv, var_item) < 0)
			goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_shvar_get_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *var_obj;
	str name;
	sh_var_t *shv = NULL;

	if (get_mi_string_param(params, "name", &name.s, &name.len) < 0)
		return init_mi_param_error();

	if(name.len==0 || name.s==NULL)
	{
		LM_ERR("bad shv name\n");
		return init_mi_error( 500, MI_SSTR("bad shv name"));
	}
	shv = get_shvar_by_name(&name);
	if(shv==NULL)
		return init_mi_error(404, MI_SSTR("Not found"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	var_obj = add_mi_object(resp_obj, MI_SSTR("VAR"));
	if (!var_obj)
		goto error;

	if (mi_print_var(shv, var_obj) < 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return 0;
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

int pv_parse_time_name(pv_spec_p sp, str *in)
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

