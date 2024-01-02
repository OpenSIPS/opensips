/*
 * Copyright (C) 2009-2020 OpenSIPS Solutions
 * Copyright (C) 2009 Voice Sistem SRL
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
*/

#include "../../mem/shm_mem.h"
#include "../../pt.h"
#include "dlg_vals.h"
#include "dlg_hash.h"



static inline unsigned int _get_name_id(const str *name)
{
	char *p;
	unsigned short id;

	id=0;
	for( p=name->s+name->len-1 ; p>=name->s ; p-- )
		id ^= *p;
	return id;
}



static inline struct dlg_val *new_dlg_val(str *name, int_str *val, int type)
{
	struct dlg_val *dv;
	int len;

	len = sizeof(struct dlg_val) + name->len + (type==DLG_VAL_TYPE_STR ?
		val->s.len : 0);
	dv =(struct dlg_val*)shm_malloc(len);
	if (dv==NULL) {
		LM_ERR("no more shm mem\n");
		return NULL;
	}

	dv->id = _get_name_id(name);
	dv->next = NULL;

	/* set name */
	dv->name.len = name->len;
	dv->name.s = (char*)(dv + 1);
	memcpy(dv->name.s, name->s, name->len);

	/* set value */
	if (type == DLG_VAL_TYPE_STR) {
		dv->val.s.len = val->s.len;
		dv->val.s.s = ((char*)(dv + 1)) + name->len;
		memcpy(dv->val.s.s, val->s.s, val->s.len);
	} else {
		dv->val.n = val->n;
	}

	dv->type = type;

	return dv;
}

int store_dlg_value_unsafe(struct dlg_cell *dlg, str *name, int_str *val, int type)
{
	struct dlg_val *dv=NULL;
	struct dlg_val *it;
	struct dlg_val *it_prev;
	unsigned int id;

	if ( val && (dv=new_dlg_val(name,val,type))==NULL) {
		LM_ERR("failed to create new dialog value\n");
		return -1;
	}

	id = val ? dv->id : _get_name_id(name);

	/* iterate the list */
	for( it_prev=NULL, it=dlg->vals ; it ; it_prev=it,it=it->next) {
		if (id==it->id && name->len==it->name.len &&
		memcmp(name->s,it->name.s,name->len)==0 ) {
			LM_DBG("var found-> <%.*s>!\n",it->name.len,it->name.s);
			/* found -> replace or delete it */
			if (val==NULL) {
				/* delete it */
				if (it_prev) it_prev->next = it->next;
				else dlg->vals = it->next;
			} else {
				/* replace the current it with dv and free the it */
				dv->next = it->next;
				if (it_prev) it_prev->next = dv;
				else dlg->vals = dv;
			}
			dlg->flags |= DLG_FLAG_VP_CHANGED;

			shm_free(it);
			return 0;
		}
	}

	/* not found */
	if (val==NULL)
		return 0;

	/* has value ? -> simply add a new one */

	/* insert at the beginning of the list */
	dv->next = dlg->vals;
	dlg->vals = dv;

	dlg->flags |= DLG_FLAG_VP_CHANGED;

	return 0;
}

int store_dlg_value(struct dlg_cell *dlg, str *name, int_str *val, int type)
{
	int ret;

	/* lock dialog (if not already locked via a callback triggering)*/
	if (dlg->locked_by!=process_no)
		dlg_lock_dlg( dlg );
	ret = store_dlg_value_unsafe(dlg,name,val,type);
	/* unlock dialog */
	if (dlg->locked_by!=process_no)
		dlg_unlock_dlg( dlg );

	return ret;
}

static str val_buf = { NULL, 0};
static int val_buf_size;

/**
 * fetch_dlg_value - search for @name in @dlg, write results to @out_val
 *
 * If @val_has_buf is true, @out_val.s may contain a user-supplied pkg buffer
 * which will be realloc'ed as necessary in order to hold the value.
 *
 * If @val_has_buf is false, the returned @out_val.s string must not be freed!
 *
 * @return:
 *  0 - success
 * -1 - error
 * -2 - not found
 */
int fetch_dlg_value(struct dlg_cell *dlg, const str *name,
	int *type, int_str *out_val, int val_has_buf)
{
	struct dlg_val *dv;
	unsigned int id;
	str *val;

	LM_DBG("looking for <%.*s>\n",name->len,name->s);

	id = _get_name_id(name);

	if (!val_has_buf) {
		val = &val_buf;
		val->len = val_buf_size;
	} else
		val = &out_val->s;

	/* lock dialog (if not already locked via a callback triggering)*/
	if (dlg->locked_by!=process_no)
		dlg_lock_dlg( dlg );

	/* iterate the list */
	for( dv=dlg->vals ; dv ; dv=dv->next) {
		if (id==dv->id && name->len==dv->name.len &&
		memcmp(name->s,dv->name.s,name->len)==0 ) {
			*type = dv->type;

			if (dv->type == DLG_VAL_TYPE_STR) {
				LM_DBG("var found-> <%.*s>!\n",dv->val.s.len,dv->val.s.s);
				/* found -> make a copy of the value under lock */
				if (dv->val.s.len > val->len) {
					val->s = (char*)pkg_realloc(val->s,dv->val.s.len);
					if (val->s==NULL) {
						if (!val_has_buf)
							val_buf_size = 0;

						if (dlg->locked_by!=process_no)
							dlg_unlock_dlg( dlg );
						LM_ERR("failed to do realloc for %d\n",dv->val.s.len);
						return -1;
					}

					if (!val_has_buf)
						val_buf_size = dv->val.s.len;
				}
				memcpy( val->s, dv->val.s.s, dv->val.s.len );
				val->len = dv->val.s.len;
				out_val->s = *val;
			} else {
				LM_DBG("var found-> <%d>!\n",dv->val.n);
				out_val->n = dv->val.n;
			}

			/* unlock dialog */
			if (dlg->locked_by!=process_no)
				dlg_unlock_dlg( dlg );
			return 0;
		}
	}

	/* unlock dialog */
	if (dlg->locked_by!=process_no)
		dlg_unlock_dlg( dlg );
	LM_DBG("var NOT found!\n");

	return -2;
}


int check_dlg_value_unsafe(struct sip_msg *msg, struct dlg_cell *dlg, str *name,
	pv_spec_t *val)
{
	struct dlg_val *dv;
	unsigned int id;
	pv_value_t pval;
	int type;

	LM_DBG("looking for <%.*s>\n", name->len, name->s);

	id = _get_name_id(name);

	if (pv_get_spec_value(msg, val, &pval) < 0) {
		LM_ERR("Failed to get value from variable\n");
		return -1;
	}
	if (pvv_is_int(&pval)) {
		type = DLG_VAL_TYPE_INT;
	} else if (pvv_is_str(&pval)) {
		type = DLG_VAL_TYPE_STR;
	} else {
		LM_ERR("Bad variable type\n");
		return -1;
	}

	/* iterate the list */
	for( dv=dlg->vals ; dv ; dv=dv->next) {
		if (id==dv->id && name->len==dv->name.len &&
		memcmp(name->s,dv->name.s,name->len)==0 && type == dv->type ) {
			if (dv->type == DLG_VAL_TYPE_STR) {
				LM_DBG("var found with val <%.*s>!\n",dv->val.s.len,dv->val.s.s);
				if ( pval.rs.len==dv->val.s.len &&
				memcmp(pval.rs.s,dv->val.s.s,pval.rs.len)==0) {
					LM_DBG("var found!\n");
					return 0;
				}
				break;
			} else {  /* DLG_VAL_TYPE_INT */
				LM_DBG("var found with val <%d>!\n",dv->val.n);
				if (pval.ri == dv->val.n)
					return 0;
			}
		}
	}

	LM_DBG("var NOT found!\n");
	return -1;
}


int pv_parse_name(pv_spec_p sp, const str *in)
{
	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	sp->pvp.pvn.u.isname.name.s = *in;

	return 0;
}



int pv_get_dlg_val(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	struct dlg_cell *dlg;
	int type;
	int_str isval;

	if (param==NULL || param->pvn.type!=PV_NAME_INTSTR ||
	param->pvn.u.isname.type!=AVP_NAME_STR ||
	param->pvn.u.isname.name.s.s==NULL ) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if ( (dlg=get_current_dialog())==NULL )
		return pv_get_null(msg, param, res);

	isval.s = param->pvv;
	if (fetch_dlg_value(dlg, &param->pvn.u.isname.name.s, &type, &isval, 1)!=0)
		return pv_get_null(msg, param, res);
	param->pvv = isval.s;

	if (type == DLG_VAL_TYPE_STR) {
		res->flags = PV_VAL_STR;
		res->rs = isval.s;
	} else {
		res->flags = PV_VAL_INT|PV_TYPE_INT;
		res->ri = isval.n;
	}

	return 0;
}


int pv_set_dlg_val(struct sip_msg* msg, pv_param_t *param, int op,
															pv_value_t *pval)
{
	struct dlg_cell *dlg;
	int_str val;
	int type;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	if (param==NULL || param->pvn.type!=PV_NAME_INTSTR ||
	param->pvn.u.isname.type!=AVP_NAME_STR ||
	param->pvn.u.isname.name.s.s==NULL ) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if (pval==NULL || pval->flags&(PV_VAL_NONE|PV_VAL_NULL|PV_VAL_EMPTY)) {
		/* if NULL, remove the value */
		if (store_dlg_value( dlg, &param->pvn.u.isname.name.s, NULL,
			DLG_VAL_TYPE_NONE)!=0) {
			LM_ERR("failed to delete dialog values <%.*s>\n",
				param->pvn.u.isname.name.s.len,param->pvn.u.isname.name.s.s);
			return -1;
		}
	} else {
		if (pvv_is_str(pval)) {
			val.s = pval->rs;
			type = DLG_VAL_TYPE_STR;
		} else if (pvv_is_int(pval)) {
			val.n = pval->ri;
			type = DLG_VAL_TYPE_INT;
		} else {
			LM_ERR("Bad value type\n");
			return -1;
		}

		if (store_dlg_value( dlg, &param->pvn.u.isname.name.s, &val, type)!=0) {
			LM_ERR("failed to store dialog values <%.*s>\n",
				param->pvn.u.isname.name.s.len,param->pvn.u.isname.name.s.s);
			return -1;
		}
	}

	return 0;
}

