/*
 * $Id$
 *
 * Copyright (C) 2006 Voice System SRL
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "dprint.h"
#include "mem/mem.h"
#include "items.h"

typedef struct _xl_extra
{
	str name;
	xl_spec_t spec;
	struct _xl_extra *next;
} xl_extra_t, *xl_extra_p;

xl_extra_p  *_xl_extra_list=0;



int xl_add_extra(char *name, item_func_t fct, unsigned int type,
															xl_param_t *param)
{
	xl_spec_t tmspec;
	str pvname;

	if(name==NULL || fct==NULL)
	{
		LOG(L_ERR, "xl_add_extra: error - invalid parameters\n");
		return -1;
	}
	
	memset(&tmspec, 0, sizeof(xl_spec_t));
	tmspec.type = type;
	tmspec.itf = fct;
	if(param!=NULL)
		memcpy(&tmspec.p, param, sizeof(xl_param_t));
	pvname.s   = name;
	pvname.len = strlen(pvname.s);
	return xl_add_extra_spec(&pvname, &tmspec);
}


/**
 *
 */
int xl_add_extra_spec(str *name, xl_spec_p sp)
{
	int size;
	int found;
	int i;
	char *p;
	xl_extra_p xe0;
	xl_extra_p xe1;
	xl_extra_p xe;

	if(name==0 || name->s==0 || name->len<=0 || sp==0)
	{
		LOG(L_ERR, "xl_add_extra_spec: bad parameters\n");
		return -1;
	}
	if(_xl_extra_list==0)
	{
		DBG("xl_add_extra_spec: extra items list is not initialized\n");
		if(xl_init_extra_spec()!=0)
		{
			LOG(L_ERR, "xl_add_extra_spec: error - cannot intit extra list\n");
			return -1;
		}
	}
	
	/* check for valid characters */
	p = name->s;
	while(p<name->s+name->len)
	{
		if((*p>='0' && *p<='9') || (*p>='a' && *p<='z') || (*p>='A' && *p<='Z')
				|| (*p=='_') || (*p=='.'))
		{
			p++;
		} else {
			LOG(L_ERR, "xl_add_extra_spec: invalid char [%c] in [%.*s]\n",
					*p, name->len, name->s);
			return -1;
		}
	}

	found = 0;
	i = 0;
	xe1 = 0;
	
	xe0 = *_xl_extra_list;
	while(xe0)
	{
		if(xe0->name.len>name->len)
			break;
		if(xe0->name.len==name->len)
		{
			found = strncmp(xe0->name.s, name->s, name->len);
			if(found>0)
				break;
			if(found==0)
			{
				LOG(L_ERR,
					"xl_add_extra_spec: extra item [%.*s] already exists\n",
					name->len, name->s);
				return -1;
			}
		}
		xe1 = xe0;
		i++;
		xe0 = xe0->next;
	}

	size = sizeof(xl_extra_t) + (name->len+1)*sizeof(char);
	if(sp->p.val.s!=0 && sp->p.val.len>0)
		size += (sp->p.val.len+1)*sizeof(char);

	xe = (xl_extra_p)pkg_malloc(size);
	if(xe == 0)
	{
		LOG(L_ERR, "xl_add_extra_spec: cannot alloc extra item\n");
		return -1;
	}
	memset(xe, 0, size);
	/* fill the structure */
	xe->name.s = (char*)(((char*)xe)+sizeof(xl_extra_t));
	memcpy(xe->name.s, name->s, name->len);
	xe->name.s[name->len] = '\0';
	xe->name.len = name->len;
	memcpy(&xe->spec, sp, sizeof(xl_spec_t));
	xe->spec.type += XL_ITEM_EXTRA;
	if(sp->p.val.s!=0 && sp->p.val.len>0)
	{
		xe->spec.p.val.s = (char*)(xe->name.s+xe->name.len+1);
		memcpy(xe->spec.p.val.s, sp->p.val.s, sp->p.val.len);
		xe->spec.p.val.s[sp->p.val.len] = '\0';
		xe->spec.p.val.len = sp->p.val.len;
	}
	DBG("xl_add_extra_spec: inserting extra item [%.*s] at [%d]\n",
			name->len, name->s, i);
	if(xe1 == 0)
	{
		xe->next = *_xl_extra_list;
		*_xl_extra_list = xe;
		goto done;
	}
	xe->next = xe1->next;
	xe1->next = xe;
	
done:
	return 0;
}

/**
 *
 */
int xl_fill_extra_spec(xl_spec_p sp)
{
	str name;
	int found;
	xl_extra_p xe0;
	
	if(sp==0 || sp->p.val.s==0 || sp->p.val.len<=0)
	{
		LOG(L_ERR, "xl_fill_extra_spec: bad parameters\n");
		return -1;
	}
	
	if(_xl_extra_list==0)
	{
		LOG(L_ERR, "xl_fill_extra_spec: extra items list is not initialized\n");
		return -1;
	}

	found = 0;
	name = sp->p.val;
	
	xe0 = *_xl_extra_list;
	while(xe0)
	{
		if(xe0->name.len>name.len)
			break;
		if(xe0->name.len==name.len)
		{
			found = strncmp(xe0->name.s, name.s, name.len);
			if(found>0)
				break;
			if(found==0)
			{
				DBG("xl_fill_extra_spec: found extra item [%.*s]\n",
					name.len, name.s);
				memcpy(sp, &xe0->spec, sizeof(xl_spec_t));
				sp->flags |= XL_EXTRA_FOUND;
				return 0;
			}
		}
		xe0 = xe0->next;
	}

	LOG(L_ERR,
		"xl_fill_extra_spec: extra item [%.*s] not found\n",
		name.len, name.s);
	
	return 1;
}

/**
 *
 */
int xl_init_extra_spec(void)
{
	_xl_extra_list = (xl_extra_p*)pkg_malloc(sizeof(xl_extra_p));
	if(_xl_extra_list==0)
	{
		LOG(L_ERR, "xl_init_extra_spec: cannot alloc extra items list\n");
		return -1;
	}
	*_xl_extra_list=0;
	return 0;
}

/**
 *
 */
int xl_free_extra_spec(void)
{
	xl_extra_p xe;
	xl_extra_p xe1;
	if(_xl_extra_list!=0)
	{
		xe = *_xl_extra_list;
		while(xe!=0)
		{
			xe1 = xe;
			xe = xe->next;
			pkg_free(xe1);
		}
		pkg_free(_xl_extra_list);
		_xl_extra_list = 0;
	}
	
	return 0;
}


int register_items_mod(char *mod_name, item_export_t *items)
{
	int ret;
	int i;

	if (items==0)
		return 0;

	for ( i=0 ; items[i].name ; i++ ) {
		ret = xl_add_extra(items[i].name, items[i].fct, items[i].type,
				&items[i].param);
		if (ret!=0) {
			LOG(L_ERR,"ERROR:items:register_items_mod: failed to register"
				" pseudo-variable <%s> for module %s\n", items[i].name,
				mod_name);
		}
	}
	return 0;
}

