/*
 * load balancer module - complex call load balancing
 *
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
 *
 */



#include <ctype.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../mem/mem.h"

#include "../freeswitch/fs_api.h"

#include "lb_parser.h"

extern int fetch_freeswitch_stats;

struct lb_res_str* search_resource_str( struct lb_res_str_list *lb_rl,
																	str*name)
{
	unsigned int i;

	for( i=0 ; i<lb_rl->n ; i++) {
		if (name->len==lb_rl->resources[i].name.len &&
		memcmp(name->s, lb_rl->resources[i].name.s, name->len)==0 )
			return &lb_rl->resources[i];
	}
	return NULL;
}


struct lb_res_str_list *parse_resources_list(char *r_list, int has_val)
{
	struct lb_res_str_list *lb_rl;
	unsigned int n;
	unsigned int len;
	char *p;
	char *s;
	char *end;
	str name;
	str val;
	int i, first_fs_res = -1;

	/* validate and count */
	n = 0;
	len = 0;

	p = r_list;
	do {
		/* eat spaces */
		for( ; *p && isspace(*p) ; p++);
		if (!*p) break;
		/* name and value */
		end = strchr(p,';');
		if (end)
			*end = 0;
		name.s = p;
		p = strchr(p,'=');
		if (end)
			*end = ';';
		if (p) {
			if (!has_val) {
				LM_ERR("resource must not have value!\n");
				goto error;
			}
		} else {
			if (has_val) {
				LM_ERR("resource must have value!\n");
				goto error;
			}
			p = end?end:(r_list+strlen(r_list));
		}
		for(; (p-1)!=name.s && isspace(*(p-1)) ; p-- );
		if (p==name.s) {
			LM_ERR("empty resource name around %d\n",(unsigned int)(p-r_list));
			goto error;
		}
		name.len = p-name.s;
		/* mark */
		n++;
		len += name.len;
		/* next */
		p = end+1;
	} while(end && *p);

	if (n==0) {
		LM_ERR("empty list of resources\n");
		goto error;
	}
	LM_DBG("discovered %d resources\n",n);

	/* allocate stuff*/
	lb_rl = (struct lb_res_str_list *)pkg_malloc
		(sizeof(struct lb_res_str_list) + n*sizeof(struct lb_res_str) + len);
	if (lb_rl==NULL) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}
	memset(lb_rl+1, 0, n * sizeof(struct lb_res_str) + len);

	/* init the strucuture */
	lb_rl->n = n;
	lb_rl->resources =(struct lb_res_str*)(lb_rl+1);
	s = (char*)(lb_rl->resources + n);


	/* fill in the structures*/
	p = r_list;
	n = 0;
	do {
		/* eat spaces */
		for( ; *p && isspace(*p) ; p++);
		if (!*p) break;
		/* name .... */
		end = strchr(p,';');
		if (end)
			*end = 0;
		name.s = p;
		val.s = 0;
		p = strchr(p,'=');
		if (end)
			*end = ';';
		if (!p) {
			p = end?end:(r_list+strlen(r_list));
		} else {
			val.s = p+1;
		}
		for(; (p-1)!=name.s && isspace(*(p-1)) ; p-- );
		name.len = p-name.s;
		lb_rl->resources[n].name.len = name.len;
		lb_rl->resources[n].name.s = s;
		memcpy( s, name.s, name.len );
		s += name.len;
		/* ....and value */
		if (has_val) {
			/* eat spaces */
			for( ; *val.s && isspace(*val.s) ; val.s++);
			if (!*val.s) {
				LM_ERR("empty val !\n");
				goto error1;
			}
			val.len = ( end?end:(r_list+strlen(r_list)) ) - val.s;
			for( ; isspace(val.s[val.len-1]) ; val.len--);

			if (str2int(&val, &lb_rl->resources[n].val) != 0) {
				if (fetch_freeswitch_stats && is_fs_url(&val)) {
					lb_rl->resources[n].fs_url = val;
					lb_rl->resources[n].val = 0;
					first_fs_res = n;
				} else {
					LM_ERR("invalid value [%.*s]\n",val.len,val.s);
					goto error1;
				}
			}
		} else {
			lb_rl->resources[n].val = 0;
		}
		/* next */
		n++;
		p = end+1;
	} while(end && *p);

	if (first_fs_res >= 0) {
		for (i = 0; i < n; i++) {
			if (i != first_fs_res) {
				LM_WARN("A FreeSWITCH-enabled resource is already present: "
				        "'%.*s=%.*s'! Ignoring resource '%.*s'!\n",
				        lb_rl->resources[first_fs_res].name.len,
				        lb_rl->resources[first_fs_res].name.s,
				        lb_rl->resources[first_fs_res].fs_url.len,
				        lb_rl->resources[first_fs_res].fs_url.s,
				        lb_rl->resources[i].name.len, lb_rl->resources[i].name.s);
			}
		}

		lb_rl->resources[0] = lb_rl->resources[first_fs_res];
		lb_rl->n = 1;
	}

	return lb_rl;

error1:
	pkg_free(lb_rl);
error:
	return NULL;
}
