/*
 * JWT Authentication Module
 *
 * Copyright (C) 2020 OpenSIPS Project
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * --------
 * 2020-03-12 initial release (vlad)
 */

#ifndef _OPENSIPS_JWT_AVPS_H_
#define _OPENSIPS_JWT_AVPS_H_

#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../trim.h"
#include "../../pvar.h"

#include <string.h>


struct jwt_avp {
	int avp_name;
	unsigned short avp_type;
	str attr_name;
	struct jwt_avp *next;
};



static inline void free_jwt_avp(struct jwt_avp *avp)
{
	if (avp) {
		if (avp->attr_name.s)
			pkg_free(avp->attr_name.s);
		pkg_free(avp);
	}
}



static inline void free_jwt_avp_list(struct jwt_avp *avp)
{
	struct jwt_avp *tmp;

	while (avp) {
		tmp = avp;
		avp = avp->next;
		free_jwt_avp( tmp );
	}
}



static inline int parse_jwt_avps(char *definition,
										struct jwt_avp **avp_def, int *cnt)
{
	struct jwt_avp *avp;
	int avp_name = -1;
	pv_spec_t avp_spec;
	str  foo;
	char *p;
	char *e;
	char *s;
	char t;

	p = definition;
	*avp_def = 0;
	*cnt = 0;

	if (p==0 || *p==0)
		return 0;

	/* get element by element */
	while ( (e=strchr(p,';'))!=0 || (e=p+strlen(p))!=p ) {
		/* new jwt_avp struct */
		if ( (avp=(struct jwt_avp*)pkg_malloc(sizeof(struct jwt_avp)))==0 ) {
			LM_ERR("no more pkg mem\n");
			goto error;
		}
		memset( avp, 0, sizeof(struct jwt_avp));
		/* definition is between p and e */
		if ( (s=strchr(p,'='))!=0 && s<e ) {
			/* avp = attr */
			foo.s = p;
			foo.len = s-p;
			trim( &foo );
			if (foo.len==0)
				goto parse_error;
			t = foo.s[foo.len];
			foo.s[foo.len] = '\0';

			if (pv_parse_spec(&foo, &avp_spec)==0
					|| avp_spec.type!=PVT_AVP) {
				LM_ERR("malformed or non AVP %s AVP definition\n", foo.s);
				goto parse_error;;
			}

			if(pv_get_avp_name(0, &(avp_spec.pvp), &avp_name,
						&avp->avp_type)!=0)
			{
				LM_ERR("[%s]- invalid AVP definition\n", foo.s);
				goto parse_error;
			}
			foo.s[foo.len] = t;

			/* copy the avp name into the avp structure */
			avp->avp_name = avp_name;
			/* go to after the equal sign */
			p = s+1;
		}
		/* attr - is between p and e*/
		foo.s = p;
		foo.len = e-p;
		trim( &foo );
		if (foo.len==0)
			goto parse_error;
		/* copy the attr into the avp structure */
		avp->attr_name.s = (char*)pkg_malloc( foo.len+1 );
		if (avp->attr_name.s==0) {
			LM_ERR("no more pkg mem\n");
			goto error;
		}
		avp->attr_name.len = foo.len;
		memcpy( avp->attr_name.s, foo.s, foo.len );
		avp->attr_name.s[foo.len] = 0;
		/* was an avp name specified? */
		if (avp_name < 0) {
			if (parse_avp_spec(&avp->attr_name, &avp->avp_name) < 0) {
				LM_ERR("cannot get avp ip\n");
				goto error;
			}
		}
		/* link the element */
		avp->next = *avp_def;
		*avp_def = avp;
		(*cnt)++;
		avp = 0;
		avp_name = -1;
		/* go to the end */
		p = e;
		if (*p==';')
			p++;
		if (*p==0)
			break;
	}

	return 0;
parse_error:
	LM_ERR("parse failed in \"%s\" at pos %d(%s)\n",
		definition, (int)(long)(p-definition),p);
error:
	free_jwt_avp( avp );
	free_jwt_avp_list( *avp_def );
	*avp_def = 0;
	*cnt = 0;
	return -1;
}

#endif
