/*
 * Copyright (C) 2008-2024 OpenSIPS Solutions
 * Copyright (C) 2004-2006 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 *
 */



#include <stdlib.h>
#include <ctype.h>

#include "../../ut.h"
#include "../../dprint.h"
#include "../../usr_avp.h"
#include "../../mem/mem.h"
#include "dbops_parse.h"


#define SCHEME_UUID_COL          "uuid_col"
#define SCHEME_UUID_COL_LEN      (sizeof(SCHEME_UUID_COL)-1)
#define SCHEME_USERNAME_COL      "username_col"
#define SCHEME_USERNAME_COL_LEN  (sizeof(SCHEME_USERNAME_COL)-1)
#define SCHEME_DOMAIN_COL        "domain_col"
#define SCHEME_DOMAIN_COL_LEN    (sizeof(SCHEME_DOMAIN_COL)-1)
#define SCHEME_VALUE_COL         "value_col"
#define SCHEME_VALUE_COL_LEN     (sizeof(SCHEME_VALUE_COL)-1)
#define SCHEME_TABLE             "table"
#define SCHEME_TABLE_LEN         (sizeof(SCHEME_TABLE)-1)
#define SCHEME_VAL_TYPE          "value_type"
#define SCHEME_VAL_TYPE_LEN      (sizeof(SCHEME_VAL_TYPE)-1)
#define SCHEME_INT_TYPE          "integer"
#define SCHEME_INT_TYPE_LEN      (sizeof(SCHEME_INT_TYPE)-1)
#define SCHEME_STR_TYPE          "string"
#define SCHEME_STR_TYPE_LEN      (sizeof(SCHEME_STR_TYPE)-1)


int parse_avp_db(char *s, struct db_param *dbp, int allow_scheme)
{
	str   tmp;
	str   s0;
	str *s1;
	char  have_scheme;
	char *p;
	char *p0;
	unsigned int flags;

	LM_DBG("parse: %s\n", s);
	tmp.s = s;
	/* parse the attribute name - check first if it's not an alias */
	p0=strchr(tmp.s, '/');
	if(p0!=NULL)
		*p0=0;
	if ( *s!='$')
	{
		if(strlen(s)<1)
		{
			LM_ERR("bad param - expected : $avp(name), *, s or i value\n");
			return E_UNSPEC;
		}
		switch(*s) {
			/* deteleted because of the new avp format */
			case 's': case 'S':
			case 'i': case 'I':
			case '*': case 'a': case 'A':
				dbp->a.opd = AVPOPS_VAL_NONE;
			break;
			default:
				LM_ERR("bad param - expected : *, s or i AVP flag\n");
			return E_UNSPEC;
		}
		/* flags */
		flags = 0;
		if(*(s+1)!='\0')
		{
			s0.s = s+1;
			s0.len = strlen(s0.s);
			if(str2int(&s0, &flags)!=0)
			{
				LM_ERR("error - bad avp flags\n");
				goto error;
			}
		}
		dbp->a.u.sval.pvp.pvn.u.isname.type |= (flags<<8)&0xff00;
		dbp->a.type = AVPOPS_VAL_NONE;
	} else {
		s0.s = s; s0.len = strlen(s0.s);
		p = pv_parse_spec(&s0, &dbp->a.u.sval);
		if (p==0 || *p!='\0' || dbp->a.u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad param - expected : $avp(name) or int/str value\n");
			return E_UNSPEC;
		}
		dbp->a.type = AVPOPS_VAL_PVAR;
	}

	/* optimize and keep the attribute name as str also to
	 * speed up db querie builds */
	if (dbp->a.type == AVPOPS_VAL_PVAR)
	{
		dbp->a.opd = AVPOPS_VAL_PVAR;
		if(pv_has_iname(&dbp->a.u.sval))
		{
			s1 = get_avp_name_id(dbp->a.u.sval.pvp.pvn.u.isname.name.n);
			if (!s1)
			{
				LM_ERR("cannot find avp name\n");
				goto error;
			}
			dbp->sa.s=(char*)pkg_malloc(s1->len + 1);
			if (dbp->sa.s==0)
			{
				LM_ERR("no more pkg mem\n");
				goto error;
			}
			memcpy(dbp->sa.s, s1->s, s1->len);
			dbp->sa.len = s1->len;
			dbp->sa.s[dbp->sa.len] = 0;
			dbp->a.opd = AVPOPS_VAL_PVAR|AVPOPS_VAL_STR;
		}
	}

	/* restore '/' */
	if(p0)
		*p0 = '/';
	/* is there a table name ? */
	s = p0;
	if (s && *s)
	{
		s++;
		if (*s=='$')
		{
			if (allow_scheme==0)
			{
				LM_ERR("function doesn't support DB schemes\n");
				goto error;
			}
			if (dbp->a.opd&AVPOPS_VAL_NONE)
			{
				LM_ERR("inconsistent usage of "
					"DB scheme without complet specification of AVP name\n");
				goto error;
			}
			have_scheme = 1;
			s++;
		} else {
			have_scheme = 0;
		}
		tmp.s = s;
		tmp.len = 0;
		while ( *s ) s++;
		tmp.len = s - tmp.s;
		if (tmp.len==0)
		{
			LM_ERR("empty scheme/table name\n");
			goto error;
		}
		if (have_scheme)
		{
			dbp->scheme = get_avp_db_scheme( &tmp );
			if (dbp->scheme==0)
			{
				LM_ERR("scheme <%s> not found\n", tmp.s);
				goto error;
			}
			/* update scheme flags with AVP name type*/
			dbp->scheme->db_flags|=dbp->a.opd&AVPOPS_VAL_STR?AVP_NAME_STR:0;
		} else {
			/* duplicate table str into the db_param struct */
			pkg_str_dup( &dbp->table, &tmp);
		}
	}

	return 0;
error:
	return -1;
}


#define  duplicate_str(_p, _str, _error) \
	do { \
		_p.s = (char*)pkg_malloc(_str.len+1); \
		if (_p.s==0) \
		{ \
			LM_ERR("no more pkg memory\n");\
			goto _error; \
		} \
		_p.len = _str.len; \
		memcpy( _p.s, _str.s, _str.len); \
		_p.s[_str.len] = 0; \
	}while(0)

int parse_avp_db_scheme( char *s, struct db_scheme *scheme)
{
	str foo;
	str bar;
	char *p;

	if (s==0 || *s==0)
		goto error;
	p = s;

	/*parse the name */
	while (*p && isspace((int)*p)) p++;
	foo.s = p;
	while (*p && *p!=':' && !isspace((int)*p)) p++;
	if (foo.s==p || *p==0)
		/* missing name or empty scheme */
		goto parse_error;
	foo.len = p - foo.s;
	/* dulicate it */
	duplicate_str( scheme->name, foo, error);

	/* parse the ':' separator */
	while (*p && isspace((int)*p)) p++;
	if (*p!=':')
		goto parse_error;
	p++;
	while (*p && isspace((int)*p)) p++;
	if (*p==0)
		goto parse_error;

	/* set as default value type string */
	scheme->db_flags = AVP_VAL_STR;

	/* parse the attributes */
	while (*p)
	{
		/* get the attribute name */
		foo.s = p;
		while (*p && *p!='=' && !isspace((int)*p)) p++;
		if (p==foo.s || *p==0)
			/* missing attribute name */
			goto parse_error;
		foo.len = p - foo.s;

		/* parse the '=' separator */
		while (*p && isspace((int)*p)) p++;
		if (*p!='=')
			goto parse_error;
		p++;
		while (*p && isspace((int)*p)) p++;
		if (*p==0)
			goto parse_error;

		/* parse the attribute value */
		bar.s = p;
		while (*p && *p!=';' && !isspace((int)*p)) p++;
		if (p==bar.s)
			/* missing attribute value */
			goto parse_error;
		bar.len = p - bar.s;

		/* parse the ';' separator, if any */
		while (*p && isspace((int)*p)) p++;
		if (*p!=0 && *p!=';')
			goto parse_error;
		if (*p==';') p++;
		while (*p && isspace((int)*p)) p++;

		/* identify the attribute */
		if ( foo.len==SCHEME_UUID_COL_LEN &&
		!strncasecmp( foo.s, SCHEME_UUID_COL, foo.len) )
		{
			if (scheme->uuid_col.s) goto parse_error;
			duplicate_str( scheme->uuid_col, bar, error);
		} else
		if ( foo.len==SCHEME_USERNAME_COL_LEN &&
		!strncasecmp( foo.s, SCHEME_USERNAME_COL, foo.len) )
		{
			if (scheme->username_col.s) goto parse_error;
			duplicate_str( scheme->username_col, bar, error);
		} else
		if ( foo.len==SCHEME_DOMAIN_COL_LEN &&
		!strncasecmp( foo.s, SCHEME_DOMAIN_COL, foo.len) )
		{
			if (scheme->domain_col.s) goto parse_error;
			duplicate_str( scheme->domain_col, bar, error);
		} else
		if ( foo.len==SCHEME_VALUE_COL_LEN &&
		!strncasecmp( foo.s, SCHEME_VALUE_COL, foo.len) )
		{
			if (scheme->value_col.s) goto parse_error;
			duplicate_str( scheme->value_col, bar, error);
		} else
		if ( foo.len==SCHEME_TABLE_LEN &&
		!strncasecmp( foo.s, SCHEME_TABLE, foo.len) )
		{
			if (scheme->table.s) goto parse_error;
			duplicate_str( scheme->table, bar, error);
		} else
		if ( foo.len==SCHEME_VAL_TYPE_LEN &&
		!strncasecmp( foo.s, SCHEME_VAL_TYPE, foo.len) )
		{
			if ( bar.len==SCHEME_INT_TYPE_LEN &&
			!strncasecmp( bar.s, SCHEME_INT_TYPE, bar.len) )
				scheme->db_flags &= (~AVP_VAL_STR);
			else if ( bar.len==SCHEME_STR_TYPE_LEN &&
			!strncasecmp( bar.s, SCHEME_STR_TYPE, bar.len) )
				scheme->db_flags = AVP_VAL_STR;
			else
			{
				LM_ERR("unknown value type <%.*s>\n",bar.len,bar.s);
				goto error;
			}
		} else {
			LM_ERR("unknown attribute <%.*s>\n",foo.len,foo.s);
			goto error;
		}
	} /* end while */

	return 0;
parse_error:
	LM_ERR("parse error in <%s> around %ld\n", s, (long)(p-s));
error:
	return -1;
}

