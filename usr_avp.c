/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * ---------
 *  2004-07-21  created (bogdan)
 *  2004-10-09  interface more flexible - more function available (bogdan)
 *  2004-11-07  AVP string values are kept 0 terminated (bogdan)
 *  2004-11-14  global aliases support added (bogdan)
 */


#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "sr_module.h"
#include "dprint.h"
#include "str.h"
#include "ut.h"
#include "mem/shm_mem.h"
#include "mem/mem.h"
#include "usr_avp.h"


/* usr_avp data bodies */
struct str_int_data {
	str  name;
	int  val;
};

struct str_str_data {
	str  name;
	str  val;
};

/* avp aliases structs*/
struct avp_spec {
	int type;
	int_str name;
};

struct avp_galias {
	str alias;
	struct avp_spec  avp;
	struct avp_galias *next;
};

static struct avp_galias *galiases = 0;
static struct usr_avp *global_avps = 0;
static struct usr_avp **crt_avps  = &global_avps;



inline static unsigned short compute_ID( str *name )
{
	char *p;
	unsigned short id;

	id=0;
	for( p=name->s+name->len-1 ; p>=name->s ; p-- )
		id ^= *p;
	return id;
}

struct usr_avp* new_avp(unsigned short flags, int_str name, int_str val)
{
	struct usr_avp *avp;
	str *s;
	struct str_int_data *sid;
	struct str_str_data *ssd;
	int len;

	assert( crt_avps!=0 );

	if ( name.n==0 ) {
		LM_ERR("0 ID or NULL NAME AVP!\n");
		goto error;
	}

	/* compute the required mem size */
	len = sizeof(struct usr_avp);
	if (flags&AVP_NAME_STR) {
		if ( name.s.s==0 || name.s.len==0) {
			LM_ERR("empty avp name!\n");
			goto error;
		}
		if (flags&AVP_VAL_STR)
			len += sizeof(struct str_str_data)-sizeof(void*) + name.s.len
				+ (val.s.len+1);
		else
			len += sizeof(struct str_int_data)-sizeof(void*) + name.s.len;
	} else if (flags&AVP_VAL_STR)
			len += sizeof(str)-sizeof(void*) + (val.s.len+1);

	avp = (struct usr_avp*)shm_malloc( len );
	if (avp==0) {
		LM_ERR("no more shm mem\n");
		goto error;
	}

	avp->flags = flags;
	avp->id = (flags&AVP_NAME_STR)? compute_ID(&name.s) : name.n ;


	switch ( flags&(AVP_NAME_STR|AVP_VAL_STR) )
	{
		case 0:
			/* avp type ID, int value */
			avp->data = (void*)(long)val.n;
			break;
		case AVP_NAME_STR:
			/* avp type str, int value */
			sid = (struct str_int_data*)(void*)&(avp->data);
			sid->val = val.n;
			sid->name.len =name.s.len;
			sid->name.s = (char*)sid + sizeof(struct str_int_data);
			memcpy( sid->name.s , name.s.s, name.s.len);
			break;
		case AVP_VAL_STR:
			/* avp type ID, str value */
			s = (str*)(void*)&(avp->data);
			s->len = val.s.len;
			s->s = (char*)s + sizeof(str);
			memcpy( s->s, val.s.s , s->len);
			s->s[s->len] = 0;
			break;
		case AVP_NAME_STR|AVP_VAL_STR:
			/* avp type str, str value */
			ssd = (struct str_str_data*)(void*)&(avp->data);
			ssd->name.len = name.s.len;
			ssd->name.s = (char*)ssd + sizeof(struct str_str_data);
			memcpy( ssd->name.s , name.s.s, name.s.len);
			ssd->val.len = val.s.len;
			ssd->val.s = ssd->name.s + ssd->name.len;
			memcpy( ssd->val.s , val.s.s, val.s.len);
			ssd->val.s[ssd->val.len] = 0;
			break;
	}

	return avp;
error:
	return NULL;
}

int add_avp(unsigned short flags, int_str name, int_str val)
{
	struct usr_avp* avp;

	avp = new_avp(flags, name, val);
	if(avp == NULL) {
		LM_ERR("Failed to create new avp structure\n");
		return -1;
	}

	avp->next = *crt_avps;
	*crt_avps = avp;
	return 0;
}

struct usr_avp *search_index_avp(unsigned short flags,
					int_str name, int_str *val, unsigned int index)
{
	struct usr_avp *avp = NULL;

	while ( (avp=search_first_avp( flags, name, 0, avp))!=0 ) {
		if( index == 0 ){
			return avp;
		}
		index--;
	}
	return 0;
}

int replace_avp(unsigned short flags, int_str name, int_str val, int index)
{
	struct usr_avp* avp, *avp_prev;
	struct usr_avp* avp_new, *avp_del;

	if(index < 0) {
		LM_ERR("Index with negative value\n");
		return -1;
	}

	avp_del = search_index_avp(flags, name, 0, index);
	if(avp_del == NULL) {
		LM_DBG("AVP to replace not found\n");
		return -1;
	}

	avp_new = new_avp(flags, name, val);
	if(avp_new == NULL) {
		LM_ERR("Failed to create new avp structure\n");
		return -1;
	}

	for( avp_prev=0,avp=*crt_avps ; avp ; avp_prev=avp,avp=avp->next ) {
		if (avp==avp_del) {
			if (avp_prev)
				avp_prev->next=avp_new;
			else
				*crt_avps = avp_new;
			avp_new->next = avp_del->next;
			shm_free(avp_del);
			return 0;
		}
	}
	return 0;
}

/* get value functions */

inline str* get_avp_name(struct usr_avp *avp)
{
	void *data;
	switch ( avp->flags&(AVP_NAME_STR|AVP_VAL_STR) )
	{
		case 0:
			/* avp type ID, int value */
		case AVP_VAL_STR:
			/* avp type ID, str value */
			return 0;
		case AVP_NAME_STR:
			/* avp type str, int value */
			data = (void*)&avp->data;
			return &((struct str_int_data*)data)->name;
		case AVP_NAME_STR|AVP_VAL_STR:
			/* avp type str, str value */
			data = (void*)&avp->data;
			return &((struct str_str_data*)data)->name;
	}

	LM_ERR("unknown avp type (name&val) %d\n",
		avp->flags&(AVP_NAME_STR|AVP_VAL_STR));
	return 0;
}


inline void get_avp_val(struct usr_avp *avp, int_str *val)
{
	void *data;

	if (avp==0 || val==0)
		return;

	switch ( avp->flags&(AVP_NAME_STR|AVP_VAL_STR) ) {
		case 0:
			/* avp type ID, int value */
			val->n = (long)(avp->data);
			break;
		case AVP_NAME_STR:
			/* avp type str, int value */
			data = (void*)&avp->data;
			val->n = ((struct str_int_data*)data)->val;
			break;
		case AVP_VAL_STR:
			/* avp type ID, str value */
			data = (void*)&avp->data;
			val->s = *((str*)data);
			break;
		case AVP_NAME_STR|AVP_VAL_STR:
			/* avp type str, str value */
			data = (void*)&avp->data;
			val->s = ((struct str_str_data*)data)->val;
			break;
	}
}


struct usr_avp** get_avp_list(void)
{
	assert( crt_avps!=0 );
	return crt_avps;
}




/* search functions */

inline static struct usr_avp *internal_search_ID_avp( struct usr_avp *avp,
								unsigned short id, unsigned short flags)
{
	for( ; avp ; avp=avp->next ) {
		if ( id==avp->id && (avp->flags&AVP_NAME_STR)==0 
				&& (flags==0 || (flags&avp->flags))) {
			return avp;
		}
	}
	return 0;
}



inline static struct usr_avp *internal_search_name_avp( struct usr_avp *avp,
						unsigned short id, str *name, unsigned short flags)
{
	str * avp_name;

	for( ; avp ; avp=avp->next )
		if ( id==avp->id && avp->flags&AVP_NAME_STR
		&& (flags==0 || (flags&avp->flags))
		&& (avp_name=get_avp_name(avp))!=0 && avp_name->len==name->len
		&& !strncasecmp( avp_name->s, name->s, name->len) ) {
			return avp;
		}
	return 0;
}


/**
 * search first avp begining with 'start->next'
 * if start==NULL, beging from head of avp list
 */
struct usr_avp *search_first_avp( unsigned short flags,
					int_str name, int_str *val,  struct usr_avp *start)
{
	struct usr_avp *head;
	struct usr_avp *avp;

	if(start==0)
	{
		assert( crt_avps!=0 );
	
		if (*crt_avps==0)
			return 0;
		head = *crt_avps;
	} else {
		if(start->next==0)
			return 0;
		head = start->next;
	}

	if ( name.n==0) {
		LM_ERR("0 ID or NULL NAME AVP!\n");
		return 0;
	}

	/* search for the AVP by ID (&name) */
	if (flags&AVP_NAME_STR) {
		if ( name.s.s==0 || name.s.len==0) {
			LM_ERR("empty avp name!\n");
			return 0;
		}
		avp = internal_search_name_avp(head,compute_ID(&name.s),&name.s,
				flags&AVP_SCRIPT_MASK);
	} else {
		avp = internal_search_ID_avp(head, name.n,
				flags&AVP_SCRIPT_MASK);
	}

	/* get the value - if required */
	if (avp && val)
		get_avp_val(avp, val);

	return avp;
}



struct usr_avp *search_next_avp( struct usr_avp *avp,  int_str *val )
{
	if (avp==0 || avp->next==0)
		return 0;

	if (avp->flags&AVP_NAME_STR)
		avp = internal_search_name_avp( avp->next, avp->id, get_avp_name(avp),
				avp->flags&AVP_SCRIPT_MASK );
	else
		avp = internal_search_ID_avp( avp->next, avp->id,
				avp->flags&AVP_SCRIPT_MASK );

	if (avp && val)
		get_avp_val(avp, val);

	return avp;
}



/********* free functions ********/

void destroy_avp( struct usr_avp *avp_del)
{
	struct usr_avp *avp;
	struct usr_avp *avp_prev;

	for( avp_prev=0,avp=*crt_avps ; avp ; avp_prev=avp,avp=avp->next ) {
		if (avp==avp_del) {
			if (avp_prev)
				avp_prev->next=avp->next;
			else
				*crt_avps = avp->next;
			shm_free(avp);
			return;
		}
	}
}

int destroy_avps( unsigned short flags, int_str name, int all)
{
	struct usr_avp *avp;
	int n;

	n = 0;
	while ( (avp=search_first_avp( flags, name, 0, 0))!=0 ) {
		destroy_avp( avp );
		n++;
		if ( !all )
			break;
	}
	return n;
}

void destroy_index_avp( unsigned short flags, int_str name, int index)
{
	struct usr_avp *avp = NULL;

	avp = search_index_avp(flags, name, 0, index);
	if(avp== NULL) {
		LM_DBG("AVP with the specified index not found\n");
		return;
	}

	destroy_avp( avp );
}


void destroy_avp_list_unsafe( struct usr_avp **list )
{
	struct usr_avp *avp, *foo;

	avp = *list;
	while( avp ) {
		foo = avp;
		avp = avp->next;
		shm_free_unsafe( foo );
	}
	*list = 0;
}


inline void destroy_avp_list( struct usr_avp **list )
{
	struct usr_avp *avp, *foo;

	LM_DBG("destroying list %p\n", *list);
	avp = *list;
	while( avp ) {
		foo = avp;
		avp = avp->next;
		shm_free( foo );
	}
	*list = 0;
}


void reset_avps(void)
{
	assert( crt_avps!=0 );
	
	if ( crt_avps!=&global_avps) {
		crt_avps = &global_avps;
	}
	destroy_avp_list( crt_avps );
}


struct usr_avp** set_avp_list( struct usr_avp **list )
{
	struct usr_avp **foo;
	
	assert( crt_avps!=0 );

	foo = crt_avps;
	crt_avps = list;
	return foo;
}




/********* global aliases functions ********/

static inline int check_avp_galias(str *alias, int type, int_str avp_name)
{
	struct avp_galias *ga;

	type &= AVP_NAME_STR;

	for( ga=galiases ; ga ; ga=ga->next ) {
		/* check for duplicated alias names */
		if ( alias->len==ga->alias.len &&
		(strncasecmp( alias->s, ga->alias.s, alias->len)==0) )
			return -1;
		/*check for duplicated avp names */
		if (type==ga->avp.type) {
			if (type&AVP_NAME_STR){
				if (avp_name.s.len==ga->avp.name.s.len &&
				(strncasecmp(avp_name.s.s, ga->avp.name.s.s,
							 					avp_name.s.len)==0) )
					return -1;
			} else {
				if (avp_name.n==ga->avp.name.n)
					return -1;
			}
		}
	}
	return 0;
}


int add_avp_galias(str *alias, int type, int_str avp_name)
{
	struct avp_galias *ga;

	if ((type&AVP_NAME_STR && (!avp_name.s.s ||
								!avp_name.s.len)) ||!alias || !alias->s ||
		!alias->len ){
		LM_ERR("null params received\n");
		goto error;
	}

	if (check_avp_galias(alias,type,avp_name)!=0) {
		LM_ERR("duplicate alias/avp entry\n");
		goto error;
	}

	ga = (struct avp_galias*)pkg_malloc( sizeof(struct avp_galias) );
	if (ga==0) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	ga->alias.s = (char*)pkg_malloc( alias->len+1 );
	if (ga->alias.s==0) {
		LM_ERR("no more pkg memory\n");
		goto error1;
	}
	memcpy( ga->alias.s, alias->s, alias->len);
	ga->alias.len = alias->len;

	ga->avp.type = type&AVP_NAME_STR;

	if (type&AVP_NAME_STR) {
		ga->avp.name.s.s = (char*)pkg_malloc(avp_name.s.len+1);
		if (ga->avp.name.s.s==0) {
			LM_ERR("no more pkg memory\n");
			goto error2;
		}
		ga->avp.name.s.len = avp_name.s.len;
		memcpy(ga->avp.name.s.s, avp_name.s.s, avp_name.s.len);
		ga->avp.name.s.s[avp_name.s.len] = 0;
		LM_DBG("registering <%s> for avp name <%s>\n",
			ga->alias.s, ga->avp.name.s.s);
	} else {
		ga->avp.name.n = avp_name.n;
		LM_DBG("registering <%s> for avp id <%d>\n",
			ga->alias.s, ga->avp.name.n);
	}

	ga->next = galiases;
	galiases = ga;

	return 0;
error2:
	pkg_free(ga->alias.s);
error1:
	pkg_free(ga);
error:
	return -1;
}


int lookup_avp_galias(str *alias, int *type, int_str *avp_name)
{
	struct avp_galias *ga;

	for( ga=galiases ; ga ; ga=ga->next )
		if (alias->len==ga->alias.len &&
		(strncasecmp( alias->s, ga->alias.s, alias->len)==0) ) {
			*type = ga->avp.type;
			*avp_name = ga->avp.name;
			return 0;
		}

	return -1;
}


/* parsing functions */

int parse_avp_name( str *name, int *type, int_str *avp_name)
{
	unsigned int id;
	unsigned int flags;
	char *p;
	char c;
	str s;

	if (name==0 || name->s==0 || name->len==0)
		goto error;

	p = (char*)memchr((void*)name->s, AVP_NAME_DELIM, name->len);
	c = name->s[0];
	if((c!='i' && c!='I' && c!='s' && c!='S') || p==NULL)
	{
		LM_ERR("- use type (s: or i:) in front of avp name\n");
		goto error;
	}
	/* flags */
	flags = 0;
	if(p>name->s+1)
	{
		s.s = name->s+1;
		s.len = p - s.s;
		if(str2int(&s, &flags)!=0)
		{
			LM_ERR("bad avp flags\n");
			goto error;
		}
	}
	name->len -= p-name->s+1;
	name->s    = p+1;
	switch (c) {
		case 's': case 'S':
			*type = AVP_NAME_STR;
			avp_name->s = *name;
			break;
		case 'i': case 'I':
			*type = 0;
			if (str2int( name, &id)!=0) {
				LM_ERR("invalid ID <%.*s> not a number\n", name->len, name->s);
				goto error;
			}
			avp_name->n = (int)id;
			break;
		default:
			LM_ERR("unsupported type [%c]\n", c);
			goto error;
	}

	*type |= avp_script_flags(flags);
	return 0;
error:
	return -1;
}


int parse_avp_spec( str *name, int *type, int_str *avp_name)
{
	char *p;

	if (name==0 || name->s==0 || name->len==0)
		return -1;

	p = (char*)memchr((void*)name->s, AVP_NAME_DELIM, name->len);
	if (p==NULL) {
		/* it's an avp alias */
		return lookup_avp_galias( name, type, avp_name);
	} else {
		return parse_avp_name( name, type, avp_name);
	}
}


int add_avp_galias_str(char *alias_definition)
{
	int_str avp_name;
	char *s;
	str  name;
	str  alias;
	int  type;

	s = alias_definition;
	while(*s && isspace((int)*s))
		s++;

	while (*s) {
		/* parse alias name */
		alias.s = s;
		while(*s && *s!=';' && !isspace((int)*s) && *s!='=')
			s++;
		if (alias.s==s || *s==0 || *s==';')
			goto parse_error;
		alias.len = s-alias.s;
		while(*s && isspace((int)*s))
			s++;
		/* equal sign */
		if (*s!='=')
			goto parse_error;
		s++;
		while(*s && isspace((int)*s))
			s++;
		/* avp name */
		name.s = s;
		while(*s && *s!=';' && !isspace((int)*s))
			s++;
		if (name.s==s)
			goto parse_error;
		name.len = s-name.s;
		while(*s && isspace((int)*s))
			s++;
		/* check end */
		if (*s!=0 && *s!=';')
			goto parse_error;
		if (*s==';') {
			for( s++ ; *s && isspace((int)*s) ; s++ );
			if (*s==0)
				goto parse_error;
		}

		if (parse_avp_name( &name, &type, &avp_name)!=0) {
			LM_ERR("<%.*s> not a valid AVP name\n", name.len, name.s);
			goto error;
		}

		if (add_avp_galias( &alias, type, avp_name)!=0) {
			LM_ERR("add global alias failed\n");
			goto error;
		}
	} /*end while*/

	return 0;
parse_error:
	LM_ERR("parse error in <%s> around pos %ld\n", 
			alias_definition, (long)(s-alias_definition));
error:
	return -1;
}


