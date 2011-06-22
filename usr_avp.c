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
#include "locking.h"


/* usr_avp data bodies */
struct avp_alias {
	str alias;
	int id;
	struct avp_alias *next;
};

static struct avp_alias *galiases = 0;
static struct avp_alias **extra_galiases = 0;
static gen_lock_t *extra_lock;
static struct usr_avp *global_avps = 0;
static struct usr_avp **crt_avps  = &global_avps;


int init_extra_avps(void)
{
	extra_lock = lock_alloc();
	if (!extra_lock) {
		LM_ERR("cannot allocate lock\n");
		return -1;
	}
	if (!lock_init(extra_lock)) {
		LM_ERR("cannot init lock\n");
		return -1;
	}
	extra_galiases = shm_malloc(sizeof(struct avp_alias *));
	if (!extra_galiases) {
		LM_ERR("no more shm memory for extra aliases\n");
		return -1;
	}
	*extra_galiases = 0;
	return 0;
}


struct usr_avp* new_avp(unsigned short flags, int id, int_str val)
{
	struct usr_avp *avp;
	str *s;
	int len;

	assert( crt_avps!=0 );

	if (id < 0) {
		LM_ERR("invalid AVP name!\n");
		goto error;
	}

	/* compute the required mem size */
	len = sizeof(struct usr_avp);
	if (flags & AVP_VAL_STR)
		len += sizeof(str)-sizeof(void*) + (val.s.len+1);

	avp = (struct usr_avp*)shm_malloc( len );
	if (avp==0) {
		LM_ERR("no more shm mem\n");
		goto error;
	}

	avp->flags = flags;
	avp->id = id ;

	if (flags & AVP_VAL_STR) {
		/* avp type ID, str value */
		s = (str*)(void*)&(avp->data);
		s->len = val.s.len;
		s->s = (char*)s + sizeof(str);
		memcpy( s->s, val.s.s , s->len);
		s->s[s->len] = 0;
	} else {
		avp->data = (void *)(long)val.n;
	}

	return avp;
error:
	return NULL;
}

int add_avp(unsigned short flags, int name, int_str val)
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
					int name, int_str *val, unsigned int index)
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

int replace_avp(unsigned short flags, int name, int_str val, int index)
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

/* get name functions */
static inline str* __get_avp_name(int id, struct avp_alias *head)
{
	for ( ; head; head = head->next) {
		if (head->id == id)
			return &head->alias;
	}
	return NULL;
}


inline str* get_avp_name_id(int id)
{
	str *name;

	if (id < 0)
		return NULL;

	name = __get_avp_name(id, galiases);
	/* search extra galiases */
	if (name)
		return name;
	lock_get(extra_lock);
	name = __get_avp_name(id, *extra_galiases);
	lock_release(extra_lock);
	return name;
}

inline str* get_avp_name(struct usr_avp *avp)
{
	return get_avp_name_id(avp->id);
}

/* get value functions */
inline void get_avp_val(struct usr_avp *avp, int_str *val)
{
	void *data;

	if (avp==0 || val==0)
		return;

	if (avp->flags & AVP_VAL_STR) {
		/* avp type ID, str value */
		data = (void*)&avp->data;
		val->s = *((str*)data);
	} else {
		/* avp type ID, int value */
			val->n = (long)(avp->data);
	}
}


struct usr_avp** get_avp_list(void)
{
	assert( crt_avps!=0 );
	return crt_avps;
}




/* search functions */

inline static struct usr_avp *internal_search_ID_avp( struct usr_avp *avp,
								int id, unsigned short flags)
{
	for( ; avp ; avp=avp->next ) {
		if ( id==avp->id && (flags==0 || (flags&avp->flags))) {
			return avp;
		}
	}
	return 0;
}



/**
 * search first avp begining with 'start->next'
 * if start==NULL, beging from head of avp list
 */
struct usr_avp *search_first_avp( unsigned short flags,
					int id, int_str *val,  struct usr_avp *start)
{
	struct usr_avp *head;
	struct usr_avp *avp;

	if (id < 0) {
		LM_ERR("invalid avp id %d\n", id);
		return 0;
	}

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

	/* search for the AVP by ID (&name) */
	avp = internal_search_ID_avp(head, id, flags&AVP_SCRIPT_MASK);

	/* get the value - if required */
	if (avp && val)
		get_avp_val(avp, val);

	return avp;
}



struct usr_avp *search_next_avp( struct usr_avp *avp,  int_str *val )
{
	if (avp==0 || avp->next==0)
		return 0;

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

int destroy_avps( unsigned short flags, int name, int all)
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

void destroy_index_avp( unsigned short flags, int name, int index)
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

static inline int __search_avp_alias(str *alias, struct avp_alias *head)
{
	for ( ; head; head = head->next) {
		if (head->alias.len == alias->len &&
				memcmp(alias->s, head->alias.s, alias->len) == 0)
			return head->id;
	}
	return -1;
}


static int lookup_avp_alias_str(str *alias, int extra)
{
	int id;
	if (!alias || !alias->len || !alias->s)
		return -2;

	id = __search_avp_alias(alias, galiases);
	if (id < 0 && extra) {
		/* search extra alias */
		lock_get(extra_lock);
		id = __search_avp_alias(alias, *extra_galiases);
		lock_release(extra_lock);
	}
	return id;
}

static inline int new_avp_alias(str *alias)
{
	struct avp_alias * new_alias;

	new_alias = pkg_malloc(sizeof(struct avp_alias) + alias->len);
	if (!new_alias) {
		LM_ERR("no more pkg mem to add avp\n");
		return 0;
	}
	new_alias->id = galiases ? galiases->id + 1 : 0;
	new_alias->next = galiases;
	new_alias->alias.len = alias->len;
	new_alias->alias.s = (char *)new_alias + sizeof(struct avp_alias);
	memcpy(new_alias->alias.s, alias->s, alias->len);
	galiases = new_alias;

	LM_DBG("added alias %.*s with id %hu\n",alias->len,alias->s,new_alias->id);

	return new_alias->id;
}

static inline int new_avp_extra_alias(str *alias)
{
	struct avp_alias * new_alias;

	new_alias = shm_malloc(sizeof(struct avp_alias) + alias->len);
	if (!new_alias) {
		LM_ERR("no more shm mem to add avp\n");
		return 0;
	}

	lock_get(extra_lock);
	if (*extra_galiases)
		new_alias->id = (*extra_galiases)->id + 1;
	else 
		new_alias->id = galiases ? galiases->id + 1 : 0;
	new_alias->next = *extra_galiases;
	new_alias->alias.len = alias->len;
	new_alias->alias.s = (char *)new_alias + sizeof(struct avp_alias);
	memcpy(new_alias->alias.s, alias->s, alias->len);
	*extra_galiases = new_alias;
	lock_release(extra_lock);

	LM_DBG("added extra alias %.*s with id %d\n",
			alias->len,alias->s,new_alias->id);

	return new_alias->id;
}

static int parse_avp_spec_aux( str *name, int *avp_name, int extra)
{
	int id;

	if (name==0 || name->s==0 || name->len==0)
		return -1;

	id = lookup_avp_alias_str(name, extra);
	if (id < 0) {
		if (name->len > 2 && name->s[1] == AVP_NAME_DELIM &&
				(name->s[0] == 'i' || name->s[0] == 's'))
			LM_WARN("Deprecated AVP name format \"%.*s\" - use \"%.*s\" instead\n",
					name->len, name->s, name->len - 2, name->s + 2);
		id = extra ? new_avp_extra_alias(name) : new_avp_alias(name);
		if (id < 0)
			return -1;
	}
	if (avp_name)
		*avp_name = id;
	return 0;
}

int parse_avp_spec( str *name, int *avp_name)
{
	return parse_avp_spec_aux(name, avp_name, 0);
}

int get_avp_id(str *name)
{
	int id;
	if (parse_avp_spec_aux(name, &id, 1)) {
		LM_ERR("unable to get id\n");
		return -1;
	}
	return id;
}
