/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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

#include "map.h"


static gen_lock_t *extra_lock;
static struct usr_avp *global_avps = 0;
static struct usr_avp **crt_avps  = &global_avps;

static map_t avp_map = 0;
static map_t avp_map_shm = 0;
static int last_avp_index = 0;
/* it is also used to indicate that the extra AVPs that are stored in the
 * shared memory have been initialized */
static int *last_avp_index_shm = 0;

#define p2int(_p) (int)(unsigned long)(_p)
#define int2p(_i) (void *)(unsigned long)(_i)

int init_global_avps(void)
{
	/* initialize map for static avps */
	avp_map = map_create(0);
	if (!avp_map) {
		LM_ERR("cannot create avp_map\n");
		return -1;
	}
	return 0;
}


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
	last_avp_index_shm = shm_malloc(sizeof(int));
	if (!last_avp_index_shm) {
		LM_ERR("not enough shm mem\n");
		return -1;
	}
	*last_avp_index_shm = last_avp_index;
	/* initialize map for dynamic avps */
	avp_map_shm = map_create(AVLMAP_SHARED);
	if (!avp_map_shm) {
		LM_ERR("cannot create shared avp_map\n");
		return -1;
	}
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
		s = (str *)&avp->data;
		s->len = val.s.len;
		s->s = (char*)s + sizeof(str);
		memcpy( s->s, val.s.s , s->len);
		s->s[s->len] = 0;
	} else if (flags & AVP_VAL_NULL) {
                avp->data = NULL;
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

int add_avp_last(unsigned short flags, int name, int_str val)
{
	struct usr_avp* avp;
	struct usr_avp* last_avp;

	avp = new_avp(flags, name, val);
	if(avp == NULL) {
		LM_ERR("Failed to create new avp structure\n");
		return -1;
	}

	/* get end of the list */
	for( last_avp=*crt_avps ; last_avp && last_avp->next ; last_avp=last_avp->next);

	if (last_avp==NULL) {
		avp->next = *crt_avps;
		*crt_avps = last_avp = avp;
	} else {
		last_avp->next = avp;
		avp->next = NULL;
		last_avp = avp;
	}
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
static inline str* __get_avp_name(int id, map_t m)
{
	map_iterator_t it;
	int **idp;

	if (map_first(m, &it) < 0) {
		LM_ERR("map doesn't exist\n");
		return NULL;
	}
	for (;;) {
		if (!iterator_is_valid(&it))
			return NULL;

		idp = (int**)iterator_val(&it);
		if (!idp) {
			LM_ERR("[BUG] while getting avp name\n");
			return NULL;
		}
		if (p2int(*idp) == id)
			return iterator_key(&it);
		if (iterator_next(&it) < 0)
			return NULL;

	}
}


inline str* get_avp_name_id(int id)
{
	str *name;

	if (id < 0)
		return NULL;

	name = __get_avp_name(id, avp_map);
	/* search extra galiases */
	if (name)
		return name;
	lock_get(extra_lock);
	name = __get_avp_name(id, avp_map_shm);
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
	if (avp==0 || val==0)
		return;

	if (avp->flags & AVP_VAL_STR) {
		/* avp type ID, str value */
		val->s = *(str *)(&avp->data);
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
 * search first avp beginning with 'start->next'
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

void destroy_avp_list_bulk( struct usr_avp **list )
{
	struct usr_avp *avp, *foo;

	avp = *list;
	while( avp ) {
		foo = avp;
		avp = avp->next;
		shm_free_bulk( foo );
	}
	*list = 0;
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

static inline int __search_avp_map(str *alias, map_t m)
{
	int **id = (int **)map_find(m, *alias);
	LM_DBG("looking for [%.*s] avp %s - found %d\n", alias->len, alias->s,
			m == avp_map_shm ? "in shm": "", id ? p2int(*id) : -1);
	return id ? p2int(*id) : -1;
}


static int lookup_avp_alias_str(str *alias, int extra)
{
	int id;
	if (!alias || !alias->len || !alias->s)
		return -2;

	id = __search_avp_map(alias, avp_map);
	if (id < 0 && extra) {
		/* search extra alias */
		lock_get(extra_lock);
		id = __search_avp_map(alias, avp_map_shm);
		lock_release(extra_lock);
	}
	return id;
}

static inline int new_avp_alias(str *alias)
{
	int id = last_avp_index + 1;

	if (map_put(avp_map, *alias, int2p(id))) {
		LM_WARN("[BUG] Value should have already be found [%.*s]\n",
				alias->len, alias->s);
		return -1;
	}
	/* successfully added avp */
	last_avp_index++;

	LM_DBG("added alias %.*s with id %d\n",alias->len,alias->s,id);

	return id;
}

static inline int new_avp_extra_alias(str *alias)
{
	int id;

	if (!last_avp_index_shm) {
		LM_ERR("extra AVPs are not initialized yet\n");
		return -1;
	}

	/* check if last avp is valid */
	lock_get(extra_lock);
	id = (*last_avp_index_shm) + 1;
	if (map_put(avp_map_shm, *alias, int2p(id))) {
		lock_release(extra_lock);
		LM_WARN("[BUG] Value should have already be found [%.*s]\n",
				alias->len, alias->s);
		return -1;
	}
	(*last_avp_index_shm)++;
	lock_release(extra_lock);

	LM_DBG("added extra alias %.*s with id %d\n",alias->len,alias->s,id);

	return id;
}

int parse_avp_spec( str *name, int *avp_name)
{
	int id, extra;

	if (name==0 || name->s==0 || name->len==0)
		return -1;

	extra = last_avp_index_shm ? 1 : 0;

	if (name->len > 2 && name->s[1] == AVP_NAME_DELIM &&
			(name->s[0] == 'i' || name->s[0] == 's'))
		LM_WARN("Deprecated AVP name format \"%.*s\" - use \"%.*s\" instead\n",
				name->len, name->s, name->len - 2, name->s + 2);

	id = lookup_avp_alias_str(name, extra);
	if (id < 0) {
		id = extra ? new_avp_extra_alias(name) : new_avp_alias(name);
		if (id < 0) {
			LM_ERR("cannot add new avp\n");
			return -1;
		}
	}
	if (avp_name)
		*avp_name = id;
	return 0;
}

int get_avp_id(str *name)
{
	int id;
	if (parse_avp_spec(name, &id)) {
		LM_ERR("unable to get id\n");
		return -1;
	}
	return id;
}


struct usr_avp *clone_avp_list(struct usr_avp *old)
{
	struct usr_avp *a;
	int_str val;

	if (!old) return NULL;

	/* create a copy of the old AVP */
	get_avp_val( old, &val );
	a = new_avp( old->flags, old->id, val);
	if (a==NULL) {
		LM_ERR("cloning failed, trunking the list\n");
		return NULL;
	}

	a->next = clone_avp_list(old->next);
	return a;
}

