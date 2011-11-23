/*
 * $Id$
 *
 * Copyright (C) 2008 Voice System SRL
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
 * --------
 * 2008-04-20  initial version (bogdan)
 * 2008-09-16  speed optimization (andreidragus)
 *
 */

#include <stdio.h>
#include "../../mem/shm_mem.h"
#include "../../hash_func.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "dlg_hash.h"
#include "dlg_profile.h"

#define PROFILE_HASH_SIZE 16

static struct dlg_profile_table *profiles = NULL;
static struct lock_set_list * all_locks = NULL;
static struct lock_set_list * cur_lock = NULL;
static int finished_allocating_locks = 0;

extern int log_profile_hash_size;

static struct dlg_profile_table* new_dlg_profile( str *name,
		unsigned int size, unsigned int has_value);


/* method that tries to get a new lock_set, if one cannot be allocated
 * an older one is reused */
static gen_lock_set_t * get_a_lock_set(int no )
{
	gen_lock_set_t *ret, *new;
	struct lock_set_list * node;

	if( ! finished_allocating_locks )
	{
		new = lock_set_alloc(no);

		if( new == NULL )
		{
			LM_ERR("Unable to allocate locks\n");
			return NULL;
		}

		ret =  lock_set_init( new );
	
	
		if( ret == NULL )
		{
			lock_set_dealloc( new );
			finished_allocating_locks = 1;
		}
		else
		{
			node = (struct lock_set_list *)shm_malloc( sizeof * node);

			if( node == NULL )
			{
				LM_ERR("Unable to allocate list\n");
				return NULL;
			}

			node->locks = ret;
			node->next = all_locks;
			all_locks = node;
		}
	}

	if( finished_allocating_locks )
	{
		if( all_locks == NULL )
		{
			LM_ERR("Unable to init any locks\n");
			return NULL;
		}

		if ( !cur_lock )
			cur_lock = all_locks;

		if ( cur_lock )
		{
			ret = cur_lock->locks;
			cur_lock = cur_lock->next;
		}
	}

	return ret;
}

void destroy_all_locks(void)
{
	struct lock_set_list * node;

	while( all_locks )
	{
		node = all_locks;
		all_locks = all_locks -> next;
		lock_set_destroy( node->locks);
		lock_set_dealloc( node->locks);
		shm_free(node);
	}
}

int add_profile_definitions( char* profiles, unsigned int has_value)
{
	char *p;
	char *d;
	str name;
	unsigned int i;

	if (profiles==NULL || strlen(profiles)==0 )
		return 0;

	p = profiles;
	do {
		/* locate name of profile */
		name.s = p;
		d = strchr( p, ';');
		if (d) {
			name.len = d-p;
			d++;
		} else {
			name.len = strlen(p);
		}

		/* we have the name -> trim it for spaces */
		trim_spaces_lr( name );

		/* check len name */
		if (name.len==0)
			/* ignore */
			continue;

		/* check the name format */
		for(i=0;i<name.len;i++) {
			if ( !isalnum(name.s[i]) ) {
				LM_ERR("bad profile name <%.*s>, char %c - use only "
					"alphanumerical characters\n", name.len,name.s,name.s[i]);
				return -1;
			}
		}

		/* name ok -> create the profile */
		LM_DBG("creating profile <%.*s>\n",name.len,name.s);

		if (new_dlg_profile( &name, 1 << log_profile_hash_size, has_value)==NULL) {
			LM_ERR("failed to create new profile <%.*s>\n",name.len,name.s);
			return -1;
		}

	}while( (p=d)!=NULL );

	return 0;
}


struct dlg_profile_table* search_dlg_profile(str *name)
{
	struct dlg_profile_table *profile;

	for( profile=profiles ; profile ; profile=profile->next ) {
		if (name->len==profile->name.len &&
		memcmp(name->s,profile->name.s,name->len)==0 )
			return profile;
	}
	return NULL;
}



static struct dlg_profile_table* new_dlg_profile( str *name, unsigned int size,
													unsigned int has_value)
{
	struct dlg_profile_table *profile;
	struct dlg_profile_table *ptmp;
	unsigned int len;
	unsigned int i;

	if ( name->s==NULL || name->len==0 || size==0 ) {
		LM_ERR("invalid parameters\n");
		return NULL;
	}

	for( len=0,i=0 ; i<8*sizeof(size) ; i++ ) {
		if ( size & (1<<i) ) len++;
	}
	if (len!=1) {
		LM_ERR(" size %u is not power of 2!\n", size);
		return NULL;
	}

	profile = search_dlg_profile(name);
	if (profile!=NULL) {
		LM_ERR("duplicate dialog profile registered <%.*s>\n",
			name->len, name->s);
		return NULL;
	}

	len = sizeof(struct dlg_profile_table) +
		size  * ( (has_value == 0 ) ? sizeof( int ) : sizeof( map_t ) ) +
		name->len + 1;
	profile = (struct dlg_profile_table *)shm_malloc(len);
	if (profile==NULL) {
		LM_ERR("no more shm mem\n");
		return NULL;
	}

	memset( profile , 0 , len);
	profile->size = size;
	profile->has_value = (has_value==0)?0:1;


	/* init locks */
	profile->locks = get_a_lock_set(size) ;

	

	if( !profile->locks )
	{
		LM_ERR("failed to init lock\n");
		shm_free(profile);
		return NULL;
	}

	if( has_value )
	{
		

		/* set inner pointers */
		profile->entries = ( map_t *)(profile + 1);

		for( i= 0; i < size; i++)
		{
			profile->entries[i] = map_create(1);
			if( !profile->entries[i] )
			{
				LM_ERR("Unable to create a map\n");
				shm_free(profile);
				return NULL;
			}

		}

		profile->name.s = ((char*)profile->entries) +
			size*sizeof( map_t );
	}
	else
	{
		
		profile->counts = ( int *)(profile + 1);
		profile->name.s = (char*) (profile->counts) + size*sizeof( int ) ;

	}
	
	/* copy the name of the profile */
	memcpy( profile->name.s, name->s, name->len );
	profile->name.len = name->len;
	profile->name.s[profile->name.len] = 0;

	/* link profile */
	for( ptmp=profiles ; ptmp && ptmp->next; ptmp=ptmp->next );
	if (ptmp==NULL)
		profiles = profile;
	else
		ptmp->next = profile;

	return profile;
}


static void destroy_dlg_profile(struct dlg_profile_table *profile)
{
	int i;
	
	if (profile==NULL)
		return;
	if( profile -> has_value)
	{
		for( i= 0; i < profile->size; i++)
			map_destroy( profile->entries[i], NULL );
	}
	

	shm_free( profile );
	return;
}


void destroy_dlg_profiles(void)
{
	struct dlg_profile_table *profile;

	while(profiles) {
		profile = profiles;
		profiles = profiles->next;
		destroy_dlg_profile( profile );
	}

	destroy_all_locks();
	
	return;
}



void destroy_linkers(struct dlg_profile_link *linker)
{
	map_t entry;
	struct dlg_profile_link *l;
	void ** dest;
	
	while(linker) {
		l = linker;
		linker = linker->next;
		/* unlink from profile table */

		
		lock_set_get( l->profile->locks, l->hash_idx);

		if( l->profile->has_value)
		{
			entry = l->profile->entries[l->hash_idx];
			dest = map_find( entry, l->value );
			if( dest )
			{
				(*dest) = (void*) ( (long)(*dest) - 1 );

				if( *dest == 0 )
				{
					map_remove( entry,l->value );
				}
			}
		}
		else
			l->profile->counts[l->hash_idx]--;
		
		lock_set_release( l->profile->locks, l->hash_idx  );

		/* free memory */
		shm_free(l);
	}
}



inline static unsigned int calc_hash_profile( str *value, struct dlg_cell *dlg,
										struct dlg_profile_table *profile )
{
	if (profile->has_value) {
		/* do hash over the value */
		return core_hash( value, NULL, profile->size);
	} else {
		/* do hash over dialog pointer */
		return ((unsigned long)dlg) % profile->size ;
	}
}



static void link_dlg_profile(struct dlg_profile_link *linker,
													struct dlg_cell *dlg)
{
	unsigned int hash;
	map_t p_entry;
	struct dlg_entry *d_entry;
	void ** dest;

	/* add the linker to the dialog */
	/* FIXME zero h_id is not 100% for testing if the dialog is inserted
	 * into the hash table -> we need circular lists  -bogdan */
	if (dlg->h_id) {
		d_entry = &d_table->entries[dlg->h_entry];
		dlg_lock( d_table, d_entry);
		linker->next = dlg->profile_links;
		dlg->profile_links =linker;
		dlg_unlock( d_table, d_entry);
	} else {
		linker->next = dlg->profile_links;
		dlg->profile_links =linker;
	}

	/* calculate the hash position */
	hash = calc_hash_profile(&linker->value, dlg, linker->profile);
	linker->hash_idx = hash;

	/* insert into profile hash table */
	
	lock_set_get( linker->profile->locks, hash );

	LM_DBG("Entered here with hash = %d \n",hash);
	if( linker->profile->has_value)
	{
		p_entry = linker->profile->entries[hash];
		dest = map_get( p_entry, linker->value );
		(*dest) = (void*) ( (long)(*dest) + 1 );
	}
	else
		linker->profile->counts[hash]++;

	lock_set_release( linker->profile->locks,hash );
}



int set_dlg_profile(struct sip_msg *msg, str *value,
									struct dlg_profile_table *profile)
{
	struct dlg_cell *dlg;
	struct dlg_profile_link *linker;

	/* get current dialog */
	dlg = get_current_dialog();
	if (dlg==NULL) {
		LM_ERR("dialog was not yet created - script error\n");
		return -1;
	}

	/* build new linker */
	linker = (struct dlg_profile_link*)shm_malloc(
		sizeof(struct dlg_profile_link) + (profile->has_value?value->len:0) );
	if (linker==NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(linker, 0, sizeof(struct dlg_profile_link));

	/* set backpointer to profile */
	linker->profile = profile;

	/* set the value */
	if (profile->has_value) {
		linker->value.s = (char*)(linker+1);
		memcpy( linker->value.s, value->s, value->len);
		linker->value.len = value->len;
	}

	/* add linker to the dialog and profile */
	link_dlg_profile( linker, dlg);

	return 0;
}


int unset_dlg_profile(struct sip_msg *msg, str *value,
									struct dlg_profile_table *profile)
{
	struct dlg_cell *dlg;
	struct dlg_profile_link *linker;
	struct dlg_profile_link *linker_prev;
	struct dlg_entry *d_entry;

	/* get current dialog */
	dlg = get_current_dialog();
	if (dlg==NULL) {
		LM_ERR("dialog was not yet created - script error\n");
		return -1;
	}

	/* check the dialog linkers */
	d_entry = &d_table->entries[dlg->h_entry];
	dlg_lock( d_table, d_entry);
	linker = dlg->profile_links;
	linker_prev = NULL;
	for( ; linker ; linker_prev=linker,linker=linker->next) {
		if (linker->profile==profile) {
			if (profile->has_value==0) {
				goto found;
			} else if (value && value->len==linker->value.len &&
			memcmp(value->s,linker->value.s,value->len)==0){
				goto found;
			}
			/* allow further search - maybe the dialog is inserted twice in
			 * the same profile, but with different values -bogdan
			 */
		}
	}
	dlg_unlock( d_table, d_entry);
	return -1;

found:
	/* table still locked */
	/* remove the linker element from dialog */
	if (linker_prev==NULL) {
		dlg->profile_links = linker->next;
	} else {
		linker_prev->next = linker->next;
	}
	linker->next = NULL;
	dlg_unlock( d_table, d_entry);
	/* remove linker from profile table and free it */
	destroy_linkers(linker);
	return 1;
}



int is_dlg_in_profile(struct sip_msg *msg, struct dlg_profile_table *profile,
																str *value)
{
	struct dlg_cell *dlg;
	struct dlg_profile_link *linker;
	struct dlg_entry *d_entry;

	/* get current dialog */
	dlg = get_current_dialog();
	if (dlg==NULL)
		return -1;

	/* check the dialog linkers */
	d_entry = &d_table->entries[dlg->h_entry];
	dlg_lock( d_table, d_entry);
	for( linker=dlg->profile_links ; linker ; linker=linker->next) {
		if (linker->profile==profile) {
			if (profile->has_value==0) {
				dlg_unlock( d_table, d_entry);
				return 1;
			} else if (value && value->len==linker->value.len &&
			memcmp(value->s,linker->value.s,value->len)==0){
				dlg_unlock( d_table, d_entry);
				return 1;
			}
			/* allow further search - maybe the dialog is inserted twice in
			 * the same profile, but with different values -bogdan
			 */
		}
	}
	dlg_unlock( d_table, d_entry);
	return -1;
}


unsigned int get_profile_size(struct dlg_profile_table *profile, str *value)
{
	unsigned int n,i;
	map_t entry ;
	void ** dest;


	if (profile->has_value==0)
	{
		/* iterate through the hash and count all records */

		n=0;

		for( i=0; i<profile->size; i++ )
		{

			lock_set_get( profile->locks, i);

			n += profile->counts[i];

			lock_set_release( profile->locks, i);
			
		}


		return n;

	} else {

		n=0;

		if(  value==NULL )
		{
			

			for( i=0; i<profile->size; i++ )
			{

				lock_set_get( profile->locks, i);

				n += map_size(profile->entries[i]);

				lock_set_release( profile->locks, i);

			}

		}
		else
		{
			/* iterate through the hash entry and count only matching */
			/* calculate the hash position */
			i = calc_hash_profile( value, NULL, profile);
			n = 0;
			lock_set_get( profile->locks, i);
			entry = profile->entries[i];

			dest = map_find(entry,*value);
			if( dest )
				n = (int)(long) *dest;

			lock_set_release( profile->locks, i);
		}

		
		return n;
	}
}


/****************************** MI commands *********************************/

struct mi_root * mi_get_profile(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	struct mi_root* rpl_tree= NULL;
	struct mi_node* rpl = NULL;
	struct mi_attr* attr;
	struct dlg_profile_table *profile;
	str *value;
	str *profile_name;
	unsigned int size;
	int len;
	char *p;

	node = cmd_tree->node.kids;
	if (node==NULL || !node->value.s || !node->value.len)
		return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
	profile_name = &node->value;

	if (node->next) {
		node = node->next;
		if (!node->value.s || !node->value.len)
			return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM));
		if (node->next)
			return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
		value = &node->value;
	} else {
		value = NULL;
	}

	/* search for the profile */
	profile = search_dlg_profile( profile_name );
	if (profile==NULL)
		return init_mi_tree( 404, MI_SSTR("Profile not found"));

	size = get_profile_size( profile , value );

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	node = add_mi_node_child(rpl, MI_DUP_VALUE, "profile", 7, NULL, 0);
	if (node==0) {
		free_mi_tree(rpl_tree);
		return NULL;
	}

	attr = add_mi_attr(node, MI_DUP_VALUE, "name", 4, 
		profile->name.s, profile->name.len);
	if(attr == NULL) {
		goto error;
	}

	if (value) {
		attr = add_mi_attr(node, MI_DUP_VALUE, "value", 5, value->s, value->len);
	} else {
		attr = add_mi_attr(node, MI_DUP_VALUE, "value", 5, NULL, 0);
	}
	if(attr == NULL) {
		goto error;
	}

	p= int2str((unsigned long)size, &len);
	attr = add_mi_attr(node, MI_DUP_VALUE, "count", 5, p, len);
	if(attr == NULL) {
		goto error;
	}

	return rpl_tree;
error:
	free_mi_tree(rpl_tree);
	return NULL;
}



static inline int add_val_to_rpl(void * param, str key, void * val)
{
	struct mi_node* rpl = (struct mi_node* ) param;
	struct mi_node* node;
	struct mi_attr* attr;
	int len;
	char *p;

	node = add_mi_node_child(rpl, MI_DUP_VALUE, "value", 5, key.s , key.len );

	if( node == NULL )
		return -1;

	p= int2str((unsigned long)val, &len);
	attr = add_mi_attr(node, MI_DUP_VALUE, "count", 5,  p, len );

	if( attr == NULL )
		return -1;

	return 0;
}

struct mi_root * mi_get_profile_values(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	struct mi_root* rpl_tree= NULL;
	struct mi_node* rpl = NULL;
	struct dlg_profile_table *profile;
	str *profile_name;
	int i, ret,n;
/*
	struct dlg_profile_value_name dpvn;
	unsigned int combined;
	str *value;
*/
	str tmp;

	/* dpvn.values_string=NULL;
	dpvn.values_count=NULL;
	dpvn.size = 0;
	combined = 0; */
	node = cmd_tree->node.kids;
	if (node==NULL || !node->value.s || !node->value.len)
		return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
	profile_name = &node->value;
	if (node->next) {
		node = node->next;
		if (!node->value.s || !node->value.len)
			return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM));
		if (node->next)
			return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
/* XXX not used anywhere
		value = &node->value;
	} else {
		value = NULL;
*/
	}
	profile = search_dlg_profile( profile_name );
	if (profile==NULL)
		return init_mi_tree( 404, MI_SSTR("Profile not found"));
	/* gather dialog count for all values in this profile */
	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		goto error;
	rpl = &rpl_tree->node;

	ret = 0;

	if( profile->has_value )
	{
		for( i=0; i<profile->size; i++ )
		{
			lock_set_get( profile->locks, i);
			ret |= map_for_each( profile->entries[i], add_val_to_rpl, rpl);
			lock_set_release( profile->locks, i);
		}
	}
	else
	{
		n = 0;
		
		for( i=0; i<profile->size; i++ )
		{
			lock_set_get( profile->locks, i);
			n += profile->counts[i];
			lock_set_release( profile->locks, i);
		}

		tmp.s = "WITHOUT VALUE";
		tmp.len = sizeof("WITHOUT VALUE")-1;
		ret =  add_val_to_rpl(rpl, tmp , (void *)(long)n );

	}

	if ( ret )
		goto error;
	
	return rpl_tree;
error:

	free_mi_tree(rpl_tree);
	return NULL;
}

struct mi_root * mi_profile_list(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	struct mi_root* rpl_tree= NULL;
	struct mi_node* rpl = NULL;
	struct dlg_profile_table *profile;
	str *profile_name;
	str *value;
	unsigned int i,found,n;
	struct dlg_entry *d_entry;
	struct dlg_cell    *cur_dlg;
	struct dlg_profile_link *cur_link;

	node = cmd_tree->node.kids;
	if (node==NULL || !node->value.s || !node->value.len)
		return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
	profile_name = &node->value;

	if (node->next) {
		node = node->next;
		if (!node->value.s || !node->value.len)
			return init_mi_tree( 400, MI_SSTR(MI_BAD_PARM));
		if (node->next)
			return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
		value = &node->value;
	} else {
		value = NULL;
	}

	/* search for the profile */
	profile = search_dlg_profile( profile_name );
	if (profile==NULL)
		return init_mi_tree( 404, MI_SSTR("Profile not found"));

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;

	/* go through the hash and print the dialogs */

	for( n=0,i=0; i<d_table->size; i++)
	{
		d_entry = &(d_table->entries[i]);
		lock_set_get(d_table->locks,d_entry->lock_idx);

		
		cur_dlg = d_entry->first;
		while( cur_dlg )
		{
			found = 0;

			cur_link = cur_dlg ->profile_links;

			while(cur_link)
			{
				if( cur_link->profile == profile &&
					( value == NULL ||
					( value->len == cur_link->value.len
					 && !strncmp(value->s,cur_link->value.s, value->len))
					))
				{
					found = 1;
					break;
				}
				cur_link = cur_link->next;
			}

			if( found ) {

				if( mi_print_dlg( rpl, cur_dlg, 0) ) {
					lock_set_release(d_table->locks,d_entry->lock_idx);
					goto error;
				}

				n++;

				if ( (n % 50) == 0 )
					flush_mi_tree(rpl_tree);
			}

			cur_dlg = cur_dlg->next;
		}

		lock_set_release(d_table->locks,d_entry->lock_idx);
	}
	

	return rpl_tree;
error:
	free_mi_tree(rpl_tree);
	return NULL;
}

