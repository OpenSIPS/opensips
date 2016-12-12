/*
 * Copyright (C) 2009-2014 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2008-04-20  initial version (bogdan)
 * 2008-09-16  speed optimization (andreidragus)
 *
 */

#include <stdio.h>
#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"
#include "../../mem/shm_mem.h"
#include "../../hash_func.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "dlg_hash.h"
#include "dlg_profile.h"
#include "dlg_repl_profile.h"
#include "dlg_req_within.h"

#define PROFILE_HASH_SIZE 16

struct dlg_profile_table *profiles = NULL;
static struct lock_set_list * all_locks = NULL;
static struct lock_set_list * cur_lock = NULL;
static int finished_allocating_locks = 0;

extern int log_profile_hash_size;

static struct dlg_profile_table* new_dlg_profile( str *name,
		unsigned int size, unsigned int has_value, unsigned repl_type);

/* used by cachedb interface */
static cachedb_funcs cdbf;
static cachedb_con *cdbc = 0;
str cdb_val_prefix = str_init("dlg_val_");
str cdb_noval_prefix = str_init("dlg_noval_");
str cdb_size_prefix = str_init("dlg_size_");
int profile_timeout = 60 * 60 * 24;      /* 24 hours */
str dlg_prof_val_buf = {0, 0};
str dlg_prof_noval_buf = {0, 0};
str dlg_prof_size_buf = {0, 0};

/* TODO if needed to change the separator */
str dlg_prof_sep = str_init("_");

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
	char *e;
	str name;
	unsigned int i;
	enum repl_types type;
	if (profiles==NULL || strlen(profiles)==0 )
		return 0;

	p = profiles;
	do {
		/* By default no replication (no CACHEDB nor BIN)*/
		type = REPL_NONE;

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
		e = name.s + name.len;

		/* check len name */
		if (name.len==0)
			/* ignore */
			continue;

		/* check if it should be shared with cachedb */
		p = memchr(name.s, '/', name.len);
		if (p) {
			name.len = p - name.s;
			trim_spaces_lr( name );
			/* skip spaces after p */
			for (++p; *p == ' ' && p < e; p++);
			if ( p < e && *p == 's') {
				if (cdb_url.len && cdb_url.s) {
					type= REPL_CACHEDB;
				} else {
					LM_WARN("profile %.*s configured to be stored in CacheDB, "
							"but the cachedb_url was not defined\n",
							name.len, name.s);
				}
			} else if ( p < e && *p == 'b') {
				if (profile_replicate_cluster) {
					type = REPL_PROTOBIN;
				} else {
					LM_WARN("profile %.*s configured to be replicated over BIN, "
							"but replicate_profiles_to param is not defined\n",
							name.len, name.s);
				}
			} else if (isalnum(*p)) {
				LM_ERR("Invalid letter in profile definitition </%c>!\n", *p);
				return -1;
			}
		}

		/* check the name format */
		for(i=0;i<name.len;i++) {
			if ( !isalnum(name.s[i]) ) {
				LM_ERR("bad profile name <%.*s>, char %c - use only "
						"alphanumerical characters\n", name.len,name.s,name.s[i]);
				return -1;
			}
		}

		/* name ok -> create the profile */
		LM_DBG("creating profile <%.*s> %s\n", name.len, name.s,
				type ==REPL_CACHEDB ? "cached" :
				(type==REPL_PROTOBIN ? "bin replicated": ""));

		if (new_dlg_profile( &name, 1 << log_profile_hash_size,
					has_value, type)==NULL) {
			LM_ERR("failed to create new profile <%.*s>\n",name.len,name.s);
			return -1;
		}

	}while( (p=d)!=NULL );

	return 0;
}

#define DLG_COPY(_d, _s) \
	do { \
		memcpy((_d).s + (_d).len, (_s)->s, (_s)->len); \
		(_d).len += (_s)->len; \
	} while (0)


static inline char * dlg_prof_realloc(char * ptr, int size)
{
	ptr = pkg_realloc(ptr, size);
	if (!ptr) {
		LM_ERR("not enough memory for cachedb buffer\n");
		return NULL;
	}
	return ptr;
}

static int dlg_fill_value(str *name, str *value)
{
	char * buf;

	int val_len = calc_base64_encode_len(value->len);
	int len = cdb_val_prefix.len /* prefix */ +
			name->len /* profile name */ +
			dlg_prof_sep.len /* value separator */ +
			val_len /* profile value, b64 encoded */;

	/* reallocate the appropriate size */
	if (!(buf = dlg_prof_realloc(dlg_prof_val_buf.s, len))) {
		LM_ERR("cannot realloc profile with value buffer\n");
		return -1;
	}

	dlg_prof_val_buf.s = buf;
	dlg_prof_val_buf.len = cdb_val_prefix.len;

	DLG_COPY(dlg_prof_val_buf, name);
	DLG_COPY(dlg_prof_val_buf, &dlg_prof_sep);
	base64encode((unsigned char*)dlg_prof_val_buf.s + dlg_prof_val_buf.len,
			(unsigned char *)value->s, value->len);

	dlg_prof_val_buf.len += val_len;

	return 0;
}

static int dlg_fill_name(str *name)
{
	char * buf;

	if (!(buf = dlg_prof_realloc(dlg_prof_noval_buf.s,
			cdb_noval_prefix.len /* prefix */ +
			name->len /* profile name */))) {
		LM_ERR("cannot realloc buffer profile name writing\n");
		return -1;
	}

	dlg_prof_noval_buf.s = buf;
	dlg_prof_noval_buf.len = cdb_noval_prefix.len;
	DLG_COPY(dlg_prof_noval_buf, name);
	return 0;
}

static int dlg_fill_size(str *name)
{
	char * buf;

	if (!(buf = dlg_prof_realloc(dlg_prof_size_buf.s,
			cdb_size_prefix.len + name->len))) {
		LM_ERR("cannot realloc profile size buffer\n");
		return -1;
	}
	dlg_prof_size_buf.s = buf;
	dlg_prof_size_buf.len = cdb_size_prefix.len;

	DLG_COPY(dlg_prof_size_buf, name);

	return 0;
}

int init_cachedb(void)
{
	if (!cdbf.init) {
		LM_ERR("cachedb function not initialized\n");
		return -1;
	}

	cdbc = cdbf.init(&cdb_url);
	if (!cdbc) {
		LM_ERR("cannot connect to cachedb_url %.*s\n", cdb_url.len, cdb_url.s);
		return -1;
	}
	LM_DBG("Inited cachedb \n");
	return 0;
}

void destroy_cachedb(int final)
{
	if (cdbc)
		cdbf.destroy(cdbc);
	cdbc = NULL;
	if (!final)
		return;

	if (dlg_prof_val_buf.s)
		pkg_free(dlg_prof_val_buf.s);
	if (dlg_prof_noval_buf.s)
		pkg_free(dlg_prof_noval_buf.s);
	if (dlg_prof_size_buf.s)
		pkg_free(dlg_prof_size_buf.s);
}

int init_cachedb_utils(void)
{
	if (profile_timeout<=0) {
		LM_ERR("0 or negative profile_timeout not accepted!!\n");
		return -1;
	}
	if (cachedb_bind_mod(&cdb_url, &cdbf) < 0) {
		LM_ERR("cannot bind functions for cachedb_url %.*s\n",
				cdb_url.len, cdb_url.s);
		return -1;
	}
	if (!CACHEDB_CAPABILITY(&cdbf,
				CACHEDB_CAP_GET|CACHEDB_CAP_ADD|CACHEDB_CAP_SUB)) {
		LM_ERR("not enough capabilities\n");
		return -1;
	}

	cdbc = cdbf.init(&cdb_url);
	if (!cdbc) {
		LM_ERR("cannot connect to cachedb_url %.*s\n", cdb_url.len, cdb_url.s);
		return -1;
	}

	dlg_prof_val_buf.s = pkg_malloc(cdb_val_prefix.len + 32);
	if (!dlg_prof_val_buf.s) {
		LM_ERR("no more memory to allocate buffer\n");
		return -1;
	}

	dlg_prof_noval_buf.s = pkg_malloc(cdb_noval_prefix.len + 32);
	if (!dlg_prof_noval_buf.s) {
		LM_ERR("no more memory to allocate buffer\n");
		return -1;
	}

	dlg_prof_size_buf.s = pkg_malloc(cdb_size_prefix.len + 32);
	if (!dlg_prof_size_buf.s) {
		LM_ERR("no more memory to allocate buffer\n");
		return -1;
	}

	/* copy prefixes in buffer */
	memcpy(dlg_prof_val_buf.s, cdb_val_prefix.s, cdb_val_prefix.len);
	memcpy(dlg_prof_noval_buf.s, cdb_noval_prefix.s, cdb_noval_prefix.len);
	memcpy(dlg_prof_size_buf.s, cdb_size_prefix.s, cdb_size_prefix.len);

	return 0;
}

/* faster method to match a profile by name, no other checks */
struct dlg_profile_table *get_dlg_profile(str *name)
{
	struct dlg_profile_table *profile;
	for (profile=profiles ;profile ;profile=profile->next) {
		if (name->len == profile->name.len &&
				memcmp(name->s, profile->name.s, name->len) == 0)
			return profile;
	}

	return NULL;
}

struct dlg_profile_table* search_dlg_profile(str *name)
{
	struct dlg_profile_table *profile;
	char *p,*e;
	unsigned repl_type=REPL_NONE;
	str profile_name = *name;

	/* check if this is a shared profile, and remove /s for lookup */
	p = memchr(profile_name.s, '/', profile_name.len);

	if (p) {
		e = profile_name.s + profile_name.len;
		profile_name.len = p - profile_name.s;
		trim_spaces_lr( profile_name );
		/* skip spaces after p */
		for (++p; *p == ' ' && p < e; p++);
		if ( p < e && *p == 's')
		repl_type=REPL_CACHEDB;
		else if (p < e && *p == 'b')
		repl_type=REPL_PROTOBIN;
	}

	for( profile=profiles ; profile ; profile=profile->next ) {
		if (profile->repl_type == repl_type &&
				profile_name.len ==profile->name.len &&
		memcmp(profile_name.s,profile->name.s,profile_name.len)==0 )
			return profile;
	}

	return NULL;
}

static struct dlg_profile_table* new_dlg_profile( str *name, unsigned int size,
		unsigned int has_value, unsigned repl_type)
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

	len = sizeof(struct dlg_profile_table) + name->len + 1;
	/* anything else than only CACHEDB */
	if (repl_type !=  REPL_CACHEDB)
		len += size * ((has_value==0) ? sizeof(int):sizeof(map_t));

	profile = (struct dlg_profile_table *)shm_malloc(len);

	if (profile==NULL) {
		LM_ERR("no more shm mem\n");
		return NULL;
	}
	memset( profile , 0 , len);

	if (!has_value)
		profile->repl = repl_prof_allocate();

	profile->size = size;
	profile->has_value = (has_value==0)?0:1;
	profile->repl_type = repl_type;

	/* init locks */
	if (repl_type != REPL_CACHEDB) {
		profile->locks = get_a_lock_set(size) ;

		if( !profile->locks )
		{
			LM_ERR("failed to init lock\n");
			shm_free(profile);
			return NULL;
		}
	}

	if( repl_type == REPL_CACHEDB ) {

		profile->name.s = (char *)(profile + 1);

	} else if (has_value ) {

		/* set inner pointers */
		profile->entries = ( map_t *)(profile + 1);

		for( i= 0; i < size; i++)
		{
			profile->entries[i] = map_create(AVLMAP_SHARED);
			if( !profile->entries[i] )
			{
				LM_ERR("Unable to create a map\n");
				shm_free(profile);
				return NULL;
			}

		}

		profile->name.s = ((char*)profile->entries) +
			size*sizeof( map_t );
	} else {

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
	if( profile->has_value && !(profile->repl_type==REPL_CACHEDB) )
	{
		for( i= 0; i < profile->size; i++)
			map_destroy( profile->entries[i], free_profile_val);
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



void destroy_linkers(struct dlg_profile_link *linker, char is_replicated)
{
	map_t entry;
	struct dlg_profile_link *l;
	void ** dest;

	while(linker) {
		l = linker;
		linker = linker->next;
		/* unlink from profile table */


		if (!(l->profile->repl_type==REPL_CACHEDB)) {
			lock_set_get( l->profile->locks, l->hash_idx);

			if( l->profile->has_value)
			{
				entry = l->profile->entries[l->hash_idx];
				dest = map_find( entry, l->value );
				if( dest )
				{
					repl_prof_dec(dest);

					if( *dest == 0 )
					{
						/* warn everybody we are deleting */
						/* XXX: we should queue these */
						repl_prof_remove(&l->profile->name, &l->value);
						map_remove(entry,l->value );
					}
				}
			}
			else
				l->profile->counts[l->hash_idx]--;

			lock_set_release( l->profile->locks, l->hash_idx  );
		} else if (!is_replicated) {
			if (!cdbc) {
				LM_WARN("CacheDB not initialized - some information might"
						" not be deleted from the cachedb engine\n");
				goto skip_and_continue;
			}

			/* prepare buffers */
			if( l->profile->has_value) {

				if (dlg_fill_value(&l->profile->name, &l->value) < 0)
					goto skip_and_continue;
				if (dlg_fill_size(&l->profile->name) < 0)
					goto skip_and_continue;
				/* not really interested in the new val */
				if (cdbf.sub(cdbc, &dlg_prof_val_buf, 1,
							profile_timeout, NULL) < 0) {
					LM_ERR("cannot remove profile from CacheDB\n");
					goto skip_and_continue;
				}
				/* fill size into name */
				if (cdbf.sub(cdbc, &dlg_prof_size_buf, 1,
							profile_timeout, NULL) < 0) {
					LM_ERR("cannot remove size profile from CacheDB\n");
					goto skip_and_continue;
				}
			} else {
				if (dlg_fill_name(&l->profile->name) < 0)
					goto skip_and_continue;
				if (cdbf.sub(cdbc, &dlg_prof_noval_buf, 1,
							profile_timeout, NULL) < 0) {
					LM_ERR("cannot remove profile from CacheDB\n");
					goto skip_and_continue;
				}
			}
		}

skip_and_continue:
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
									struct dlg_cell *dlg, char is_replicated)
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
		if (dlg->locked_by!=process_no)
			dlg_lock( d_table, d_entry);
		linker->next = dlg->profile_links;
		dlg->profile_links =linker;
		if (dlg->locked_by!=process_no)
			dlg_unlock( d_table, d_entry);
	} else {
		linker->next = dlg->profile_links;
		dlg->profile_links =linker;
	}

	/* insert into profile hash table */
	/* but only if cachedb is not used */
	if (!(linker->profile->repl_type==REPL_CACHEDB)) {
		/* calculate the hash position */
		hash = calc_hash_profile(&linker->value, dlg, linker->profile);
		linker->hash_idx = hash;


		lock_set_get( linker->profile->locks, hash );

		LM_DBG("Entered here with hash = %d \n",hash);
		if( linker->profile->has_value)
		{
			p_entry = linker->profile->entries[hash];
			dest = map_get( p_entry, linker->value );
			/* if we accept replicated stuff, we have to allocate the
			 * structure for it and treat the counter differently */
			repl_prof_inc(dest);
		}
		else
			linker->profile->counts[hash]++;

		lock_set_release( linker->profile->locks,hash );
	} else if (!is_replicated) {
		if (!cdbc) {
			LM_WARN("Cachedb not initialized yet - cannot update profile\n");
			LM_WARN("Make sure that the dialog profile information is persistent\n");
			LM_WARN(" in your cachedb storage, because otherwise you might loose profile data\n");
			return;
		}
		/* prepare buffers */
		if( linker->profile->has_value) {

			if (dlg_fill_value(&linker->profile->name, &linker->value) < 0)
				return;
			if (dlg_fill_size(&linker->profile->name) < 0)
				return;

			/* not really interested in the new val */
			if (cdbf.add(cdbc, &dlg_prof_val_buf, 1,
						profile_timeout, NULL) < 0) {
				LM_ERR("cannot insert profile into CacheDB\n");
				return;
			}
			/* fill size into name */
			if (cdbf.add(cdbc, &dlg_prof_size_buf, 1,
						profile_timeout, NULL) < 0) {
				LM_ERR("cannot insert size profile into CacheDB\n");
				return;
			}
		} else {
			if (dlg_fill_name(&linker->profile->name) < 0)
				return;

			if (cdbf.add(cdbc, &dlg_prof_noval_buf, 1,
						profile_timeout, NULL) < 0) {
				LM_ERR("cannot insert profile into CacheDB\n");
				return;
			}
		}
	}
}


int set_dlg_profile(struct dlg_cell *dlg, str *value,
						struct dlg_profile_table *profile, char is_replicated)
{
	struct dlg_profile_link *linker;

	/* get current dialog */
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
	link_dlg_profile( linker, dlg, is_replicated);
	dlg->flags |= DLG_FLAG_VP_CHANGED;

	return 0;
}


int unset_dlg_profile(struct dlg_cell *dlg, str *value,
											struct dlg_profile_table *profile)
{
	struct dlg_profile_link *linker;
	struct dlg_profile_link *linker_prev;
	struct dlg_entry *d_entry;

	/* get current dialog */
	if (dlg==NULL) {
		LM_ERR("dialog was not yet created - script error\n");
		return -1;
	}

	/* check the dialog linkers */
	d_entry = &d_table->entries[dlg->h_entry];
	/* lock dialog (if not already locked via a callback triggering)*/
	if (dlg->locked_by!=process_no)
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
	if (dlg->locked_by!=process_no)
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
	dlg->flags |= DLG_FLAG_VP_CHANGED;
	if (dlg->locked_by!=process_no)
		dlg_unlock( d_table, d_entry);
	/* remove linker from profile table and free it */
	destroy_linkers(linker, 0);
	return 1;
}


int is_dlg_in_profile(struct dlg_cell *dlg, struct dlg_profile_table *profile,
																str *value)
{
	struct dlg_profile_link *linker;
	struct dlg_entry *d_entry;

	/* get current dialog */
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
	unsigned int n = 0, i;
	map_t entry ;
	void ** dest;
	int ret;

	if (profile->has_value==0)
	{
		/* iterate through the hash and count all records */

		if (cdbc && (profile->repl_type == REPL_CACHEDB)) {
			if (dlg_fill_name(&profile->name) < 0)
				goto failed;

			ret = cdbf.get_counter(cdbc, &dlg_prof_noval_buf, (int *)&n);
			if (ret == -2) {
				n = 0;
			} else if (ret < 0) {
				LM_ERR("cannot fetch profile from CacheDB\n");
				goto failed;
			}

		} else {

			for( i=0; i<profile->size; i++ )
			{

				lock_set_get( profile->locks, i);

				n += profile->counts[i];

				lock_set_release( profile->locks, i);

			}

		}
		n += replicate_profiles_count(profile->repl);

	} else {

		if(  value==NULL )
		{
			if (cdbc && (profile->repl_type == REPL_CACHEDB)) {
				if (dlg_fill_size(&profile->name) < 0)
					goto failed;

				ret = cdbf.get_counter(cdbc, &dlg_prof_size_buf, (int *)&n);
				if (ret == -2) {
					n = 0;
				} else if (ret < 0) {
					LM_ERR("cannot fetch profile from CacheDB\n");
					goto failed;
				}

			} else {

				for( i=0; i<profile->size; i++ )
				{

					lock_set_get( profile->locks, i);

					n += map_size(profile->entries[i]);

					lock_set_release( profile->locks, i);

				}
			}


		}
		else
		{
			if (cdbc && (profile->repl_type == REPL_CACHEDB)) {
				if (dlg_fill_value(&profile->name, value) < 0)
					goto failed;

				ret = cdbf.get_counter(cdbc, &dlg_prof_val_buf, (int *)&n);
				if (ret == -2) {
					n = 0;
				} else if (ret < 0) {
					LM_ERR("cannot fetch profile from CacheDB\n");
					goto failed;
				}

			} else {
				/* iterate through the hash entry and count only matching */
				/* calculate the hash position */
				i = calc_hash_profile( value, NULL, profile);
				n = 0;
				lock_set_get( profile->locks, i);
				entry = profile->entries[i];

				dest = map_find(entry,*value);
				if( dest )
					n = repl_prof_get_all(dest);

				lock_set_release( profile->locks, i);

			}
		}
	}

	return n;
failed:
	LM_ERR("error while fetching cachedb key\n");
	return 0;
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

	if (profile->repl_type == REPL_CACHEDB) {
		attr = add_mi_attr(node, MI_DUP_VALUE, "shared", 6, "yes", 3);
	} else {
		attr = add_mi_attr(node, MI_DUP_VALUE, "shared", 6, "no", 2);
	}
	if (attr == NULL) {
		goto error;
	}

	if (profile->repl_type == REPL_PROTOBIN) {
		attr = add_mi_attr(node, MI_DUP_VALUE, "replicated", 10, "yes", 3);
	} else {
		attr = add_mi_attr(node, MI_DUP_VALUE, "replicated", 10, "no", 2);
	}
	if (attr == NULL) {
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
	int counter;

	node = add_mi_node_child(rpl, MI_DUP_VALUE, "value", 5, key.s , key.len );

	if( node == NULL )
		return -1;

	counter = repl_prof_get_all(&val);
	p= int2str((unsigned long)counter, &len);
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
	str tmp;

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
	}
	profile = search_dlg_profile( profile_name );
	if (profile==NULL)
		return init_mi_tree( 404, MI_SSTR("Profile not found"));
	if (profile->repl_type == REPL_CACHEDB)
		return init_mi_tree( 405, MI_SSTR("Unsupported command for shared profiles"));

	/* gather dialog count for all values in this profile */
	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		goto error;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

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
	if (rpl_tree)
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
	rpl->flags |= MI_IS_ARRAY;

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


struct mi_root * mi_list_all_profiles(struct mi_root *cmd_tree, void *param )
{
	struct mi_node* node;
	struct mi_root* rpl_tree= NULL;
	struct mi_node* rpl = NULL;
	struct dlg_profile_table *profile;

	node = cmd_tree->node.kids;
	if (node!=NULL)
		return init_mi_tree( 401, MI_SSTR(MI_MISSING_PARM));

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		return 0;

	rpl = &rpl_tree->node;

	profile = profiles;
	while (profile) {

		if (add_mi_node_child(rpl, 0, profile->name.s, profile->name.len,
							 (profile->has_value? "1" : "0"), 1) == NULL) {
			LM_ERR("Out of mem\n");
			free_mi_tree(rpl_tree);
			return init_mi_tree( 401, MI_SSTR(MI_INTERNAL_ERR));
		}

		profile = profile->next;
	}

	return rpl_tree;
}

struct mi_root * mi_profile_terminate(struct mi_root *cmd_tree, void *param ) {
	struct mi_node* node;
	struct dlg_profile_table *profile;
	str *profile_name;
	str *value;
	unsigned int i;
	struct dlg_entry *d_entry;
	struct dlg_cell    *cur_dlg;
	struct dlg_profile_link *cur_link;
	struct dialog_list *deleted = NULL, *delete_entry ;

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

	profile = search_dlg_profile( profile_name );

	if (profile==NULL)
		return init_mi_tree( 404, MI_SSTR("Profile not found"));

	for (i = 0; i < d_table->size; i++) {
		d_entry = &(d_table->entries[i]);
		lock_set_get(d_table->locks,d_entry->lock_idx);

		cur_dlg = d_entry->first;
		while( cur_dlg ) {

			cur_link = cur_dlg ->profile_links;

			while(cur_link) {
				if( cur_link->profile == profile &&
					( value == NULL ||
					( value->len == cur_link->value.len
					 && !strncmp(value->s,cur_link->value.s, value->len))
					)) {
					delete_entry = pkg_malloc(sizeof(struct dialog_list));
					if (!delete_entry) {
						LM_CRIT("no more pkg memory\n");
						lock_set_release(d_table->locks,d_entry->lock_idx);
						return init_mi_tree( 400, MI_SSTR(MI_INTERNAL_ERR));
					}

					delete_entry->dlg = cur_dlg;
					delete_entry->next = deleted;
					deleted = delete_entry;

					ref_dlg_unsafe(cur_dlg, 1);

					break;
				}
				cur_link = cur_link->next;
			}
			cur_dlg = cur_dlg->next;
		}

		lock_set_release(d_table->locks,d_entry->lock_idx);

		delete_entry = deleted;
		while(delete_entry){
			init_dlg_term_reason(delete_entry->dlg,"MI Termination",sizeof("MI Termination")-1);

			if ( dlg_end_dlg( delete_entry->dlg, NULL) ) {
				while(delete_entry){
					deleted = delete_entry;
					delete_entry = delete_entry->next;
					pkg_free(deleted);
				}
				LM_CRIT("error while terminating dlg\n");
				return init_mi_tree( 400, MI_SSTR("Dialog internal error"));
			}

			unref_dlg(delete_entry->dlg, 1);
			deleted = delete_entry;
			delete_entry = delete_entry->next;
			pkg_free(deleted);
		}

		deleted = NULL;
	}

	return init_mi_tree(400, MI_SSTR(MI_OK));
}
