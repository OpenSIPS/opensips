/*
 * DBText library
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2003-01-30 created by Daniel
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>

#include "../../mem/shm_mem.h"
#include "../../mem/mem.h"
#include "../../dprint.h"

#include "dbt_util.h"
#include "dbt_lib.h"

static dbt_cache_p *_dbt_cachedb = NULL;
static gen_lock_t *_dbt_cachesem = NULL;

static dbt_tbl_cachel_p _dbt_cachetbl = NULL;

#define DBT_CACHETBL_SIZE	16

/**
 *
 */
int dbt_init_cache(void)
{
	int i, j;
	if(!_dbt_cachesem)
	{
	/* init locks */
		_dbt_cachesem = lock_alloc();
		if(!_dbt_cachesem)
		{
			LM_CRIT("could not alloc a lock\n");
			return -1;
		}
		if (lock_init(_dbt_cachesem)==0)
		{
			LM_CRIT("could not initialize a lock\n");
			lock_dealloc(_dbt_cachesem);
			return -1;
		}
	}
	/* init pointer to caches list */
	if (!_dbt_cachedb) {
		_dbt_cachedb = shm_malloc( sizeof(dbt_cache_p) );
		if (!_dbt_cachedb) {
			LM_CRIT("no enough shm mem\n");
			lock_dealloc(_dbt_cachesem);
			return -1;
		}
		*_dbt_cachedb = NULL;
	}
	/* init tables' hash table */
	if (!_dbt_cachetbl) {
		_dbt_cachetbl
			= (dbt_tbl_cachel_p)shm_malloc(DBT_CACHETBL_SIZE*
					sizeof(dbt_tbl_cachel_t));
		if(_dbt_cachetbl==NULL)
		{
			LM_CRIT("no enough shm mem\n");
			lock_dealloc(_dbt_cachesem);
			shm_free(_dbt_cachedb);
			return -1;
		}
		memset(_dbt_cachetbl, 0, DBT_CACHETBL_SIZE*sizeof(dbt_tbl_cachel_t));
		for(i=0; i<DBT_CACHETBL_SIZE; i++)
		{
			if (lock_init(&_dbt_cachetbl[i].sem)==0)
			{
				LM_CRIT("cannot init tables' sem's\n");
				for(j=i-1; j>=0; j--)
					lock_destroy(&_dbt_cachetbl[j].sem);
				lock_dealloc(_dbt_cachesem);
				shm_free(_dbt_cachedb);
				return -1;
			}
		}
	}


	return 0;
}

/**
 *
 */
dbt_cache_p dbt_cache_get_db(str *_s)
{
	dbt_cache_p _dcache=NULL;;
	if(!_dbt_cachesem || !_dbt_cachedb)
	{
		LM_ERR("dbtext cache is not initialized! Check if you loaded"
				" dbtext before any other module that uses it\n");
		return NULL;
	}
	if(!_s || !_s->s || _s->len<=0)
		return NULL;

	LM_DBG("looking for db %.*s!\n",_s->len,_s->s);

	lock_get(_dbt_cachesem);

	_dcache = *_dbt_cachedb;
	while(_dcache)
	{
		if(_dcache->name.len==_s->len
				&& !strncasecmp(_dcache->name.s, _s->s, _s->len))
		{
			LM_DBG("db already cached!\n");
			goto done;
		}

		_dcache = _dcache->next;
	}
	if(!dbt_is_database(_s))
	{
		LM_ERR("database [%.*s] does not exist!\n", _s->len, _s->s);
		goto done;
	}
	LM_DBG("new db!\n");

	_dcache = (dbt_cache_p)shm_malloc(sizeof(dbt_cache_t));
	if(!_dcache)
	{
		LM_ERR(" no shm memory for dbt_cache_t.\n");
		goto done;
	}
	memset(_dcache, 0, sizeof(dbt_cache_t));

	_dcache->name.s = (char*)shm_malloc((_s->len+1)*sizeof(char));
	if(!_dcache->name.s)
	{
		LM_ERR(" no shm memory for s!!\n");
		shm_free(_dcache);
		_dcache = NULL;
		goto done;
	}

	memcpy(_dcache->name.s, _s->s, _s->len);
	_dcache->name.s[_s->len] = '\0';
	_dcache->name.len = _s->len;

	if(*_dbt_cachedb)
		_dcache->next = *_dbt_cachedb;

	*_dbt_cachedb = _dcache;

done:
	lock_release(_dbt_cachesem);
	return _dcache;
}

/**
 *
 */
int dbt_cache_check_db(str *_s)
{
	dbt_cache_p _dcache=NULL;;
	if(!_dbt_cachesem || !(*_dbt_cachedb)
			|| !_s || !_s->s || _s->len<=0)
		return -1;

	lock_get(_dbt_cachesem);

	_dcache = *_dbt_cachedb;
	while(_dcache)
	{
		if(_dcache->name.len == _s->len &&
			!strncasecmp(_dcache->name.s, _s->s, _s->len))
		{
			lock_release(_dbt_cachesem);
			return 0;
		}
		_dcache = _dcache->next;
	}

	lock_release(_dbt_cachesem);
	return -1;
}

/**
 *
 */
int dbt_db_del_table(dbt_cache_p _dc, const str *_s, int sync)
{
	dbt_table_p _tbc = NULL;
	int hash;
	int hashidx;
	if(!_dbt_cachetbl || !_dc || !_s || !_s->s || _s->len<=0)
		return -1;

	hash = core_hash(&_dc->name, _s, DBT_CACHETBL_SIZE);
	hashidx = hash % DBT_CACHETBL_SIZE;

	if(sync)
		lock_get(&_dbt_cachetbl[hashidx].sem);

	_tbc = _dbt_cachetbl[hashidx].dtp;

	while(_tbc)
	{
		if(_tbc->hash==hash && _tbc->dbname.len == _dc->name.len
				&& _tbc->name.len == _s->len
				&& !strncasecmp(_tbc->dbname.s, _dc->name.s, _dc->name.len)
				&& !strncasecmp(_tbc->name.s, _s->s, _s->len))
		{
			if(_tbc->prev)
				(_tbc->prev)->next = _tbc->next;
			else
				_dbt_cachetbl[hashidx].dtp = _tbc->next;

			if(_tbc->next)
				(_tbc->next)->prev = _tbc->prev;
			break;
		}
		_tbc = _tbc->next;
	}

	if(sync)
		lock_release(&_dbt_cachetbl[hashidx].sem);

	dbt_table_free(_tbc);

	return 0;
}

/**
 *
 */
dbt_table_p dbt_db_get_table(dbt_cache_p _dc, const str *_s)
{
	dbt_table_p _tbc = NULL;
	int hash;
	int hashidx;

	if(!_dbt_cachetbl || !_dc || !_s || !_s->s || _s->len<=0)
		return NULL;

	hash = core_hash(&_dc->name, _s, DBT_CACHETBL_SIZE);
	hashidx = hash % DBT_CACHETBL_SIZE;

	lock_get(&_dbt_cachetbl[hashidx].sem);

	_tbc = _dbt_cachetbl[hashidx].dtp;

	while(_tbc)
	{
		if(_tbc->hash==hash && _tbc->dbname.len == _dc->name.len
				&& _tbc->name.len == _s->len
				&& !strncasecmp(_tbc->dbname.s, _dc->name.s, _dc->name.len)
				&& !strncasecmp(_tbc->name.s, _s->s, _s->len))
		{
			/* found - if cache mode or no-change, return */
			if(db_mode==0 || dbt_check_mtime(_s, &(_dc->name), &(_tbc->mt))!=1)
			{
				LM_DBG("cache or mtime succeeded for [%.*s]\n",
						_tbc->name.len, _tbc->name.s);
				return _tbc;
			}
			break;
		}
		_tbc = _tbc->next;
	}

	/* new table */
	if(_tbc) /* free old one */
	{
		dbt_db_del_table(_dc, _s, 0);

	}

	_tbc = dbt_load_file(_s, &(_dc->name));

	if(!_tbc)
	{
		lock_release(&_dbt_cachetbl[hashidx].sem);
		return NULL;
	}

	_tbc->hash = hash;
	_tbc->next = _dbt_cachetbl[hashidx].dtp;
	if(_dbt_cachetbl[hashidx].dtp)
		_dbt_cachetbl[hashidx].dtp->prev = _tbc;

	_dbt_cachetbl[hashidx].dtp = _tbc;

	/* table is locked */
	return _tbc;
}

int dbt_release_table(dbt_cache_p _dc, const str *_s)
{
	int hash;
	int hashidx;

	if(!_dbt_cachetbl || !_dc || !_s || !_s->s || _s->len<=0)
		return -1;

	hash = core_hash(&_dc->name, _s, DBT_CACHETBL_SIZE);
	hashidx = hash % DBT_CACHETBL_SIZE;

	lock_release(&_dbt_cachetbl[hashidx].sem);

	return 0;
}

/**
 *
 */
int dbt_cache_destroy(void)
{
	int i;
	dbt_cache_p _dc=NULL, _dc0=NULL;
	dbt_table_p _tbc = NULL;
	dbt_table_p _tbc0 = NULL;

	if(!_dbt_cachesem)
		return -1;

	lock_get(_dbt_cachesem);
	if(	_dbt_cachedb!=NULL )
	{
		_dc = *_dbt_cachedb;
		while(_dc)
		{
			_dc0 = _dc;
			_dc = _dc->next;
			shm_free(_dc0->name.s);
			shm_free(_dc0);
		}
		shm_free(_dbt_cachedb);
	}
	lock_destroy(_dbt_cachesem);
	lock_dealloc(_dbt_cachesem);

	/* destroy tables' hash table*/
	if(_dbt_cachetbl==0)
		return 0;
	for(i=0; i<DBT_CACHETBL_SIZE; i++)
	{
		lock_destroy(&_dbt_cachetbl[i].sem);
		_tbc = _dbt_cachetbl[i].dtp;
		while(_tbc)
		{
			_tbc0 = _tbc;
			_tbc = _tbc->next;
			dbt_table_free(_tbc0);
		}
		_dbt_cachetbl[i].dtp = NULL;
	}
	shm_free(_dbt_cachetbl);
	return 0;
}

/**
 *
 */
int dbt_cache_print(int _f)
{
	int i;
	dbt_table_p _tbc;

	if(!_dbt_cachetbl)
		return -1;

	for(i=0; i< DBT_CACHETBL_SIZE; i++)
	{
		lock_get(&_dbt_cachetbl[i].sem);
		_tbc = _dbt_cachetbl[i].dtp;
		while(_tbc)
		{
			if(_f)
				fprintf(stdout, "\n--- Database [%.*s]\n", _tbc->dbname.len,
								_tbc->dbname.s);
			if(_f)
			{
				fprintf(stdout, "\n----- Table [%.*s]\n",
						_tbc->name.len, _tbc->name.s);
				fprintf(stdout, "-------  LA=<%d> FL=<%x> AC=<%d>"
						" AV=<%d>\n", _tbc->mark, _tbc->flag,
						_tbc->auto_col, _tbc->auto_val);
				dbt_print_table(_tbc, NULL);
			} else {
				if(_tbc->flag & DBT_TBFL_MODI)
				{
					dbt_print_table(_tbc, &(_tbc->dbname));
					dbt_table_update_flags(_tbc,DBT_TBFL_MODI, DBT_FL_UNSET, 0);
				}
			}
			_tbc = _tbc->next;
		}
		lock_release(&_dbt_cachetbl[i].sem);
	}

	return 0;
}

int dbt_cache_reload(const str *dbname, const str *name)
{
	dbt_cache_p _dc;
	dbt_table_p _tbc, _tbc_new;
	int hash, hashidx;
	int i, res = 0;


	if( !_dbt_cachesem || !_dbt_cachedb || !_dbt_cachetbl ) {
		LM_ERR("dbtext cache is not initialized! Check if you loaded"
			" dbtext before attempting to reload it\n");
		return -2;
	}
	if( dbname && !(dbname->s && (dbname->len > 0)) ) {
		LM_ERR("request to reload an invalid dbtext database.\n");
		return -1;
	}
	if( name && !(name->s && (name->len > 0)) ) {
		LM_ERR("request to reload an invalid dbtext table.\n");
		return -1;
	}


	// lock to disable any cache modfifications while in reload
	lock_get(_dbt_cachesem);

	// resolve dbname in database cache if specified
	_dc = NULL;
	if( dbname ) {
		_dc = *_dbt_cachedb;
		while( _dc ) {
			if( (_dc->name.len == dbname->len) && !strncasecmp(_dc->name.s, dbname->s, dbname->len) ) {
				LM_DBG("resolved database [%.*s]\n", _dc->name.len, _dc->name.s);
				break;
			}
			_dc = _dc->next;
		}
		if( !_dc ) {
			LM_ERR("dbtext database [%.*s] not exists and cannot be reloaded!\n", dbname->len, dbname->s);
			lock_release(_dbt_cachesem);
			return -1;
		}
	}

	// calculate hash & hashidx if dbname & name specified
	hash = hashidx = -1;
	if( _dc && name ) {
		hash = core_hash(&_dc->name, name, DBT_CACHETBL_SIZE);
		hashidx = hash % DBT_CACHETBL_SIZE;
	}

	for(i=0; i<DBT_CACHETBL_SIZE; i++) {
		// iterate all table caches or only one if hashidx calculated
		if( (hashidx < 0) || (hashidx == i) ) {
			lock_get(&_dbt_cachetbl[i].sem);

			_tbc = _dbt_cachetbl[i].dtp;
			while( _tbc ) {
				if(
					// match hash if calcuated
					((hashidx < 0) || (_tbc->hash == hash)) &&
					// match table name if specified
					(!name || ((_tbc->name.len == name->len) && !strncasecmp(_tbc->name.s, name->s, name->len))) &&
					// match database name if specified
					(!_dc || ((_tbc->dbname.len == _dc->name.len) && !strncasecmp(_tbc->dbname.s, _dc->name.s, _dc->name.len)))
				) {
					// load new version from disk
					_tbc_new = dbt_load_file(&(_tbc->name), &(_tbc->dbname));
					if( _tbc_new ) {
						// inherit old version properties
						_tbc_new->hash = _tbc->hash;
						_tbc_new->prev = _tbc->prev;
						_tbc_new->next = _tbc->next;

						// update linked list links
						if( _tbc_new->prev ) (_tbc_new->prev)->next = _tbc_new;
						if( _tbc_new->next ) (_tbc_new->next)->prev = _tbc_new;
						if( _dbt_cachetbl[i].dtp == _tbc ) _dbt_cachetbl[i].dtp = _tbc_new;

						// delete old version and update iterator
						dbt_table_free(_tbc);
						_tbc = _tbc_new;

						LM_INFO("dbtext table [%.*s]->[%.*s] successfully reloaded\n", _tbc->dbname.len, _tbc->dbname.s, _tbc->name.len, _tbc->name.s);
					} else {
						// report failure if any reload fails
						res = -2;
						LM_ERR("dbtext table [%.*s]->[%.*s] loading of a new version failed and old version preserved!\n", _tbc->dbname.len, _tbc->dbname.s, _tbc->name.len, _tbc->name.s);
					}

					// exit loop if name specified and in 'match only one' scenario
					if( name ) break;
				}
				_tbc = _tbc->next;
			}

			lock_release(&_dbt_cachetbl[i].sem);

			if( name && !_tbc ) {
				LM_ERR("dbtext table [%.*s]->[%.*s] not exists and cannot be reloaded!\n", dbname->len, dbname->s, name->len, name->s);
				lock_release(_dbt_cachesem);
				return -1;
			}
		}
	}

	lock_release(_dbt_cachesem);
	return res;
}
