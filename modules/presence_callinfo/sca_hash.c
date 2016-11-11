/*
 * Add "call-info" event to presence module
 *
 * Copyright (C) 2013 OpenSIPS Solutions
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
 *  2010-07-13  added support for SCA Broadsoft with dialog module (bogdan)
 */




#include "../../dprint.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../hash_func.h"
#include "../../parser/parse_uri.h"
#include "sca_hash.h"
#include "add_events.h"

static struct sca_hash *sca_table = NULL;

#define sca_lock(_entry) \
		lock_set_get( sca_table->locks, sca_table->entries[_entry].lock_idx)

#define sca_unlock(_entry) \
		lock_set_release( sca_table->locks, sca_table->entries[_entry].lock_idx)

#define sca_hash(_line) core_hash(_line, 0, sca_table->size)

int init_sca_hash(int size)
{
	unsigned int n;

	/* check/ajust the size of the hash table */
	if (size == 0) {
		LM_ERR("Invalid hash size!\n");
		goto error0;
	}
	if (size != 1) {
		for( n=1 ; n<(8*sizeof(n)) - 1 ; n++) {
			if (size==(1<<n))
				break;
			if ( size < (1<<n) ) {
				LM_WARN("hash size is not a power "
					"of 2 as it should be -> rounding from %d to %d\n",
					size, 1<<(n-1));
				size = 1<<(n-1);
				break;
			}
		}
	}

	/* allocate the hash table + entries */
	sca_table = (struct sca_hash*)shm_malloc
		( sizeof(struct sca_hash) + size*sizeof(struct sca_entry));
	if (sca_table==0) {
		LM_ERR("no more shm mem for SCA hash table\n");
		goto error0;
	}

	memset( sca_table, 0,
		sizeof(struct sca_hash) + size*sizeof(struct sca_entry) );

	sca_table->size = size;
	sca_table->entries = (struct sca_entry*)(sca_table+1);

	/* calculate how many locks we can get */
	n = (size<MAX_SCA_LOCKS)?size:MAX_SCA_LOCKS;
	for(  ; n>=MIN_SCA_LOCKS ; n-- ) {
		sca_table->locks = lock_set_alloc(n);
		if (sca_table->locks==0)
			continue;
		if (lock_set_init(sca_table->locks)==0) {
			lock_set_dealloc(sca_table->locks);
			sca_table->locks = 0;
			continue;
		}
		sca_table->locks_no = n;
		break;
	}

	if (sca_table->locks==0) {
		LM_ERR("unable to allocted at least %d locks for the hash table\n",
			MIN_SCA_LOCKS);
		goto error1;
	}

	/* distribute the locks over all entries */
	for( n=0 ; n<size; n++ )
		sca_table->entries[n].lock_idx = n % sca_table->locks_no;

	return 0;
error1:
	shm_free( sca_table );
error0:
	return -1;
}


/*
 * Creates new SCA structure, adds into hash table
 * Assumes hash entry is locked !!!!
 */
static struct sca_line* create_sca_line(str *line, unsigned int hash)
{
	struct sca_line *scal;
	struct sip_uri puri;

	/* parse the URI line */
	if ( parse_uri( line->s, line->len, &puri)<0 ) {
		LM_ERR("failed to parse URI line <%.*s> \n", line->len, line->s);
		return NULL;
	}

	scal = (struct sca_line *)shm_malloc( sizeof(struct sca_line)
		+ line->len + MD5_LEN );
	if (scal==NULL) {
		LM_ERR("no more shm - failed to allocate new SCA structure\n");
		return NULL;
	}

	memset( scal, 0, sizeof(struct sca_line));
	scal->hash = hash;
	/* name of the line */
	scal->line.s = (char*)(scal+1);
	scal->line.len = line->len;
	memcpy( scal->line.s, line->s, line->len);
	/* user anf host, just as pointers */
	scal->user.s = scal->line.s + (puri.user.s - line->s);
	scal->user.len = puri.user.len;
	scal->domain.s = scal->line.s + (puri.host.s - line->s);
	scal->domain.len = puri.host.len;
	/* etag space */
	scal->etag.s = scal->line.s + scal->line.len;
	scal->etag.len = 0;

	/* insert into hash */
	if (sca_table->entries[hash].first!=NULL) {
		scal->next = sca_table->entries[hash].first;
		scal->next->prev = scal;
	}
	sca_table->entries[hash].first = scal;

	return scal;
}


/*
 * Searches for an SCA by name ; if found, it will returned with the lock taken !!
 */
struct sca_line* get_sca_line(str *line, int create)
{
	unsigned int hash;
	struct sca_line *scal;

	hash = sca_hash( line );

	sca_lock(hash);

	/* search */
	for( scal=sca_table->entries[hash].first ; scal ; scal=scal->next ) {
		if ( (scal->line.len==line->len) && (memcmp(scal->line.s, line->s , line->len)==0) )
			return scal;
	}

	/* not found */
	if (create==0) {
		sca_unlock(hash);
		return NULL;
	}

	/* create */
	scal = create_sca_line(line, hash);
	if (scal==NULL) {
		LM_ERR("failed to create new SCA record\n");
		sca_unlock(hash);
		return NULL;
	}
	return scal;
}


/*
 * sets a new state for an index - it assumes the line is locked
 */
int set_sca_index_state(struct sca_line *line, unsigned int idx,
														unsigned int state)
{
	struct sca_idx *scai;
	struct sca_idx *prev;

	/* search for the index */
	for( scai=line->indexes,prev=NULL ; scai ; prev=scai,scai=scai->next)
		if (scai->idx>=idx) break;

	/* if not found, add it to the right position */
	if (scai==NULL || scai->idx!=idx) {
		scai = (struct sca_idx*)shm_malloc(sizeof(struct sca_idx));
		if (scai==NULL) {
			LM_ERR("not enough shm mem for a new sca index\n");
			return -1;
		}
		scai->idx = idx;
		/* insert it after prev */
		if (prev==NULL) {
			scai->next = line->indexes;
			line->indexes = scai;
		} else {
			scai->next = prev->next;
			prev->next = scai;
		}
	}

	/* set the state */
	scai->state = state;

	return 0;
}


char * sca_print_line_status(struct sca_line *line, int *l)
{
	unsigned int len;
	struct sca_idx *scai;
	char *buf;
	char *p, *q;
	int n;

	len = CI_hdr_name_len + 1/*<*/ + line->line.len + 1 /*>*/
		 + 1/*;*/  + CI_hdr_AI_param_len + 2/* =* */
		 + 1/*;*/  + CI_hdr_AS_param_len + 15/* =idle */
		 + CRLF_LEN;

	for( scai=line->indexes ; scai ; scai=scai->next ) {
		if (scai->state!=SCA_STATE_IDLE)
			len += 1/*;*/ + CI_hdr_AI_param_len +1 + 3 /* =idx */
				+ 1/*;*/ + CI_hdr_AS_param_len + 1 + 3 /* =state */;
	}

	buf = (char *)pkg_malloc(len);
	if (buf==NULL) {
		LM_ERR("no more mem (needed %d)\n",len);
		return NULL;
	}

	p = buf;
	memcpy( p, CI_hdr_name_s "<", CI_hdr_name_len+1);
	p += CI_hdr_name_len+1;
	memcpy( p, line->line.s, line->line.len);
	p += line->line.len;
	*(p++) = '>';

	for( scai=line->indexes ; scai ; scai=scai->next ) {
		if (scai->state==SCA_STATE_IDLE)
			continue;
		memcpy( p, ";"CI_hdr_AI_param_s "=", CI_hdr_AI_param_len+2 );
		p += CI_hdr_AI_param_len+2 ;
		q = int2str(scai->idx, &n);
		memcpy( p , q, n);
		p += n;
		memcpy( p, ";"CI_hdr_AS_param_s "=", CI_hdr_AS_param_len+2 );
		p += CI_hdr_AS_param_len+2 ;
		switch (scai->state) {
			case SCA_STATE_SEIZED:
				memcpy( p, "seized", 6); p += 6 ;
				break;
			case SCA_STATE_PROGRESSING:
				memcpy( p, "progressing", 11); p += 11 ;
				break;
			case SCA_STATE_ALERTING:
				memcpy( p, "alerting", 8); p += 8 ;
				break;
			case SCA_STATE_ACTIVE:
				memcpy( p, "active", 6); p += 6 ;
				break;
			default:
				LM_ERR("unsupported state %d for index %d line %.*s\n",
					scai->state, scai->idx, line->line.len, line->line.s);
				pkg_free(buf);
				return NULL;
		}
	}

	/* add the idle state */
	memcpy( p, ";"CI_hdr_AI_param_s "=*;" CI_hdr_AS_param_s "=idle" CRLF,
		1+CI_hdr_AI_param_len+3+CI_hdr_AS_param_len+5+CRLF_LEN );
	p += 1+CI_hdr_AI_param_len+3+CI_hdr_AS_param_len+5+CRLF_LEN ;

	*l = (int)(p-buf);

	if (p-buf>len)
		LM_ERR("BUG: allocated %d, wrote, %d\n",len,(int)(p-buf));
	LM_DBG("hdr is <%.*s>",*l,buf);

	return buf;
}



void unlock_sca_line(struct sca_line *scal)
{
	sca_unlock(scal->hash);
}


void free_sca_line(struct sca_line *scal)
{
	struct sca_idx *idx,*tmp;

	/* free indexes */
	for( idx=scal->indexes ; idx ; ) {
		tmp = idx;
		idx = idx->next;
		shm_free(tmp);
	}
	/* free main structure */
	shm_free(scal);
}


void destroy_sca_hash(void)
{
	struct sca_line *sline, *l_sline;
	unsigned int i;

	if (sca_table==NULL)
		return;

	if (sca_table->locks) {
		lock_set_destroy(sca_table->locks);
		lock_set_dealloc(sca_table->locks);
	}

	for( i=0 ; i<sca_table->size; i++ ) {
		sline = sca_table->entries[i].first;
		while (sline) {
			l_sline = sline;
			sline = sline->next;
			free_sca_line(l_sline);
		}

	}

	shm_free(sca_table);
	sca_table = NULL;
}

