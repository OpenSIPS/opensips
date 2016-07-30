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
 * History
 * -------
 * 2003-03-06  200/INV to-tag list deallocation added;
 *             setting "kill_reason" moved in here -- it is moved
 *             from transaction state to a static var(jiri)
 * 2003-03-16  removed _TOTAG (jiri)
 * 2003-03-30  set_kr for requests only (jiri)
 * 2003-04-04  bug_fix: REQ_IN callback not called for local
 *             UAC transactions (jiri)
 * 2003-09-12  timer_link->tg will be set only if EXTRA_DEBUG (andrei)
 * 2003-12-04  global callbacks replaceed with callbacks per transaction;
 *             completion callback merged into them as LOCAL_COMPETED (bogdan)
 * 2004-02-11  FIFO/CANCEL + alignments (hash=f(callid,cseq)) (uli+jiri)
 * 2004-02-13  t->is_invite and t->local replaced with flags;
 *             timer_link.payload removed (bogdan)
 * 2004-08-23  avp support added - move and remove avp list to/from
 *             transactions (bogdan)
 * 2007-01-25  DNS failover at transaction level added (bogdan)
 */

#include <stdlib.h>


#include "../../mem/shm_mem.h"
#include "../../hash_func.h"
#include "../../dprint.h"
#include "../../md5utils.h"
#include "../../ut.h"
#include "../../error.h"
#include "t_reply.h"
#include "t_cancel.h"
#include "t_stats.h"
#include "h_table.h"
#include "fix_lumps.h" /* free_via_clen_lump */
#include "t_hooks.h"
#include "t_fwd.h"
#include "t_lookup.h"

/* indicates how much we have to shift the transaction pointer in order to
 * obtain a fair distribution on the tm timers */
int tm_timer_shift = 0;
static enum kill_reason kr;

/* pointer to the big table where all the transaction data
   lives */
static struct s_table*  tm_table;

int syn_branch = 1;


void reset_kr(void)
{
	kr = 0;
}

void set_kr( enum kill_reason _kr )
{
	kr|=_kr;
}


enum kill_reason get_kr(void) {
	return kr;
}


void lock_hash(int i)
{
	lock(&tm_table->entrys[i].mutex);
}


void unlock_hash(int i)
{
	unlock(&tm_table->entrys[i].mutex);
}


struct s_table* get_tm_table(void)
{
	return tm_table;
}


unsigned int transaction_count( void )
{
	unsigned int i;
	unsigned int count;

	count=0;
	for (i=0; i<TM_TABLE_ENTRIES; i++)
		count+=tm_table->entrys[i].cur_entries;
	return count;
}


void free_cell( struct cell* dead_cell )
{
	char *b;
	int i;
	struct sip_msg *rpl;
	struct totag_elem *tt, *foo;
	struct proxy_l *p;

	if ( has_tran_tmcbs( dead_cell, TMCB_TRANS_DELETED) )
		run_trans_callbacks( TMCB_TRANS_DELETED, dead_cell, 0, 0, 0);

	empty_tmcb_list(&dead_cell->tmcb_hl);

	release_cell_lock( dead_cell );

	tm_shm_lock();

	/* UA Server */
	if ( dead_cell->uas.request )
		free_cloned_msg_unsafe( dead_cell->uas.request );

	if ( dead_cell->uas.response.buffer.s )
		tm_shm_free_unsafe( dead_cell->uas.response.buffer.s );

	/* UA Clients */
	for ( i =0 ; i<dead_cell->nr_of_outgoings;  i++ )
	{
		/* retransmission buffer */
		if ( (b=dead_cell->uac[i].request.buffer.s) )
			tm_shm_free_unsafe( b );
		b=dead_cell->uac[i].local_cancel.buffer.s;
		if (b!=0 && b!=BUSY_BUFFER)
			tm_shm_free_unsafe( b );
		rpl=dead_cell->uac[i].reply;
		if (rpl && rpl!=FAKED_REPLY && rpl->msg_flags&FL_SHM_CLONE) {
			free_cloned_msg_unsafe( rpl );
		}
		if ( (p=dead_cell->uac[i].proxy)!=NULL ) {
			if ( p->host.h_addr_list )
				tm_shm_free_unsafe( p->host.h_addr_list );
			if ( p->dn ) {
				if ( p->dn->kids )
					tm_shm_free_unsafe( p->dn->kids );
				tm_shm_free_unsafe( p->dn );
			}
			tm_shm_free_unsafe(p);
		}
		if (dead_cell->uac[i].path_vec.s) {
			tm_shm_free_unsafe(dead_cell->uac[i].path_vec.s);
		}
		if (dead_cell->uac[i].adv_address.s) {
			tm_shm_free_unsafe(dead_cell->uac[i].adv_address.s);
		}
		if (dead_cell->uac[i].adv_port.s) {
			tm_shm_free_unsafe(dead_cell->uac[i].adv_port.s);
		}
		if (dead_cell->uac[i].duri.s) {
			tm_shm_free_unsafe(dead_cell->uac[i].duri.s);
		}
		if (dead_cell->uac[i].user_avps) {
			tm_destroy_avp_list_unsafe( &dead_cell->uac[i].user_avps);
		}
	}

	/* collected to tags */
	tt=dead_cell->fwded_totags;
	while(tt) {
		foo=tt->next;
		tm_shm_free_unsafe(tt->tag.s);
		tm_shm_free_unsafe(tt);
		tt=foo;
	}

	/* free the avp list */
	if (dead_cell->user_avps)
		tm_destroy_avp_list_unsafe( &dead_cell->user_avps );

	/* extra hdrs */
	if ( dead_cell->extra_hdrs.s )
		tm_shm_free_unsafe( dead_cell->extra_hdrs.s );

	/* the cell's body */
	tm_shm_free_unsafe( dead_cell );

	tm_shm_unlock();
}



static inline void init_synonym_id( struct cell *t )
{
	struct sip_msg *p_msg;
	int size;
	char *c;
	unsigned int myrand;

	if (!syn_branch) {
		p_msg=t->uas.request;
		if (p_msg) {
			/* char value of a proxied transaction is
			   calculated out of header-fields forming
			   transaction key
			*/
			char_msg_val( p_msg, t->md5 );
		} else {
			/* char value for a UAC transaction is created
			   randomly -- UAC is an originating stateful element
			   which cannot be refreshed, so the value can be
			   anything
			*/
			/* HACK : not long enough */
			myrand=rand();
			c=t->md5;
			size=MD5_LEN;
			memset(c, '0', size );
			int2reverse_hex( &c, &size, myrand );
		}
	}
}

static inline void init_branches(struct cell *t, unsigned int set)
{
	unsigned int i;
	struct ua_client *uac;

	for(i=0;i<MAX_BRANCHES;i++)
	{
		uac=&t->uac[i];
		uac->request.my_T = t;
		uac->request.branch = i;
#ifdef EXTRA_DEBUG
		uac->request.fr_timer.tg = TG_FR;
		uac->request.retr_timer.tg = TG_RT;
#endif
		uac->request.fr_timer.set = set;
		uac->request.retr_timer.set = set;
		uac->local_cancel.fr_timer.set = set;
		uac->local_cancel.retr_timer.set = set;
		uac->local_cancel=uac->request;
	}
}


struct cell*  build_cell( struct sip_msg* p_msg, int full_uas)
{
	struct cell* new_cell;
	int          sip_msg_len;
	struct usr_avp **old;
	struct tm_callback *cbs, *cbs_tmp;
	unsigned short set;

	/* allocs a new cell */
	new_cell = (struct cell*)shm_malloc(sizeof(struct cell) + context_size(CONTEXT_TRAN));
	if  ( !new_cell ) {
		ser_error=E_OUT_OF_MEM;
		return NULL;
	}

	/* filling with 0 */
	memset( new_cell, 0, sizeof( struct cell ) + context_size(CONTEXT_TRAN));

	/* get timer set id based on the transaction pointer, but
	 * devide by 64 to avoid issues because pointer are 64 bits
	 * aligned */
	set = ( ((unsigned long)new_cell)>>tm_timer_shift ) % tm_table->timer_sets;

	/* UAS */
#ifdef EXTRA_DEBUG
	new_cell->uas.response.retr_timer.tg=TG_RT;
	new_cell->uas.response.fr_timer.tg=TG_FR;
#endif
	new_cell->uas.response.retr_timer.set = set;
	new_cell->uas.response.fr_timer.set = set;
	new_cell->uas.response.my_T=new_cell;

	/* dcm: - local generation transactions should not inherit AVPs
	 * - commpletely new message */
	if(p_msg) {
		/* move the current avp list to transaction -bogdan */
		old = set_avp_list( &new_cell->user_avps );
		new_cell->user_avps = *old;
		*old = 0;

		/* set now the hash index & label, in case begin callbacks need them
		 * we are now under hash lock, so it's safe - vlad */
		new_cell->hash_index = p_msg->hash_index;
		new_cell->label = tm_table->entrys[ new_cell->hash_index].next_label;

		/* move the pending callbacks to transaction -bogdan */
		if (p_msg->id==tmcb_pending_id) {
			new_cell->tmcb_hl = tmcb_pending_hl;
			tmcb_pending_hl.first = 0;
		}
		set_t(new_cell);

		/* enter callback, which may potentially want to parse some stuff,
		 * before the request is shmem-ized */
		if (has_reqin_tmcbs() )
			run_reqin_callbacks( new_cell, p_msg, p_msg->REQ_METHOD);

		/* clean possible previous added vias/clen header or else they would
		 * get propagated in the failure routes */
		free_via_clen_lump(&p_msg->add_rm);
		new_cell->uas.request = sip_msg_cloner(p_msg,&sip_msg_len,full_uas?1:2);
		if (!new_cell->uas.request)
			goto error;
		new_cell->uas.end_request=((char*)new_cell->uas.request)+sip_msg_len;
	}

	/* UAC */
	init_branches(new_cell, set);
	new_cell->fr_timeout = fr_timeout;
	new_cell->fr_inv_timeout = fr_inv_timeout;

	new_cell->relaied_reply_branch   = -1;
	/* new_cell->T_canceled = T_UNDEFINED; */
#ifdef EXTRA_DEBUG
	new_cell->wait_tl.tg=TG_WT;
	new_cell->dele_tl.tg=TG_DEL;
#endif
	new_cell->wait_tl.set = set;
	new_cell->dele_tl.set = set;

	init_synonym_id(new_cell);
	init_cell_lock(  new_cell );
	return new_cell;

error:
	if (new_cell->user_avps)
		destroy_avp_list( &new_cell->user_avps );
	if (new_cell->tmcb_hl.first) {
		for( cbs=new_cell->tmcb_hl.first ; cbs ; ) {
			cbs_tmp = cbs;
			cbs = cbs->next;
			shm_free( cbs_tmp );
		}
	}
	shm_free(new_cell);
	set_t(NULL);
	/* unlink transaction AVP list and link back the global AVP list (bogdan)*/
	reset_avps();
	return NULL;
}



/* Release all the data contained by the hash table. All the aux. structures
 *  as sems, lists, etc, are also released */
void free_hash_table(void)
{
	struct cell* p_cell;
	struct cell* tmp_cell;
	int    i;

	if (tm_table)
	{
		/* remove the data contained by each entry */
		for( i = 0 ; i<TM_TABLE_ENTRIES; i++)
		{
			release_entry_lock( (tm_table->entrys)+i );
			/* delete all synonyms at hash-collision-slot i */
			p_cell=tm_table->entrys[i].first_cell;
			for( ; p_cell; p_cell = tmp_cell )
			{
				tmp_cell = p_cell->next_cell;
				free_cell( p_cell );
			}
		}
		shm_free(tm_table);
	}
}


/*
 */
struct s_table* init_hash_table( unsigned int timer_sets )
{
	int              i;

	/*allocs the table*/
	tm_table= (struct s_table*)shm_malloc( sizeof( struct s_table ) );
	if ( !tm_table) {
		LM_ERR("no more share memory\n");
		goto error;
	}

	memset( tm_table, 0, sizeof (struct s_table ) );

	tm_table->timer_sets = timer_sets;

	/* inits the entrys */
	for(  i=0 ; i<TM_TABLE_ENTRIES; i++ )
	{
		init_entry_lock( tm_table, (tm_table->entrys)+i );
		tm_table->entrys[i].next_label = rand();
	}

	return  tm_table;

error:
	return 0;
}


/*  Takes an already created cell and links it into hash table on the
 *  appropriate entry. */
void insert_into_hash_table_unsafe( struct cell * p_cell, unsigned int _hash )
{
	struct entry* p_entry;

	p_cell->hash_index=_hash;

	/* locates the appropriate entry */
	p_entry = &tm_table->entrys[ _hash ];

	p_cell->label = p_entry->next_label++;
	if ( p_entry->last_cell )
	{
		p_entry->last_cell->next_cell = p_cell;
		p_cell->prev_cell = p_entry->last_cell;
	} else p_entry->first_cell = p_cell;

	p_entry->last_cell = p_cell;

	/* update stats */
	p_entry->cur_entries++;
	p_entry->acc_entries++;
	stats_trans_new( is_local(p_cell) );
}


/*  Un-link a  cell from hash_table, but the cell itself is not released */
void remove_from_hash_table_unsafe( struct cell * p_cell)
{
	struct entry*  p_entry  = &(tm_table->entrys[p_cell->hash_index]);

	if ( p_cell->prev_cell )
		p_cell->prev_cell->next_cell = p_cell->next_cell;
	else
		p_entry->first_cell = p_cell->next_cell;

	if ( p_cell->next_cell )
		p_cell->next_cell->prev_cell = p_cell->prev_cell;
	else
		p_entry->last_cell = p_cell->prev_cell;
# ifdef EXTRA_DEBUG
	if (p_entry->cur_entries==0) {
		LM_CRIT("bad things happened: cur_entries=0\n");
		abort();
	}
# endif
	/* update stats */
	p_entry->cur_entries--;
	if_update_stat(tm_enable_stats, tm_trans_inuse , -1 );
}
