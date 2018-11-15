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
 * --------
 *  2003-02-18  updated various function prototypes (andrei)
 *  2003-03-10  removed ifdef _OBSO & made redefined all the *UNREF* macros
 *               in a non-gcc specific way (andrei)
 *  2003-03-13  now send_pr_buffer will be called w/ function/line info
 *               only when compiling w/ -DEXTRA_DEBUG (andrei)
 *  2003-03-31  200 for INVITE/UAS resent even for UDP (jiri)
 *  2007-01-25  DNS failover at transaction level added (bogdan)
 */



#ifndef _T_FUNCS_H
#define _T_FUNCS_H

#include <errno.h>
#include <netdb.h>

#include "../../mem/shm_mem.h"
#include "../../lib/osips_malloc.h"
#include "../../parser/msg_parser.h"
#include "../../globals.h"
#include "../../msg_translator.h"
#include "../../timer.h"
#include "../../forward.h"
#include "../../mem/mem.h"
#include "../../md5utils.h"
#include "../../ip_addr.h"
#include "../../parser/parse_uri.h"
#include "../../usr_avp.h"

struct s_table;
struct timer;
struct entry;
struct cell;
struct retr_buf;

#include "t_lookup.h"
#include "config.h"
#include "lock.h"
#include "timer.h"
#include "sip_msg.h"
#include "h_table.h"
#include "ut.h"

extern int noisy_ctimer;


/* t_relay_to flags */
#define TM_T_RELAY_repl_FLAG          (1<<0) /* replicated */
#define TM_T_RELAY_not_used           (1<<1)
#define TM_T_RELAY_noerr_FLAG         (1<<2)
#define TM_T_RELAY_nodnsfo_FLAG       (1<<3)
#define TM_T_RELAY_reason_FLAG        (1<<4)
#define TM_T_RELAY_do_cancel_dis_FLAG (1<<5)


/* send a private buffer: utilize a retransmission structure
   but take a separate buffer not referred by it; healthy
   for reducing time spend in REPLIES locks
*/


/* send a buffer -- 'PR' means private, i.e., it is assumed noone
   else can affect the buffer during sending time
*/
#ifdef EXTRA_DEBUG
int send_pr_buffer( struct retr_buf *rb,
	void *buf, int len, char* file, const char *function, int line, void* ctx);
#define SEND_PR_BUFFER(_rb,_bf,_le ) \
	send_pr_buffer( (_rb), (_bf), (_le), __FILE__,  __FUNCTION__, __LINE__, NULL)
#define SEND_PR_CONTEXTS_BUFFER(_rb,_bf,_le, _ctx ) \
	send_pr_buffer( (_rb), (_bf), (_le), __FILE__, __FUNCTION, __LINE__ ,_ctx)
#else
int send_pr_buffer( struct retr_buf *rb, void *buf, int len, void* ctx);
#define SEND_PR_BUFFER(_rb,_bf,_le ) \
	send_pr_buffer( (_rb), (_bf), (_le), NULL)
#define SEND_PR_CONTEXTS_BUFFER(_rb,_bf,_le, _ctx ) \
	send_pr_buffer( (_rb), (_bf), (_le), _ctx)
#endif

#define SEND_BUFFER( _rb ) \
	SEND_PR_BUFFER( (_rb) , (_rb)->buffer.s , (_rb)->buffer.len )

#define SEND_CONTEXTS_BUFFER( _rb, ctx) \
	SEND_PR_CONTEXTS_BUFFER( (_rb) , (_rb)->buffer.s, (_rb)->buffer.len, ctx)


#define UNREF_UNSAFE(_T_cell) do { \
	((_T_cell)->ref_count--);\
	LM_DBG("UNREF_UNSAFE: [%p] after is %d\n",_T_cell, (_T_cell)->ref_count);\
	}while(0)

#define REF(_T_cell) do{ \
	LOCK_HASH( (_T_cell)->hash_index ); \
	REF_UNSAFE(_T_cell); \
	UNLOCK_HASH( (_T_cell)->hash_index ); }while(0)

#define UNREF(_T_cell) do{ \
	LOCK_HASH( (_T_cell)->hash_index ); \
	UNREF_UNSAFE(_T_cell); \
	UNLOCK_HASH( (_T_cell)->hash_index ); }while(0)
#define REF_UNSAFE(_T_cell) do {\
	((_T_cell)->ref_count++);\
	LM_DBG("REF_UNSAFE:[%p] after is %d\n",_T_cell, (_T_cell)->ref_count);\
	}while(0)
#define INIT_REF_UNSAFE(_T_cell) ((_T_cell)->ref_count=1)
#define IS_REFFED_UNSAFE(_T_cell) ((_T_cell)->ref_count!=0)

#define unset_timeout(timeout) ((timeout) = 0)
#define is_timeout_set(timeout) ((timeout) != 0)

static inline void _set_fr_retr( struct retr_buf *rb, int retr )
{
	utime_t timer;

	if (retr && !rb->retr_timer.deleted) {
		rb->retr_list=RT_T1_TO_1;
		set_timer( &rb->retr_timer, RT_T1_TO_1, NULL );
	}

	if (!rb->my_T || !is_timeout_set(rb->my_T->fr_timeout))
		set_1timer(&rb->fr_timer, FR_TIMER_LIST, NULL);
	else {
		timer = rb->my_T->fr_timeout;
		set_1timer(&rb->fr_timer, FR_TIMER_LIST, &timer);
	}
}


static inline void start_retr(struct retr_buf *rb)
{
	_set_fr_retr(rb, rb->dst.proto==PROTO_UDP);
}


static inline void force_retr(struct retr_buf *rb)
{
	_set_fr_retr(rb, 1);
}

#define _clean_branch(br, free_f, avp_destr_f) \
	do { \
		if ((br).path_vec.s) \
			free_f((br).path_vec.s); \
		if ((br).adv_address.s) \
			free_f((br).adv_address.s); \
		if ((br).adv_port.s) \
			free_f((br).adv_port.s); \
		if ((br).duri.s) \
			free_f((br).duri.s); \
		if ((br).user_avps) \
			avp_destr_f(&(br).user_avps); \
	} while (0)

#define clean_branch(br) \
	_clean_branch(br, shm_free, destroy_avp_list)

static inline void init_branch(struct ua_client *uac, unsigned int branch_idx,
								unsigned int timer_set, struct cell *t)
{
	uac->request.my_T = t;
	uac->request.branch = branch_idx;
#ifdef EXTRA_DEBUG
	uac->request.fr_timer.tg = TG_FR;
	uac->request.retr_timer.tg = TG_RT;
#endif
	uac->request.fr_timer.set = timer_set;
	uac->request.retr_timer.set = timer_set;
	uac->local_cancel.fr_timer.set = timer_set;
	uac->local_cancel.retr_timer.set = timer_set;
	uac->local_cancel=uac->request;
}

void tm_shutdown();

/* function returns:
 *       1 - a new transaction was created
 *      -1 - error, including retransmission
 */
int  t_add_transaction( struct sip_msg* p_msg  );


/* returns 1 if everything was OK or -1 for error */
int t_release_transaction( struct cell *trans );


int get_ip_and_port_from_uri( str* uri , unsigned int *param_ip,
	unsigned int *param_port);


void put_on_wait(  struct cell  *Trans  );


void cleanup_localcancel_timers( struct cell *t );


int t_relay_to( struct sip_msg  *p_msg, struct proxy_l *proxy, int replicate);


int tm_has_request_disponsition_no_cancel(struct sip_msg *msg);

#endif

