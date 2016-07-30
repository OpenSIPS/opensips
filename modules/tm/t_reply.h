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
 */



#ifndef _T_REPLY_H
#define _T_REPLY_H

#include "../../tags.h"

#include "h_table.h"


extern int restart_fr_on_each_reply;
extern int onreply_avp_mode;

/* reply processing status */
enum rps {
	/* something bad happened */
	RPS_ERROR=0,
	/* transaction completed but we still accept the reply */
	RPS_PUSHED_AFTER_COMPLETION,
	/* reply discarded */
	RPS_DISCARDED,
	/* reply stored for later processing */
	RPS_STORE,
	/* transaction completed */
	RPS_COMPLETED,
	/* provisional reply not affecting transaction state */
	RPS_PROVISIONAL
};

extern char tm_tags[TOTAG_VALUE_LEN];
extern char *tm_tag_suffix;

extern int disable_6xx_block;

/* flag for marching minor branches */
extern int minor_branch_flag;
extern char *minor_branch_flag_str;

/* has this to-tag been never seen in previous 200/INVs? */
int unmatched_totag(struct cell *t, struct sip_msg *ack);

/* branch bitmap type */
typedef unsigned int branch_bm_t;

/* reply export types */
typedef int (*treply_f)(struct sip_msg * , unsigned int , str * );
typedef int (*treply_wb_f)( struct cell* trans, unsigned int code, str *text,
	str *body, str *new_header, str *to_tag);

#define LOCK_REPLIES(_t) lock(&(_t)->reply_mutex )
#define UNLOCK_REPLIES(_t) unlock(&(_t)->reply_mutex )

/* This function is called whenever a reply for our module is received;
 * we need to register this function on module initialization;
 * Returns :   0 - core router stops
 *             1 - core router relay statelessly
 */
int reply_received( struct sip_msg  *p_msg ) ;


/* send a UAS reply
 * Warning: 'buf' and 'len' should already have been build.
 * returns 1 if everything was OK or -1 for error
 */

#ifdef _OBSO
int t_reply_light( struct cell *trans, char* buf, unsigned int len,
		   unsigned int code, char * text,
		   char *to_tag, unsigned int to_tag_len);
#endif

int t_reply_with_body( struct cell *trans, unsigned int code,
		       str *text, str *body, str *new_header, str *to_tag );


/* send a UAS reply
 * returns 1 if everything was OK or -1 for error
 */
int t_reply( struct cell *t, struct sip_msg * , unsigned int , str * );
/* the same as t_reply, except it does not claim
   REPLY_LOCK -- useful to be called within reply
   processing
*/

int w_t_reply_body(struct sip_msg* msg,str* code,str *text, str *body);

int t_reply_unsafe( struct cell *t, struct sip_msg * , unsigned int , str * );


enum rps relay_reply( struct cell *t, struct sip_msg *p_msg, int branch,
	unsigned int msg_status, branch_bm_t *cancel_bitmap );

enum rps local_reply( struct cell *t, struct sip_msg *p_msg, int branch,
    unsigned int msg_status, branch_bm_t *cancel_bitmap );

void set_final_timer( /* struct s_table *h_table,*/ struct cell *t );

void cleanup_uac_timers( struct cell *t );

void on_negative_reply( struct cell* t, struct sip_msg* msg,
	int code, void *param  );

typedef int (*tget_picked_f)(void);

int t_get_picked_branch();

/* set which 'reply' structure to take if only negative
   replies arrive
*/
void t_on_negative( unsigned int go_to );
unsigned int get_on_negative();
void t_on_reply( unsigned int go_to );
unsigned int get_on_reply();

/* Retransmits the last sent inbound reply.
 * Returns  -1 - error
 *           1 - OK
 */
int t_retransmit_reply( struct cell *t );

void tm_init_tags();

int unixsock_t_reply(str* msg);

#endif

