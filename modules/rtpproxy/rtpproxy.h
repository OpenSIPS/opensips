/* $Id: nathelper.h 7546 2010-12-15 17:19:49Z anca_vamanu $
 *
 * Copyright (C) 2003-2008 Sippy Software, Inc., http://www.sippysoft.com
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
 * 2007-04-13   splitted from nathelper.c (ancuta)
*/


#ifndef _NATHELPER_NATHELPER_H
#define _NATHELPER_NATHELPER_H

#include "../../str.h"
#include "../../pvar.h"
#include "../dialog/dlg_load.h"

/* Handy macros */
#define STR2IOVEC(sx, ix)       do {(ix).iov_base = (sx).s; (ix).iov_len = (sx).len;} while(0)
#define SZ2IOVEC(sx, ix)        do {(ix).iov_base = (sx); (ix).iov_len = strlen(sx);} while(0)

struct rtpp_node {
	unsigned int		idx;			/* overall index */
	str					rn_url;			/* unparsed, deletable */
	int					rn_umode;
	char				*rn_address;	/* substring of rn_url */
	int					rn_disabled;	/* found unaccessible? */
	unsigned			rn_weight;		/* for load balancing */
	unsigned int		rn_recheck_ticks;
	int			rn_rep_supported;
	int			rn_ptl_supported;
	int			abr_supported;
	struct rtpp_node	*rn_next;
};


struct rtpp_set{
	unsigned int 		id_set;
	unsigned			weight_sum;
	unsigned int		rtpp_node_count;
	int 				set_disabled;
	unsigned int		set_recheck_ticks;
	struct rtpp_node	*rn_first;
	struct rtpp_node	*rn_last;
	struct rtpp_set     *rset_next;
};


struct rtpp_set_head{
	struct rtpp_set		*rset_first;
	struct rtpp_set		*rset_last;
};

struct force_rtpp_args {
    char *arg1;
    char *arg2;
    int offer;
    str body;
    str callid;
    struct rtpp_node *node;
    str raddr;
};

/* used in timeout_listener_process */
struct rtpp_notify_node {
	int index;
	int fd;
	int mode;
	char* addr;
	struct rtpp_notify_node *next;
};

struct rtpp_notify_head {
	int changed;
	gen_lock_t *lock;
	struct rtpp_notify_node *rtpp_list;
};


/* parameter type for set_rtp_proxy_set() */

#define NH_VAL_SET_FIXED              0
#define NH_VAL_SET_SPEC             1

typedef struct rtpp_set_param{
        int t;
        union {
                struct rtpp_set * fixed_set;
                pv_spec_t var_set;
        } v;
} nh_set_param_t;

extern str rtpp_notify_socket;
extern struct dlg_binds dlg_api;
extern int detect_rtp_idle;
extern struct rtpp_set_head * rtpp_set_list;
extern struct rtpp_notify_head * rtpp_notify_h;
int init_rtpp_notify_list();
void timeout_listener_process(int rank);

/* Functions from nathelper */
struct rtpp_node *select_rtpp_node(str, int);
char *send_rtpp_command(struct rtpp_node *, struct iovec *, int);
int force_rtp_proxy_body(struct sip_msg *, struct force_rtpp_args *);

#endif
