/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
#include "../../rw_locking.h"

/* Handy macros */
#define STR2IOVEC(sx, ix)       do {(ix).iov_base = (sx).s; (ix).iov_len = (sx).len;} while(0)
#define SZ2IOVEC(sx, ix)        do {(ix).iov_base = (sx); (ix).iov_len = strlen(sx);} while(0)

struct rtpp_node {
	unsigned int		idx;			/* overall index */
	str					rn_url;			/* unparsed, deletable */
	int					rn_umode;
	char				*rn_address;	/* substring of rn_url */
	char				*adv_address;	/* advertised address of rtpproxy */
	int					rn_disabled;	/* found unaccessible? */
	unsigned			rn_weight;		/* for load balancing */
	unsigned int		rn_recheck_ticks;
	unsigned int		capabilities;
	struct rtpp_node	*rn_next;
};

/* Supported version of the RTP proxy command protocol */
#define	SUP_CPROTOVER	20040107
/* Required additional version of the RTP proxy command protocol */
#define	REQ_CPROTOVER	"20050322"
/* Additional capabilities */
#define REPACK_CAP				(1<<0)
#define	REPACK_CPROTOVER		"20071116"
#define CODECS_CAP				(1<<1)
#define	CODECS_CPROTOVER		"20081102"
#define AUTOBRIDGE_CAP			(1<<2)
#define	AUTOBRIDGE_CPROTOVER	"20090810"
#define	NOTIFY_CAP				(1<<3)
#define	NOTIFY_CPROTOVER		"20081224"
#define	STATS_CAP				(1<<4)
#define	STATS_CPROTOVER			"20080403"
#define	NOTIFY_WILD_CAP			(1<<5)
#define	NOTIFY_WILD_CPROTOVER	"20150617"
#define	STATS_EXTRA_CAP			(1<<6)
#define	STATS_EXTRA_CPROTOVER	"20150420"
#define	TTL_CHANGE_CAP			(1<<7)
#define	TTL_CHANGE_CPROTOVER	"20170313"
#define	RECORD_CAP				(1<<8)
#define	RECORD_CPROTOVER		"20071218"
#define	SUBCOMMAND_CAP			(1<<9)
#define	SUBCOMMAND_CPROTOVER	"20191015"

#define RTP_CAP(_c) _c ## _CPROTOVER, sizeof(_c ## _CPROTOVER) - 1
#define SET_CAP(_n, _c) (_n)->capabilities |= (_c ## _CAP)
#define HAS_CAP(_n, _c) ((_n)->capabilities & _c ## _CAP)


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
    struct rtpp_set *set;
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

#define NH_VAL_SET_FIXED            0
#define NH_VAL_SET_UNDEF            2

typedef struct rtpp_set_param{
        int t;
        union {
                struct rtpp_set * fixed_set;
                int int_set;
        } v;
} nh_set_param_t;

struct rtpp_dtmf_event {
	char digit;
	unsigned int volume;
	unsigned int duration;
	unsigned int is_callid;
	unsigned int stream;
	str id;
};
void rtpproxy_raise_dtmf_event(int sender, void *p);

extern rw_lock_t *nh_lock;
extern str rtpp_notify_socket;
extern int rtpp_notify_socket_un;
extern struct dlg_binds dlg_api;
extern int detect_rtp_idle;
extern struct rtpp_set_head ** rtpp_set_list;
extern struct rtpp_notify_head * rtpp_notify_h;
int init_rtpp_notify_list();
void notification_listener_process(int rank);

/* Functions from nathelper */
struct rtpp_set *get_rtpp_set(nh_set_param_t *);
struct rtpp_node *select_rtpp_node(struct sip_msg *, str, struct rtpp_set *, pv_spec_p, int);
char *send_rtpp_command(struct rtpp_node *, struct iovec *, int);
int force_rtp_proxy_body(struct sip_msg* msg, struct force_rtpp_args *args,
               pv_spec_p var, pv_spec_p ipvar);

#endif
