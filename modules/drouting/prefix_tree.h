/*
 * $Id$
 *
 * Copyright (C) 2005-2008 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (OpenSIPS).
 *
 * DROUTING OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * DROUTING OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * For any questions about this software and its license, please contact
 * Voice Sistem at following e-mail address:
 *         office@voice-system.ro
 *
 * History:
 * ---------
 *  2005-02-20  first version (cristian)
 *  2005-02-27  ported to 0.9.0 (bogdan)
 */



#ifndef prefix_tree_h
#define prefix_tree_h

#include "../../str.h"
#include "../../ip_addr.h"
#include "../../time_rec.h"

#define PTREE_CHILDREN 10
#define IS_DECIMAL_DIGIT(d) \
	(((d)>='0') && ((d)<= '9'))

extern int tree_size;

#define INIT_PTREE_NODE(p, n) \
do {\
	(n) = (ptree_t*)shm_malloc(sizeof(ptree_t));\
	if(NULL == (n))\
		goto err_exit;\
	tree_size+=sizeof(ptree_t);\
	memset((n), 0, sizeof(ptree_t));\
	(n)->bp=(p);\
}while(0);


#define DR_DST_PING_DSBL_FLAG   (1<<0)
#define DR_DST_PING_PERM_FLAG   (1<<1)
#define DR_DST_STAT_DSBL_FLAG   (1<<2)
#define DR_DST_STAT_NOEN_FLAG   (1<<3)
#define DR_DST_STAT_DIRT_FLAG   (1<<4)
#define DR_DST_STAT_MASK        (DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_NOEN_FLAG)

#define DR_MAX_IPS  32

/* list of PSTN gw */
typedef struct pgw_ {
	/* internal numerical ID, not DB related */
	unsigned int _id;
	/* GW ID from DB */
	str id;
	/* type of gateway */
	int type;
	str ip_str;
	struct socket_info *sock;
	/* strip / pri and attrs */
	str pri;
	int strip;
	str attrs;
	/* addres and port */
	struct ip_addr ips[DR_MAX_IPS];
	unsigned short ports[DR_MAX_IPS];
	unsigned short protos[DR_MAX_IPS];
	unsigned short ips_no;
	struct pgw_ *next;
	int flags;
}pgw_t;

typedef struct pcr_ pcr_t;

/* GW/CARRIER linker as kept in arrays, by rules */
typedef struct pgw_list_ {
	unsigned int is_carrier;
	union {
		pgw_t *gw;
		pcr_t *carrier;
	}dst;
	unsigned int weight;
}pgw_list_t;

#define DR_CR_FLAG_WEIGHT (1<<0)
#define DR_CR_FLAG_FIRST  (1<<1)
#define DR_CR_FLAG_IS_OFF (1<<2)
#define DR_CR_FLAG_DIRTY  (1<<3)

/* list of carriers */
struct pcr_ {
	/* carrier ID/name from DB */
	str id;
	/* flags */
	unsigned int flags;
	/* array of pointers into the PSTN gw list */
	pgw_list_t *pgwl;
	/* length of the PSTN gw array */
	unsigned short pgwa_len;
	/* attributes string */
	str attrs;
	/* linker in list */
	pcr_t *next;
};


/* element containing routing information */
typedef struct rt_info_ {
	/* id matching the one in db */
	unsigned int id;
	/* priority of the rule */
	unsigned int priority;
	/* timerec says when the rule is on */
	tmrec_t *time_rec;
	/* script route to be executed */
	int route_idx;
	/* opaque string with rule attributes */
	str attrs;
	/* array of pointers into the PSTN gw list */
	pgw_list_t *pgwl;
	/* length of the PSTN gw array */
	unsigned short pgwa_len;
	/* how many lists link this element */
	unsigned short ref_cnt;
} rt_info_t;

typedef struct rt_info_wrp_ {
	rt_info_t     *rtl;
	struct rt_info_wrp_  *next;
} rt_info_wrp_t;

typedef struct rg_entry_ {
	unsigned int rgid;
	rt_info_wrp_t *rtlw;
} rg_entry_t;

typedef struct ptree_node_ {
	unsigned int rg_len;
	unsigned int rg_pos;
	rg_entry_t *rg;
	struct ptree_ *next;
} ptree_node_t;

typedef struct ptree_ {
	/* backpointer */
	struct ptree_ *bp;
	ptree_node_t ptnode[PTREE_CHILDREN];
} ptree_t;

void
print_interim(
		int,
		int,
		ptree_t*
		);

int
del_tree(
	ptree_t *
	);

int
add_prefix(
	ptree_t*,
	/* prefix */
	str*,
	rt_info_t *,
	unsigned int
	);

rt_info_t*
get_prefix(
	ptree_t *ptree,
	str* prefix,
	unsigned int rgid,
	unsigned int *rgidx,
	unsigned int *matched_len
	);

int
add_rt_info(
	ptree_node_t*,
	rt_info_t*,
	unsigned int
	);

pgw_t*
get_gw_by_id(
	pgw_t *gw,
	str *id
	);

pgw_t*
get_gw_by_internal_id(
	pgw_t *gw,
	unsigned int id
	);

pcr_t*
get_carrier_by_id(
	pcr_t *carrier,
	str *id
	);

void
del_rt_list(
	rt_info_wrp_t *rl
	);

void
free_rt_info(
	rt_info_t*
	);

rt_info_t*
check_rt(
	ptree_node_t *ptn,
	unsigned int rgid
	);

#endif
