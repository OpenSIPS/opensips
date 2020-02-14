/*
 * Copyright (C) 2005-2008 Voice Sistem SRL
 * Copyright (C) 2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */



#ifndef prefix_tree_h
#define prefix_tree_h

#include "../../str.h"
#include "../../ip_addr.h"
#include "../../time_rec.h"
#include "../../map.h"
#include "../../mem/mem_funcs.h"

#include "dr_cb_sorting.h"

#define IS_DECIMAL_DIGIT(d) \
	(((d)>='0') && ((d)<= '9'))

extern int ptree_children;
extern int tree_size;
struct head_db;

#define INIT_PTREE_NODE(f, p, n) \
do {\
	(n) = (ptree_t*)func_malloc(f, sizeof(ptree_t) +\
		ptree_children*sizeof(ptree_node_t));\
	if(NULL == (n))\
		goto err_exit;\
	tree_size+=sizeof(ptree_t);\
	memset((n), 0, sizeof(ptree_t)+ptree_children*sizeof(ptree_node_t));\
	(n)->bp=(p);\
	(n)->ptnode=(ptree_node_t*)((n)+1);\
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
	/* address and port */
	struct ip_addr ips[DR_MAX_IPS];
	unsigned short ports[DR_MAX_IPS];
	unsigned short protos[DR_MAX_IPS];
	unsigned short ips_no;
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

//#define DR_CR_FLAG_WEIGHT (1<<0)
#define DR_CR_FLAG_FIRST  (1<<0)
#define DR_CR_FLAG_IS_OFF (1<<1)
#define DR_CR_FLAG_DIRTY  (1<<2)
//#define DR_CR_FLAG_QR (1<<4)

/* list of carriers */
struct pcr_ {
	/* carrier ID/name from DB */
	str id;
	/* flags */
	unsigned int flags;
	/* gateway sorting algorithm */
	sort_cb_type sort_alg;
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
	char* route_idx;
	/* opaque string with rule attributes */
	str attrs;
	/* array of pointers into the PSTN gw list */
	pgw_list_t *pgwl;
	/* length of the PSTN gw array */
	unsigned short pgwa_len;
	/* how many lists link this element */
	unsigned short ref_cnt;
	/* handler used by qr for accounting (actually qr_rule_t *) */
	void *qr_handler;
	/* sorting algorithm for the destinations */
	sort_cb_type sort_alg;
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
	ptree_node_t *ptnode;
} ptree_t;



int
init_prefix_tree(
	char *extra_prefix_chars
	);

void
print_interim(
		int,
		int,
		ptree_t*
		);

int
del_tree(
	ptree_t *,
	osips_free_f
	);

int
add_prefix(
	ptree_t*,
	/* prefix */
	str*,
	rt_info_t *,
	unsigned int,
	osips_malloc_f,
	osips_free_f
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
	unsigned int,
	osips_malloc_f,
	osips_free_f
	);

pgw_t*
get_gw_by_internal_id(
	map_t gw_tree,
	unsigned int id
	);


pgw_t*
get_gw_by_id(
		map_t pgw_tree,
		str *id
		);

pcr_t*
get_carrier_by_id(
		map_t carriers_tree,
		str *id
		);



void
del_rt_list(
	rt_info_wrp_t *rl,
	osips_free_f
	);

void
free_rt_info(
	rt_info_t*,
	osips_free_f
	);

rt_info_t*
check_rt(
	ptree_node_t *ptn,
	unsigned int rgid
	);

#endif
