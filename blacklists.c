/*
 * Copyright (C) 2007 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*!
 * \file
 * \brief OpenSIPS Blacklist functions
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <time.h>
#include <unistd.h>

#include "mem/mem.h"
#include "mem/shm_mem.h"
#include "mi/mi.h"
#include "dprint.h"
#include "blacklists.h"
#include "context.h"
#include "timer.h"
#include "ut.h"

static struct bl_head *blst_heads;
static unsigned int bl_default_marker;

static unsigned int max_heads = 8 * sizeof(int);
static unsigned int used_heads;

static int bl_ctx_idx = -1;

static void delete_expired_routine(unsigned int ticks, void *param);
static mi_response_t *mi_print_blacklists(const mi_params_t *params,
											struct mi_handler *async_hdl);


static mi_export_t mi_bl_cmds[] = {
	{ "list_blacklists", "lists all the defined (static or learned) blacklists", 0, 0, {
		{mi_print_blacklists, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
};

int init_black_lists(void)
{
	bl_ctx_idx = context_register_int(CONTEXT_GLOBAL, NULL);
	if (bl_ctx_idx < 0)
		return -1;

	/* register timer routine  */
	if (register_timer("blcore-expire", delete_expired_routine, 0, 1,
	    TIMER_FLAG_SKIP_ON_DELAY) < 0) {
		LM_ERR("failed to register timer\n");
		return -1;
	}

	/* register MI commands */
	if (register_mi_mod("blacklists", mi_bl_cmds) < 0) {
		LM_ERR("unable to register MI cmds\n");
		return -1;
	}

	return 0;
}

/*
 * get_bl_marker() and store_bl_marker():
 *    easy manipulation of the blacklist bitmask stored in global context
 */
static int get_bl_marker(unsigned int *marker)
{
	if (!current_processing_ctx)
		return -1;

	if (marker)
		*marker = (unsigned int)context_get_int(
		                   CONTEXT_GLOBAL, current_processing_ctx, bl_ctx_idx);

	return 0;
}

#define store_bl_marker(value) \
	(context_put_int( \
		CONTEXT_GLOBAL, current_processing_ctx, bl_ctx_idx, value))

struct bl_head *create_bl_head(int owner, int flags, struct bl_rule *head,
											struct bl_rule *tail, str *name)
{
	unsigned int i;

	if (!blst_heads) {
		blst_heads = shm_malloc(max_heads * sizeof *blst_heads);
		if (!blst_heads) {
			LM_ERR("no more shared memory!\n");
			return NULL;
		}
		memset(blst_heads, 0, max_heads * sizeof *blst_heads);
	}
	i = used_heads;
	if (i == max_heads) {
		LM_ERR("too many lists\n");
		return NULL;
	}

	if (get_bl_head_by_name(name)) {
		LM_CRIT("duplicated name!\n");
		return NULL;
	}

	if (flags & BL_READONLY_LIST && flags & BL_DO_EXPIRE) {
		LM_CRIT("RO lists cannot accept EXPIRES!\n");
		return NULL;
	}

	/* copy list name */
	blst_heads[i].name.s = shm_malloc(name->len + 1);
	if (!blst_heads[i].name.s) {
		LM_ERR("no more shm memory!\n");
		return NULL;
	}
	memcpy(blst_heads[i].name.s, name->s, name->len);
	blst_heads[i].name.s[name->len] = '\0';
	blst_heads[i].name.len = name->len;

	/* build lock? */
	if (!(flags & BL_READONLY_LIST)) {
		if (!(blst_heads[i].lock = lock_alloc())) {
			LM_ERR("failed to create lock!\n");
			shm_free(blst_heads[i].name.s);
			return NULL;
		}
		if (!lock_init(blst_heads[i].lock)) {
			LM_ERR("failed to init lock!\n");
			shm_free(blst_heads[i].name.s);
			lock_dealloc(blst_heads[i].lock);
			return NULL;
		}
	}

	used_heads++;

	blst_heads[i].owner = owner;
	blst_heads[i].flags = flags;
	blst_heads[i].first = head;
	blst_heads[i].last = tail;

	if (flags & BL_BY_DEFAULT)
		bl_default_marker |= (1 << i);

	return blst_heads + i;
}



void destroy_black_lists(void)
{
	unsigned int i;
	struct bl_rule *p, *q;

	for (i = 0; i < used_heads; i++) {
		if (blst_heads[i].lock) {
			lock_destroy(blst_heads[i].lock);
			lock_dealloc(blst_heads[i].lock);
		}

		for (p = blst_heads[i].first; p; ) {
			q = p;
			p = p->next;
			shm_free(q);
		}

		if (blst_heads[i].name.s)
			shm_free(blst_heads[i].name.s);

		blst_heads[i].first = blst_heads[i].last = NULL;
	}

	if (blst_heads)
		shm_free(blst_heads);
}



static inline void delete_expired(struct bl_head *elem, unsigned int ticks)
{
	struct bl_rule *p, *q;

	p = q = 0;

	/* get list for write */
	lock_get(elem->lock);
	while (elem->count_write){
		lock_release(elem->lock);
		sleep_us(5);
		lock_get(elem->lock);
	}
	elem->count_write = 1;

	while (elem->count_read){
		lock_release(elem->lock);
		sleep_us(5);
		lock_get(elem->lock);
	}
	lock_release(elem->lock);

	if (!elem->first)
		goto done;

	for (q = 0, p = elem->first; p; q = p, p = p->next)
		if (p->expire_end > ticks)
			break;

	if (!q)
		goto done; /* nothing to remove */

	if (!p) {
		/* remove everything */
		q = elem->first;
		elem->first = elem->last = NULL;
	} else {
		/* remove up to p */
		q->next = NULL;
		q = elem->first;
		elem->first = p;
	}

done:
	elem->count_write = 0;

	for (; q; ) {
		p = q;
		q = q->next;
		shm_free(p);
	}
}



static void delete_expired_routine(unsigned int ticks, void *param)
{
	unsigned int i;

	for (i = 0 ; i < used_heads ; i++)
		if (blst_heads[i].flags&BL_DO_EXPIRE && blst_heads[i].first)
				delete_expired(blst_heads + i, ticks);
}



static inline int ip_class_compare(struct net *net1, struct net *net2)
{
	unsigned int r;

	if (net1->ip.af == net2->ip.af){
		/* ipv4 & ipv6 addresses are all multiples of 4 */
		for(r=0; r<net1->ip.len/4; r++)
			if ((net1->ip.u.addr32[r]&net1->mask.u.addr32[r])!=
			     (net2->ip.u.addr32[r]&net2->mask.u.addr32[r]))
				return 0;
		return 1;
	}

	return -1;
}


/*! \brief adds a new rule to a list of rules */
int add_rule_to_list(struct bl_rule **first, struct bl_rule **last,
			struct net *ip_net, str *body, unsigned short port,
			unsigned short proto, int flags)
{
	struct bl_rule *p;
	struct bl_rule *q;

	if (!first || !last || !ip_net){
		LM_ERR("wrong input parameter format\n");
		return -1;
	}

	if (body && body->len==0)
		body = 0;

	/* is it a duplicate? */
	for (q = *first; q; q = q->next) {
		if ( (flags==q->flags) && (port==q->port) &&
			(proto==q->proto) &&
			(ip_class_compare(ip_net, &q->ip_net)==1) &&
			((body==NULL && q->body.s==NULL) || (body && q->body.s &&
				(body->len==q->body.len) &&
				!strncmp(body->s,q->body.s,body->len)) )
			) {
				return 1;
		}
	}

	/* alloc memory */
	p = shm_malloc(sizeof *p + (body?(body->len + 1):0));
	if (!p) {
		LM_ERR("no more  shm memory!\n");
		return -1;
	}

	/* fill in the structure */
	p->flags = flags;
	p->ip_net = *ip_net;
	p->proto = proto;
	p->port = port;
	if (body) {
		p->body.s = (char *)(p + 1);
		memcpy(p->body.s, body->s, body->len);
		p->body.s[body->len] = '\0';
		p->body.len = body->len;
	} else {
		p->body.s = NULL;
		p->body.len = 0;
	}
	p->next = NULL;
	p->expire_end = 0;

	/* link the structure */
	if (!*first) {
		*first = *last = p;
	} else {
		(*last)->next = p;
		*last = p;
	}

	return 0;
}



static inline void rm_dups(struct bl_head *head,
						struct bl_rule **first, struct bl_rule **last)
{
	struct bl_rule *p, *q;
	struct bl_rule *r;

	for( p=0,q=*first ; q ; ) {
		for( r=head->first; r ; r = r->next) {
			if ( (r->flags==q->flags) && (r->port==q->port) &&
			(r->proto==q->proto) &&
			(ip_class_compare(&r->ip_net, &q->ip_net)==1) &&
			((!r->body.s && !q->body.s) || ((r->body.len==q->body.len) &&
                r->body.s!=NULL && q->body.s!=NULL &&
				!strncmp(r->body.s,q->body.s,q->body.len)) )
			) {
				break;
			}
		}
		if (r) {
			/* q duplicates r -> free q */
			if (q->next==NULL) *last=p;
			if (p) {
				p->next = q->next;
				shm_free(q);
				q = p->next;
			} else {
				*first = q->next;
				shm_free(q);
				q = *first;
			}
		} else {
			p=q;
			q=q->next;
		}
	}
}



static inline int reload_permanent_list(struct bl_rule *first,
					struct bl_rule *last,
					struct bl_head *head)
{
	struct bl_rule *p, *q;

	/* get list for write */
	lock_get( head->lock);
	while(head->count_write){
		lock_release( head->lock );
		sleep_us(5);
		lock_get( head->lock );
	}
	head->count_write = 1;
	while(head->count_read){
		lock_release( head->lock );
		sleep_us(5);
		lock_get( head->lock );
	}
	lock_release( head->lock );

	for(p = head->first ; p ; ){
		q = p;
		p = p->next;
		shm_free(q);
	}

	head->first = first;
	head->last = last;

	head->count_write = 0;

	return 0;
}



/* should NOT add ANY DUPLICATES */
int add_list_to_head(struct bl_head *head,
			struct bl_rule *first, struct bl_rule *last,
			int truncate, int expire_limit)
{
	struct bl_rule *p;
	unsigned int expire_end = 0;

	if (!head || !first || !last)
		return -1;

	/* may I add to this list? */
	if (head->flags & BL_READONLY_LIST) {
		LM_CRIT("list is readonly!!!\n");
		return -1;
	}

	LM_DBG("adding to bl %.*s %p,%p\n",
		   head->name.len, head->name.s, first, last);

	/* for expiring lists, sets the timeout */
	if (head->flags & BL_DO_EXPIRE) {
		if (expire_limit==0) {
			LM_CRIT("expire is zero!!!\n");
			return -1;
		}
		expire_end = get_ticks() + expire_limit;

		for (p = first; p; p = p->next)
			p->expire_end = expire_end;
	}

	/* truncate? -> just do reload */
	if (truncate)
		return reload_permanent_list( first, last, head);

	/* get list for write */
	lock_get(head->lock);
	while (head->count_write){
		lock_release(head->lock);
		sleep_us(5);
		lock_get(head->lock);
	}
	head->count_write = 1;

	while (head->count_read){
		lock_release(head->lock);
		sleep_us(5);
		lock_get(head->lock);
	}
	lock_release(head->lock);

	rm_dups(head, &first, &last);
	if (!first)
		goto done;

	if (!head->first) {
		head->last  = last;
		head->first = first;
	} else if (!(head->flags & BL_DO_EXPIRE)) {
		head->last->next = first;
		head->last = last;
	} else if (head->first->expire_end >= expire_end) {
		last->next = head->first;
		head->first = first;
	} else if (head->last->expire_end <= expire_end) {
		head->last->next = first;
		head->last = last;
	} else {
		for (p = head->first; ; p = p->next)
			if (p->next->expire_end >= expire_end)
				break;
		last->next = p->next;
		p->next = first;
	}

done:
	head->count_write = 0;

	return 0;
}



struct bl_head *get_bl_head_by_name(str *name)
{
	unsigned int i;

	for (i = 0; i < used_heads; i++)
		if ((name->len == blst_heads[i].name.len) &&
		    !strncmp(name->s, blst_heads[i].name.s, name->len))
			return blst_heads + i;

	return NULL;
}



int mark_for_search(struct bl_head *list, unsigned int set)
{
	unsigned int n;
	unsigned int bl_marker;

	if (get_bl_marker(&bl_marker) != 0)
		return 1;

	/* is it an "all" operation? */
	if (!list) {
		store_bl_marker(set ? (unsigned int)-1 : 0);
		return 0;
	}

	n = list - blst_heads;
	if (list < blst_heads || n >= used_heads)
		return 1;

	if (set)
		store_bl_marker(bl_marker | (1 << n));
	else
		store_bl_marker(bl_marker & ~(1 << n));

	return 0;
}



/*
 * If possible, reset the bitmask stored in the current global context
 */
void reset_bl_markers(void)
{
	if (get_bl_marker(NULL) == 0)
		store_bl_marker(bl_default_marker);
}



static inline int check_against_rule_list(struct ip_addr *ip, str *text,
					  unsigned short port,
					  unsigned short proto,
					  int i)
{
	struct bl_rule *p;
	int t_val;
	int ret = 0;

	LM_DBG("using list %.*s \n",
		blst_heads[i].name.len, blst_heads[i].name.s);

	if( !(blst_heads[i].flags&BL_READONLY_LIST) ) {
		/* get list for read */
		lock_get( blst_heads[i].lock );
		while(blst_heads[i].count_write) {
			lock_release( blst_heads[i].lock );
			sleep_us(5);
			lock_get( blst_heads[i].lock );
		}
		blst_heads[i].count_read++;
		lock_release(blst_heads[i].lock);
	}

	for(p = blst_heads[i].first ; p ; p = p->next) {
		t_val = (p->port==0 || p->port==port) &&
			(p->proto==PROTO_NONE || p->proto==proto) &&
			(matchnet(ip, &(p->ip_net)) == 1) &&
			(p->body.s==NULL || !fnmatch(p->body.s, text->s, 0));
		if(!!(p->flags & BLR_APPLY_CONTRARY) ^ !!(t_val)){
			ret = 1;
			LM_DBG("matched list %.*s \n",
				blst_heads[i].name.len,blst_heads[i].name.s);
			break;
		}
	}

	if( !(blst_heads[i].flags&BL_READONLY_LIST) ) {
		lock_get( blst_heads[i].lock );
		blst_heads[i].count_read--;
		lock_release(blst_heads[i].lock);
	}
	return ret;
}



int check_against_blacklist(struct ip_addr *ip, str *text,
			unsigned short port, unsigned short proto)
{
	unsigned int i;
	unsigned int bl_marker;

	/* no context -> no blacklists at all -> successful check */
	if (get_bl_marker(&bl_marker) != 0)
		return 0;

	for (i = 0; i < used_heads; i++)
		if (bl_marker & (1 << i) &&
		    check_against_rule_list(ip, text, port, proto, i))
			return 1;

	return 0;
}



static mi_response_t *mi_print_blacklists(const mi_params_t *params,
											struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *lists_arr, *list_item, *rules_arr, *rule_item;
	unsigned int i;
	struct bl_rule *blr;
	char *p;
	int len;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	lists_arr = add_mi_array(resp_obj, MI_SSTR("Lists"));
	if (!lists_arr) {
		free_mi_response(resp);
		return 0;
	}

	for ( i=0 ; i<used_heads ; i++ ) {

		if( !(blst_heads[i].flags&BL_READONLY_LIST) ) {
			/* get list for read */
				lock_get( blst_heads[i].lock );
			while(blst_heads[i].count_write) {
				lock_release( blst_heads[i].lock );
				sleep_us(5);
				lock_get( blst_heads[i].lock );
			}
			blst_heads[i].count_read++;
			lock_release(blst_heads[i].lock);
		}

		list_item = add_mi_object(lists_arr, NULL, 0);
		if (!list_item)
			goto error;

		if (add_mi_string(list_item, MI_SSTR("name"),
			blst_heads[i].name.s, blst_heads[i].name.len) < 0)
			goto error;

		if (add_mi_number(list_item, MI_SSTR("owner"), blst_heads[i].owner) < 0)
			goto error;
		if (add_mi_number(list_item, MI_SSTR("flags"), blst_heads[i].flags) < 0)
			goto error;

		rules_arr = add_mi_array(list_item, MI_SSTR("Rules"));
		if (!rules_arr)
			goto error;

		for( blr = blst_heads[i].first ; blr ; blr = blr->next) {
			rule_item = add_mi_object(rules_arr, NULL, 0);
			if (!rule_item)
				goto error;

			if (add_mi_number(rule_item, MI_SSTR("flags"), blr->flags) < 0)
				goto error;

			p = ip_addr2a(&blr->ip_net.ip);
			len = p?strlen(p):0;
			if (add_mi_string(rule_item, MI_SSTR("IP"), p, len) < 0)
				goto error;

			p = ip_addr2a(&blr->ip_net.mask);
			len = p?strlen(p):0;
			if (add_mi_string(rule_item, MI_SSTR("Mask"), p, len) < 0)
				goto error;

			if (add_mi_number(rule_item, MI_SSTR("Proto"), blr->proto) < 0)
				goto error;

			if (add_mi_number(rule_item, MI_SSTR("Port"), blr->port) < 0)
				goto error;

			if (blr->body.s) {
				if (add_mi_string(rule_item, MI_SSTR("Match"),
					blr->body.s, blr->body.len) < 0)
					goto error;

			}

			if (blst_heads[i].flags&BL_DO_EXPIRE) {
				if (add_mi_number(rule_item, MI_SSTR("Expire"), blr->expire_end) < 0)
					goto error;
			}
		}

		if( !(blst_heads[i].flags&BL_READONLY_LIST) ) {
			lock_get( blst_heads[i].lock );
			blst_heads[i].count_read--;
			lock_release(blst_heads[i].lock);
		}

	}

	return resp;

error:
	if( !(blst_heads[i].flags&BL_READONLY_LIST) ) {
		lock_get( blst_heads[i].lock );
		blst_heads[i].count_read--;
		lock_release(blst_heads[i].lock);
	}

	free_mi_response(resp);
	return 0;
}
