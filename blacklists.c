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
#include "socket_info.h"
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
static mi_response_t *mi_check_all_blacklists(const mi_params_t *params,
											struct mi_handler *async_hdl);
static mi_response_t *mi_check_blacklist(const mi_params_t *params,
											struct mi_handler *async_hdl);
static mi_response_t *mi_add_blacklist_rule(const mi_params_t *params,
											struct mi_handler *async_hdl);
static mi_response_t *mi_del_blacklist_rule(const mi_params_t *params,
											struct mi_handler *async_hdl);


static mi_export_t mi_bl_cmds[] = {
	{ "list_blacklists", "lists all the defined (static or learned) blacklists", 0, 0, {
		{mi_print_blacklists, {0}},
		{mi_print_blacklists, {"name", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "check_blacklists", "returns all the blacklists where proto:IP:port pattern pair matches", 0, 0, {
		{mi_check_all_blacklists, {"ip", 0}},
		{mi_check_all_blacklists, {"proto", "ip", 0}},
		{mi_check_all_blacklists, {"proto", "ip", "port", 0}},
		{mi_check_all_blacklists, {"proto", "ip", "port", "pattern", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "check_blacklist", "checks whether an proto:IP:port pattern matches a blacklist", 0, 0, {
		{mi_check_blacklist, {"name", "ip", 0}},
		{mi_check_blacklist, {"name", "proto", "ip", 0}},
		{mi_check_blacklist, {"name", "proto", "ip", "port", 0}},
		{mi_check_blacklist, {"name", "proto", "ip", "port", "pattern", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "add_blacklist_rule", "adds a new rule to a blacklist", 0, 0, {
		{mi_add_blacklist_rule, {"name", "rule", 0}},
		{mi_add_blacklist_rule, {"name", "rule", "expire", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "del_blacklist_rule", "removes a rule from a blacklist", 0, 0, {
		{mi_del_blacklist_rule, {"name", "rule", 0}},
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

struct bl_head *create_bl_head(const str *owner, int flags, struct bl_rule *head,
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
		if (!(blst_heads[i].lock = lock_init_rw())) {
			LM_ERR("failed to create lock!\n");
			shm_free(blst_heads[i].name.s);
			return NULL;
		}
	}

	used_heads++;

	blst_heads[i].owner = *owner;
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
	struct bl_rule *last_no_expire;

	p = q = 0;

	/* get list for write */
	lock_start_write(elem->lock);

	if (!elem->first || elem->last->expire_end == 0)
		goto done;

	for (last_no_expire = 0, p = elem->first;
			p && p->expire_end == 0;
			last_no_expire = p, p = p->next);

	/* p continues from where it as left */
	for (q = 0; p; q = p, p = p->next)
		if (p->expire_end > ticks)
			break;

	if (!q)
		goto done; /* nothing to remove */

	if (!p) {
		/* remove everything */
		if (last_no_expire) {
			q = last_no_expire->next;
			elem->last = last_no_expire;
			last_no_expire->next = NULL;
		} else {
			q = elem->first;
			elem->first = elem->last = NULL;
		}
	} else {
		/* remove up to p */
		q->next = NULL;
		if (last_no_expire) {
			q = last_no_expire->next;
			last_no_expire->next = p;
		} else {
			q = elem->first;
			elem->first = p;
		}
	}

done:
	lock_stop_write(elem->lock);

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


static int del_rule_from_list(struct bl_head *head,
			struct net *ip_net, str *body, unsigned short port,
			unsigned short proto, int flags)
{
	struct bl_rule *r, *q;
	int ret = -1;

	lock_start_write(head->lock);

	for (q = NULL, r = head->first; r; q = r, r = r->next) {
		if ( (r->flags==flags) && (r->port==port) &&
			(r->proto==proto) &&
			(ip_class_compare(&r->ip_net, ip_net)==1) &&
			((!r->body.s && !body->s) || ((r->body.len==body->len) &&
				r->body.s!=NULL && body->s!=NULL &&
				!strncmp(r->body.s,body->s,body->len)) )
		   ) {
			if (q) {
				q->next = r->next;
			} else {
				head->first = r->next;
			}
			shm_free(r);
			ret = 0;
			break;
		}
	}
	lock_stop_write(head->lock);
	return ret;
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
	lock_start_write(head->lock);

	for(p = head->first ; p ; ){
		q = p;
		p = p->next;
		shm_free(q);
	}

	head->first = first;
	head->last = last;

	lock_stop_write(head->lock);

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
		if (expire_limit!=0) {
			expire_end = get_ticks() + expire_limit;
			for (p = first; p; p = p->next)
				p->expire_end = expire_end;
		} else {
			LM_DBG("expire is zero - rule never expires\n");
		}
	}

	/* truncate? -> just do reload */
	if (truncate)
		return reload_permanent_list( first, last, head);

	/* get list for write */
	lock_start_write(head->lock);

	rm_dups(head, &first, &last);
	if (!first)
		goto done;

	/* the list is built as it follows:
	 * - rules that do not expire are always first
	 * - rules that expire are oredered based on their expiration time
	 */

	if (!head->first) {
		head->last  = last;
		head->first = first;
	} else if (!(head->flags & BL_DO_EXPIRE)) {
		head->last->next = first;
		head->last = last;
	} else if (expire_end == 0) {
		/* non-expiry rules are always first */
		last->next = head->first;
		head->first = first;
	} else {
		/* find first element with expiration */
		for (p = head->first;
			p->next && p->next->expire_end == 0;
			p = p->next);
		if (p == head->last || head->last->expire_end <= expire_end) {
			/* no expiration rules, add at last */
			head->last->next = first;
			head->last = last;
		} else {
			for (;; p = p->next)
				if (p->next->expire_end >= expire_end)
					break;
			last->next = p->next;
			p->next = first;
		}
	}

done:
	lock_stop_write(head->lock);

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

static inline int match_bl_rule(struct ip_addr *ip, str *text,
					  unsigned short port,
					  unsigned short proto,
					  struct bl_rule *p)
{
	int t_val = (p->port==0 || p->port==port) &&
		(p->proto==PROTO_NONE || p->proto==proto) &&
		(matchnet(ip, &(p->ip_net)) == 1) &&
		(p->body.s==NULL || !fnmatch(p->body.s, text->s, 0));
	return (!!(p->flags & BLR_APPLY_CONTRARY) ^ !!(t_val));
}


static inline int check_against_rule_list(struct ip_addr *ip, str *text,
					  unsigned short port,
					  unsigned short proto,
					  int i)
{
	struct bl_rule *p;
	int ret = 0;

	LM_DBG("using list %.*s \n",
		blst_heads[i].name.len, blst_heads[i].name.s);

	if( !(blst_heads[i].flags&BL_READONLY_LIST) ) {
		/* get list for read */
		lock_start_read(blst_heads[i].lock);
	}

	for(p = blst_heads[i].first ; p ; p = p->next) {
		if(match_bl_rule(ip, text, port, proto, p)) {
			ret = 1;
			LM_DBG("matched list %.*s \n",
				blst_heads[i].name.len,blst_heads[i].name.s);
			break;
		}
	}

	if( !(blst_heads[i].flags&BL_READONLY_LIST) )
		lock_stop_read(blst_heads[i].lock);

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

static int mi_print_blacklist_rule(mi_item_t *rule_item,
		struct bl_rule *blr, int expire)
{
	char *p;
	int len;

	if (add_mi_number(rule_item, MI_SSTR("flags"), blr->flags) < 0)
		return -1;

	p = ip_addr2a(&blr->ip_net.ip);
	len = p?strlen(p):0;
	if (add_mi_string(rule_item, MI_SSTR("IP"), p, len) < 0)
		return -1;

	p = ip_addr2a(&blr->ip_net.mask);
	len = p?strlen(p):0;
	if (add_mi_string(rule_item, MI_SSTR("Mask"), p, len) < 0)
		return -1;

	if (blr->proto == PROTO_NONE)
		p = "any";
	else
		p = proto2a(blr->proto);
	len = strlen(p);
	if (add_mi_string(rule_item, MI_SSTR("Proto"), p, len) < 0)
		return -1;

	if (add_mi_number(rule_item, MI_SSTR("Port"), blr->port) < 0)
		return -1;

	if (blr->body.s) {
		if (add_mi_string(rule_item, MI_SSTR("Match"),
				blr->body.s, blr->body.len) < 0)
			return -1;
	}

	if (expire && blr->expire_end && add_mi_number(rule_item,
			MI_SSTR("Expire"), (blr->expire_end - get_ticks())) < 0)
		return -1;
	return 0;
}

static int mi_print_blacklist_head(mi_item_t *list_item, struct bl_head *head)
{
	int ret = -1;
	struct bl_rule *blr;
	mi_item_t *rules_arr, *rule_item, *flags_arr;

	if (!(head->flags&BL_READONLY_LIST) )
		lock_start_read(head->lock);

	if (add_mi_string(list_item, MI_SSTR("name"),
			head->name.s, head->name.len) < 0)
		goto end;

	if (add_mi_string(list_item, MI_SSTR("owner"),
			head->owner.s, head->owner.len) < 0)
		goto end;

	flags_arr = add_mi_array(list_item, MI_SSTR("flags"));
	if (!flags_arr)
		goto end;
	if (head->flags & BL_READONLY_LIST &&
			add_mi_string(flags_arr, NULL, 0, MI_SSTR("read-only")) < 0)
		goto end;
	if (head->flags & BL_DO_EXPIRE &&
			add_mi_string(flags_arr, NULL, 0, MI_SSTR("expire")) < 0)
		goto end;
	if (head->flags & BL_BY_DEFAULT &&
			add_mi_string(flags_arr, NULL, 0, MI_SSTR("default")) < 0)
		goto end;

	rules_arr = add_mi_array(list_item, MI_SSTR("Rules"));
	if (!rules_arr)
		goto end;

	for (blr = head->first; blr; blr = blr->next) {
		rule_item = add_mi_object(rules_arr, NULL, 0);
		if (!rule_item)
			goto end;

		if (mi_print_blacklist_rule(rule_item, blr,
				head->flags&BL_DO_EXPIRE) < 0)
			goto end;
	}

	ret = 0;
end:
	if (!(head->flags&BL_READONLY_LIST) )
		lock_stop_read(head->lock);
	return ret;
}

static mi_response_t *mi_print_blacklists(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *lists_arr, *list_item;
	struct bl_head *head;
	unsigned int i;
	str name;

	switch (try_get_mi_string_param(params, "name", &name.s, &name.len)) {
		case -1:
			head = NULL;
			break;
		case 0:
			head = get_bl_head_by_name(&name);
			if (!head)
				return init_mi_error(404, MI_SSTR("Unknown name"));
			break;
		default:
			return NULL;
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (head) {
		/* already have a head, print only it */
		if(mi_print_blacklist_head(resp_obj, head) < 0)
			goto error;
		return resp;
	}

	lists_arr = add_mi_array(resp_obj, MI_SSTR("Lists"));
	if (!lists_arr)
		goto error;

	for (i=0; i<used_heads; i++ ) {
		list_item = add_mi_object(lists_arr, NULL, 0);
		if (!list_item)
			goto error;

		if (mi_print_blacklist_head(list_item, &blst_heads[i]) < 0)
			goto error;
	}

	return resp;

error:

	free_mi_response(resp);
	return NULL;
}

static struct bl_head *mi_bl_get_head(const mi_params_t *params)
{
	str name;

	if (get_mi_string_param(params, "name", &name.s, &name.len) < 0)
		return NULL;
	return get_bl_head_by_name(&name);
}

static struct ip_addr *mi_bl_get_ip(const mi_params_t *params)
{
	str ip;

	if (get_mi_string_param(params, "ip", &ip.s, &ip.len) < 0)
		return NULL;
	return str2ip(&ip);
}

static int mi_bl_get_extra(const mi_params_t *params,
		unsigned short *proto, unsigned short *port, str *text)
{
	str proto_str;
	int tmp;

	switch (try_get_mi_string_param(params, "proto", &proto_str.s, &proto_str.len)) {
		case -1:
			proto = PROTO_NONE;
			break;
		case 0:
			if (parse_proto((unsigned char *)proto_str.s,
					proto_str.len, &tmp) < 0) {
				LM_ERR("could not parse protocol %.*s\n",
						proto_str.len, proto_str.s);
				return -1;
			}
			*proto = tmp;
			break;
		default:
			return -1;
	}
	switch (try_get_mi_int_param(params, "port", &tmp)) {
		case -1:
			port = 0;
			break;
		case 0:
			*port = tmp;
			break;
		default:
			return -1;
	}
	switch (try_get_mi_string_param(params, "pattern", &text->s, &text->len)) {
		case -1:
			text->s = NULL;
			text->len = 0;
			break;
		case 0:
			break;
		default:
			return -1;
	}
	return 0;
}

static int parse_ip_net(char *in, int len, struct net *ipnet)
{
	char *p = NULL;
	str ip_s, mask_s;
	struct ip_addr ip, *mask = NULL, *ip_tmp;
	struct net *ipnet_tmp;
	int af;
	unsigned int bitlen;

	p = q_memchr(in, '.', len);
	if (p)
		af = AF_INET;
	else if (q_memchr(in, ':', len)) {
		af = AF_INET6;
	} else {
		LM_ERR("Not an IP");
		return -1;
	}

	p = q_memchr(in, '/', len);
	if (p) {
		ip_s.s = in;
		ip_s.len = p - in;
	} else {
		ip_s.s = in;
		ip_s.len = len;
	}

	ip_tmp = (af == AF_INET) ? str2ip(&ip_s) : str2ip6(&ip_s);
	/* save the IP */
	ip = *ip_tmp;

	if (p) {
		mask_s.s = p + 1;
		mask_s.len = len - ip_s.len - 1;
		if (!mask_s.s || mask_s.len == 0) {
			LM_ERR("Empty netmask\n");
			return -1;
		}
		if ((p = (af == AF_INET)?
			q_memchr(p, '.', len-(p-in)+1):
			q_memchr(p, ':', len-(p-in)+1)) != NULL) {
			/* has net */
			mask = (af == AF_INET) ? str2ip(&mask_s) : str2ip6(&mask_s);
			if (!mask) {
				LM_ERR("Invalid netmask\n");
				return -1;
			}
			ipnet_tmp = mk_net(&ip, mask);
		} else {
			if (str2int(&mask_s, &bitlen) < 0) {
				LM_ERR("Invalid netmask bitlen\n");
				return -1;
			}

			ipnet_tmp = mk_net_bitlen(&ip, bitlen);
		}
	} else {
		ipnet_tmp = mk_net_bitlen(&ip, ip.len*8);
	}

	*ipnet = *ipnet_tmp;
	pkg_free(ipnet_tmp);

	return 0;
}

static int mi_bl_get_rule(const mi_params_t *params,
		struct net *ip_net, unsigned short *proto,
		unsigned short *port, str *text, int *flags)
{
	str rule, token;
	char *p;
	int tmp;

	*proto = PROTO_NONE;
	*port = 0;
	text->s = NULL;
	text->len = 0;
	*flags = 0;

	if (get_mi_string_param(params, "rule", &rule.s, &rule.len) < 0) {
		LM_INFO("command does not contain a rule\n");
		return -1;
	}
	trim_leading(&rule);
	if (rule.len > 0 && rule.s[0] == '!') {
		rule.s++;
		rule.len--;
		*flags = BLR_APPLY_CONTRARY;
	}
	/* first token should always be ip or net*/
	p = q_memchr(rule.s, ',', rule.len);
	token.s = rule.s;
	token.len = (p? (p - rule.s): rule.len);
	rule.s += token.len + 1;
	rule.len -= token.len + 1;
	if (str_casematch_nt(&token, "any")) {
		*proto = PROTO_NONE;
	} else if (parse_proto((unsigned char *)token.s, token.len, &tmp) >= 0) {
		/* valid proto */
		*proto = tmp;

		/* advance to next token */
		p = q_memchr(rule.s, ',', rule.len);
		token.s = rule.s;
		token.len = (p? (p - rule.s): rule.len);
		rule.s += token.len + 1;
		rule.len -= token.len + 1;
	}
	if (parse_ip_net(token.s, token.len, ip_net) < 0)
		return -1;
	if (rule.len <= 0)
		return 0;

	p = q_memchr(rule.s, ',', rule.len);
	token.s = rule.s;
	token.len = (p? (p - rule.s): rule.len);


	/* we should have a port here */
	if (str2int(&token, (unsigned int *)&tmp) < 0) {
		LM_INFO("invalid port %.*s\n", token.len, token.s);
		return -1;
	}
	*port = tmp;
	text->s = rule.s + token.len + 1;
	text->len = rule.len - token.len - 1;
	if (text->len <= 0) {
		text->s = NULL;
		text->len = 0;
	}


	return 0;
}


static mi_response_t *mi_check_all_blacklists(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_arr;
	unsigned short proto, port;
	struct ip_addr *ip;
	str text, text_nt;
	unsigned int i;

	ip = mi_bl_get_ip(params);
	if (!ip)
		return init_mi_error(400, MI_SSTR("Missing or bad IP"));

	if (mi_bl_get_extra(params, &proto, &port, &text) < 0)
		return init_mi_error(404, MI_SSTR("Bad params"));

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return NULL;

	/* if there is a text, duplicate it to obtain NULL-terminated */
	if (text.len) {
		if (pkg_nt_str_dup(&text_nt, &text) < 0) {
			free_mi_response(resp);
			return NULL;
		}
	} else {
		text_nt.s = "";
		text_nt.len = 0;
	}

	for (i = 0; i < used_heads; i++) {
		if (!check_against_rule_list(ip, &text_nt, port, proto, i))
			continue;
		if (add_mi_string(resp_arr, NULL, 0, blst_heads[i].name.s,
				blst_heads[i].name.len) < 0) {
			LM_ERR("cannot add blacklist %.*s\n",
					blst_heads[i].name.len, blst_heads[i].name.s);
			free_mi_response(resp);
			resp = NULL;
			goto end;
		}
	}

end:
	if (text.len)
		pkg_free(text_nt.s);
	return resp;
}

static mi_response_t *mi_check_blacklist(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	static mi_response_t *resp;
	unsigned short proto, port;
	mi_item_t *obj;
	struct bl_head *head;
	struct bl_rule *p;
	struct ip_addr *ip;
	str text, text_nt;

	ip = mi_bl_get_ip(params);
	if (!ip)
		return init_mi_error(400, MI_SSTR("Missing or bad IP"));

	head = mi_bl_get_head(params);
	if (!head)
		return init_mi_error(400, MI_SSTR("Missing or bad blacklist name"));

	if (mi_bl_get_extra(params, &proto, &port, &text) < 0)
		return init_mi_error(404, MI_SSTR("Bad params"));

	/* if there is a text, duplicate it to obtain NULL-terminated */
	if (text.len) {
		if (pkg_nt_str_dup(&text_nt, &text) < 0)
			return NULL;
	} else {
		text_nt.s = "";
		text_nt.len = 0;
	}

	if (!(head->flags&BL_READONLY_LIST))
		lock_start_read(head->lock);

	for(p = head->first; p; p = p->next)
		if(match_bl_rule(ip, &text_nt, port, proto, p))
			break;

	if (text.len)
		pkg_free(text_nt.s);

	if (p) {
		resp = init_mi_result_object(&obj);
		if (resp && mi_print_blacklist_rule(obj, p, head->flags&BL_DO_EXPIRE) < 0) {
			free_mi_response(resp);
			resp = NULL;
		}

	} else {
		resp = init_mi_error(404, MI_SSTR("Not Matched"));
	}
	if (!(head->flags&BL_READONLY_LIST))
		lock_stop_read(head->lock);
	return resp;
}

static mi_response_t *mi_add_blacklist_rule(const mi_params_t *params,
											struct mi_handler *async_hdl)
{
	struct bl_head *head;
	struct bl_rule *list = NULL;
	struct net ip_net;
	unsigned short proto, port;
	int expire, flags;
	str text;

	head = mi_bl_get_head(params);
	if (!head)
		return init_mi_error(400, MI_SSTR("Missing or bad blacklist name"));
	/* if a read-only list, we cannot modify */
	if (head->flags & BL_READONLY_LIST)
		return init_mi_error(403, MI_SSTR("Cannot modify read-only blacklist"));

	if (mi_bl_get_rule(params, &ip_net, &proto, &port, &text, &flags) < 0)
		return init_mi_error(404, MI_SSTR("Bad rule"));

	switch (try_get_mi_int_param(params, "expire", &expire)) {
		case -1:
			expire = 0;
			break;
		case 0:
			if (expire <= 0)
				return init_mi_error(404, MI_SSTR("Bad expire value"));
			if (!(head->flags & BL_DO_EXPIRE))
				return init_mi_error(404, MI_SSTR("Blacklist without expire support"));
			break;
		default:
			return NULL;
	}
	if (add_rule_to_list(&list, &list, &ip_net, &text, port, proto, flags) != 0) {
		LM_ERR("cannot build blacklist rule!\n");
		return NULL;
	}
	if (add_list_to_head(head, list, list, 0, expire) < 0) {
		LM_ERR("cannot add blacklist rule!\n");
		return NULL;
	}
	return init_mi_result_ok();
}

static mi_response_t *mi_del_blacklist_rule(const mi_params_t *params,
											struct mi_handler *async_hdl)
{
	struct bl_head *head;
	unsigned short proto, port;
	struct net ip_net;
	str text;
	int flags;

	head = mi_bl_get_head(params);
	if (!head)
		return init_mi_error(400, MI_SSTR("Missing or bad blacklist name"));
	/* if a read-only list, we cannot modify */
	if (head->flags & BL_READONLY_LIST)
		return init_mi_error(403, MI_SSTR("Cannot modify read-only blacklist"));

	if (mi_bl_get_rule(params, &ip_net, &proto, &port, &text, &flags) < 0)
		return init_mi_error(404, MI_SSTR("Bad rule"));

	if (del_rule_from_list(head, &ip_net, &text, port, proto, flags) != 0)
		return init_mi_error(404, MI_SSTR("Rule not found"));

	return init_mi_result_ok();
}

int w_check_blacklist(struct sip_msg *msg, struct bl_head *head,
		struct ip_addr *ip, int *_port, unsigned short _proto, str *_pattern)
{
	int ret, idx;
	unsigned short port = (_port?*_port:0);

	if (head) {
		/* we need to check against a specific list */
		idx = head - blst_heads;
		ret = check_against_rule_list(ip, _pattern, port, _proto, idx);
	} else {
		/* if we do not have a head, we check against all enabled */
		ret = check_against_blacklist(ip, _pattern, port, _proto);
	}
	return ret ?1:-1;
}

int fixup_blacklist_proto(void** param)
{
	int proto = PROTO_NONE;
	str *s = (str*)*param;
	if (s && parse_proto((unsigned char *)s->s, s->len, &proto) < 0)
		return E_BAD_PROTO;

	*param = (void *)(unsigned long)proto;
	return 0;
}

int fixup_blacklist_net(void** param)
{
	str *s = (str*)*param;
	str tmp = *s;
	struct bl_net_flags *nf = pkg_malloc(sizeof *nf);
	if (!nf)
		return E_OUT_OF_MEM;
	trim(&tmp);
	if (tmp.s[0] == '!') {
		nf->flags = BLR_APPLY_CONTRARY;
		tmp.s++;
		tmp.len--;
		trim(&tmp);
	}

	if (parse_ip_net(tmp.s, tmp.len, &nf->ipnet) < 0) {
		pkg_free(nf);
		return E_BAD_ADDRESS;
	}
	*param = nf;
	return 0;
}

int fixup_blacklist_net_free(void** param)
{
	pkg_free(*param);
	return 0;
}

int w_add_blacklist_rule(struct sip_msg *msg, struct bl_head *head,
		struct bl_net_flags *nf, int *_port, unsigned short _proto,
		str *_pattern, int *_exp)
{
	struct bl_rule *list = NULL;
	unsigned short port = (_port?*_port:0);

	if (head->flags & BL_READONLY_LIST) {
		LM_ERR("cannot modify read-only blacklist!\n");
		return -1;
	}

	if (_exp && *_exp && !(head->flags & BL_DO_EXPIRE)) {
		LM_ERR("blacklist does not support expiring rules!\n");
		return -1;
	}

	if (add_rule_to_list(&list, &list, &nf->ipnet, _pattern,
			port, _proto, nf->flags) != 0) {
		LM_ERR("cannot build blacklist rule!\n");
		return -1;
	}
	if (add_list_to_head(head, list, list, 0, (_exp?*_exp:0)) < 0) {
		LM_ERR("cannot add blacklist rule!\n");
		return -1;
	}
	return 1;
}

int w_del_blacklist_rule(struct sip_msg *msg, struct bl_head *head,
		struct bl_net_flags *nf, int *_port, unsigned short _proto,
		str *_pattern)
{
	unsigned short port = (_port?*_port:0);

	if (head->flags & BL_READONLY_LIST) {
		LM_ERR("cannot modify read-only blacklist!\n");
		return -1;
	}
	if (del_rule_from_list(head, &nf->ipnet,
			_pattern, port, _proto, nf->flags) != 0)
		return -1;
	return 1;
}
