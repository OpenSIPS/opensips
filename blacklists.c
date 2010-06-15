/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include "timer.h"
#include "ut.h"

static struct bl_head *blst_heads = 0;
static unsigned int bl_marker = 0;
static unsigned int bl_default_marker = 0;

static unsigned int max_heads  = 8*sizeof(bl_marker);
static unsigned int used_heads = 0;
static unsigned int no_shm = 1;


static void delete_expired_routine(unsigned int ticks, void* param);
static struct mi_root* mi_print_blacklists(struct mi_root *cmd, void *param);


static mi_export_t mi_bl_cmds[] = {
	{ "list_blacklists", mi_print_blacklists,  MI_NO_INPUT_FLAG  ,  0,  0 },
	{ 0, 0, 0, 0, 0}
};



int preinit_black_lists(void)
{
	blst_heads = (struct bl_head*)pkg_malloc(max_heads*sizeof(struct bl_head));
	if (blst_heads==NULL) {
		LM_ERR("no more pkg memory!\n");
		return -1;
	}
	memset( blst_heads, 0, max_heads*sizeof(struct bl_head));

	used_heads = 0;

	/* black lists were successfully allocated */
	return 0;
}



int init_black_lists(void)
{
	struct bl_head *old_blst_heads;
	struct bl_rule *head;
	struct bl_rule *tail;
	struct bl_rule *it, *it1;
	unsigned int old_used_heads;
	unsigned int i;

	if (!no_shm) {
		LM_CRIT("called twice\n");
		return -1;
	}
	no_shm = 0;

	old_blst_heads = blst_heads;
	blst_heads = (struct bl_head*)shm_malloc(max_heads*sizeof(struct bl_head));
	if (blst_heads==NULL) {
		LM_ERR("no more shm memory!\n");
		return -1;
	}
	memset( blst_heads, 0, max_heads * sizeof(struct bl_head));
	old_used_heads = used_heads;

	used_heads = 0;
	bl_default_marker = 0;

	/*for lists already created, init locks and move them into shm */
	for( i=0 ; i<old_used_heads ; i++ ) {

		/* duplicate in shm */
		it = old_blst_heads[i].first;
		head = tail = 0;

		for( it1=it ; it ; it=it1 ) {
			if (add_rule_to_list( &head, &tail, &it->ip_net,
			&it->body, it->port, it->proto, it->flags)!=0) {
				LM_ERR("failed to clone rule!\n");
				return -1;
			}

			it1 = it->next;
			pkg_free(it);
		}

		if (create_bl_head( old_blst_heads[i].owner, old_blst_heads[i].flags,
		head, tail, &old_blst_heads[i].name )==NULL ) {
				LM_ERR("failed to clone head!\n");
				return -1;
		}

		pkg_free(old_blst_heads[i].name.s);
	}

	pkg_free(old_blst_heads);

	/* register timer routine  */
	if (register_timer( delete_expired_routine, 0, 1)<0) {
		LM_ERR("failed to register timer\n");
		return -1;
	}

	/* register MI commands */
	if (register_mi_mod( "blacklists", mi_bl_cmds)<0) {
		LM_ERR("unable to register MI cmds\n");
		return -1;
	}

	return 0;
}



struct bl_head *create_bl_head(int owner, int flags, struct bl_rule *head,
											struct bl_rule *tail, str *name)
{
	unsigned int i;

	i = used_heads;
	if (i==max_heads) {
		LM_ERR("too many lists\n");
		return NULL;
	}

	if (get_bl_head_by_name(name)!=NULL) {
		LM_CRIT("duplicated name!\n");
		return NULL;
	}

	if ( flags&BL_READONLY_LIST && flags&BL_DO_EXPIRE){
		LM_CRIT("RO lists cannot accept EXPIRES!\n");
		return NULL;
	}

	/* copy list name */
	if (no_shm)
		blst_heads[i].name.s = (char*)pkg_malloc(name->len + 1);
	else
		blst_heads[i].name.s = (char*)shm_malloc(name->len + 1);
	if (blst_heads[i].name.s==NULL) {
		LM_ERR("no more pkg memory!\n");
		return NULL;
	}
	memcpy( blst_heads[i].name.s, name->s, name->len);
	blst_heads[i].name.s[name->len] = '\0';
	blst_heads[i].name.len = name->len;

	/* build lock? */
	if (!no_shm && !(flags&BL_READONLY_LIST)) {
		if ( (blst_heads[i].lock=lock_alloc())==NULL ) {
			LM_ERR("failed to create lock!\n");
			shm_free(blst_heads[i].name.s);
			return NULL;
		}
		if ( lock_init(blst_heads[i].lock)==NULL ) {
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

	if (flags&BL_BY_DEFAULT)
		bl_default_marker |= (1<<i);

	return blst_heads + i;
}



void destroy_black_lists(void)
{
	unsigned int i;
	struct bl_rule *p, *q;

	if (no_shm)
		return;

	for(i = 0 ; i < used_heads ; i++){

		if (blst_heads[i].lock) {
			lock_destroy(blst_heads[i].lock);
			lock_dealloc(blst_heads[i].lock);
		}

		for( p=blst_heads[i].first ; p ; ) {
			q = p;
			p = p->next;
			shm_free(q);
		}

		if (blst_heads[i].name.s)
			shm_free(blst_heads[i].name.s);

		blst_heads[i].first = blst_heads[i].last = NULL;
	}

	shm_free(blst_heads);
}



static inline void delete_expired(struct bl_head *elem, unsigned int ticks)
{
	struct bl_rule *p, *q;

	p = q = 0;

	/* get list for write */
	lock_get(elem->lock);
	while(elem->count_write){
		lock_release(elem->lock);
		sleep_us(5);
		lock_get(elem->lock);
	}
	elem->count_write = 1;
	while(elem->count_read){
		lock_release(elem->lock);
		sleep_us(5);
		lock_get(elem->lock);
	}
	lock_release(elem->lock);

	if(elem->first==NULL)
		goto done;

	for( q=0,p = elem->first ; p ; q=p,p=p->next) {
		if(p->expire_end > ticks)
			break;
	}

	if (q==NULL)
		/* nothing to remove */
		goto done;

	if (p==NULL) {
		/* remove everything */
		q = elem->first;
		elem->first = elem->last = NULL;
	} else {
		/* remove up to p */
		q->next = 0;
		q = elem->first;
		elem->first = p;
	}

done:
	elem->count_write = 0;

	for( ; q ; ){
		p = q;
		q = q->next;
		shm_free(p);
	}

	return;
}



static void delete_expired_routine(unsigned int ticks, void* param)
{
	unsigned int i;

	for(i = 0 ; i < used_heads ; i++){
		if( blst_heads[i].flags&BL_DO_EXPIRE &&  blst_heads[i].first)
				delete_expired(blst_heads + i, ticks);
		}
}



static inline int ip_class_compare(struct net *net1, struct net *net2)
{
	unsigned int r;

	if (net1->ip.af == net2->ip.af){
		for(r=0; r<net1->ip.len/4; r++){ /* ipv4 & ipv6 addresses are
										    all multiples of 4*/
			if ((net1->ip.u.addr32[r]&net1->mask.u.addr32[r])!=
			     (net2->ip.u.addr32[r]&net2->mask.u.addr32[r]) ){
				return 0;
			}
		}
		return 1;
	};
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
	for(q = *first ; q ; q = q->next) {
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
	if (no_shm)
		p = (struct bl_rule*)pkg_malloc
			(sizeof(struct bl_rule) + (body?(body->len + 1):0));
	else
		p = (struct bl_rule*)shm_malloc
			(sizeof(struct bl_rule) + (body?(body->len + 1):0));
	if(!p){
		LM_ERR("no more %s memory!\n", no_shm?"pkg":"shm");
		return -1;
	}

	/* fill in the structure */
	p->flags = flags;
	p->ip_net = *ip_net;
	p->proto = proto;
	p->port = port;
	if (body) {
		p->body.s = (char *)p + sizeof(struct bl_rule);
		memcpy(p->body.s, body->s, body->len);
		(p->body.s)[body->len] = '\0';
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
				if (no_shm) pkg_free(q);
				else shm_free(q);
				q = p->next;
			} else {
				*first = q->next;
				if (no_shm) pkg_free(q);
				else shm_free(q);
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
int add_list_to_head( struct bl_head *head,
			struct bl_rule *first, struct bl_rule *last,
			int truncate, int expire_limit)
{
	struct bl_rule *p;
	unsigned int expire_end=0;

	if (!head || !first || !last)
		return -1;

	/* may I add to this list? */
	if (head->flags&BL_READONLY_LIST) {
		LM_CRIT("list is readonly!!!\n");
		return -1;
	}

	LM_DBG("adding to bl %.*s %p,%p\n",
		head->name.len, head->name.s, first,last);

	/* for expiring lists, sets the timeout */
	if (head->flags&BL_DO_EXPIRE) {
		if (expire_limit==0) {
			LM_CRIT("expire is zero!!!\n");
			return -1;
		}
		expire_end = get_ticks() + expire_limit;

		for(p = first ; p ; p = p->next)
			p->expire_end = expire_end;
	}

	/* truncate? -> just do reload */
	if (truncate)
		return reload_permanent_list( first, last, head);

	/* get list for write */
	lock_get(head->lock);
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

	rm_dups( head, &first, &last);
	if (first==NULL)
		goto done;

	if (head->first==NULL) {
		head->last  = last;
		head->first = first;
	} else
	if ( !(head->flags&BL_DO_EXPIRE) ) {
		head->last->next = first;
		head->last = last;
	} else
	if( head->first->expire_end >= expire_end){
		last->next = head->first;
		head->first = first;
	} else
	if(head->last->expire_end <= expire_end){
		head->last->next = first;
		head->last = last;
	} else {
		for(p = head->first ; ; p = p->next)
			if( p->next->expire_end >= expire_end)
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

	for(i = 0 ; i < used_heads ; i++){
		if ((name->len == blst_heads[i].name.len) &&
		!strncmp(name->s, blst_heads[i].name.s, name->len))
			return (blst_heads + i);
	}

	return NULL;
}



int mark_for_search(struct bl_head *list, int unsigned set)
{
	unsigned int n;

	/* is it an "all" operation ? */
	if (list==0) {
		bl_marker = set ? (unsigned int)-1 : 0 ;
		return 1;
	}

	if( list<blst_heads || (n=(list - blst_heads)) >= used_heads )
		return 0;

	if (set)
		bl_marker |= (1<<n);
	else
		bl_marker &= ~(1<<n);

	return 1;
}



void reset_bl_markers(void)
{
	bl_marker = bl_default_marker;
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

	if( !blst_heads[i].flags&BL_READONLY_LIST ) {
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

	if( !blst_heads[i].flags&BL_READONLY_LIST ) {
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

	for(i = 0 ; i < used_heads ; i++)
		if( (bl_marker&(1<<i)) &&
		check_against_rule_list(ip, text, port, proto, i))
			return 1;
	return 0;
}



static struct mi_root* mi_print_blacklists(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl;
	struct mi_node *node;
	struct mi_node *node1;
	struct mi_node *node2;
	struct mi_attr *attr;
	unsigned int i;
	struct bl_rule *blr;
	char *p;
	int len;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL)
		return 0;
	rpl = &rpl_tree->node;

	for ( i=0 ; i<used_heads ; i++ ) {

		if( !blst_heads[i].flags&BL_READONLY_LIST ) {
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

		/* add a list node */
		node = add_mi_node_child( rpl, 0, "List", 4,
					blst_heads[i].name.s, blst_heads[i].name.len );
		if (node==0)
			goto error;

		/* add some attributes to the list node */
		p= int2str((unsigned long)blst_heads[i].owner, &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "owner", 5, p, len);
		if (attr==0)
			goto error;
		p= int2str((unsigned long)blst_heads[i].flags, &len);
		attr = add_mi_attr( node, MI_DUP_VALUE, "flags", 5, p, len);
		if (attr==0)
			goto error;

		for( blr = blst_heads[i].first ; blr ; blr = blr->next) {
			/* add a rule node */
			node1 = add_mi_node_child( node, 0, "Rule", 4, 0, 0 );
			if (node1==0)
				goto error;
			/* add attributes to the rule node */
			p= int2str((unsigned long)blr->flags, &len);
			attr = add_mi_attr( node1, MI_DUP_VALUE, "flags", 5, p, len);
			if (attr==0)
				goto error;

			/* add to rule node */
			p = ip_addr2a(&blr->ip_net.ip);
			len = p?strlen(p):0;
			node2 = add_mi_node_child( node1, MI_DUP_VALUE, "IP", 2, p, len);
			if (node2==0)
				goto error;

			p = ip_addr2a(&blr->ip_net.mask);
			len = p?strlen(p):0;
			node2 = add_mi_node_child( node1, MI_DUP_VALUE, "Mask", 4, p, len);
			if (node2==0)
				goto error;

			p= int2str((unsigned long)blr->proto, &len);
			node2 = add_mi_node_child( node1, MI_DUP_VALUE, "Proto", 5, p,len);
			if (node2==0)
				goto error;

			p= int2str((unsigned long)blr->port, &len);
			node2 = add_mi_node_child( node1, MI_DUP_VALUE, "Port", 4, p,len);
			if (node2==0)
				goto error;

			if (blr->body.s) {
				node2 = add_mi_node_child( node1, MI_DUP_VALUE, "Match", 5,
					blr->body.s, blr->body.len);
				if (node2==0)
					goto error;
			}

			if (blst_heads[i].flags&BL_DO_EXPIRE) {
				p= int2str((unsigned long)blr->expire_end, &len);
				node2 = add_mi_node_child( node1, MI_DUP_VALUE, "Expire", 6,
					p, len);
				if (node2==0)
					goto error;
			}

		}

		if( !blst_heads[i].flags&BL_READONLY_LIST ) {
			lock_get( blst_heads[i].lock );
			blst_heads[i].count_read--;
			lock_release(blst_heads[i].lock);
		}

	}

	return rpl_tree;
error:
	if( !blst_heads[i].flags&BL_READONLY_LIST ) {
		lock_get( blst_heads[i].lock );
		blst_heads[i].count_read--;
		lock_release(blst_heads[i].lock);
	}
	free_mi_tree(rpl_tree);
	return 0;
}


