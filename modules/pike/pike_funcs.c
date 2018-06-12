
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../mem/shm_mem.h"
#include "../../timer.h"
#include "pike_funcs.h"




void print_timer_list(struct pike_timer_head *pth)
{
	struct pike_timer_link *tl;

	tl = pth->first;
	DBG("--->");
	while (tl) {
		DBG(" [%x][%d]",((struct ip_node*)tl)->byte, tl->timeout);
		tl = tl->next;
	}
	DBG("\n");
}



int pike_check_req(struct sip_msg *msg, char *foo, char *bar)
{
	struct ip_node *node;
	struct ip_node *father;
	char   flag;
	int    ret;

	lock( &locks[TREE_LOCK] );
	node = add_node( tree, msg->src_ip.u.addr,msg->src_ip.len,&father,&flag);

	DBG("DEBUG:pike_check_req: src IP [%.*s]; hit node = [%d][%d] flags=%d\n",
		msg->src_ip.len,msg->src_ip.u.addr,
		node->hits,node->leaf_hits,flag);

	/* do all the job with the timer */
	lock( &locks[TIMER_LOCK]);
	if ( flag&NEW_NODE ) {
		/* put this node into the timer list and remove from list its
		   father, if this is not a LEAF_NODE */
		node->tl.timeout =  get_ticks() + timeout;
		append_to_timer(timer,&(node->tl));
		if (father->leaf_hits<=0)
			remove_from_timer(timer,&(father->tl));
	} else {
		/* update the timer */
		//remove_from_timer(timer,&(node->tl));
		node->tl.timeout = get_ticks() + timeout;
		append_to_timer(timer,&(node->tl));
	}
	unlock(&locks[TIMER_LOCK]);

	/*DEBUG*/print_timer_list(timer);

	ret = ( (flag&LEAF_NODE)&&(flag&RED_NODE) )?-1:1;
	unlock( &locks[TREE_LOCK] );

	if (ret==-1)
		DBG("DEBUG:pike_check_req: ------RED ALARM<->TOO MANY HITS------!!\n");
	return ret;
}



void clean_routine(unsigned int ticks , void *param)
{
	struct pike_timer_link *tl;
	struct ip_node         *dad;
	struct ip_node         *node;

	if ( !is_empty(timer) ) {
		/* get the expired elements */
		lock( &locks[TIMER_LOCK] );
		tl = check_and_split_timer( timer, ticks);
		unlock( &locks[TIMER_LOCK] );
		/* process them */
		if (tl) {
				lock( &locks[TREE_LOCK] );
				for(;tl;tl=tl->next) {
					node = (struct ip_node*)tl;
					DBG("DEBUG:pike:clean_routine: del node [%X] \n",
						node->byte);
					/* if it's a node, leaf for an ipv4 address inside an
					   ipv6 address -> just remove it from timer*/
					if (node->children) {
						node->leaf_hits = 0;
						node->tl.timeout = 0;
						node->tl.prev = node->tl.next = 0;
					} else {
						/* we have to put the father into timer list*/
						/* get the father node */
						dad = node;
						while (dad->prev->children!=dad)
							dad=dad->prev;
						dad = dad->prev;
						/* put it in the list 
						   (only if it isnot the tree root) */
						if (dad!=tree) {
							lock(&locks[TIMER_LOCK]);
							dad->tl.timeout = get_ticks() + timeout;
							append_to_timer(timer,&(dad->tl));
							unlock(&locks[TIMER_LOCK]);
						}
						/* del the node */
						remove_node( tree, node);
					}
					/*DEBUG*/print_timer_list(timer);
				}
				unlock( &locks[TREE_LOCK] );
		}
	}
}




void refresh_node( struct ip_node *node)
{
	struct ip_node *kid;

	if (!node) return;
	kid = node->children;
	while(kid) {
		kid->hits = 0;
		kid->leaf_hits = 0;
		refresh_node( kid );
		kid = kid->next;
	}
}




void swap_routine( unsigned int ticks, void *param)
{
	lock( &locks[TREE_LOCK] );

	if (tree)
		refresh_node( tree );

	unlock( &locks[TREE_LOCK] );
}



