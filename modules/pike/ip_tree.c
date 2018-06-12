#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ip_tree.h"
#include "../../dprint.h"



struct ip_node  *tree_root;
unsigned int    max_hits;




struct ip_node* init_ip_tree(int maximum_hits)
{
	struct ip_node *root;

	root = (struct ip_node*)ip_malloc(sizeof(struct ip_node));
	if (!root)
		return 0;
	memset(root,0,sizeof(struct ip_node));
	max_hits = maximum_hits;
	return root;
}




struct ip_node *split_node(struct ip_node* dad, char byte)
{
	struct ip_node *new_node;
	struct ip_node *foo;

	/* creat a new node */
	new_node = (struct ip_node*)ip_malloc(sizeof(struct ip_node));
	if (!new_node)
		return 0;
	new_node->byte = byte;
	new_node->leaf_hits = 0;
	new_node->hits = (dad->hits)/2;
	new_node->children = 0;
	new_node->next = 0;
	/* link it */
	foo = dad->children;
	while(foo && foo->next)
		foo = foo->next;
	if (foo) {
		foo->next = new_node;
		new_node->prev = foo;
	} else {
		dad->children = new_node;
		new_node->prev = dad;
	}
	/* update dad */
	dad->hits /= 2;

	return new_node;
}




struct ip_node* add_node(struct ip_node *root,char *ip,int ip_len,
										struct ip_node **father,char *flag)
{
	struct ip_node *node;
	struct ip_node *kid;
	int    byte_pos;
	int    exit;

	if (!root || !ip || !ip_len)
		return 0;

	node = root;
	byte_pos = 0;
	exit = 0;

	while (byte_pos<ip_len && !exit)
	{
		kid = node->children;
		while (kid && kid->byte!=(unsigned char)ip[byte_pos]) {
				kid = kid->next;
		}
		if (kid) {
			node = kid;
			byte_pos++;
		} else {
			exit = 1;
		}
	}
	DBG("Only first %d were mached!\n",byte_pos);
	if (byte_pos==ip_len) {
		/* we found the entire address */
		if (node->leaf_hits<max_hits) node->leaf_hits++;
		if (flag) *flag = LEAF_NODE|(node->leaf_hits>=max_hits?RED_NODE:0);
		if (father) *father = 0;
		return node;
	} else {
		node->hits++;
		/* we have only a prefix of the address into the tree */
		if ( node==root || node->hits>=max_hits) {
			/* we have to split the node */
			if (flag) *flag = NEW_NODE ;
			DBG("Splitting node %p [%x]\n",node,node->byte);
			if (father) *father = node;
			return split_node(node,ip[byte_pos]);
		} else {
			/* we just had marked the node as hit */
			if (flag) *flag = 0;
			if (father) *father = 0;
			return node;
		}
	}
	return 0;
}




void del_node(struct ip_node *node)
{
	struct ip_node *foo, *bar;

	foo = node->children;
	while (foo){
		bar = foo;
		foo = foo->next;
		del_node(bar);
	}

	ip_free(node);
}




void remove_node(struct ip_node *root, struct ip_node *node)
{
	if (root==node || !node || !root)
		return;

	if (node->prev->children==node)
		/* it's the head of the list! */
		node->prev->children = node->next;
	else
		/* it's somewhere in the list */
		node->prev->next = node->next;
	if (node->next) node->next->prev = node->prev;
	node->next = node->prev = 0;

	del_node(node);
}




void destroy_ip_tree(struct ip_node *root)
{
	if (root)
		del_node(root);
}




void print_node(struct ip_node *node,int sp)
{
	struct ip_node *foo;
	int i;

	for(i=0;i<sp;i++) DBG(" ");
	DBG("node %p; byte=%x , hits=%d , leaf_hits=%d\n", node, node->byte,
		node->hits,node->leaf_hits);
	foo = node->children;
	while(foo){
		print_node(foo,sp+2);
		foo = foo->next;
	}
}


/*
int main()
{
	char ip[16],c;
	int  len,f;
	char flag;
	struct ip_node *n, *root;

	root = init_ip_tree();

	while (1) {
		len =0 ;
		f = 0;
		while (read(1,&c,1) && c!=10 && c!=13)
		{
			if (c>='0' && c<='9')
				c-='0';
			else
				c=c+10-'a';
			if (f) {
				ip[len] = ip[len]*16+c;
				len++;
			} else
				ip[len] = c;
			f = !f;
		}
		if (!len)
			break;
		DBG("Ip <%d>:%.*s\n",len,len,ip);
		n = add_node(root,(char*)&ip, len, &flag);
		DBG("result: %p ->flag = %d\n",n,flag);
	}
		print_node(root,0);

	return 1;
}*/
