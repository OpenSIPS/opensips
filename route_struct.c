/*
 * $Id$
 *
 * route structures helping functions
 */


#include  "route_struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "dprint.h"

#ifdef DEBUG_DMALLOC
#include <dmalloc.h>
#endif

struct expr* mk_exp(int op, struct expr* left, struct expr* right)
{
	struct expr * e;
	e=(struct expr*)malloc(sizeof (struct expr));
	if (e==0) goto error;
	e->type=EXP_T;
	e->op=op;
	e->l.expr=left;
	e->r.expr=right;
	return e;
error:
	LOG(L_CRIT, "ERROR: mk_exp: memory allocation failure\n");
	return 0;
}


struct expr* mk_elem(int op, int subtype, int operand, void* param)
{
	struct expr * e;
	e=(struct expr*)malloc(sizeof (struct expr));
	if (e==0) goto error;
	e->type=ELEM_T;
	e->op=op;
	e->subtype=subtype;
	e->l.operand=operand;
	e->r.param=param;
	return e;
error:
	LOG(L_CRIT, "ERROR: mk_elem: memory allocation failure\n");
	return 0;
}



struct action* mk_action(int type, int p1_type, int p2_type, void* p1, void* p2)
{
	struct action* a;
	a=(struct action*)malloc(sizeof(struct action));
	if (a==0) goto  error;
	a->type=type;
	a->p1_type=p1_type;
	a->p2_type=p2_type;
	a->p1.string=(char*) p1;
	a->p2.string=(char*) p2;
	a->next=0;
	return a;
	
error:
	LOG(L_CRIT, "ERROR: mk_action: memory allocation failure\n");
	return 0;

}


struct action* append_action(struct action* a, struct action* b)
{
	struct action *t;
	if (b==0) return a;
	if (a==0) return b;
	
	for(t=a;t->next;t=t->next);
	t->next=b;
	return a;
}



struct net* mk_net(unsigned long ip, unsigned long mask)
{
	struct net* n;

	n=(struct net*)malloc(sizeof(struct net));
	if (n==0) goto error;
	n->ip=ip;
	n->mask=mask;
	return n;
error:
	LOG(L_CRIT, "ERROR: mk_net_mask: memory allocation failure\n");
	return 0;
}

	
	

void print_ip(unsigned ip)
{
	DBG("%d.%d.%d.%d", ((unsigned char*)&ip)[0],
						  ((unsigned char*)&ip)[1],
						  ((unsigned char*)&ip)[2],
						  ((unsigned char*)&ip)[3]);
}


void print_net(struct net* net)
{
	if (net==0){
		LOG(L_WARN, "ERROR: print net: null pointer\n");
		return;
	}
	print_ip(net->ip); DBG("/"); print_ip(net->mask);
}



void print_expr(struct expr* exp)
{
	if (exp==0){
		LOG(L_CRIT, "ERROR: print_expr: null expression!\n");
		return;
	}
	if (exp->type==ELEM_T){
		switch(exp->l.operand){
			case METHOD_O:
				DBG("method");
				break;
			case URI_O:
				DBG("uri");
				break;
			case SRCIP_O:
				DBG("srcip");
				break;
			case DSTIP_O:
				DBG("dstip");
				break;
			default:
				DBG("UNKNOWN");
		}
		switch(exp->op){
			case EQUAL_OP:
				DBG("==");
				break;
			case MATCH_OP:
				DBG("=~");
				break;
			default:
				DBG("<UNKNOWN>");
		}
		switch(exp->subtype){
			case NOSUBTYPE: 
					DBG("N/A");
					break;
			case STRING_ST:
					DBG("\"%s\"", (char*)exp->r.param);
					break;
			case NET_ST:
					print_net((struct net*)exp->r.param);
					break;
			case IP_ST:
					print_ip(exp->r.intval);
					break;
			default:
					DBG("type<%d>", exp->subtype);
		}
	}else if (exp->type==EXP_T){
		switch(exp->op){
			case AND_OP:
					DBG("AND( ");
					print_expr(exp->l.expr);
					DBG(", ");
					print_expr(exp->r.expr);
					DBG(" )");
					break;
			case OR_OP:
					DBG("OR( ");
					print_expr(exp->l.expr);
					DBG(", ");
					print_expr(exp->r.expr);
					DBG(" )");
					break;
			case NOT_OP:	
					DBG("NOT( ");
					print_expr(exp->l.expr);
					DBG(" )");
					break;
			default:
					DBG("UNKNOWN_EXP ");
		}
					
	}else{
		DBG("ERROR:print_expr: unknown type\n");
	}
}
					

					

void print_action(struct action* a)
{
	struct action* t;
	for(t=a; t!=0;t=t->next){
		switch(t->type){
			case FORWARD_T:
					DBG("forward(");
					break;
			case SEND_T:
					DBG("send(");
					break;
			case DROP_T:
					DBG("drop(");
					break;
			case LOG_T:
					DBG("log(");
					break;
			case ERROR_T:
					DBG("error(");
					break;
			case ROUTE_T:
					DBG("route(");
					break;
			case EXEC_T:
					DBG("exec(");
					break;
			case SET_HOST_T:
					DBG("sethost(");
					break;
			case SET_HOSTPORT_T:
					DBG("sethostport(");
					break;
			case SET_USER_T:
					DBG("setuser(");
					break;
			case SET_USERPASS_T:
					DBG("setuserpass(");
					break;
			case SET_PORT_T:
					DBG("setport(");
					break;
			case SET_URI_T:
					DBG("seturi(");
					break;
			default:
					DBG("UNKNOWN(");
		}
		switch(t->p1_type){
			case STRING_ST:
					DBG("\"%s\"", t->p1.string);
					break;
			case NUMBER_ST:
					DBG("%d",t->p1.number);
					break;
			case IP_ST:
					print_ip(t->p1.number);
					break;
			default:
					DBG("type<%d>", t->p1_type);
		}
		switch(t->p2_type){
			case NOSUBTYPE:
					break;
			case STRING_ST:
					DBG(", \"%s\"", t->p2.string);
					break;
			case NUMBER_ST:
					DBG(", %d",t->p2.number);
					break;
			default:
					DBG(", type<%d>", t->p2_type);
		}
		DBG("); ");
	}
}
			
	

	
	

