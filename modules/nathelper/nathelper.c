/* $Id$
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
 * 2003-10-09	nat_uac_test introduced (jiri)
 *
 * 2003-11-06   nat_uac_test permitted from onreply_route (jiri)
 *
 * 2004-01-28	nat_uac_test extended to allow testing SDP body (sobomax)
 *
 *		nat_uac_test extended to allow testing top Via (sobomax)
 *
 * 2005-02-25	Force for pinging the socket returned by USRLOC (bogdan)
 *
 *
 * 2005-07-11  SIP ping support added (bogdan)
 *
 *
 * 2006-03-08  fix_nated_sdp() may take one more param to force a specific IP;
 *             force_rtp_proxy() accepts a new flag 's' to swap creation/
 *              confirmation between requests/replies;
 *             add_rcv_param() may take as parameter a flag telling if the
 *              parameter should go to the contact URI or contact header;
 *             (bogdan)
 *             nh_enable_ping used to enable or disable natping
 * 2007-09-11 Separate timer process and support for multiple timer processes
 *             (bogdan)
 * 2010-09-23 Remove force-rtp-proxy function
 */

#include <sys/types.h>
#include <netinet/in.h>
#ifndef __USE_BSD
#define  __USE_BSD
#endif
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../forward.h"
#include "../../parser/parse_uri.h"
#include "../../parser/sdp/sdp_helpr_funcs.h"
#include "../../timer.h"
#include "../../msg_translator.h"
#include "../../socket_info.h"
#include "../../mod_fix.h"
#include "../registrar/sip_msg.h"
#include "../usrloc/usrloc.h"
#include "sip_pinger.h"
#include "../../parser/parse_content.h"


/* NAT UAC test constants */
#define	NAT_UAC_TEST_C_1918	0x01
#define	NAT_UAC_TEST_V_RCVD	0x02
#define	NAT_UAC_TEST_V_1918	0x04
#define	NAT_UAC_TEST_S_1918	0x08
#define	NAT_UAC_TEST_RPORT	0x10
#define	NAT_UAC_TEST_C_RCVD	0x20
#define	NAT_UAC_TEST_C_RPORT	0x40

#define MI_SET_NATPING_STATE		"nh_enable_ping"
#define MI_DEFAULT_NATPING_STATE	1

#define MI_PING_DISABLED			"NATping disabled from script"
#define MI_PING_DISABLED_LEN		(sizeof(MI_PING_DISABLED)-1)



static int nat_uac_test_f(struct sip_msg* msg, char* str1, char* str2);
static int fix_nated_contact_f(struct sip_msg *, char *, char *);
static int fix_nated_sdp_f(struct sip_msg *, char *, char *);
static int fix_nated_register_f(struct sip_msg *, char *, char *);
static int fixup_fix_nated_register(void** param, int param_no);
static int fixup_fix_sdp(void** param, int param_no);
static int add_rcv_param_f(struct sip_msg *, char *, char *);

static void nh_timer(unsigned int, void *);
static int mod_init(void);
static void mod_destroy(void);

/*mi commands*/
static struct mi_root* mi_enable_natping(struct mi_root* cmd_tree,
		void* param );
static usrloc_api_t ul;
static int cblen = 0;
static str nortpproxy_str = str_init("a=nortpproxy:yes");
static int natping_interval = 0;
struct socket_info* force_socket = 0;

static struct {
	const char *cnetaddr;
	uint32_t netaddr;
	uint32_t mask;
} nets_1918[] = {
	{"10.0.0.0",    0, 0xffffffffu << 24},	/* RFC 1918 */
	{"172.16.0.0",  0, 0xffffffffu << 20},  /* RFC 1918 */
	{"192.168.0.0", 0, 0xffffffffu << 16},  /* RFC 1918 */
	{"100.64.0.0",  0, 0xffffffffu << 22},	/* RFC 6598 */
	{NULL, 0, 0}
};
/*
 * Extract URI from the Contact header field - iterates through all contacts
 */
int
get_contact_uri(struct sip_msg* _m, struct sip_uri *uri, contact_t** _c,
													struct hdr_field **_hdr)
{
	if (*_hdr==NULL) {
		if ((parse_headers(_m, HDR_EOH_F, 0) == -1) || !_m->contact)
			return -1;
		if (!_m->contact->parsed && parse_contact(_m->contact) < 0) {
			LM_ERR("failed to parse Contact body\n");
			return -1;
		}
		*_hdr = _m->contact;
		*_c = ((contact_body_t*)_m->contact->parsed)->contacts;
	} else {
		*_c = (*_c)->next;
	}

	while (*_c==NULL) {
		*_hdr = (*_hdr)->sibling;
		if (*_hdr==NULL)
			/* no more contact headers */
			return -1;
		if (!(*_hdr)->parsed && parse_contact(*_hdr) < 0) {
			LM_ERR("failed to parse Contact body\n");
			return -1;
		}
		*_c = ((contact_body_t*)(*_hdr)->parsed)->contacts;
	}

	if (*_c == NULL)
		/* no more contacts found */
		return -1;

	/* contact found -> parse it */
	if (parse_uri((*_c)->uri.s, (*_c)->uri.len, uri)<0 || uri->host.len<=0) {
		LM_ERR("failed to parse Contact URI\n");
		return -1;
	}

	return 0;
}

/*
 * If this parameter is set then the natpinger will ping only contacts
 * that have the NAT flag set in user location database
 */
static int ping_nated_only = 0;
static const char sbuf[4] = {0, 0, 0, 0};
static char *force_socket_str = 0;
static int sipping_flag = -1;
static char *sipping_flag_str = 0;
static int natping_tcp = 0;
static int natping_processes = 1;

static char* rcv_avp_param = NULL;
static unsigned short rcv_avp_type = 0;
static int rcv_avp_name = -1;

static char *natping_socket = 0;
static int raw_sock = -1;
static unsigned int raw_ip = 0;
static unsigned short raw_port = 0;

/*0-> disabled, 1 ->enabled*/
unsigned int *natping_state=0;


static cmd_export_t cmds[] = {
	{"fix_nated_contact",  (cmd_function)fix_nated_contact_f,    0,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"fix_nated_contact",  (cmd_function)fix_nated_contact_f,    1,
		fixup_str_null, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"fix_nated_sdp",      (cmd_function)fix_nated_sdp_f,        1,
		fixup_fix_sdp,  0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"fix_nated_sdp",      (cmd_function)fix_nated_sdp_f,        2,
		fixup_fix_sdp, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"nat_uac_test",       (cmd_function)nat_uac_test_f,         1,
		fixup_uint_null, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"fix_nated_register", (cmd_function)fix_nated_register_f,   0,
		fixup_fix_nated_register, 0,
		REQUEST_ROUTE },
	{"add_rcv_param",      (cmd_function)add_rcv_param_f,        0,
		0, 0,
		REQUEST_ROUTE },
	{"add_rcv_param",      (cmd_function)add_rcv_param_f,        1,
		fixup_uint_null, 0,
		REQUEST_ROUTE },
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[] = {
	{"natping_interval",      INT_PARAM, &natping_interval      },
	{"ping_nated_only",       INT_PARAM, &ping_nated_only       },
	{"nortpproxy_str",        STR_PARAM, &nortpproxy_str.s      },
	{"received_avp",          STR_PARAM, &rcv_avp_param         },
	{"force_socket",          STR_PARAM, &force_socket_str      },
	{"sipping_from",          STR_PARAM, &sipping_from.s        },
	{"sipping_method",        STR_PARAM, &sipping_method.s      },
	{"sipping_bflag",         STR_PARAM, &sipping_flag_str      },
	{"sipping_bflag",         INT_PARAM, &sipping_flag          },
	{"natping_tcp",           INT_PARAM, &natping_tcp           },
	{"natping_processes",     INT_PARAM, &natping_processes     },
	{"natping_socket",        STR_PARAM, &natping_socket        },
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{MI_SET_NATPING_STATE, 0, mi_enable_natping,    0,                0, 0},
	{ 0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
	"nathelper",
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,
	params,
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	0,           /* exported pseudo-variables */
	0,           /* extra processes */
	mod_init,
	0,           /* reply processing */
	mod_destroy, /* destroy function */
	0
};


static int
fixup_fix_sdp(void** param, int param_no)
{
	pv_elem_t *model;
	str s;

	if (param_no==1) {
		/* flags */
		return fixup_uint_null( param, param_no);
	}
	/* new IP */
	model=NULL;
	s.s = (char*)(*param); s.len = strlen(s.s);
	if(pv_parse_format(&s,&model)<0) {
		LM_ERR("wrong format[%s]!\n", (char*)(*param));
		return E_UNSPEC;
	}
	if (model==NULL) {
		LM_ERR("empty parameter!\n");
		return E_UNSPEC;
	}
	*param = (void*)model;
	return 0;
}

static int fixup_fix_nated_register(void** param, int param_no)
{
	if (rcv_avp_name < 0) {
		LM_ERR("you must set 'received_avp' parameter. Must be same value as"
				" parameter 'received_avp' of registrar module\n");
		return -1;
	}
	return 0;
}




static struct mi_root* mi_enable_natping(struct mi_root* cmd_tree,
											void* param )
{
	unsigned int value;
	struct mi_node* node;
	struct mi_root* root;
	char *s;
	int len;

	if (natping_state==NULL)
		return init_mi_tree( 400, MI_PING_DISABLED, MI_PING_DISABLED_LEN);

	node = cmd_tree->node.kids;
	if(node == NULL) {
		root = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (root==NULL)
			return NULL;
		node = &root->node;
		s =  int2str(*natping_state, &len);
		if (!add_mi_node_child(node, MI_DUP_VALUE, MI_SSTR("Status"), s, len)){
				LM_ERR("cannot add the child node to the tree\n");
				goto error;
			}
		return root;
	}

	value = 0;
	if( strno2int( &node->value, &value) <0)
		goto error;

	(*natping_state) = value?1:0;

	return  init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}



static int init_raw_socket(void)
{
	int on = 1;

	raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_sock ==-1) {
		LM_ERR("cannot create raw socket\n");
		return -1;
	}

	if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
		LM_ERR("cannot set socket options\n");
		return -1;
	}

	return raw_sock;
}


static int get_natping_socket(char *socket,
										unsigned int *ip, unsigned short *port)
{
	struct hostent* he;
	str host;
	int lport;
	int lproto;

	if (parse_phostport( socket, strlen(socket), &host.s, &host.len,
	&lport, &lproto)!=0){
		LM_CRIT("invalid natping_socket parameter <%s>\n",natping_socket);
		return -1;
	}

	if (lproto!=PROTO_UDP && lproto!=PROTO_NONE) {
		LM_CRIT("natping_socket can be only UDP <%s>\n",natping_socket);
		return 0;
	}
	lproto = PROTO_UDP;
	*port = lport?(unsigned short)lport:SIP_PORT;

	he = sip_resolvehost( &host, port, (unsigned short*)(void*)&lproto, 0, 0);
	if (he==0) {
		LM_ERR("could not resolve hostname:\"%.*s\"\n", host.len, host.s);
		return -1;
	}
	if (he->h_addrtype != AF_INET) {
		LM_ERR("only ipv4 addresses allowed in natping_socket\n");
		return -1;
	}

	memcpy( ip, he->h_addr_list[0], he->h_length);

	return 0;
}



static int
mod_init(void)
{
	int i;
	bind_usrloc_t bind_usrloc;
	str socket_str;
	struct in_addr addr;
	pv_spec_t avp_spec;
	str s;

	if (rcv_avp_param && *rcv_avp_param) {
		s.s = rcv_avp_param; s.len = strlen(s.s);
		if (pv_parse_spec(&s, &avp_spec)==0
				|| avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %s AVP definition\n", rcv_avp_param);
			return -1;
		}

		if(pv_get_avp_name(0, &avp_spec.pvp, &rcv_avp_name, &rcv_avp_type)!=0)
		{
			LM_ERR("[%s]- invalid AVP definition\n", rcv_avp_param);
			return -1;
		}
	} else {
		rcv_avp_name = -1;
		rcv_avp_type = 0;
	}

	if (force_socket_str) {
		socket_str.s=force_socket_str;
		socket_str.len=strlen(socket_str.s);
		force_socket=grep_sock_info(&socket_str,0,0);
	}

	/* create raw socket? */
	if (natping_socket && natping_socket[0]) {
		if (get_natping_socket( natping_socket, &raw_ip, &raw_port)!=0)
			return -1;
		if (init_raw_socket() < 0)
			return -1;
	}

	if (nortpproxy_str.s==NULL || nortpproxy_str.s[0]==0) {
		nortpproxy_str.len = 0;
		nortpproxy_str.s = NULL;
	} else {
		nortpproxy_str.len = strlen(nortpproxy_str.s);
		while (nortpproxy_str.len > 0 && (nortpproxy_str.s[nortpproxy_str.len - 1] == '\r' ||
		    nortpproxy_str.s[nortpproxy_str.len - 1] == '\n'))
			nortpproxy_str.len--;
		if (nortpproxy_str.len == 0)
			nortpproxy_str.s = NULL;
	}

	if (natping_interval > 0) {
		bind_usrloc = (bind_usrloc_t)find_export("ul_bind_usrloc", 1, 0);
		if (!bind_usrloc) {
			LM_ERR("can't find usrloc module\n");
			return -1;
		}

		if (bind_usrloc(&ul) < 0) {
			return -1;
		}

		natping_state =(unsigned int *) shm_malloc(sizeof(unsigned int));
		if (!natping_state) {
			LM_ERR("no shmem left\n");
			return -1;
		}
		*natping_state = MI_DEFAULT_NATPING_STATE;

		if (ping_nated_only && ul.nat_flag==0) {
			LM_ERR("bad config - ping_nated_only enabled, but no nat bflag"
				" set in usrloc module\n");
			return -1;
		}
		if (natping_processes>8) {
			LM_ERR("too many natping processes (%d) max=8\n",
				natping_processes);
			return -1;
		}

		fix_flag_name(sipping_flag_str, sipping_flag);
		sipping_flag = get_flag_id_by_name(FLAG_TYPE_BRANCH, sipping_flag_str);

		sipping_flag = (sipping_flag==-1)?0:(1<<sipping_flag);

		/* set reply function if SIP natping is enabled */
		if (sipping_flag) {
			if (sipping_from.s==0 || sipping_from.s[0]==0) {
				LM_ERR("SIP ping enabled, but SIP ping FROM is empty!\n");
				return -1;
			}
			if (sipping_method.s==0 || sipping_method.s[0]==0) {
				LM_ERR("SIP ping enabled, but SIP ping method is empty!\n");
				return -1;
			}
			sipping_method.len = strlen(sipping_method.s);
			sipping_from.len = strlen(sipping_from.s);
			exports.response_f = sipping_rpl_filter;
			init_sip_ping();
		}

		for( i=0 ; i<natping_processes ; i++ ) {
			if (register_timer_process( "nh-timer", nh_timer,
			(void*)(unsigned long)i, 1, TIMER_PROC_INIT_FLAG)==NULL) {
				LM_ERR("failed to register timer routine as process\n");
				return -1;
			}
		}
	}

	/* Prepare 1918/6598 networks list */
	for (i = 0; nets_1918[i].cnetaddr != NULL; i++) {
		if (inet_aton(nets_1918[i].cnetaddr, &addr) != 1)
			abort();
		nets_1918[i].netaddr = ntohl(addr.s_addr) & nets_1918[i].mask;
	}


	return 0;
}


static void mod_destroy(void)
{
	/*free the shared memory*/
	if (natping_state)
		shm_free(natping_state);

}



static int
isnulladdr(str *sx, int pf)
{
	char *cp;

	if (pf == AF_INET6) {
		for(cp = sx->s; cp < sx->s + sx->len; cp++)
			if (*cp != '0' && *cp != ':')
				return 0;
		return 1;
	}
	return (sx->len == 7 && memcmp("0.0.0.0", sx->s, 7) == 0);
}

/*
 * Replaces ip:port pair in the Contact: field with the source address
 * of the packet.
 */
static int
fix_nated_contact_f(struct sip_msg* msg, char* str1, char* str2)
{
	int len, len1;
	char *cp, *buf, temp, *p;
	contact_t *c;
	struct hdr_field *hdr;
	struct lump *anchor;
	struct sip_uri uri;
	str hostport, left, left2;
	int is_enclosed;
	str *params = (str*)str1;

	if (params && params->len==0)
		params = 0;

	for ( c=NULL,hdr=NULL ; get_contact_uri(msg, &uri, &c, &hdr)==0 ; ) {

		/* if uri string points outside the original msg buffer, it means
		   the URI was already changed, and we cannot do it again */
		if( c->uri.s < msg->buf || c->uri.s > msg->buf+msg->len ) {
			LM_ERR("SCRIPT BUG - second attempt to change URI Contact \n");
			return -1;
		}

		hostport = uri.host;
		if (uri.port.len > 0)
			hostport.len = uri.port.s + uri.port.len - uri.host.s;
		left.s = hostport.s + hostport.len;
		left.len = c->uri.s+c->uri.len - left.s;

		if (uri.maddr.len) {
			left2.s = uri.maddr_val.s + uri.maddr_val.len;
			left2.len = left.s + left.len - left2.s;
			left.len=uri.maddr.s-1-left.s;
		} else {
			left2.s = "";
			left2.len = 0;
		}

		is_enclosed = 0;
		p = hostport.s + hostport.len; /*start searching after ip:port */
		cp = (c->name.s?c->name.s:c->uri.s) + c->len; /* where to end */
		for( ; p<cp ; p++ )
			if (*p=='>') {is_enclosed=1;hostport.len=p-uri.host.s;break;}

		//LM_DBG("--removing %d |%.*s|\n",hostport.s+hostport.len-c->uri.s,
		//	hostport.s+hostport.len-c->uri.s, c->uri.s);
		anchor = del_lump(msg, c->uri.s-msg->buf /* offset */,
			hostport.s+hostport.len-c->uri.s /* len */, HDR_CONTACT_T);
		if (anchor == 0)
			return -1;

		cp = ip_addr2a(&msg->rcv.src_ip);
		len = (hostport.s-c->uri.s) + strlen(cp) + 6 /* :port */
			+ 2 /* just in case if IPv6 */
			+ (params?params->len+(is_enclosed?0:2):0)
			+ 1 + left.len + left2.len;
		buf = pkg_malloc(len);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		temp = hostport.s[0]; hostport.s[0] = '\0';
		if (params==NULL) {
			if (msg->rcv.src_ip.af==AF_INET6)
				len1 = snprintf(buf, len, "%s[%s]:%d%.*s%.*s", c->uri.s, cp,
					msg->rcv.src_port,left.len,left.s,left2.len,left2.s);
			else
				len1 = snprintf(buf, len, "%s%s:%d%.*s%.*s", c->uri.s, cp,
					msg->rcv.src_port,left.len,left.s,left2.len,left2.s);
		} else if (!is_enclosed) {
			if (msg->rcv.src_ip.af==AF_INET6)
				len1 = snprintf(buf, len, "<%s[%s]:%d%.*s>", c->uri.s, cp,
					msg->rcv.src_port,params->len,params->s);
			else
				len1 = snprintf(buf, len, "<%s%s:%d%.*s>", c->uri.s, cp,
					msg->rcv.src_port,params->len,params->s);
		} else {
			if (msg->rcv.src_ip.af==AF_INET6)
				len1 = snprintf(buf, len, "%s[%s]:%d%.*s%.*s%.*s", c->uri.s, cp,
					msg->rcv.src_port,params->len,params->s,
					left.len,left.s,left2.len,left2.s);
			else
				len1 = snprintf(buf, len, "%s%s:%d%.*s%.*s%.*s", c->uri.s, cp,
					msg->rcv.src_port,params->len,params->s,
					left.len,left.s,left2.len,left2.s);
		}
		if (len1 < len)
			len = len1;
		hostport.s[0] = temp;
		//LM_DBG("lump--- |%.*s|\n",len,buf);
		if (insert_new_lump_after(anchor, buf, len, HDR_CONTACT_T) == 0) {
			pkg_free(buf);
			return -1;
		}
		if (params==NULL || is_enclosed) {
			c->uri.s = buf;
			c->uri.len = len1;
		} else {
			c->uri.s = buf + 1;
			c->uri.len = len - 2;
		}
		//LM_DBG("new uri is--- |%.*s|\n",c->uri.len,c->uri.s);
	}

	return 1;
}


/*
 * Test if IP address pointed to by saddr belongs to RFC1918 / RFC6598 networks
 */
static inline int
is1918addr(str *saddr)
{
	struct in_addr addr;
	uint32_t netaddr;
	int i, rval;
	char backup;

	rval = -1;
	backup = saddr->s[saddr->len];
	saddr->s[saddr->len] = '\0';
	if (inet_aton(saddr->s, &addr) != 1)
		goto theend;
	netaddr = ntohl(addr.s_addr);
	for (i = 0; nets_1918[i].cnetaddr != NULL; i++) {
		if ((netaddr & nets_1918[i].mask) == nets_1918[i].netaddr) {
			rval = 1;
			goto theend;
		}
	}
	rval = 0;

theend:
	saddr->s[saddr->len] = backup;
	return rval;
}

/*
 * test for occurrence of RFC1918 / RFC6598 IP address in Contact HF
 */
static int
contact_1918(struct sip_msg* msg)
{
	struct sip_uri uri;
	struct hdr_field *hdr;
	contact_t* c;

	for( hdr=NULL,c=NULL ; get_contact_uri(msg, &uri, &c, &hdr)==0 ; )
		if ( is1918addr(&(uri.host)) == 1) return 1;

	return 0;
}

/*
 * test for occurrence of RFC1918 / RFC6598 IP address in SDP
 */
static int
sdp_1918(struct sip_msg* msg)
{
	str body, ip;
	int pf;
	struct multi_body * bodies;
	struct part *p;
	int ret = 0;

	bodies = get_all_bodies(msg);

	if( bodies == NULL)
	{
		LM_DBG("Unable to get bodies from message\n");
		return 0;
	}

	p = bodies->first;

	while(p)
	{

		body = p->body;
		trim_r(body);
		if( p->content_type != ((TYPE_APPLICATION << 16) + SUBTYPE_SDP)
							 || body.len == 0)
		{
			p=p->next;
			continue;
		}


		if (extract_mediaip(&body, &ip, &pf, "c=") == -1)
		{
			LM_ERR("can't extract media IP from the SDP\n");
			return 0;
		}
		if (pf != AF_INET || isnulladdr(&ip, pf))
			return 0;

		ret |= (is1918addr(&ip) == 1) ? 1 : 0;
		p= p->next;
	}

	return ret;
}

/*
 * test for occurrence of RFC1918 / RFC6598 IP address in top Via
 */
static int
via_1918(struct sip_msg* msg)
{

	return (is1918addr(&(msg->via1->host)) == 1) ? 1 : 0;
}

/*
 * test for Contact IP against received IP
 */
static int
contact_rcv(struct sip_msg* msg)
{
	struct sip_uri uri;
	contact_t* c;
	struct hdr_field *hdr;

	for( hdr=NULL,c=NULL ; get_contact_uri(msg, &uri, &c, &hdr)==0 ; )
		if ( check_ip_address(&msg->rcv.src_ip,
		&uri.host, uri.port_no, uri.proto, received_dns)!=0 ) return 1;

	return 0;

}


/*
 * test for Contact port against received port
 */
static int
contact_rport(struct sip_msg* msg)
{
	struct sip_uri uri;
	contact_t* c;
	struct hdr_field *hdr;
	int ct_port;

	for( hdr=NULL,c=NULL ; get_contact_uri(msg, &uri, &c, &hdr)==0 ; ) {
		ct_port=uri.port_no?uri.port_no:((uri.type==SIPS_URI_T)?SIPS_PORT:SIP_PORT);
		if ( msg->rcv.src_port != ct_port ) return 1;
	}

	return 0;

}




static int
nat_uac_test_f(struct sip_msg* msg, char* str1, char* str2)
{
	int tests;

	tests = (int)(long)str1;

	/* return true if any of the NAT-UAC tests holds */

	/* test if the source port is different from the port in Via */
	if ((tests & NAT_UAC_TEST_RPORT) &&
		 (msg->rcv.src_port!=(msg->via1->port?msg->via1->port:SIP_PORT)) ){
		return 1;
	}
	/*
	 * test if source address of signaling is different from
	 * address advertised in Via
	 */
	if ((tests & NAT_UAC_TEST_V_RCVD) && received_test(msg))
		return 1;
	/*
	 * test for occurrences of RFC1918 / RFC6598 addresses in Contact
	 * header field
	 */
	if ((tests & NAT_UAC_TEST_C_1918) && (contact_1918(msg)>0))
		return 1;
	/*
	 * test for occurrences of RFC1918 / RFC6598 addresses in SDP body
	 */
	if ((tests & NAT_UAC_TEST_S_1918) && sdp_1918(msg))
		return 1;
	/*
	 * test for occurrences of RFC1918 / RFC6598 addresses top Via
	 */
	if ((tests & NAT_UAC_TEST_V_1918) && via_1918(msg))
		return 1;
	/*
	 * test if source address of signaling is different from
	 * address advertised in Contact
	 */
	if ((tests & NAT_UAC_TEST_C_RCVD) && contact_rcv(msg))
		return 1;
	/*
	 * test if source port of signaling is different from
	 * port advertised in Contact
	 */
	if ((tests & NAT_UAC_TEST_C_RPORT) && contact_rport(msg))
		return 1;

	/* no test succeeded */
	return -1;
}

#define	ADD_ADIRECTION	0x01
#define	FIX_MEDIP	0x02
#define	ADD_ANORTPPROXY	0x04
#define	FIX_ORGIP	0x08

#define	ADIRECTION	"a=direction:active"
#define	ADIRECTION_LEN	(sizeof(ADIRECTION) - 1)

#define	AOLDMEDIP	"a=oldmediaip:"
#define	AOLDMEDIP_LEN	(sizeof(AOLDMEDIP) - 1)

#define	AOLDMEDIP6	"a=oldmediaip6:"
#define	AOLDMEDIP6_LEN	(sizeof(AOLDMEDIP6) - 1)

static int
alter_mediaip(struct sip_msg *msg, str *body, str *oldip, int oldpf,
  str *newip, int newpf, int preserve)
{
	char *buf;
	int offset;
	struct lump* anchor;
	str omip, nip, oip;

	/* check that updating mediaip is really necessary */
	if (oldpf == newpf && isnulladdr(oldip, oldpf))
		return 0;
	if (newip->len == oldip->len &&
	    memcmp(newip->s, oldip->s, newip->len) == 0)
		return 0;

	if (preserve != 0) {
		anchor = anchor_lump(msg, body->s + body->len - msg->buf, 0, 0);
		if (anchor == NULL) {
			LM_ERR("anchor_lump failed\n");
			return -1;
		}
		if (oldpf == AF_INET6) {
			omip.s = AOLDMEDIP6;
			omip.len = AOLDMEDIP6_LEN;
		} else {
			omip.s = AOLDMEDIP;
			omip.len = AOLDMEDIP_LEN;
		}
		buf = pkg_malloc(omip.len + oldip->len + CRLF_LEN);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		memcpy(buf, CRLF, CRLF_LEN);
		memcpy(buf + CRLF_LEN, omip.s, omip.len);
		memcpy(buf + CRLF_LEN + omip.len, oldip->s, oldip->len);
		if (insert_new_lump_after(anchor, buf,
		    omip.len + oldip->len + CRLF_LEN, 0) == NULL) {
			LM_ERR("insert_new_lump_after failed\n");
			pkg_free(buf);
			return -1;
		}
	}

	if (oldpf == newpf) {
		nip.len = newip->len;
		nip.s = pkg_malloc(nip.len);
		if (nip.s == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		memcpy(nip.s, newip->s, newip->len);
	} else {
		nip.len = newip->len + 2;
		nip.s = pkg_malloc(nip.len);
		if (nip.s == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		memcpy(nip.s + 2, newip->s, newip->len);
		nip.s[0] = (newpf == AF_INET6) ? '6' : '4';
		nip.s[1] = ' ';
	}

	oip = *oldip;
	if (oldpf != newpf) {
		do {
			oip.s--;
			oip.len++;
		} while (*oip.s != '6' && *oip.s != '4');
	}
	offset = oip.s - msg->buf;
	anchor = del_lump(msg, offset, oip.len, 0);
	if (anchor == NULL) {
		LM_ERR("del_lump failed\n");
		pkg_free(nip.s);
		return -1;
	}

	if (insert_new_lump_after(anchor, nip.s, nip.len, 0) == 0) {
		LM_ERR("insert_new_lump_after failed\n");
		pkg_free(nip.s);
		return -1;
	}
	return 0;
}

static inline int
replace_sdp_ip(struct sip_msg* msg, str *org_body, char *line, str *ip)
{
	str body1, oldip, newip;
	str body = *org_body;
	unsigned hasreplaced = 0;
	int pf, pf1 = 0;
	str body2;
	char *bodylimit = body.s + body.len;

	/* Iterate all lines and replace ips in them. */
	if (!ip) {
		newip.s = ip_addr2a(&msg->rcv.src_ip);
		newip.len = strlen(newip.s);
	} else {
		newip = *ip;
	}
	body1 = body;
	for(;;) {
		if (extract_mediaip(&body1, &oldip, &pf,line) == -1)
			break;
		if (pf != AF_INET) {
			LM_ERR("not an IPv4 address in '%s' SDP\n",line);
				return -1;
			}
		if (!pf1)
			pf1 = pf;
		else if (pf != pf1) {
			LM_ERR("mismatching address families in '%s' SDP\n",line);
			return -1;
		}
		body2.s = oldip.s + oldip.len;
		body2.len = bodylimit - body2.s;
		if (alter_mediaip(msg, &body1, &oldip, pf, &newip, pf,1) == -1) {
			LM_ERR("can't alter '%s' IP\n",line);
			return -1;
		}
		hasreplaced = 1;
		body1 = body2;
	}
	if (!hasreplaced) {
		LM_ERR("can't extract '%s' IP from the SDP\n",line);
		return -1;
	}

	return 0;
}


static int
fix_nated_sdp_f(struct sip_msg* msg, char* str1, char* str2)
{
	str body;
	str ip;
	int level;
	char *buf;
	struct lump* anchor;
	struct multi_body * bodies;
	struct part * p;

	level = (int)(long)str1;
	if (str2 && pv_printf_s( msg, (pv_elem_p)str2, &ip)!=0)
		return -1;

	bodies = get_all_bodies(msg);

	if( bodies == NULL)
	{
		LM_ERR("Unable to get bodies from message\n");
		return -1;
	}

	p = bodies->first;

	while(p)
	{
		body = p->body;
		trim_r(body);
		if( p->content_type != ((TYPE_APPLICATION << 16) + SUBTYPE_SDP)
							 || body.len == 0)
		{
			p=p->next;
			continue;
		}
		if (level & (ADD_ADIRECTION | ADD_ANORTPPROXY)) {
			msg->msg_flags |= FL_FORCE_ACTIVE;
			anchor = anchor_lump(msg, body.s + body.len - msg->buf, 0, 0);
			if (anchor == NULL) {
				LM_ERR("anchor_lump failed\n");
				return -1;
			}
			if (level & ADD_ADIRECTION) {
				buf = pkg_malloc((ADIRECTION_LEN + CRLF_LEN) * sizeof(char));
				if (buf == NULL) {
					LM_ERR("out of pkg memory\n");
					return -1;
				}
				memcpy(buf, CRLF, CRLF_LEN);
				memcpy(buf + CRLF_LEN, ADIRECTION, ADIRECTION_LEN);
				if (insert_new_lump_after(anchor, buf, ADIRECTION_LEN + CRLF_LEN, 0) == NULL) {
					LM_ERR("insert_new_lump_after failed 1\n");
					pkg_free(buf);
					return -1;
				}
			}
			if ((level & ADD_ANORTPPROXY) && nortpproxy_str.len) {
				buf = pkg_malloc((nortpproxy_str.len + CRLF_LEN) * sizeof(char));
				if (buf == NULL) {
					LM_ERR("out of pkg memory\n");
					return -1;
				}
				memcpy(buf, CRLF, CRLF_LEN);
				memcpy(buf + CRLF_LEN, nortpproxy_str.s, nortpproxy_str.len);
				if (insert_new_lump_after(anchor, buf, nortpproxy_str.len + CRLF_LEN, 0) == NULL) {
					LM_ERR("insert_new_lump_after failed 2\n");
					pkg_free(buf);
					return -1;
				}
			}
		}

		if (level & FIX_MEDIP) {
			/* Iterate all c= and replace ips in them. */
			if (replace_sdp_ip(msg, &body, "c=", str2?&ip:0)==-1)
				return -1;
		}

		if (level & FIX_ORGIP) {
			/* Iterate all o= and replace ips in them. */
			if (replace_sdp_ip(msg, &body, "o=", str2?&ip:0)==-1)
				return -1;
		}
		p= p->next;
	}

	return 1;
}




static u_short raw_checksum(unsigned char *buffer, int len)
{
	u_long sum = 0;

	while (len > 1) {
		sum += *buffer << 8;
		buffer++;
		sum += *buffer;
		buffer++;
		len -= 2;
	}
	if (len) {
		sum += *buffer << 8;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum);

	return (u_short) ~sum;
}


static int send_raw(const char *buf, int buf_len, union sockaddr_union *to,
							const unsigned int s_ip, const unsigned int s_port)
{
	struct ip *ip;
	struct udphdr *udp;
	unsigned char packet[50];
	int len = sizeof(struct ip) + sizeof(struct udphdr) + buf_len;

	if (len > sizeof(packet)) {
		LM_ERR("payload too big\n");
		return -1;
	}

	ip = (struct ip*) packet;
	udp = (struct udphdr *) (packet + sizeof(struct ip));
	memcpy(packet + sizeof(struct ip) + sizeof(struct udphdr), buf, buf_len);

	ip->ip_v = 4;
	ip->ip_hl = sizeof(struct ip) / 4; // no options
	ip->ip_tos = 0;
	ip->ip_len = htons(len);
	ip->ip_id = 23;
	ip->ip_off = 0;
	ip->ip_ttl = 69;
	ip->ip_p = 17;
	ip->ip_src.s_addr = s_ip;
	ip->ip_dst.s_addr = to->sin.sin_addr.s_addr;

	ip->ip_sum = raw_checksum((unsigned char *) ip, sizeof(struct ip));

	udp->uh_sport = htons(s_port);
	udp->uh_dport = to->sin.sin_port;
	udp->uh_ulen = htons((unsigned short) sizeof(struct udphdr) + buf_len);
	udp->uh_sum = 0;

	return sendto(raw_sock, packet, len, 0, (struct sockaddr *) to, sizeof(struct sockaddr_in));
}


static void
nh_timer(unsigned int ticks, void *timer_idx)
{
	static unsigned int iteration = 0;
	int rval;
	void *buf = NULL;
	void *cp;
	str c;
	str opt;
	str path;
	union sockaddr_union to;
	struct hostent *he;
	struct socket_info* send_sock;
	unsigned int flags;
	struct proxy_l next_hop;

	if ((*natping_state) == 0)
		goto done;

	if (cblen > 0) {
		buf = pkg_malloc(cblen);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			goto done;
		}
	}
	rval = ul.get_all_ucontacts(buf, cblen, (ping_nated_only?ul.nat_flag:0),
		((unsigned int)(unsigned long)timer_idx)*natping_interval+iteration,
		natping_processes*natping_interval);
	if (rval<0) {
		LM_ERR("failed to fetch contacts\n");
		goto done;
	}
	if (rval > 0) {
		if (buf != NULL)
			pkg_free(buf);
		cblen += rval + 128 /*some extra*/;
		buf = pkg_malloc(cblen);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			goto done;
		}
		rval = ul.get_all_ucontacts(buf,cblen,(ping_nated_only?ul.nat_flag:0),
		   ((unsigned int)(unsigned long)timer_idx)*natping_interval+iteration,
		   natping_processes*natping_interval);
		if (rval != 0) {
			goto done;
		}
	}

	if (buf == NULL)
		goto done;

#ifdef USE_TCP
		tcp_no_new_conn = 1;
#endif

	cp = buf;
	while (1) {
		memcpy(&(c.len), cp, sizeof(c.len));
		if (c.len == 0)
			break;

		c.s = (char*)cp + sizeof(c.len);
		cp = (char*)cp + sizeof(c.len) + c.len;
		memcpy(&path.len, cp, sizeof(path.len));
		path.s = path.len ? ((char*)cp + sizeof(path.len)) : NULL;
		cp = (char*)cp + sizeof(path.len) + path.len;
		memcpy(&send_sock, cp, sizeof(send_sock));
		cp = (char*)cp + sizeof(send_sock);
		memcpy(&flags, cp, sizeof(flags));
		cp = (char*)cp + sizeof(flags);
		memcpy(&next_hop, cp, sizeof(next_hop));
		cp = (char*)cp + sizeof(next_hop);

		if (next_hop.proto != PROTO_NONE && next_hop.proto != PROTO_UDP &&
		    (natping_tcp == 0 || (next_hop.proto != PROTO_TCP &&
		                          next_hop.proto != PROTO_TLS)))
			continue;

		LM_DBG("resolving next hop: '%.*s'\n",
		        next_hop.name.len, next_hop.name.s);
		he = sip_resolvehost(&next_hop.name, &next_hop.port,
		                     &next_hop.proto, 0, NULL);
		if (!he) {
			LM_ERR("failed to resolve next hop: '%.*s'\n",
			        next_hop.name.len, next_hop.name.s);
			continue;
		}

		hostent2su(&to, he, 0, next_hop.port);

		if (!send_sock) {
			send_sock = force_socket ? force_socket :
			                           get_send_socket(0, &to, next_hop.proto);
			if (!send_sock) {
				LM_ERR("can't get sending socket\n");
				continue;
			}
		}

		if ((flags & sipping_flag) &&
		    (opt.s = build_sipping(&c, send_sock, &path, &opt.len))) {
			if (msg_send(send_sock, next_hop.proto, &to, 0, opt.s, opt.len) < 0) {
				LM_ERR("sip msg_send failed\n");
			}
		} else if (raw_ip && next_hop.proto == PROTO_UDP) {
			if (send_raw((char*)sbuf, sizeof(sbuf), &to, raw_ip, raw_port)<0) {
				LM_ERR("send_raw failed\n");
			}
		} else {
			if (msg_send(send_sock, next_hop.proto, &to, 0,
			             (char *)sbuf, sizeof(sbuf)) < 0) {
				LM_ERR("sip msg_send failed!\n");
			}
		}
	}

#ifdef USE_TCP
		tcp_no_new_conn = 0;
#endif

done:
	if (buf)
		pkg_free(buf);
	iteration++;
	if (iteration==natping_interval)
		iteration = 0;
}


/*
 * Create received SIP uri that will be either
 * passed to registrar in an AVP or apended
 * to Contact header field as a parameter
 */
static int
create_rcv_uri(str* uri, struct sip_msg* m)
{
	static char buf[MAX_URI_SIZE];
	char* p;
	str ip, port;
	int len;
	str proto;

	if (!uri || !m) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	ip.s = ip_addr2a(&m->rcv.src_ip);
	ip.len = strlen(ip.s);

	port.s = int2str(m->rcv.src_port, &port.len);

	switch(m->rcv.proto) {
	case PROTO_NONE:
	case PROTO_UDP:
		proto.s = 0; /* Do not add transport parameter, UDP is default */
		proto.len = 0;
		break;

	case PROTO_TCP:
		proto.s = "TCP";
		proto.len = 3;
		break;

	case PROTO_TLS:
		proto.s = "TLS";
		proto.len = 3;
		break;

	case PROTO_SCTP:
		proto.s = "SCTP";
		proto.len = 4;
		break;

	default:
		LM_ERR("unknown transport protocol\n");
		return -1;
	}

	len = 4 + ip.len + 2*(m->rcv.src_ip.af==AF_INET6)+ 1 + port.len;
	if (proto.s) {
		len += TRANSPORT_PARAM_LEN;
		len += proto.len;
	}

	if (len > MAX_URI_SIZE) {
		LM_ERR("buffer too small\n");
		return -1;
	}

	p = buf;
	memcpy(p, "sip:", 4);
	p += 4;

	if (m->rcv.src_ip.af==AF_INET6)
		*p++ = '[';
	memcpy(p, ip.s, ip.len);
	p += ip.len;
	if (m->rcv.src_ip.af==AF_INET6)
		*p++ = ']';

	*p++ = ':';

	memcpy(p, port.s, port.len);
	p += port.len;

	if (proto.s) {
		memcpy(p, TRANSPORT_PARAM, TRANSPORT_PARAM_LEN);
		p += TRANSPORT_PARAM_LEN;

		memcpy(p, proto.s, proto.len);
		p += proto.len;
	}

	uri->s = buf;
	uri->len = len;

	return 0;
}


/*
 * Add received parameter to Contacts for further
 * forwarding of the REGISTER requuest
 */
static int
add_rcv_param_f(struct sip_msg* msg, char* str1, char* str2)
{
	contact_t* c;
	struct lump* anchor;
	char* param;
	str uri;
	int hdr_param;

	hdr_param = str1?0:1;

	if (create_rcv_uri(&uri, msg) < 0) {
		return -1;
	}

	if (contact_iterator(&c, msg, 0) < 0) {
		return -1;
	}

	while(c) {
		param = (char*)pkg_malloc(RECEIVED_LEN + 2 + uri.len);
		if (!param) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
		memcpy(param, RECEIVED, RECEIVED_LEN);
		param[RECEIVED_LEN] = '\"';
		memcpy(param + RECEIVED_LEN + 1, uri.s, uri.len);
		param[RECEIVED_LEN + 1 + uri.len] = '\"';

		if (hdr_param) {
			/* add the param as header param */
			anchor = anchor_lump(msg, c->name.s + c->len - msg->buf, 0, 0);
		} else {
			/* add the param as uri param */
			anchor = anchor_lump(msg, c->uri.s + c->uri.len - msg->buf, 0, 0);
		}
		if (anchor == NULL) {
			LM_ERR("anchor_lump failed\n");
			return -1;
		}

		if (insert_new_lump_after(anchor, param, RECEIVED_LEN + 1 + uri.len + 1, 0) == 0) {
			LM_ERR("insert_new_lump_after failed\n");
			pkg_free(param);
			return -1;
		}

		if (contact_iterator(&c, msg, c) < 0) {
			return -1;
		}
	}

	return 1;
}





/*
 * Create an AVP to be used by registrar with the source IP and port
 * of the REGISTER
 */
static int
fix_nated_register_f(struct sip_msg* msg, char* str1, char* str2)
{
	str uri;
	int_str val;

	if(rcv_avp_name < 0)
		return 1;

	if (create_rcv_uri(&uri, msg) < 0) {
		return -1;
	}

	val.s = uri;

	if (add_avp(AVP_VAL_STR|rcv_avp_type, rcv_avp_name, val) < 0) {
		LM_ERR("failed to create AVP\n");
		return -1;
	}

	return 1;
}
