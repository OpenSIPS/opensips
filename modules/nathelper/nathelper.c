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
 * 2003-12-01   unforce_rtp_proxy introduced (sobomax)
 *
 * 2004-01-07	RTP proxy support updated to support new version of the
 *		RTP proxy (20040107).
 *
 *		force_rtp_proxy() now inserts a special flag
 *		into the SDP body to indicate that this session already
 *		proxied and ignores sessions with such flag.
 *
 *		Added run-time check for version of command protocol
 *		supported by the RTP proxy.
 *
 * 2004-01-16   Integrated slightly modified patch from Tristan Colgate,
 *		force_rtp_proxy function with IP as a parameter (janakj)
 *
 * 2004-01-28	nat_uac_test extended to allow testing SDP body (sobomax)
 *
 *		nat_uac_test extended to allow testing top Via (sobomax)
 *
 * 2004-02-21	force_rtp_proxy now accepts option argument, which
 *		consists of string of chars, each of them turns "on"
 *		some feature, currently supported ones are:
 *
 *		 `a' - flags that UA from which message is received
 *		       doesn't support symmetric RTP;
 *		 `l' - force "lookup", that is, only rewrite SDP when
 *		       corresponding session is already exists in the
 *		       RTP proxy. Only makes sense for SIP requests,
 *		       replies are always processed in "lookup" mode;
 *		 `i' - flags that message is received from UA in the
 *		       LAN. Only makes sense when RTP proxy is running
 *		       in the bridge mode.
 *
 *		force_rtp_proxy can now be invoked without any arguments,
 *		as previously, with one argument - in this case argument
 *		is treated as option string and with two arguments, in
 *		which case 1st argument is option string and the 2nd
 *		one is IP address which have to be inserted into
 *		SDP (IP address on which RTP proxy listens).
 *
 * 2004-03-12	Added support for IPv6 addresses in SDPs. Particularly,
 *		force_rtp_proxy now can work with IPv6-aware RTP proxy,
 *		replacing IPv4 address in SDP with IPv6 one and vice versa.
 *		This allows creating full-fledged IPv4<->IPv6 gateway.
 *		See 4to6.cfg file for example.
 *
 *		Two new options added into force_rtp_proxy:
 *
 *		 `f' - instructs nathelper to ignore marks inserted
 *		       by another nathelper in transit to indicate
 *		       that the session is already goes through another
 *		       proxy. Allows creating chain of proxies.
 *		 `r' - flags that IP address in SDP should be trusted.
 *		       Without this flag, nathelper ignores address in the
 *		       SDP and uses source address of the SIP message
 *		       as media address which is passed to the RTP proxy.
 *
 *		Protocol between nathelper and RTP proxy in bridge
 *		mode has been slightly changed. Now RTP proxy expects SER
 *		to provide 2 flags when creating or updating session
 *		to indicate direction of this session. Each of those
 *		flags can be either `e' or `i'. For example `ei' means
 *		that we received INVITE from UA on the "external" network
 *		network and will send it to the UA on "internal" one.
 *		Also possible `ie' (internal->external), `ii'
 *		(internal->internal) and `ee' (external->external). See
 *		example file alg.cfg for details.
 *
 * 2004-03-15	If the rtp proxy test failed (wrong version or not started)
 *		retry test from time to time, when some *rtpproxy* function
 *		is invoked. Minimum interval between retries can be
 *		configured via rtpproxy_disable_tout module parameter (default
 *		is 60 seconds). Setting it to -1 will disable periodic
 *		rechecks completely, setting it to 0 will force checks
 *		for each *rtpproxy* function call. (andrei)
 *
 * 2004-03-22	Fix assignment of rtpproxy_retr and rtpproxy_tout module
 *		parameters.
 *
 * 2004-03-22	Fix get_body position (should be called before get_callid)
 * 				(andrei)
 *
 * 2004-03-24	Fix newport for null ip address case (e.g onhold re-INVITE)
 * 				(andrei)
 *
 * 2004-09-30	added received port != via port test (andrei)
 *
 * 2004-10-10   force_socket option introduced (jiri)
 *
 * 2005-02-24	Added support for using more than one rtp proxy, in which
 *		case traffic will be distributed evenly among them. In addition,
 *		each such proxy can be assigned a weight, which will specify
 *		which share of the traffic should be placed to this particular
 *		proxy.
 *
 *		Introduce failover mechanism, so that if SER detects that one
 *		of many proxies is no longer available it temporarily decreases
 *		its weight to 0, so that no traffic will be assigned to it.
 *		Such "disabled" proxies are periodically checked to see if they
 *		are back to normal in which case respective weight is restored
 *		resulting in traffic being sent to that proxy again.
 *
 *		Those features can be enabled by specifying more than one "URI"
 *		in the rtpproxy_sock parameter, optionally followed by the weight,
 *		which if absent is assumed to be 1, for example:
 *
 *		rtpproxy_sock="unix:/foo/bar=4 udp:1.2.3.4:3456=3 udp:5.6.7.8:5432=1"
 *
 * 2005-02-25	Force for pinging the socket returned by USRLOC (bogdan)
 *
 * 2005-03-22	support for multiple media streams added (netch)
 *
 * 2005-07-11  SIP ping support added (bogdan)
 *
 * 2005-07-14  SDP origin (o=) IP may be also changed (bogdan)
 *
 * 2006-03-08  fix_nated_sdp() may take one more param to force a specific IP;
 *             force_rtp_proxy() accepts a new flag 's' to swap creation/
 *              confirmation between requests/replies; 
 *             add_rcv_param() may take as parameter a flag telling if the
 *              parameter should go to the contact URI or contact header;
 *             (bogdan)
 * 2006-03-28 Support for changing session-level SDP connection (c=) IP when
 *            media-description also includes connection information (bayan)
 * 2007-04-13 Support multiple sets of rtpproxies and set selection added
 *            (ancuta)
 * 2007-04-26 Added some MI commands:
 *             nh_enable_ping used to enable or disable natping
 *             nh_enable_rtpp used to enable or disable a specific rtp proxy
 *             nh_show_rtpp   used to display information for all rtp proxies 
 *             (ancuta)
 * 2007-05-09 New function start_recording() allowing to start recording RTP 
 *             session in the RTP proxy (Carsten Bock - ported from SER)
 * 2007-09-11 Separate timer process and support for multiple timer processes
 *             (bogdan)
 * 2010-09-23 Remove force-rt-proxy funxtion
 *             - obsolete by rtpproxy_offer/rtpproxy_answer
 *            (osas)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#ifndef __USE_BSD
#define  __USE_BSD
#endif
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../flags.h"
#include "../../dprint.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../error.h"
#include "../../forward.h"
#include "../../mem/mem.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parser_f.h"
#include "../../parser/sdp/sdp_helpr_funcs.h"
#include "../../resolve.h"
#include "../../timer.h"
#include "../../trim.h"
#include "../../ut.h"
#include "../../mi/attr.h"
#include "../../pvar.h"
#include "../../msg_translator.h"
#include "../../usr_avp.h"
#include "../../socket_info.h"
#include "../../mod_fix.h"
#include "../registrar/sip_msg.h"
#include "../usrloc/usrloc.h"
#include "nathelper.h"
#include "nhelpr_funcs.h"
#include "sip_pinger.h"
#include "rtpproxy_stream.h"
#include "../../db/db.h"
#include "../../locking.h"
#include "../../parser/parse_content.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_multipart.h"

#include "../dialog/dlg_load.h"
#include "../../rw_locking.h"

#define NH_TABLE_VERSION  0

#if !defined(AF_LOCAL)
#define	AF_LOCAL AF_UNIX
#endif
#if !defined(PF_LOCAL)
#define	PF_LOCAL PF_UNIX
#endif

/* NAT UAC test constants */
#define	NAT_UAC_TEST_C_1918	0x01
#define	NAT_UAC_TEST_V_RCVD	0x02
#define	NAT_UAC_TEST_V_1918	0x04
#define	NAT_UAC_TEST_S_1918	0x08
#define	NAT_UAC_TEST_RPORT	0x10
#define	NAT_UAC_TEST_C_RCVD	0x20


#define DEFAULT_RTPP_SET_ID		0

#define MI_SET_NATPING_STATE		"nh_enable_ping"
#define MI_DEFAULT_NATPING_STATE	1

#define MI_ENABLE_RTP_PROXY			"nh_enable_rtpp"
#define MI_MIN_RECHECK_TICKS		0
#define MI_MAX_RECHECK_TICKS		(unsigned int)-1


#define MI_SHOW_RTP_PROXIES			"nh_show_rtpp"
#define MI_RELOAD_RTP_PROXIES       "nh_reload_rtpp"

#define MI_RTP_PROXY_NOT_FOUND		"RTP proxy not found"
#define MI_RTP_PROXY_NOT_FOUND_LEN	(sizeof(MI_RTP_PROXY_NOT_FOUND)-1)
#define MI_PING_DISABLED			"NATping disabled from script"
#define MI_PING_DISABLED_LEN		(sizeof(MI_PING_DISABLED)-1)
#define MI_SET						"set"
#define MI_SET_LEN					(sizeof(MI_SET)-1)
#define MI_INDEX					"index"
#define MI_INDEX_LEN				(sizeof(MI_INDEX)-1)
#define MI_DISABLED					"disabled"
#define MI_DISABLED_LEN				(sizeof(MI_DISABLED)-1)
#define MI_WEIGHT					"weight"
#define MI_WEIGHT_LEN				(sizeof(MI_WEIGHT)-1)
#define MI_RECHECK_TICKS			"recheck_ticks"
#define MI_RECHECK_T_LEN			(sizeof(MI_RECHECK_TICKS)-1)



/* Supported version of the RTP proxy command protocol */
#define	SUP_CPROTOVER	20040107
/* Required additional version of the RTP proxy command protocol */
#define	REQ_CPROTOVER	"20050322"
/* Additional version necessary for re-packetization support */
#define	REP_CPROTOVER	"20071116"
#define	PTL_CPROTOVER	"20081224"

#define	CPORT		"22222"

static int nat_uac_test_f(struct sip_msg* msg, char* str1, char* str2);
static int fix_nated_contact_f(struct sip_msg *, char *, char *);
static int fix_nated_sdp_f(struct sip_msg *, char *, char *);
static int extract_mediainfo(str *, str *, str *);
static int alter_mediaip(struct sip_msg *, str *, str *, int, str *, int, int);
static char *gencookie();
static int rtpp_test(struct rtpp_node*, int, int);
static int unforce_rtp_proxy_f(struct sip_msg *, char *, char *);
static int force_rtp_proxy(struct sip_msg *, char *, char *, int);
static int fix_nated_register_f(struct sip_msg *, char *, char *);
static int fixup_fix_nated_register(void** param, int param_no);
static int fixup_fix_sdp(void** param, int param_no);
static int add_rcv_param_f(struct sip_msg *, char *, char *);
static int start_recording_f(struct sip_msg *, char *, char *);
static int rtpproxy_answer1_f(struct sip_msg *, char *, char *);
static int rtpproxy_answer2_f(struct sip_msg *, char *, char *);
static int rtpproxy_offer1_f(struct sip_msg *, char *, char *);
static int rtpproxy_offer2_f(struct sip_msg *, char *, char *);

static int add_rtpproxy_socks(struct rtpp_set * rtpp_list, char * rtpproxy);
static int fixup_set_id(void ** param, int param_no);
static int set_rtp_proxy_set_f(struct sip_msg * msg, char * str1, char * str2);
static struct rtpp_set * select_rtpp_set(int id_set);

static int rtpproxy_set_store(modparam_t type, void * val);
static int nathelper_add_rtpproxy_set( char * rtp_proxies, int set_id);
static int _add_proxies_from_database();

static void nh_timer(unsigned int, void *);
static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);
static int mi_child_init(void);

/*mi commands*/
static struct mi_root* mi_enable_natping(struct mi_root* cmd_tree,
		void* param );
static struct mi_root* mi_enable_rtp_proxy(struct mi_root* cmd_tree,
		void* param );
static struct mi_root* mi_show_rtpproxies(struct mi_root* cmd_tree,
		void* param);
static struct mi_root* mi_reload_rtpproxies(struct mi_root* cmd_tree,
                void* param);

void free_rtpp_sets();

static usrloc_api_t ul;
struct dlg_binds dlg_api;

static int cblen = 0;
static int natping_interval = 0;
struct socket_info* force_socket = 0;
int detect_rtp_idle = 0;
struct rtpp_notify_head * rtpp_notify_h = 0;

int connect_rtpproxies();
int update_rtpp_proxies();


static struct {
	const char *cnetaddr;
	uint32_t netaddr;
	uint32_t mask;
} nets_1918[] = {
	{"10.0.0.0",    0, 0xffffffffu << 24},
	{"172.16.0.0",  0, 0xffffffffu << 20},
	{"192.168.0.0", 0, 0xffffffffu << 16},
	{NULL, 0, 0}
};

static struct {
	const char *s;
	int len;
	int is_rtp;
} sup_ptypes[] = {
	{.s = "udp",       .len = 3, .is_rtp = 0},
	{.s = "udptl",     .len = 5, .is_rtp = 0},
	{.s = "rtp/avp",   .len = 7, .is_rtp = 1},
	{.s = "rtp/avpf",  .len = 8, .is_rtp = 1},
	{.s = "rtp/savp",  .len = 8, .is_rtp = 1},
	{.s = "rtp/savpf", .len = 9, .is_rtp = 1},
	{.s = "udp/bfcp",  .len = 8, .is_rtp = 0},
	{.s = NULL,        .len = 0, .is_rtp = 0}
};

/*
 * If this parameter is set then the natpinger will ping only contacts
 * that have the NAT flag set in user location database
 */
static int ping_nated_only = 0;
static const char sbuf[4] = {0, 0, 0, 0};
static char *force_socket_str = 0;
static int rtpproxy_disable_tout = 60;
static int rtpproxy_retr = 5;
static int rtpproxy_tout = -1;
static char *rtpproxy_timeout = 0;
static pid_t mypid;
static unsigned int myseqn = 0;
static str nortpproxy_str = str_init("a=nortpproxy:yes");
static int sipping_flag = -1;
static int natping_processes = 1;

static char* rcv_avp_param = NULL;
static unsigned short rcv_avp_type = 0;
static int_str rcv_avp_name;

static char *natping_socket = 0;
static int raw_sock = -1;
static unsigned int raw_ip = 0;
static unsigned short raw_port = 0;
str rtpp_notify_socket = {0, 0};

/* used in rtpproxy_set_store() */
static int rtpp_sets=0; 
static char **rtpp_strings=0;
static int rtpp_set_count = 0;
static unsigned int current_msg_id = (unsigned int)-1;
/* RTP proxy balancing list */
struct rtpp_set_head * rtpp_set_list =0;
struct rtpp_set * selected_rtpp_set =0;
struct rtpp_set ** default_rtpp_set=0;

/* array with the sockets used by rtpporxy (per process)*/
static int *rtpp_socks = 0;
static unsigned int *rtpp_no = 0;
static unsigned int *list_version;
static unsigned int my_version = 0;
static unsigned int rtpp_number = 0;


/*0-> disabled, 1 ->enabled*/
unsigned int *natping_state=0;

/* DB support for loading proxies */
static str db_url = {NULL, 0};
static str table = str_init("nh_sockets");
static str rtpp_sock_col = str_init("rtpproxy_sock");
static str set_id_col = str_init("set_id");
static db_con_t *db_connection = NULL;
static db_func_t db_functions;

static rw_lock_t *nh_lock=NULL;

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
	{"set_rtp_proxy_set",  (cmd_function)set_rtp_proxy_set_f,    1,
		fixup_set_id, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"unforce_rtp_proxy",  (cmd_function)unforce_rtp_proxy_f,    0,
		0, 0,
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
	{"start_recording",    (cmd_function)start_recording_f,      0,
		0, 0,
		REQUEST_ROUTE | ONREPLY_ROUTE },
	{"rtpproxy_offer",	(cmd_function)rtpproxy_offer1_f,     0,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_offer",	(cmd_function)rtpproxy_offer1_f,     1,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_offer",	(cmd_function)rtpproxy_offer2_f,     2,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_answer",	(cmd_function)rtpproxy_answer1_f,    0,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_answer",	(cmd_function)rtpproxy_answer1_f,    1,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_answer",	(cmd_function)rtpproxy_answer2_f,    2,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_stream2uac",(cmd_function)rtpproxy_stream2uac2_f, 2,
		fixup_var_str_int, 0,
		REQUEST_ROUTE | ONREPLY_ROUTE },
	{"rtpproxy_stream2uas",(cmd_function)rtpproxy_stream2uas2_f, 2,
		fixup_var_str_int, 0,
		REQUEST_ROUTE | ONREPLY_ROUTE },
	{"rtpproxy_stop_stream2uac",(cmd_function)rtpproxy_stop_stream2uac2_f,0,
		NULL, 0,
		REQUEST_ROUTE | ONREPLY_ROUTE },
	{"rtpproxy_stop_stream2uas",(cmd_function)rtpproxy_stop_stream2uas2_f,0,
		NULL, 0,
		REQUEST_ROUTE | ONREPLY_ROUTE },
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[] = {
	{"natping_interval",      INT_PARAM, &natping_interval      },
	{"ping_nated_only",       INT_PARAM, &ping_nated_only       },
	{"nortpproxy_str",        STR_PARAM, &nortpproxy_str.s      },
	{"rtpproxy_sock",         STR_PARAM|USE_FUNC_PARAM,
	                         (void*)rtpproxy_set_store          },
	{"rtpproxy_disable_tout", INT_PARAM, &rtpproxy_disable_tout },
	{"rtpproxy_retr",         INT_PARAM, &rtpproxy_retr         },
	{"rtpproxy_tout",         INT_PARAM, &rtpproxy_tout         },
	{"rtpproxy_timeout",      STR_PARAM, &rtpproxy_timeout      },
	{"received_avp",          STR_PARAM, &rcv_avp_param         },
	{"force_socket",          STR_PARAM, &force_socket_str      },
	{"sipping_from",          STR_PARAM, &sipping_from.s        },
	{"sipping_method",        STR_PARAM, &sipping_method.s      },
	{"sipping_bflag",         INT_PARAM, &sipping_flag          },
	{"natping_processes",     INT_PARAM, &natping_processes     },
	{"natping_socket",        STR_PARAM, &natping_socket        },
	{"db_url",                STR_PARAM, &db_url.s              },
	{"db_table",              STR_PARAM, &table.s               },
	{"rtpp_socket_col",       STR_PARAM, &rtpp_sock_col.s       },
	{"set_id_col",            STR_PARAM, &set_id_col.s          },
	{"detect_rtp_idle",       INT_PARAM, &detect_rtp_idle       },
	{"rtpp_notify_socket",    STR_PARAM, &rtpp_notify_socket.s  },
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{MI_SET_NATPING_STATE,    mi_enable_natping,    0,                0, 0},
	{MI_ENABLE_RTP_PROXY,     mi_enable_rtp_proxy,  0,                0, 0},
	{MI_SHOW_RTP_PROXIES,     mi_show_rtpproxies,   MI_NO_INPUT_FLAG, 0, 0},
	{MI_RELOAD_RTP_PROXIES,   mi_reload_rtpproxies, MI_NO_INPUT_FLAG, 0,
		mi_child_init},
	{ 0, 0, 0, 0, 0}
};

static proc_export_t procs[] = {
	{"RTPP timeout receiver",  0,  0, timeout_listener_process, 1, 0},
	{0,0,0,0,0,0}
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
	procs,       /* extra processes */
	mod_init,
	0,           /* reply processing */
	mod_destroy, /* destroy function */
	child_init
};


static int rtpproxy_set_store(modparam_t type, void * val){

	char * p;
	int len;

	p = (char* )val;

	if(p==0 || *p=='\0'){
		return 0;
	}

	if(rtpp_sets==0){
		rtpp_strings = (char**)pkg_malloc(sizeof(char*));
		if(!rtpp_strings){
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	} else {/*realloc to make room for the current set*/
		rtpp_strings = (char**)pkg_realloc(rtpp_strings, 
										  (rtpp_sets+1)* sizeof(char*));
		if(!rtpp_strings){
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	}
	
	/*allocate for the current set of urls*/
	len = strlen(p);
	rtpp_strings[rtpp_sets] = (char*)pkg_malloc((len+1)*sizeof(char));

	if(!rtpp_strings[rtpp_sets]){
		LM_ERR("no pkg memory left\n");
		return -1;
	}
	
	memcpy(rtpp_strings[rtpp_sets], p, len);
	rtpp_strings[rtpp_sets][len] = '\0';
	rtpp_sets++;

	return 0;
}


static int add_rtpproxy_socks(struct rtpp_set * rtpp_list, 
										char * rtpproxy){
	/* Make rtp proxies list. */
	char *p, *p1, *p2, *plim;
	struct rtpp_node *pnode;
	int weight;

	p = rtpproxy;
	plim = p + strlen(p);

	for(;;) {
			weight = 1;
		while (*p && isspace((int)*p))
			++p;
		if (p >= plim)
			break;
		p1 = p;
		while (*p && !isspace((int)*p))
			++p;
		if (p <= p1)
			break; /* may happen??? */
		/* Have weight specified? If yes, scan it */
		p2 = memchr(p1, '=', p - p1);
		if (p2 != NULL) {
			weight = strtoul(p2 + 1, NULL, 10);
		} else {
			p2 = p;
		}
		pnode = shm_malloc(sizeof(struct rtpp_node));
		if (pnode == NULL) {
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(pnode, 0, sizeof(*pnode));
		pnode->idx = *rtpp_no;
		*rtpp_no = *rtpp_no + 1;
		pnode->rn_recheck_ticks = 0;
		pnode->rn_weight = weight;
		pnode->rn_umode = 0;
		pnode->rn_disabled = 0;
		pnode->rn_url.s = shm_malloc(p2 - p1 + 1);
		if (pnode->rn_url.s == NULL) {
			shm_free(pnode);
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memmove(pnode->rn_url.s, p1, p2 - p1);
		pnode->rn_url.s[p2 - p1] 	= 0;
		pnode->rn_url.len 			= p2-p1;

		LM_DBG("url is %s, len is %i\n", pnode->rn_url.s, pnode->rn_url.len);
		/* Leave only address in rn_address */
		pnode->rn_address = pnode->rn_url.s;
		if (strncasecmp(pnode->rn_address, "udp:", 4) == 0) {
			pnode->rn_umode = 1;
			pnode->rn_address += 4;
		} else if (strncasecmp(pnode->rn_address, "udp6:", 5) == 0) {
			pnode->rn_umode = 6;
			pnode->rn_address += 5;
		} else if (strncasecmp(pnode->rn_address, "unix:", 5) == 0) {
			pnode->rn_umode = 0;
			pnode->rn_address += 5;
		}

		if (rtpp_list->rn_first == NULL) {
			rtpp_list->rn_first = pnode;
		} else {
			rtpp_list->rn_last->rn_next = pnode;
		}

		rtpp_list->rn_last = pnode;
		rtpp_list->rtpp_node_count++;
	}
	return 0;
}


/*	0-succes
 *  -1 - erorr
 * */
static int nathelper_add_rtpproxy_set( char * rtp_proxies, int set_id)
{
	char *p,*p2;
	struct rtpp_set * rtpp_list;
	unsigned int my_current_id;
	str id_set;
	int new_list;

	/* empty definition? */
	p= rtp_proxies;
	if(!p || *p=='\0'){
		return 0;
	}

	for(;*p && isspace(*p);p++);
	if(*p=='\0'){
		return 0;
	}

	if(set_id < 0)
	{
		rtp_proxies = strstr(p, "==");
		if(rtp_proxies){
			if(*(rtp_proxies +2)=='\0'){
				LM_ERR("script error -invalid rtp proxy list!\n");
				return -1;
			}
			
			*rtp_proxies = '\0';
			p2 = rtp_proxies-1;
			for(;isspace(*p2); *p2 = '\0',p2--);
			id_set.s = p;	id_set.len = p2 - p+1;
				
			if(id_set.len <= 0 ||str2int(&id_set, &my_current_id)<0 ){
			LM_ERR("script error -invalid set_id value!\n");
				return -1;
			}
				
			rtp_proxies+=2;
		}else{
			rtp_proxies = p;
			my_current_id = DEFAULT_RTPP_SET_ID;
		}
	}
	else{
		rtp_proxies = p;
		my_current_id = set_id;
	}

	for(;*rtp_proxies && isspace(*rtp_proxies);rtp_proxies++);

	if(!(*rtp_proxies)){
		LM_ERR("script error -empty rtp_proxy list\n");
		return -1;
	}

	/*search for the current_id*/
	rtpp_list = rtpp_set_list ? rtpp_set_list->rset_first : 0;
	while( rtpp_list != 0 && rtpp_list->id_set!=my_current_id)
		rtpp_list = rtpp_list->rset_next;

	if(rtpp_list==NULL){	/*if a new id_set : add a new set of rtpp*/
		rtpp_list = shm_malloc(sizeof(struct rtpp_set));
		if(!rtpp_list){
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(rtpp_list, 0, sizeof(struct rtpp_set));
		rtpp_list->id_set = my_current_id;
		new_list = 1;
	} else {
		new_list = 0;
	}

	if(add_rtpproxy_socks(rtpp_list, rtp_proxies)!= 0){
		/*if this list will not be inserted, clean it up*/
		goto error;
	}

	if (new_list) {
		if(!rtpp_set_list){/*initialize the list of set -
							 executed only on the first call*/
			rtpp_set_list = shm_malloc(sizeof(struct rtpp_set_head));
			if(!rtpp_set_list){
				LM_ERR("no shm memory left\n");
				return -1;
			}
			memset(rtpp_set_list, 0, sizeof(struct rtpp_set_head));
		}

		/*update the list of set info*/
		if(!rtpp_set_list->rset_first){
			rtpp_set_list->rset_first = rtpp_list;
		}else{
			rtpp_set_list->rset_last->rset_next = rtpp_list;
		}

		rtpp_set_list->rset_last = rtpp_list;
		rtpp_set_count++;
	}

	return 0;
error:
	return -1;
}


static int fixup_set_id(void ** param, int param_no)
{
	int int_val, err;
	struct rtpp_set* rtpp_list;
	nh_set_param_t * pset;
	char *p;

	pset = (nh_set_param_t *) pkg_malloc(sizeof(nh_set_param_t));
	if(pset == NULL){
		LM_ERR("no more pkg memory to allocate set parameter\n");
		return E_OUT_OF_MEM;
	}
	memset(pset, 0, sizeof(nh_set_param_t));

	if (param_no > 1) {
		LM_ERR("set_rtp_proxy_set() takes only one parameter.\n");
		pkg_free(pset);
		return E_CFG;
	}

	p = (char*) *param;
	if(*p != '$')
	{
		/* Fixed value specifed for RTP rpoxy set */
		int_val = str2s(p, strlen(p), &err);
		if (err == 0) {
			pkg_free(*param);
			rtpp_list = select_rtpp_set(int_val);
			if(rtpp_list ==0){
				LM_ERR("rtpp_proxy set %i not configured\n", int_val);
				return E_CFG;
			}
			pset->t = NH_VAL_SET_FIXED ;
			pset->v.fixed_set = rtpp_list;
			*param = (void *) pset;
			return 0;
		} else {
			LM_ERR("bad rtp set number <%s> specified\n", p);
			pkg_free(pset);
			return E_CFG;
		}
	} else {
		/* proxyset is specified as an AVP */
		str lstr;
		
		lstr.s = p;
		lstr.len = strlen(p);
		if ( pv_parse_spec( &lstr, &pset->v.var_set) == NULL ) {
			LM_ERR("bad rtp set variable <%s> specified\n",   p);
			pkg_free(pset);
			return E_CFG;
		}

		pset->t = NH_VAL_SET_SPEC;
		*param = (void *) pset;
		return 0;
	}
}



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
	if (rcv_avp_name.n == 0) {
		LM_ERR("you must set 'received_avp' parameter. Must be same value as"
				" parameter 'received_avp' of registrar module\n");
		return -1;
	}
	return 0;
}

static struct mi_root* mi_enable_rtp_proxy(struct mi_root* cmd_tree, 
												void* param )
{	struct mi_node* node;
	str rtpp_url;
	unsigned int enable;
	struct rtpp_set * rtpp_list;
	struct rtpp_node * crt_rtpp;
	int found;

	found = 0;

	if(rtpp_set_list ==NULL)
		goto end;

	node = cmd_tree->node.kids;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if(node->value.s == NULL || node->value.len ==0)
		return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

	rtpp_url = node->value;

	node = node->next;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	enable = 0;
	if( strno2int( &node->value, &enable) <0)
		goto error;

	for(rtpp_list = rtpp_set_list->rset_first; rtpp_list != NULL; 
					rtpp_list = rtpp_list->rset_next){

		for(crt_rtpp = rtpp_list->rn_first; crt_rtpp != NULL;
						crt_rtpp = crt_rtpp->rn_next){
			/*found a matching rtpp*/
			
			if(crt_rtpp->rn_url.len == rtpp_url.len){
				
				if(strncmp(crt_rtpp->rn_url.s, rtpp_url.s, rtpp_url.len) == 0){
					/*set the enabled/disabled status*/
					found = 1;
					crt_rtpp->rn_recheck_ticks = 
						enable? MI_MIN_RECHECK_TICKS : MI_MAX_RECHECK_TICKS;
					crt_rtpp->rn_disabled = enable?0:1;
				}
			}
		}
	}

end:
	if(found)
		return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	return init_mi_tree(404,MI_RTP_PROXY_NOT_FOUND,MI_RTP_PROXY_NOT_FOUND_LEN);
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
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



#define add_rtpp_node_int_info(_parent, _name, _name_len, _value, _child,\
								_len, _string, _error)\
	do {\
		(_string) = int2str((_value), &(_len));\
		if((_string) == 0){\
			LM_ERR("cannot convert int value\n");\
				goto _error;\
		}\
		if(((_child) = add_mi_node_child((_parent), MI_DUP_VALUE, (_name), \
				(_name_len), (_string), (_len))   ) == 0)\
			goto _error;\
	}while(0);

static struct mi_root* mi_reload_rtpproxies(struct mi_root* cmd_tree, void* param)
{
	if(db_url.s == NULL) {
		LM_ERR("Dynamic loading of rtpproxies not enabled\n");
		return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
	}

	lock_start_write( nh_lock );
	if(rtpp_set_list) {
		free_rtpp_sets();
	}
	*rtpp_no = 0;
	(*list_version)++;

	/* notify timeout process that the rtpp proxy list changes */
	lock_get( rtpp_notify_h->lock );
	rtpp_notify_h->changed = 1;

	if(_add_proxies_from_database() < 0) {
		lock_release( rtpp_notify_h->lock );
		goto error;
	}
	lock_release( rtpp_notify_h->lock );
	
	if (update_rtpp_proxies())
		goto error;

	/* update pointer to default_rtpp_set*/
	*default_rtpp_set = select_rtpp_set(DEFAULT_RTPP_SET_ID);
	
	/* release the readers */
	lock_stop_write( nh_lock );

	return init_mi_tree(200, MI_OK_S, MI_OK_LEN);
error:
	lock_stop_write( nh_lock );
	return init_mi_tree( 500, MI_INTERNAL_ERR_S, MI_INTERNAL_ERR_LEN);
}

static struct mi_root* mi_show_rtpproxies(struct mi_root* cmd_tree, 
												void* param)
{
	struct mi_node* node, *crt_node, *child;
	struct mi_root* root;
	struct mi_attr * attr;
	struct rtpp_set * rtpp_list;
	struct rtpp_node * crt_rtpp;
	char * string, *id;
	int id_len, len;

	string = id = 0;

	root = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (!root) {
		LM_ERR("the MI tree cannot be initialized!\n");
		return 0;
	}

	if(rtpp_set_list ==NULL)
		return root;

	node = &root->node;

	for(rtpp_list = rtpp_set_list->rset_first; rtpp_list != NULL; 
					rtpp_list = rtpp_list->rset_next){

		for(crt_rtpp = rtpp_list->rn_first; crt_rtpp != NULL;
						crt_rtpp = crt_rtpp->rn_next){

			id =  int2str(rtpp_list->id_set, &id_len);
			if(!id){
				LM_ERR("cannot convert set id\n");
				goto error;
			}

			if(!(crt_node = add_mi_node_child(node, 0, crt_rtpp->rn_url.s, 
					crt_rtpp->rn_url.len, 0,0)) ) {
				LM_ERR("cannot add the child node to the tree\n");
				goto error;
			}

			LM_DBG("adding node name %s \n",crt_rtpp->rn_url.s );

			if((attr = add_mi_attr(crt_node, MI_DUP_VALUE, MI_SET, MI_SET_LEN, 
									id, id_len))== 0){
				LM_ERR("cannot add attributes to the node\n");
				goto error;
			}

			add_rtpp_node_int_info(crt_node, MI_INDEX, MI_INDEX_LEN,
				crt_rtpp->idx, child, len,string,error);
			add_rtpp_node_int_info(crt_node, MI_DISABLED, MI_DISABLED_LEN,
				crt_rtpp->rn_disabled, child, len,string,error);
			add_rtpp_node_int_info(crt_node, MI_WEIGHT, MI_WEIGHT_LEN,
				crt_rtpp->rn_weight,  child, len, string,error);
			add_rtpp_node_int_info(crt_node, MI_RECHECK_TICKS,MI_RECHECK_T_LEN,
				crt_rtpp->rn_recheck_ticks, child, len, string, error);
		}
	}

	return root;
error:
	if (root)
		free_mi_tree(root);
	return 0;
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
	struct in_addr addr;
	str socket_str;
	pv_spec_t avp_spec;
	str s;
	float timeout;

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
		rcv_avp_name.n = 0;
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
		if (natping_processes>=8) {
			LM_ERR("too many natping processes (%d) max=8\n",
				natping_processes);
			return -1;
		}

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
			if (register_timer_process( nh_timer, (void*)(unsigned long)i, 1,
			TIMER_PROC_INIT_FLAG)<0) {
				LM_ERR("failed to register timer routine as process\n");
				return -1;
			}
		}
	}

	/* Prepare 1918 networks list */
	for (i = 0; nets_1918[i].cnetaddr != NULL; i++) {
		if (inet_aton(nets_1918[i].cnetaddr, &addr) != 1)
			abort();
		nets_1918[i].netaddr = ntohl(addr.s_addr) & nets_1918[i].mask;
	}
	
	rtpp_no = (unsigned int*)shm_malloc(sizeof(unsigned int));
	list_version = (unsigned int*)shm_malloc(sizeof(unsigned int));
	*rtpp_no = 0;
	*list_version = 0;
	my_version = 0;
	
	if(!rtpp_no || !list_version) {
		LM_ERR("No more shared memory\n");
		return -1;
	}

	if(db_url.s == NULL)
	{
		/* storing the list of rtp proxy sets in shared memory*/
		for(i=0;i<rtpp_sets;i++){
			if(nathelper_add_rtpproxy_set(rtpp_strings[i], -1) !=0){
				for(;i<rtpp_sets;i++)
					if(rtpp_strings[i])
						pkg_free(rtpp_strings[i]);
				pkg_free(rtpp_strings);
				return -1;
			}
			if(rtpp_strings[i])
				pkg_free(rtpp_strings[i]);
		}
		if (rtpp_strings)
			pkg_free(rtpp_strings);
	} else {
		db_url.len = strlen(db_url.s);
		table.len = strlen(table.s);
		rtpp_sock_col.len = strlen(rtpp_sock_col.s);
		set_id_col.len = strlen(set_id_col.s);

		if(db_bind_mod(&db_url, &db_functions) == -1) {
			LM_ERR("Failed bind to database\n");
			return -1;
		} 

		if (!DB_CAPABILITY(db_functions, DB_CAP_ALL))
		{
			LM_ERR("Database module does not implement all functions"
					" needed by presence module\n");
			return -1;
		}

		db_connection = db_functions.init(&db_url);
		if(db_connection == NULL) {
			LM_ERR("Failed to connect to database");
			return -1;
		}

		/*verify table versions */
		if(db_check_table_version(&db_functions, db_connection, &table,
					NH_TABLE_VERSION) < 0){
				LM_ERR("error during table version check\n");
				return -1;
		}

		if(_add_proxies_from_database() != 0) {
			return -1;
		}
		
		db_functions.close(db_connection);
		db_connection = NULL;
		if ((nh_lock = lock_init_rw()) == NULL) {
			LM_CRIT("failed to init lock\n");
			return -1;
		}
	}
	
	default_rtpp_set = (struct rtpp_set**)shm_malloc(sizeof(struct rtpp_set*));
	if(default_rtpp_set == NULL)
	{
		LM_ERR("No more shared memory\n");
		return -1;
	}
	*default_rtpp_set = NULL;

	/* any rtpproxy configured? */
	if(rtpp_set_list)
		*default_rtpp_set = select_rtpp_set(DEFAULT_RTPP_SET_ID);

	/* configure rtpproxy timeout */
	if(rtpproxy_timeout && sscanf(rtpproxy_timeout, "%f", &timeout)) {
		if(rtpproxy_tout != -1) {
			LM_ERR("you can't use rtpproxy_timeout and rtpproxy_tout : \n"
				"check your config !\n");
			return -1;
		}
		rtpproxy_tout = (int) (timeout * 1000);
	} else if(rtpproxy_tout < 0) {
		/* not defined : set default value */
		rtpproxy_tout = 1000;
	} else {
		LM_WARN("rtpproxy_tout param is obsolete, please replace with \n"
			"rtpproxy_timeout\n");
		rtpproxy_tout = rtpproxy_tout * 1000;
	}

	/* load dlg api */
	memset(&dlg_api, 0, sizeof(struct dlg_binds));
	if (load_dlg_api(&dlg_api)!=0)
		LM_DBG("dialog module not loaded.\n");

    if(detect_rtp_idle) {
        /* check if the notify socket parameter is set */
        if(rtpp_notify_socket.s == NULL) {
            LM_ERR("If you want to detect RTP idle, you need to define rtpp_notify_socket\n");
            return -1;
        }
        rtpp_notify_socket.len = strlen(rtpp_notify_socket.s);
        if(dlg_api.get_dlg == 0) {
            LM_ERR("You need to load dialog module if you want to use the"
                    " detect_rtp_idle feature\n");
            return -1;
        }

		rtpp_notify_h = (struct rtpp_notify_head *)
			shm_malloc(sizeof(struct rtpp_notify_head));
		if (!rtpp_notify_h) {
			LM_ERR("no more shm memory\n");
			return -1;
		}
		rtpp_notify_h->lock = lock_alloc();
		if(!rtpp_notify_h->lock) {
			LM_ERR("failed to alloc timeout notify lock\n");
			return -1;
		}
		if (!lock_init(rtpp_notify_h->lock)) {
			LM_CRIT("failed to init timeout notify lock\n");
			return -1;
		}
		rtpp_notify_h->changed = 0;
		rtpp_notify_h->rtpp_list = NULL;

		if (init_rtpp_notify_list() < 0) {
			LM_ERR("cannot find any valid rtpproxy to use\n");
			return -1;
		}
    }
    else
    {
        exports.procs = 0;
    }

	return 0;
}

static int mi_child_init(void)
{
	if(!db_url.s)
		return 0;
	
	if (db_functions.init==0)
	{
		LM_CRIT("database not bound\n");
		return -1;
	}

	db_connection = db_functions.init(&db_url);
	if(db_connection == NULL) {
		LM_ERR("Failed to connect to database");
		return -1;
	}
	
	LM_DBG("Database connection opened successfully\n");

	return 0;
}

static int _add_proxies_from_database(void) {

	/* select * from nh_sockets */
	db_key_t colsToReturn[2];
	db_res_t *result = NULL;
	int rowCount = 0;
	char *rtpp_socket;
	db_row_t *row;
	db_val_t *row_vals;
	int set_id;

	colsToReturn[0]=&rtpp_sock_col;
	colsToReturn[1]=&set_id_col;

	if(db_functions.use_table(db_connection, &table) < 0) {
		LM_ERR("Error trying to use table\n");
		return -1;
	}

	if(db_functions.query(db_connection, 0, 0, 0,colsToReturn, 0, 2, 0,
				&result) < 0) {
		LM_ERR("Error querying database");
		if(result)
			db_functions.free_result(db_connection, result);
		return -1;
	}

	if(result == NULL)
	{
		LM_ERR("mysql query failed - NULL result");
		return -1;
	}

	if (RES_ROW_N(result)<=0 || RES_ROWS(result)[0].values[0].nul != 0) {
		LM_DBG("No proxies were found\n");
		if(db_functions.free_result(db_connection, result) < 0){
			LM_ERR("Error freeing result\n");
		}
		return -1;
	}

	for(rowCount=0; rowCount < RES_ROW_N(result); rowCount++) {
		
		row= &result->rows[rowCount];
		row_vals = ROW_VALUES(row);

		rtpp_socket = (char*)row_vals[0].val.string_val;
		if(rtpp_socket == NULL)
		{
			LM_ERR("NULL value for rtpproxy_socket column\n");
			goto error;
		}
		set_id= row_vals[1].val.int_val;

		if(nathelper_add_rtpproxy_set(rtpp_socket, set_id) == -1)
		{
			LM_ERR("faild to add rtp proxy\n");
			goto error;
		}
	}

	db_functions.free_result(db_connection, result);
		
	return 0;

error:
	if(result)
		db_functions.free_result(db_connection, result);
	return -1;
}

static int
child_init(int rank)
{
	if (rank<=0 && rank!=PROC_TIMER)
		return 0;

	if(rtpp_set_list==NULL )
		return 0;

	mypid = getpid();

	return connect_rtpproxies();
}

int connect_rtpproxies(void)
{
	int n;
	char *cp;
	struct addrinfo hints, *res;
	struct rtpp_set  *rtpp_list;
	struct rtpp_node *pnode;


	if(rtpp_set_list==NULL )
		return 0;

	if (*rtpp_no > rtpp_number) {
		rtpp_socks = (int*)pkg_realloc(rtpp_socks, *rtpp_no * sizeof(int) );
		if (rtpp_socks==NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
	}
	rtpp_number = *rtpp_no;

	for(rtpp_list = rtpp_set_list->rset_first; rtpp_list != 0;
		rtpp_list = rtpp_list->rset_next){

		for (pnode=rtpp_list->rn_first; pnode!=0; pnode = pnode->rn_next){
			char *hostname;

			if (pnode->rn_umode == 0) {
				rtpp_socks[pnode->idx] = -1;
				goto rptest;
			}

			/*
			 * This is UDP or UDP6. Detect host and port; lookup host;
			 * do connect() in order to specify peer address
			 */
			hostname = (char*)pkg_malloc(sizeof(char) * (strlen(pnode->rn_address) + 1));
			if (hostname==NULL) {
				LM_ERR("no more pkg memory\n");
				return -1;
			}
			strcpy(hostname, pnode->rn_address);

			cp = strrchr(hostname, ':');
			if (cp != NULL) {
				*cp = '\0';
				cp++;
			}
			if (cp == NULL || *cp == '\0')
				cp = CPORT;

			memset(&hints, 0, sizeof(hints));
			hints.ai_flags = 0;
			hints.ai_family = (pnode->rn_umode == 6) ? AF_INET6 : AF_INET;
			hints.ai_socktype = SOCK_DGRAM;
			if ((n = getaddrinfo(hostname, cp, &hints, &res)) != 0) {
				LM_ERR("%s\n", gai_strerror(n));
				pkg_free(hostname);
				return -1;
			}
			pkg_free(hostname);

			rtpp_socks[pnode->idx] = socket((pnode->rn_umode == 6)
			    ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
			if ( rtpp_socks[pnode->idx] == -1) {
				LM_ERR("can't create socket\n");
				freeaddrinfo(res);
				return -1;
			}

			if (connect( rtpp_socks[pnode->idx], res->ai_addr, res->ai_addrlen) == -1) {
				LM_ERR("can't connect to a RTP proxy\n");
				close( rtpp_socks[pnode->idx] );
				rtpp_socks[pnode->idx] = -1;
				freeaddrinfo(res);
				return -1;
			}
			freeaddrinfo(res);
			LM_DBG("connected %s\n", pnode->rn_address);
rptest:
			pnode->rn_disabled = rtpp_test(pnode, 0, 1);
		}
	}

	return 0;
}

int update_rtpp_proxies(void) {
	int i;

	LM_DBG("updating list from %d to %d\n", my_version, *list_version);
	my_version = *list_version;
	for (i = 0; i < rtpp_number; i++) {
		shutdown(rtpp_socks[i], SHUT_RDWR);
		close(rtpp_socks[i]);
	}

	return connect_rtpproxies();
}


void free_rtpp_sets(void)
{	
	struct rtpp_set * crt_list, * last_list;
	struct rtpp_node * crt_rtpp, *last_rtpp;

	for(crt_list = rtpp_set_list->rset_first; crt_list != NULL; ){

		for(crt_rtpp = crt_list->rn_first; crt_rtpp != NULL;  ){

			if(crt_rtpp->rn_url.s)
				shm_free(crt_rtpp->rn_url.s);

			last_rtpp = crt_rtpp;
			crt_rtpp = last_rtpp->rn_next;
			shm_free(last_rtpp);
		}

		last_list = crt_list;
		crt_list = last_list->rset_next;
		shm_free(last_list);
		last_list = NULL;
	}
	rtpp_set_list->rset_first = NULL;
	rtpp_set_list->rset_last = NULL;
}

static void mod_destroy(void)
{
	/*free the shared memory*/
	if (natping_state)
		shm_free(natping_state);

	if (default_rtpp_set)
		shm_free(default_rtpp_set);

	if(rtpp_set_list == NULL)
		return;

	free_rtpp_sets();
	shm_free(rtpp_set_list);

	if(nh_lock)
	{
		lock_destroy_rw( nh_lock );
		nh_lock = NULL;
	}
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
	str hostport, left;
	int is_enclosed;
	str *params = (str*)str1;

	if (params && params->len==0)
		params = 0;

	for ( c=NULL,hdr=NULL ; get_contact_uri(msg, &uri, &c, &hdr)==0 ; ) {

		hostport = uri.host;
		if (uri.port.len > 0)
			hostport.len = uri.port.s + uri.port.len - uri.host.s;
		left.s = hostport.s + hostport.len;
		left.len = c->uri.s+c->uri.len - left.s;

		is_enclosed = 0;
		p = hostport.s + hostport.len; /*start searching after ip:port */
		cp = (c->name.s?c->name.s:c->uri.s) + c->len; /* where to end */
		for( ; p<cp ; p++ )
			if (*p=='>') {is_enclosed=1;hostport.len=p-uri.host.s;break;}

		//LM_DBG("--removing %d |%.*s|\n",hostport.s+hostport.len-c->uri.s,
		//	hostport.s+hostport.len-c->uri.s, c->uri.s);
		anchor = del_lump(msg, c->uri.s-msg->buf /* offset */,
			hostport.s+hostport.len-c->uri.s /* len */, 0);
		if (anchor == 0)
			return -1;

		cp = ip_addr2a(&msg->rcv.src_ip);
		len = (hostport.s-c->uri.s) + strlen(cp) + 6 /* :port */
			+ (params?params->len+(is_enclosed?0:2):0) + 1 + left.len;
		buf = pkg_malloc(len);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		temp = hostport.s[0]; hostport.s[0] = '\0';
		if (params==NULL) {
			len1 = snprintf(buf, len, "%s%s:%d%.*s", c->uri.s, cp,
				msg->rcv.src_port,left.len,left.s);
		} else if (!is_enclosed) {
			len1 = snprintf(buf, len, "<%s%s:%d%.*s>", c->uri.s, cp,
				msg->rcv.src_port,params->len,params->s);
		} else {
			len1 = snprintf(buf, len, "%s%s:%d%.*s%.*s", c->uri.s, cp,
				msg->rcv.src_port,params->len,params->s,left.len,left.s);
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
 * Test if IP address pointed to by saddr belongs to RFC1918 networks
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
 * test for occurrence of RFC1918 IP address in Contact HF
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
 * test for occurrence of RFC1918 IP address in SDP
 */
static int
sdp_1918(struct sip_msg* msg)
{
	str body, ip;
	int pf;

	if (extract_body(msg, &body) == -1) {
		LM_ERR("cannot extract body from msg!\n");
		return 0;
	}
	if (extract_mediaip(&body, &ip, &pf,"c=") == -1) {
		LM_ERR("can't extract media IP from the SDP\n");
		return 0;
	}
	if (pf != AF_INET || isnulladdr(&ip, pf))
		return 0;

	return (is1918addr(&ip) == 1) ? 1 : 0;
}

/*
 * test for occurrence of RFC1918 IP address in top Via
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
	 * test for occurrences of RFC1918 addresses in Contact
	 * header field
	 */
	if ((tests & NAT_UAC_TEST_C_1918) && (contact_1918(msg)>0))
		return 1;
	/*
	 * test for occurrences of RFC1918 addresses in SDP body
	 */
	if ((tests & NAT_UAC_TEST_S_1918) && sdp_1918(msg))
		return 1;
	/*
	 * test for occurrences of RFC1918 addresses top Via
	 */
	if ((tests & NAT_UAC_TEST_V_1918) && via_1918(msg))
		return 1;
	/*
	 * test if source address of signaling is different from
	 * address advertised in Contact
	 */
	if ((tests & NAT_UAC_TEST_C_RCVD) && contact_rcv(msg))
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

#define	AOLDMEDPRT	"a=oldmediaport:"
#define	AOLDMEDPRT_LEN	(sizeof(AOLDMEDPRT) - 1)


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

	level = (int)(long)str1;
	if (str2 && pv_printf_s( msg, (pv_elem_p)str2, &ip)!=0)
		return -1;

	if (extract_body(msg, &body) == -1) {
		LM_ERR("cannot extract body from msg!\n");
		return -1;
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
				LM_ERR("insert_new_lump_after failed\n");
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
				LM_ERR("insert_new_lump_after failed\n");
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

	return 1;
}


static int
extract_mediainfo(str *body, str *mediaport, str *payload_types)
{
	char *cp, *cp1;
	int len, i;
	str ptype;

	cp1 = NULL;
	for (cp = body->s; (len = body->s + body->len - cp) > 0;) {
		cp1 = ser_memmem(cp, "m=", len, 2);
		if (cp1 == NULL || cp1[-1] == '\n' || cp1[-1] == '\r')
			break;
		cp = cp1 + 2;
	}
	if (cp1 == NULL) {
		LM_ERR("no `m=' in SDP\n");
		return -1;
	}
	mediaport->s = cp1 + 2; /* skip `m=' */
	mediaport->len = eat_line(mediaport->s, body->s + body->len -
	  mediaport->s) - mediaport->s;
	trim_len(mediaport->len, mediaport->s, *mediaport);

	/* Skip media supertype and spaces after it */
	cp = eat_token_end(mediaport->s, mediaport->s + mediaport->len);
	mediaport->len -= cp - mediaport->s;
	if (mediaport->len <= 0 || cp == mediaport->s) {
		LM_ERR("no port in `m='\n");
		return -1;
	}
	mediaport->s = cp;
	cp = eat_space_end(mediaport->s, mediaport->s + mediaport->len);
	mediaport->len -= cp - mediaport->s;
	if (mediaport->len <= 0 || cp == mediaport->s) {
		LM_ERR("no port in `m='\n");
		return -1;
	}
	/* Extract port */
	mediaport->s = cp;
	cp = eat_token_end(mediaport->s, mediaport->s + mediaport->len);
	ptype.len = mediaport->len - (cp - mediaport->s);
	if (ptype.len <= 0 || cp == mediaport->s) {
		LM_ERR("no port in `m='\n");
		return -1;
	}
	ptype.s = cp;
	mediaport->len = cp - mediaport->s;
	/* Skip spaces after port */
	cp = eat_space_end(ptype.s, ptype.s + ptype.len);
	ptype.len -= cp - ptype.s;
	if (ptype.len <= 0 || cp == ptype.s) {
		LM_ERR("no protocol type in `m='\n");
		return -1;
	}
	/* Extract protocol type */
	ptype.s = cp;
	cp = eat_token_end(ptype.s, ptype.s + ptype.len);
	if (cp == ptype.s) {
		LM_ERR("no protocol type in `m='\n");
		return -1;
	}
	payload_types->len = ptype.len - (cp - ptype.s);
	ptype.len = cp - ptype.s;
	payload_types->s = cp;

	for (i = 0; sup_ptypes[i].s != NULL; i++) {
		if (ptype.len != sup_ptypes[i].len ||
		    strncasecmp(ptype.s, sup_ptypes[i].s, ptype.len) != 0)
			continue;
		if (sup_ptypes[i].is_rtp == 0) {
			payload_types->len = 0;
			return 0;
		}
		cp = eat_space_end(payload_types->s, payload_types->s +
		    payload_types->len);
		if (cp == payload_types->s) {
			LM_ERR("no payload types in `m='\n");
			return -1;
		}
		payload_types->len -= cp - payload_types->s;
		payload_types->s = cp;
		return 0;
	}
	/* Unproxyable protocol type. Generally it isn't error. */
	return -1;
}

static int alter_rtcp(struct sip_msg *msg,str *newip, int newpf ,str* newport,
			char * line_start )
{

	static const  str field = str_init("a=rtcp:");

	str buff = {0,0} ;
	str type;
	int offset;
	struct lump* anchor;
	str body, value;
	
	body.s = line_start;
	body.len = msg->buf + msg->len - line_start;


	if( extract_field( &body, &value, field) < 0 )
	{
		LM_ERR("Unable to extract rtcp body\n");
		return -1;
	}



	if( newpf == AF_INET6 )
		type.s = " IN IP6 ";
	else
		type.s = " IN IP4 ";

	type.len = strlen(type.s);


	buff.len += newport->len + type.len + newip->len ;

	buff.s = pkg_malloc( buff.len + 1 );

	if( buff.s == 0 )
	{
		LM_ERR("Not enough memory\n");
		return -1;
	}

	sprintf( buff.s, "%.*s%.*s%.*s",
		 newport->len, newport->s,
		 type.len, type.s,
		 newip->len, newip->s );


	offset = value.s - msg->buf;

	anchor = del_lump(msg, offset, value.len, 0);

	if (anchor == NULL) {
		LM_ERR("del_lump failed\n");
		pkg_free(buff.s);
		return -1;
	}

	if (insert_new_lump_after(anchor, buff.s, buff.len, 0) == 0) {
		LM_ERR("insert_new_lump_after failed\n");
		pkg_free(buff.s);
		return -1;
	}

	return 0;
}


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

static int
alter_mediaport(struct sip_msg *msg, str *body, str *oldport, str *newport,
  int preserve)
{
	char *buf;
	int offset;
	struct lump* anchor;

	/* check that updating mediaport is really necessary */
	if (newport->len == oldport->len &&
	    memcmp(newport->s, oldport->s, newport->len) == 0)
		return 0;

	/*
	 * Since rewriting the same info twice will mess SDP up,
	 * apply simple anti foot shooting measure - put flag on
	 * messages that have been altered and check it when
	 * another request comes.
	 */
#if 0
	/* disabled: - it propagates to the reply and we don't want this
	 *  -- andrei */
	if (msg->msg_flags & FL_SDP_PORT_AFS) {
		LM_ERR("you can't rewrite the same SDP twice, check your config!\n");
		return -1;
	}
#endif

	if (preserve != 0) {
		anchor = anchor_lump(msg, body->s + body->len - msg->buf, 0, 0);
		if (anchor == NULL) {
			LM_ERR("anchor_lump failed\n");
			return -1;
		}
		buf = pkg_malloc(AOLDMEDPRT_LEN + oldport->len + CRLF_LEN);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		memcpy(buf, CRLF, CRLF_LEN);
		memcpy(buf + CRLF_LEN, AOLDMEDPRT, AOLDMEDPRT_LEN);
		memcpy(buf + CRLF_LEN + AOLDMEDPRT_LEN, oldport->s, oldport->len);
		if (insert_new_lump_after(anchor, buf,
		    AOLDMEDPRT_LEN + oldport->len + CRLF_LEN, 0) == NULL) {
			LM_ERR("insert_new_lump_after failed\n");
			pkg_free(buf);
			return -1;
		}
	}

	buf = pkg_malloc(newport->len);
	if (buf == NULL) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	offset = oldport->s - msg->buf;
	anchor = del_lump(msg, offset, oldport->len, 0);
	if (anchor == NULL) {
		LM_ERR("del_lump failed\n");
		pkg_free(buf);
		return -1;
	}
	memcpy(buf, newport->s, newport->len);
	if (insert_new_lump_after(anchor, buf, newport->len, 0) == 0) {
		LM_ERR("insert_new_lump_after failed\n");
		pkg_free(buf);
		return -1;
	}

#if 0
	msg->msg_flags |= FL_SDP_PORT_AFS;
#endif
	return 0;
}

static char * gencookie(void)
{
	static char cook[34];

	sprintf(cook, "%d_%u ", (int)mypid, myseqn);
	myseqn++;
	return cook;
}

static int
rtpp_checkcap(struct rtpp_node *node, char *cap, int caplen)
{
	char *cp;
	struct iovec vf[4] = {{NULL, 0}, {"VF", 2}, {" ", 1}, {NULL, 0}};

	vf[3].iov_base = cap;
	vf[3].iov_len = caplen;

	cp = send_rtpp_command(node, vf, 4);
	if (cp == NULL)
		return -1;
	if (cp[0] == 'E' || atoi(cp) != 1)
		return 0;
	return 1;
}

static int
rtpp_test(struct rtpp_node *node, int isdisabled, int force)
{
	int rtpp_ver, rval;
	char *cp;
	struct iovec v[2] = {{NULL, 0}, {"V", 1}};

	if(node->rn_recheck_ticks == MI_MAX_RECHECK_TICKS){
	    LM_DBG("rtpp %s disabled for ever\n", node->rn_url.s);
		return 1;
	}

	if (force == 0) {
		if (isdisabled == 0)
			return 0;
		if (node->rn_recheck_ticks > get_ticks())
			return 1;
	}
	cp = send_rtpp_command(node, v, 2);
	if (cp == NULL) {
		LM_WARN("can't get version of the RTP proxy\n");
		goto error;
	}
	rtpp_ver = atoi(cp);
	if (rtpp_ver != SUP_CPROTOVER) {
		LM_WARN("unsupported version of RTP proxy <%s> found: %d supported,"
				"%d present\n", node->rn_url.s, SUP_CPROTOVER, rtpp_ver);
		goto error;
	}
	rval = rtpp_checkcap(node, REQ_CPROTOVER, sizeof(REQ_CPROTOVER) - 1);
	if (rval == -1) {
		LM_WARN("RTP proxy went down during version query\n");
		goto error;
	}
	if (rval == 0) {
		LM_WARN("of RTP proxy <%s> doesn't support required protocol version"
				"%s\n", node->rn_url.s, REQ_CPROTOVER);
		goto error;
	}
	LM_INFO("rtp proxy <%s> found, support for it %senabled\n",
	    node->rn_url.s, force == 0 ? "re-" : "");
	/* Check for optional capabilities */
	rval = rtpp_checkcap(node, REP_CPROTOVER, sizeof(REP_CPROTOVER) - 1);
	if (rval != -1) {
		node->rn_rep_supported = rval;
	} else {
		node->rn_rep_supported = 0;
	}
	rval = rtpp_checkcap(node, PTL_CPROTOVER, sizeof(PTL_CPROTOVER) - 1);
	if (rval != -1) {
		node->rn_ptl_supported = rval;
	} else {
		node->rn_ptl_supported = 0;
	}
	return 0;
error:
	LM_WARN("support for RTP proxy <%s> has been disabled%s\n", node->rn_url.s,
	    rtpproxy_disable_tout < 0 ? "" : " temporarily");
	if (rtpproxy_disable_tout >= 0)
		node->rn_recheck_ticks = get_ticks() + rtpproxy_disable_tout;

	return 1;
}

char *
send_rtpp_command(struct rtpp_node *node, struct iovec *v, int vcnt)
{
	struct sockaddr_un addr;
	int fd, len, i;
	char *cp;
	static char buf[256];
	struct pollfd fds[1];

	len = 0;
	cp = buf;
	if (node->rn_umode == 0) {
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_LOCAL;
		strncpy(addr.sun_path, node->rn_address,
		    sizeof(addr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SA_LEN
		addr.sun_len = strlen(addr.sun_path);
#endif

		fd = socket(AF_LOCAL, SOCK_STREAM, 0);
		if (fd < 0) {
			LM_ERR("can't create socket\n");
			goto badproxy;
		}
		if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			close(fd);
			LM_ERR("can't connect to RTP proxy\n");
			goto badproxy;
		}

		do {
			len = writev(fd, v + 1, vcnt - 1);
		} while (len == -1 && errno == EINTR);
		if (len <= 0) {
			close(fd);
			LM_ERR("can't send command to a RTP proxy\n");
			goto badproxy;
		}
		do {
			len = read(fd, buf, sizeof(buf) - 1);
		} while (len == -1 && errno == EINTR);
		close(fd);
		if (len <= 0) {
			LM_ERR("can't read reply from a RTP proxy\n");
			goto badproxy;
		}
	} else {
		fds[0].fd = rtpp_socks[node->idx];
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		/* Drain input buffer */
		while ((poll(fds, 1, 0) == 1) &&
		    ((fds[0].revents & POLLIN) != 0)) {
			recv(rtpp_socks[node->idx], buf, sizeof(buf) - 1, 0);
			fds[0].revents = 0;
		}
		v[0].iov_base = gencookie();
		v[0].iov_len = strlen(v[0].iov_base);
		for (i = 0; i < rtpproxy_retr; i++) {
			do {
				len = writev(rtpp_socks[node->idx], v, vcnt);
			} while (len == -1 && (errno == EINTR || errno == ENOBUFS));
			if (len <= 0) {
				LM_ERR("can't send command to a RTP proxy\n");
				goto badproxy;
			}
			while ((poll(fds, 1, rtpproxy_tout) == 1) &&
			    (fds[0].revents & POLLIN) != 0) {
				do {
					len = recv(rtpp_socks[node->idx], buf, sizeof(buf)-1, 0);
				} while (len == -1 && errno == EINTR);
				if (len <= 0) {
					LM_ERR("can't read reply from a RTP proxy\n");
					goto badproxy;
				}
				if (len >= (v[0].iov_len - 1) &&
				    memcmp(buf, v[0].iov_base, (v[0].iov_len - 1)) == 0) {
					len -= (v[0].iov_len - 1);
					cp += (v[0].iov_len - 1);
					if (len != 0) {
						len--;
						cp++;
					}
					goto out;
				}
				fds[0].revents = 0;
			}
		}
		if (i == rtpproxy_retr) {
			LM_ERR("timeout waiting reply from a RTP proxy\n");
			goto badproxy;
		}
	}

out:
	cp[len] = '\0';
	return cp;
badproxy:
	LM_ERR("proxy <%s> does not respond, disable it\n", node->rn_url.s);
	node->rn_disabled = 1;
	node->rn_recheck_ticks = get_ticks() + rtpproxy_disable_tout;
	
	return NULL;
}

/*
 * select the set with the id_set id
 */

static struct rtpp_set * select_rtpp_set(int id_set ){

	struct rtpp_set * rtpp_list;
	/*is it a valid set_id?*/
	
	if(!rtpp_set_list || !rtpp_set_list->rset_first){
		LM_ERR("no rtp_proxy configured\n");
		return 0;
	}

	for(rtpp_list=rtpp_set_list->rset_first; rtpp_list!=0 && 
		rtpp_list->id_set!=id_set; rtpp_list=rtpp_list->rset_next);
	if(!rtpp_list){
		LM_ERR(" script error-invalid id_set to be selected\n");
	}

	return rtpp_list;
}
/*
 * Main balancing routine. This does not try to keep the same proxy for
 * the call if some proxies were disabled or enabled; proxy death considered
 * too rare. Otherwise we should implement "mature" HA clustering, which is
 * too expensive here.
 */
struct rtpp_node *
select_rtpp_node(str callid, int do_test)
{
	unsigned sum, sumcut, weight_sum;
	struct rtpp_node* node;
	int was_forced;

	/* check last list version */
	if (my_version != *list_version && update_rtpp_proxies() < 0) {
		LM_ERR("cannot update rtpp proxies list\n");
		return 0;
	}
	
	if(!selected_rtpp_set){
		LM_ERR("script error -no valid set selected\n");
		return NULL;
	}
	/* Most popular case: 1 proxy, nothing to calculate */
	if (selected_rtpp_set->rtpp_node_count == 1) {
		node = selected_rtpp_set->rn_first;
		if (node->rn_disabled && node->rn_recheck_ticks <= get_ticks())
			node->rn_disabled = rtpp_test(node, 1, 0);
		return node->rn_disabled ? NULL : node;
	}

	/* XXX Use quick-and-dirty hashing algo */
	for(sum = 0; callid.len > 0; callid.len--)
		sum += callid.s[callid.len - 1];
	sum &= 0xff;

	was_forced = 0;
retry:
	weight_sum = 0;
	for (node=selected_rtpp_set->rn_first; node!=NULL; node=node->rn_next) {

		if (node->rn_disabled && node->rn_recheck_ticks <= get_ticks()){
			/* Try to enable if it's time to try. */
			node->rn_disabled = rtpp_test(node, 1, 0);
		}
		if (!node->rn_disabled)
			weight_sum += node->rn_weight;
	}
	if (weight_sum == 0) {
		/* No proxies? Force all to be redetected, if not yet */
		if (was_forced)
			return NULL;
		was_forced = 1;
		for(node=selected_rtpp_set->rn_first; node!=NULL; node=node->rn_next) {
			node->rn_disabled = rtpp_test(node, 1, 1);
		}
		goto retry;
	}
	sumcut = sum % weight_sum;
	/*
	 * sumcut here lays from 0 to weight_sum-1.
	 * Scan proxy list and decrease until appropriate proxy is found.
	 */
	for (node=selected_rtpp_set->rn_first; node!=NULL; node=node->rn_next) {
		if (node->rn_disabled)
			continue;
		if (sumcut < node->rn_weight)
			goto found;
		sumcut -= node->rn_weight;
	}
	/* No node list */
	return NULL;
found:
	if (do_test) {
		node->rn_disabled = rtpp_test(node, node->rn_disabled, 0);
		if (node->rn_disabled)
			goto retry;
	}
	return node;
}

static int
unforce_rtp_proxy_f(struct sip_msg* msg, char* str1, char* str2)
{
	str callid, from_tag, to_tag;
	struct rtpp_node *node;
	struct iovec v[1 + 4 + 3] = {{NULL, 0}, {"D", 1}, {" ", 1}, {NULL, 0}, {" ", 1}, {NULL, 0}, {" ", 1}, {NULL, 0}};
						/* 1 */   /* 2 */   /* 3 */    /* 4 */   /* 5 */    /* 6 */   /* 1 */

	if (get_callid(msg, &callid) == -1 || callid.len == 0) {
		LM_ERR("can't get Call-Id field\n");
		return -1;
	}
	to_tag.s = 0;
	if (get_to_tag(msg, &to_tag) == -1) {
		LM_ERR("can't get To tag\n");
		return -1;
	}
	if (get_from_tag(msg, &from_tag) == -1 || from_tag.len == 0) {
		LM_ERR("can't get From tag\n");
		return -1;
	}
	STR2IOVEC(callid, v[3]);
	STR2IOVEC(from_tag, v[5]);
	STR2IOVEC(to_tag, v[7]);

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	if(msg->id != current_msg_id){
		selected_rtpp_set = *default_rtpp_set;
	}
	
	node = select_rtpp_node(callid, 1);
	if (!node) {
		LM_ERR("no available proxies\n");
		goto error;
	}
	send_rtpp_command(node, v, (to_tag.len > 0) ? 8 : 6);

	if(nh_lock)
	{
		/* we are done reading -> unref the data */
		lock_stop_read( nh_lock );
	}

	return 1;
error:
	if(!nh_lock)
		return -1;
	/* we are done reading -> unref the data */
	lock_stop_read( nh_lock );

	return -1;
}



static int
set_rtp_proxy_set_f(struct sip_msg * msg, char * str1, char * str2)
{
	nh_set_param_t * pset;
	pv_value_t value;
	int int_val;
	int err;
	struct rtpp_set * rtpp_list;

	current_msg_id = msg->id;
	pset = (nh_set_param_t *) str1;

	if (pset->t == NH_VAL_SET_FIXED) {
		selected_rtpp_set = pset->v.fixed_set;
		return 1;
	}

	if ( pv_get_spec_value(msg,&pset->v.var_set,&value)!=0 || 
	value.flags & PV_VAL_NULL || value.flags&PV_VAL_EMPTY ) {
		LM_ERR("no PV or NULL value specified for proxy set "
			"(error in scripts)\n");
		return -1;
	}

	if ( value.flags & PV_VAL_STR ) {
		int_val = str2s(value.rs.s, value.rs.len, &err);
		if (err != 0) {
			LM_ERR("Invalid value %s specified in PV as RTP proxy set.\n",
				value.rs.s );
			return -1;
		}
	} else if ( value.flags & PV_VAL_INT ) {
		int_val = value.ri;
	} else {
		LM_ERR("Unsupported PV value type for RTP ptoxy set.i\n");
		return -1;
	}

	LM_DBG("Variable proxy set %d specified.\n", int_val);

	rtpp_list = select_rtpp_set(int_val);

	if (rtpp_list != NULL) {
		selected_rtpp_set = rtpp_list;
		return 0;
	} else {
		LM_ERR("RTP Proxy set ID %d is not configured.\n", int_val);
		return -2;
	}
}


static int
rtpproxy_offer1_f(struct sip_msg *msg, char *str1, char *str2)
{
        char *cp;
        char newip[IP_ADDR_MAX_STR_SIZE];

        cp = ip_addr2a(&msg->rcv.dst_ip);
        strcpy(newip, cp);
	return rtpproxy_offer2_f(msg, str1, newip);
}

static int
rtpproxy_offer2_f(struct sip_msg *msg, char *param1, char *param2)
{
	if(detect_rtp_idle)
	{
		/* if an initial request - create a new dialog */
		if(get_to(msg)->tag_value.s == NULL)
			dlg_api.create_dlg(msg);
	}

	return force_rtp_proxy(msg, param1, param2, 1);
}

static int
rtpproxy_answer1_f(struct sip_msg *msg, char *str1, char *str2)
{
        char *cp;
        char newip[IP_ADDR_MAX_STR_SIZE];

        cp = ip_addr2a(&msg->rcv.dst_ip);
        strcpy(newip, cp);
        return rtpproxy_answer2_f(msg, str1, newip);
}

static int
rtpproxy_answer2_f(struct sip_msg *msg, char *param1, char *param2)
{

	if (msg->first_line.type == SIP_REQUEST)
		if (msg->first_line.u.request.method_value != METHOD_ACK)
			return -1;

	return force_rtp_proxy(msg, param1, param2, 0);
}

struct options {
	str s;
	int oidx;
};

static int
append_opts(struct options *op, char ch)
{
	void *p;

	if (op->s.len <= op->oidx) {
		p = pkg_realloc(op->s.s, op->oidx + 32);
		if (p == NULL) {
			return (-1);
		}
		op->s.s = p;
		op->s.len = op->oidx + 32;
	}
	op->s.s[op->oidx++] = ch;
	return (0);
}

static void
free_opts(struct options *op1, struct options *op2, struct options *op3)
{

	if (op1->s.len > 0 && op1->s.s != NULL) {
		pkg_free(op1->s.s);
		op1->s.len = 0;
	}
	if (op2->s.len > 0 && op2->s.s != NULL) {
		pkg_free(op2->s.s);
		op2->s.len = 0;
	}
	if (op3->s.len > 0 && op3->s.s != NULL) {
		pkg_free(op3->s.s);
		op3->s.len = 0;
	}
}

#define FORCE_RTP_PROXY_RET(e) \
    do { \
	free_opts(&opts, &rep_opts, &pt_opts); \
	return (e); \
    } while (0);

static int
force_rtp_proxy_body(struct sip_msg* msg, char* str1, char* str2, int offer, str body);

static int
force_rtp_proxy(struct sip_msg* msg, char* str1, char* str2, int offer)
{
	struct multi_body *m;
	struct part * p;
	str body;
	int skip;
	char c;

	m = get_all_bodies(msg);

	if (m == NULL)
	{
		LM_ERR("Unable to parse body\n");
		return -1;
	}

	p = m->first;

	while (p)
	{
		int ret = 0;
		if (p->content_type == ((TYPE_APPLICATION << 16) + SUBTYPE_SDP))
		{
			body = p->body;

			for (skip = 0; skip < body.len; skip++)
			{
				c = body.s[body.len - skip - 1];
				if (c != '\r' && c != '\n')
					break;
			}

			if (skip == body.len)
			{
				LM_ERR("empty body");
				return -1;
			}

			body.len -= skip;


			LM_DBG("Forcing body:\n[%.*s]\n", body.len, body.s);
			ret = force_rtp_proxy_body(msg, str1, str2, offer, body);

		}

		if (ret < 0)
			return ret;
		p = p->next;
	}

	return 1;
};

static int
force_rtp_proxy_body(struct sip_msg* msg, char* str1, char* str2, int offer, str body)
{
	str body1, oldport, oldip, newport, newip ,nextport;
	str callid, from_tag, to_tag, tmp, payload_types;
	int create, port, len, asymmetric, flookup, argc, proxied, real;
	int orgip, commip;
	int pf, pf1, force;
	struct options opts, rep_opts, pt_opts;
	char *cp, *cp1;
	char  *cpend, *next;
	char **ap, *argv[10];
	struct lump* anchor;
	struct rtpp_node *node;
	struct iovec v[] = {
		{NULL, 0},	/* reserved (cookie) */
		{NULL, 0},	/* command & common options */
		{NULL, 0},	/* per-media/per-node options 1 */
		{NULL, 0},	/* per-media/per-node options 2 */
		{" ", 1},	/* separator */
		{NULL, 0},	/* callid */
		{" ", 1},	/* separator */
		{NULL, 7},	/* newip */
		{" ", 1},	/* separator */
		{NULL, 1},	/* oldport */
		{" ", 1},	/* separator */
		{NULL, 0},	/* from_tag */
		{";", 1},	/* separator */
		{NULL, 0},	/* medianum */
		{" ", 1},	/* separator */
		{NULL, 0},	/* to_tag */
		{";", 1},	/* separator */
		{NULL, 0},	/* medianum */
		{" ", 1},	/* separator */
		{NULL, 0},	/* notify socket name */
		{" ", 1},	/* separator */
		{NULL, 0}	/* notify tag */
	};
	char *v1p, *v2p, *c1p, *c2p, *m1p, *m2p, *bodylimit, *o1p, *r2p;
	char medianum_buf[20];
	int medianum, media_multi;
	str medianum_str, tmpstr1;
	int c1p_altered;
	int vcnt;

	memset(&opts, '\0', sizeof(opts));
	memset(&rep_opts, '\0', sizeof(rep_opts));
	memset(&pt_opts, '\0', sizeof(pt_opts));
	/* Leave space for U/L prefix TBD later */
	if (append_opts(&opts, '?') == -1) {
		LM_ERR("out of pkg memory\n");
		FORCE_RTP_PROXY_RET (-1);
	}
	asymmetric = flookup = force = real = orgip = commip = 0;
	for (cp = str1; cp != NULL && *cp != '\0'; cp++) {
		switch (*cp) {
		case 'a':
		case 'A':
			if (append_opts(&opts, 'A') == -1) {
				LM_ERR("out of pkg memory\n");
				FORCE_RTP_PROXY_RET (-1);
			}
			asymmetric = 1;
			real = 1;
			break;

		case 'i':
		case 'I':
			if (append_opts(&opts, 'I') == -1) {
				LM_ERR("out of pkg memory\n");
				FORCE_RTP_PROXY_RET (-1);
			}
			break;

		case 'e':
		case 'E':
			if (append_opts(&opts, 'E') == -1) {
				LM_ERR("out of pkg memory\n");
				FORCE_RTP_PROXY_RET (-1);
			}
			break;

		case 'l':
		case 'L':
			if (offer == 0) {
				FORCE_RTP_PROXY_RET (-1);
			}
			flookup = 1;
			break;

		case 'f':
		case 'F':
			force = 1;
			break;

		case 'r':
		case 'R':
			real = 1;
			break;

		case 'c':
		case 'C':
			commip = 1;
			break;

		case 'o':
		case 'O':
			orgip = 1;
			break;

		case 'w':
		case 'W':
			if (append_opts(&opts, 'S') == -1) {
				LM_ERR("out of pkg memory\n");
				FORCE_RTP_PROXY_RET (-1);
			}
			break;

		case 'z':
		case 'Z':
			if (append_opts(&rep_opts, 'Z') == -1) {
				LM_ERR("out of pkg memory\n");
				FORCE_RTP_PROXY_RET (-1);
			}
			/* If there are any digits following Z copy them into the command */
			for (; cp[1] != '\0' && isdigit(cp[1]); cp++) {
				if (append_opts(&rep_opts, cp[1]) == -1) {
					LM_ERR("out of pkg memory\n");
					FORCE_RTP_PROXY_RET (-1);
				}
			}
			break;

		default:
			LM_ERR("unknown option `%c'\n", *cp);
			FORCE_RTP_PROXY_RET (-1);
		}
	}

	if (offer != 0) {
		create = 1;
	} else {
		create = 0;
	}
	
	if (get_callid(msg, &callid) == -1 || callid.len == 0) {
		LM_ERR("can't get Call-Id field\n");
		FORCE_RTP_PROXY_RET (-1);
	}
	to_tag.s = 0;
	if (get_to_tag(msg, &to_tag) == -1) {
		LM_ERR("can't get To tag\n");
		FORCE_RTP_PROXY_RET (-1);
	}
	if (get_from_tag(msg, &from_tag) == -1 || from_tag.len == 0) {
		LM_ERR("can't get From tag\n");
		FORCE_RTP_PROXY_RET (-1);
	}
	if (flookup != 0) {
		if (to_tag.len == 0) {
			FORCE_RTP_PROXY_RET (-1);
		}
		create = 0;
	} else if ((msg->first_line.type==SIP_REPLY && offer != 0) ||
	(msg->first_line.type == SIP_REQUEST && offer == 0) ) {
		if (to_tag.len == 0) {
			FORCE_RTP_PROXY_RET (-1);
		}
		tmp = from_tag;
		from_tag = to_tag;
		to_tag = tmp;
	}
	proxied = 0;
	if (nortpproxy_str.len) {
		for ( cp=body.s ; (len=body.s+body.len-cp) >= nortpproxy_str.len ; ) {
			cp1 = ser_memmem(cp, nortpproxy_str.s, len, nortpproxy_str.len);
			if (cp1 == NULL)
				break;
			if (cp1[-1] == '\n' || cp1[-1] == '\r') {
				proxied = 1;
				break;
			}
			cp = cp1 + nortpproxy_str.len;
		}
	}
	if (proxied != 0 && force == 0) {
		FORCE_RTP_PROXY_RET (-1);
	}
	/*
	 * Parsing of SDP body.
	 * It can contain a few session descriptions (each starts with
	 * v-line), and each session may contain a few media descriptions
	 * (each starts with m-line).
	 * We have to change ports in m-lines, and also change IP addresses in
	 * c-lines which can be placed either in session header (fallback for
	 * all medias) or media description.
	 * Ports should be allocated for any media. IPs all should be changed
	 * to the same value (RTP proxy IP), so we can change all c-lines
	 * unconditionally.
	 */
	bodylimit = body.s + body.len;
	v1p = find_sdp_line(body.s, bodylimit, 'v');
	if (v1p == NULL) {
		LM_ERR("no sessions in SDP\n");
		FORCE_RTP_PROXY_RET (-1);
	}
	v2p = find_next_sdp_line(v1p, bodylimit, 'v', bodylimit);
	media_multi = (v2p != bodylimit);
	v2p = v1p;
	medianum = 0;

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	if(msg->id != current_msg_id){
		selected_rtpp_set = *default_rtpp_set;
	}


	opts.s.s[0] = (create == 0) ? 'L' : 'U';
	v[1].iov_base = opts.s.s;
	v[1].iov_len = opts.oidx;
	STR2IOVEC(callid, v[5]);
	STR2IOVEC(from_tag, v[11]);
	to_tag.s="tag";
	to_tag.len=3;
	STR2IOVEC(to_tag, v[15]);

	if(detect_rtp_idle && opts.s.s[0] == 'U')
	{
		struct dlg_cell * dlg;
		char buf[32];
		str notify_tag;

		dlg = dlg_api.get_dlg();
		if(dlg == NULL)
		{
			LM_ERR("Failed to create dialog\n");
			goto error;
		}
		/* construct the notify tag from dualog ids */
		notify_tag.len= sprintf(buf, "%d.%d", dlg->h_entry, dlg->h_id);
		notify_tag.s = buf;
		LM_DBG("notify_tag= %s\n", notify_tag.s);

		if (strncmp(rtpp_notify_socket.s, "tcp:", 4) == 0) {
			rtpp_notify_socket.s += 4;
			rtpp_notify_socket.len -= 4;
		} else if (strncmp(rtpp_notify_socket.s, "unix:", 5) == 0) {
			rtpp_notify_socket.s += 5;
			rtpp_notify_socket.len -= 5;
		}
		LM_DBG("rtpp_notify_socket= %.*s\n", rtpp_notify_socket.len, rtpp_notify_socket.s);

		STR2IOVEC(rtpp_notify_socket, v[19]);
		STR2IOVEC(notify_tag, v[21]);
	}

	for(;;) {
		/* Per-session iteration. */
		v1p = v2p;
		if (v1p == NULL || v1p >= bodylimit)
			break; /* No sessions left */
		v2p = find_next_sdp_line(v1p, bodylimit, 'v', bodylimit);
		/* v2p is text limit for session parsing. */
		/* get session origin */
		o1p = find_sdp_line(v1p, v2p, 'o');
		if (o1p==0) {
			LM_ERR("no o= in session\n");
			goto error;
		}
		/* Have this session media description? */
		m1p = find_sdp_line(o1p, v2p, 'm');
		if (m1p == NULL) {
			LM_ERR("no m= in session\n");
			goto error;
		}
		/*
		 * Find c1p only between session begin and first media.
		 * c1p will give common c= for all medias.
		 */
		c1p = find_sdp_line(o1p, m1p, 'c');
		c1p_altered = 0;
		if (orgip==0)
			o1p = 0;
		/* Have session. Iterate media descriptions in session */
		m2p = m1p;
		for (;;) {
			m1p = m2p;
			if (m1p == NULL || m1p >= v2p)
				break;
			m2p = find_next_sdp_line(m1p, v2p, 'm', v2p);
			/* c2p will point to per-media "c=" */
			c2p = find_sdp_line(m1p, m2p, 'c');
			/* Extract address and port */
			r2p = find_sdp_line_complex(m1p, m2p, "a=rtcp:");

			tmpstr1.s = c2p ? c2p : c1p;
			if (tmpstr1.s == NULL) {
				/* No "c=" */
				LM_ERR("can't find media IP in the message\n");
				goto error;
			}
			tmpstr1.len = v2p - tmpstr1.s; /* limit is session limit text */
			if (extract_mediaip(&tmpstr1, &oldip, &pf,"c=") == -1) {
				LM_ERR("can't extract media IP from the message\n");
				goto error;
			}
			tmpstr1.s = m1p;
			tmpstr1.len = m2p - m1p;
			if (extract_mediainfo(&tmpstr1, &oldport, &payload_types) == -1) {
				LM_ERR("can't extract media port from the message\n");
				goto error;
			}
			++medianum;
			if (asymmetric != 0 || real != 0) {
				newip = oldip;
			} else {
				newip.s = ip_addr2a(&msg->rcv.src_ip);
				newip.len = strlen(newip.s);
			}
			/* XXX must compare address families in all addresses */
			if (pf == AF_INET6) {
				if (append_opts(&opts, '6') == -1) {
					LM_ERR("out of pkg memory\n");
					goto error;
				}
			}
			STR2IOVEC(newip, v[7]);
			STR2IOVEC(oldport, v[9]);
			if (1 || media_multi) /* XXX netch: can't choose now*/
			{
				snprintf(medianum_buf, sizeof medianum_buf, "%d", medianum);
				medianum_str.s = medianum_buf;
				medianum_str.len = strlen(medianum_buf);
				STR2IOVEC(medianum_str, v[13]);
				STR2IOVEC(medianum_str, v[17]);
			} else {
				v[12].iov_len = v[13].iov_len = 0;
				v[16].iov_len = v[17].iov_len = 0;
			}
			do {
				node = select_rtpp_node(callid, 1);
				if (!node) {
					LM_ERR("no available proxies\n");
					goto error;
				}
				if (rep_opts.oidx > 0) {
					if (node->rn_rep_supported == 0) {
						LM_WARN("re-packetization is requested but is not "
						    "supported by the selected RTP proxy node\n");
						v[2].iov_len = 0;
					} else {
						v[2].iov_base = rep_opts.s.s;
						v[2].iov_len += rep_opts.oidx;
					}
				}
				if (payload_types.len > 0 && node->rn_ptl_supported != 0) {
					pt_opts.oidx = 0;
					if (append_opts(&pt_opts, 'c') == -1) {
						LM_ERR("out of pkg memory\n");
						goto error;
					}
					/*
					 * Convert space-separated payload types list into
					 * a comma-separated list.
					 */
					for (cp = payload_types.s;
					    cp < payload_types.s + payload_types.len; cp++) {
						if (isdigit(*cp)) {
							if (append_opts(&pt_opts, *cp) == -1) {
								LM_ERR("out of pkg memory\n");
								goto error;
							}
							continue;
						}
						do {
							cp++;
						} while (!isdigit(*cp) &&
						    cp < payload_types.s + payload_types.len);
						/* Check EOL */
						if (cp >= payload_types.s + payload_types.len)
							break;
						if (append_opts(&pt_opts, ',') == -1) {
							LM_ERR("out of pkg memory\n");
							goto error;
						}
						cp--;
					}
					v[3].iov_base = pt_opts.s.s;
					v[3].iov_len = pt_opts.oidx;
				} else {
					v[3].iov_len = 0;
				}
 				if(detect_rtp_idle && opts.s.s[0] == 'U')
 					vcnt = 22;
 				else
 				{
 					vcnt = (to_tag.len > 0) ? 18 : 14;
 				}
 				cp = send_rtpp_command(node, v, vcnt);
			} while (cp == NULL);
			LM_DBG("proxy reply: %s\n", cp);
			/* Parse proxy reply to <argc,argv> */
			argc = 0;
			memset(argv, 0, sizeof(argv));
			cpend=cp+strlen(cp);
			next=eat_token_end(cp, cpend);
			for (ap=argv; cp<cpend; cp=next+1, next=eat_token_end(cp, cpend)){
				*next=0;
				if (*cp != '\0') {
					*ap=cp;
					argc++;
					if ((char*)++ap >= ((char*)argv+sizeof(argv)))
						break;
				}
			}
			if (argc < 1) {
				LM_ERR("no reply from rtp proxy\n");
				goto error;
			}
			port = atoi(argv[0]);
			if (port <= 0 || port > 65535) {
				if (port != 0 || flookup == 0)
					LM_ERR("incorrect port %i in reply "
						"from rtp proxy\n",port);
				goto error;
			}

			pf1 = (argc >= 3 && argv[2][0] == '6') ? AF_INET6 : AF_INET;

			if (isnulladdr(&oldip, pf)) {
				if (pf1 == AF_INET6) {
					newip.s = "::";
					newip.len = 2;
				} else {
					newip.s = "0.0.0.0";
					newip.len = 7;
				}
			} else {
				newip.s = (argc < 2) ? str2 : argv[1];
				newip.len = strlen(newip.s);
			}
			/* marker to double check : newport goes: str -> int -> str ?!?! */
			newport.s = int2str(port, &newport.len); /* beware static buffer */
			/* Alter port. */
			body1.s = m1p;
			body1.len = bodylimit - body1.s;
			/* do not do it if old port was 0 (means media disable)
			 * - check if actually should be better done in rtpptoxy,
			 *   by returning also 0
			 * - or by not sending to rtpproxy the old port if 0
			 */
			if(oldport.len!=1 || oldport.s[0]!='0')
			{
				if (alter_mediaport(msg, &body1, &oldport, &newport, 0) == -1)
					goto error;
			}

			nextport.s = int2str(port+1, &nextport.len);

			if( r2p )
				if (alter_rtcp(msg, &newip, pf1, &nextport, r2p) < 0 )
					goto error;
			
			/*
			 * Alter IP. Don't alter IP common for the session
			 * more than once.
			 */
			if (c2p != NULL || !c1p_altered) {
				body1.s = c2p ? c2p : c1p;
				body1.len = bodylimit - body1.s;
				if (alter_mediaip(msg, &body1, &oldip, pf, &newip, pf1, 0)==-1)
					goto error;
				if (!c2p)
					c1p_altered = 1;
			}
			/*
			 * Alter common IP if required, but don't do it more than once.
			 */
			if (commip && c1p && !c1p_altered) {
				tmpstr1.s = c1p;
				tmpstr1.len = v2p - tmpstr1.s;
				if (extract_mediaip(&tmpstr1, &oldip, &pf,"c=") == -1) {
					LM_ERR("can't extract media IP from the message\n");
					goto error;
				}
				body1.s = c1p;
				body1.len = bodylimit - body1.s;
				if (alter_mediaip(msg, &body1, &oldip, pf, &newip, pf1, 0)==-1)
					goto error;
				c1p_altered = 1;
			}
			/*
			 * Alter the IP in "o=", but only once per session
			 */
			if (o1p) {
				tmpstr1.s = o1p;
				tmpstr1.len = v2p - tmpstr1.s;
				if (extract_mediaip(&tmpstr1, &oldip, &pf,"o=") == -1) {
					LM_ERR("can't extract media IP from the message\n");
					goto error;
				}
				body1.s = o1p;
				body1.len = bodylimit - body1.s;
				if (alter_mediaip(msg, &body1, &oldip, pf, &newip, pf1, 0)==-1)
					goto error;
				o1p = 0;
			}
		} /* Iterate medias in session */
	} /* Iterate sessions */
	free_opts(&opts, &rep_opts, &pt_opts);

	if(nh_lock)
	{
		/* we are done reading -> unref the data */
		lock_stop_read( nh_lock );
	}

	if (proxied == 0 && nortpproxy_str.len) {
		cp = pkg_malloc((nortpproxy_str.len + CRLF_LEN) * sizeof(char));
		if (cp == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		anchor = anchor_lump(msg, body.s + body.len - msg->buf, 0, 0);
		if (anchor == NULL) {
			LM_ERR("anchor_lump failed\n");
			pkg_free(cp);
			return -1;
		}
		memcpy(cp, CRLF, CRLF_LEN);
		memcpy(cp + CRLF_LEN, nortpproxy_str.s, nortpproxy_str.len);
		if (insert_new_lump_after(anchor, cp, nortpproxy_str.len + CRLF_LEN, 0) == NULL) {
			LM_ERR("insert_new_lump_after failed\n");
			pkg_free(cp);
			return -1;
		}
	}

	return 1;

error:
	if(!nh_lock)
		FORCE_RTP_PROXY_RET (-1);

	/* we are done reading -> unref the data */
	lock_stop_read( nh_lock );

	FORCE_RTP_PROXY_RET (-1);
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
	void *buf, *cp;
	str c;
	str opt;
	str path;
	struct sip_uri curi;
	union sockaddr_union to;
	struct hostent* he;
	struct socket_info* send_sock;
	unsigned int flags;
	unsigned short proto;

	if((*natping_state) == 0)
		goto done;

	buf = NULL;
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
		cblen = rval * 2;
		buf = pkg_malloc(cblen);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			goto done;
		}
		rval = ul.get_all_ucontacts(buf,cblen,(ping_nated_only?ul.nat_flag:0),
		   ((unsigned int)(unsigned long)timer_idx)*natping_interval+iteration,
		   natping_processes*natping_interval);
		if (rval != 0) {
			pkg_free(buf);
			goto done;
		}
	}

	if (buf == NULL)
		goto done;

	cp = buf;
	while (1) {
		memcpy(&(c.len), cp, sizeof(c.len));
		if (c.len == 0)
			break;
		c.s = (char*)cp + sizeof(c.len);
		cp =  (char*)cp + sizeof(c.len) + c.len;
		memcpy( &send_sock, cp, sizeof(send_sock));
		cp = (char*)cp + sizeof(send_sock);
		memcpy( &flags, cp, sizeof(flags));
		cp = (char*)cp + sizeof(flags);
		memcpy( &(path.len), cp, sizeof(path.len));
		path.s = path.len ? ((char*)cp + sizeof(path.len)) : NULL ;
		cp =  (char*)cp + sizeof(path.len) + path.len;

		/* determin the destination */
		if ( path.len && (flags&sipping_flag)!=0 ) {
			/* send to first URI in path */
			if (get_path_dst_uri( &path, &opt) < 0) {
				LM_ERR("failed to get dst_uri for Path\n");
				continue;
			}
			/* send to the contact/received */
			if (parse_uri(opt.s, opt.len, &curi) < 0) {
				LM_ERR("can't parse contact dst_uri\n");
				continue;
			}
		} else {
			/* send to the contact/received */
			if (parse_uri(c.s, c.len, &curi) < 0) {
				LM_ERR("can't parse contact uri\n");
				continue;
			}
		}
		if (curi.proto != PROTO_UDP && curi.proto != PROTO_NONE)
			continue;
		if (curi.port_no == 0)
			curi.port_no = SIP_PORT;
		proto = curi.proto;
		/* we sholud get rid of this resolve (to ofen and to slow); for the
		 * moment we are lucky since the curi is an IP -bogdan */
		he = sip_resolvehost(&curi.host, &curi.port_no, &proto, 0, 0);
		if (he == NULL){
			LM_ERR("can't resolve_host\n");
			continue;
		}
		hostent2su(&to, he, 0, curi.port_no);

		if (send_sock==0) {
			send_sock=force_socket ? force_socket : 
					get_send_socket(0, &to, PROTO_UDP);
			if (send_sock == NULL) {
				LM_ERR("can't get sending socket\n");
				continue;
			}
		}

		if ( (flags&sipping_flag)!=0 &&
		(opt.s=build_sipping( &c, send_sock, &path, &opt.len))!=0 ) {
			if (udp_send(send_sock, opt.s, opt.len, &to)<0){
				LM_ERR("sip udp_send failed\n");
			}
		} else if (raw_ip) {
			if (send_raw((char*)sbuf, sizeof(sbuf), &to, raw_ip, raw_port)<0) {
				LM_ERR("send_raw failed\n");
			}
		} else {
			if (udp_send(send_sock, (char *)sbuf, sizeof(sbuf), &to)<0 ) {
				LM_ERR("udp_send failed\n");
}
		}
	}
	pkg_free(buf);
done:
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


static int start_recording_f(struct sip_msg* msg, char *foo, char *bar)
{
	int nitems;
	str callid = {0, 0};
	str from_tag = {0, 0};
	str to_tag = {0, 0};
	struct rtpp_node *node;
	struct iovec v[1 + 4 + 3] = {{NULL, 0}, {"R", 1}, {" ", 1}, {NULL, 0}, {" ", 1}, {NULL, 0}, {" ", 1}, {NULL, 0}};
	                             /* 1 */   /* 2 */   /* 3 */    /* 4 */   /* 5 */    /* 6 */   /* 1 */

	if (get_callid(msg, &callid) == -1 || callid.len == 0) {
		LM_ERR("can't get Call-Id field\n");
		return -1;
	}

	if (get_to_tag(msg, &to_tag) == -1) {
		LM_ERR("can't get To tag\n");
		return -1;
	}

	if (get_from_tag(msg, &from_tag) == -1 || from_tag.len == 0) {
		LM_ERR("can't get From tag\n");
		return -1;
	}


	STR2IOVEC(callid, v[3]);
	STR2IOVEC(from_tag, v[5]);
	STR2IOVEC(to_tag, v[7]);
	
	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	if(msg->id != current_msg_id){
		selected_rtpp_set = *default_rtpp_set;
	}
	
	node = select_rtpp_node(callid, 1);
	if (!node) {
		LM_ERR("no available proxies\n");
		goto error;
	}

	nitems = 8;
	if (msg->first_line.type == SIP_REPLY) {
		if (to_tag.len == 0)
			goto error;
		STR2IOVEC(to_tag, v[5]);
		STR2IOVEC(from_tag, v[7]);
	} else {
		STR2IOVEC(from_tag, v[5]);
		STR2IOVEC(to_tag, v[7]);
		if (to_tag.len <= 0)
			nitems = 6;
	}
	send_rtpp_command(node, v, nitems);

	if(nh_lock)
	{
		/* we are done reading -> unref the data */
		lock_stop_read( nh_lock );
	}
	return 1;

error:
	if(!nh_lock)
		return -1;

	/* we are done reading -> unref the data */
	lock_stop_read( nh_lock );
	return -1;
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

	if(rcv_avp_name.n==0)
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
