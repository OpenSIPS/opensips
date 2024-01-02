/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * ---------
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
 *		 `f' - instructs rtpproxy to ignore marks inserted
 *		       by another rtpproxy in transit to indicate
 *		       that the session is already goes through another
 *		       proxy. Allows creating chain of proxies.
 *		 `r' - flags that IP address in SDP should be trusted.
 *		       Without this flag, rtpproxy ignores address in the
 *		       SDP and uses source address of the SIP message
 *		       as media address which is passed to the RTP proxy.
 *
 *		Protocol between rtpproxy and RTP proxy in bridge
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
 *		Introduce fail-over mechanism, so that if SER detects that one
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
 * 2005-03-22	support for multiple media streams added (netch)
 * 2005-07-14  SDP origin (o=) IP may be also changed (bogdan)
 * 2006-03-28 Support for changing session-level SDP connection (c=) IP when
 *            media-description also includes connection information (bayan)
 * 2007-04-13 Support multiple sets of rtp-proxies and set selection added
 *            (ancuta)
 * 2007-04-26 Added some MI commands:
 *             nh_enable_rtpp used to enable or disable a specific rtp proxy
 *             nh_show_rtpp   used to display information for all rtp proxies
 *             (ancuta)
 * 2007-05-09 New function start_recording() allowing to start recording RTP
 *             session in the RTP proxy (Carsten Bock - ported from SER)
 *             - obsolete by rtpproxy_offer/rtpproxy_answer
 *            (osas)
 */

#define _GNU_SOURCE

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
#include <sys/un.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/uio.h>

#include "../../dprint.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../error.h"
#include "../../forward.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"
#include "../../timer.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parser_f.h"
#include "../../parser/sdp/sdp_helpr_funcs.h"
#include "../../parser/sdp/sdp.h"
#include "../../db/db.h"
#include "../../parser/parse_content.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_body.h"
#include "../../msg_callbacks.h"
#include "../../evi/evi_modules.h"
#include "../../lib/dassert.h"

#include "../dialog/dlg_load.h"
#include "../tm/tm_load.h"
#include "rtpproxy.h"
#include "rtpproxy_load.h"
#include "nhelpr_funcs.h"
#include "rtpproxy_stream.h"
#include "rtpproxy_callbacks.h"
#include "rtpproxy_vcmd.h"
#include "rtppn_connect.h"
#include "../rtp_relay/rtp_relay.h"

#define NH_TABLE_VERSION  0

#define DEFAULT_RTPP_SET_ID		0

#define MI_ENABLE_RTP_PROXY			"rtpproxy_enable"
#define MI_MIN_RECHECK_TICKS		0
#define MI_MAX_RECHECK_TICKS		(unsigned int)-1


#define MI_SHOW_RTP_PROXIES			"rtpproxy_show"
#define MI_RELOAD_RTP_PROXIES       "rtpproxy_reload"

#define MI_RTP_PROXY_NOT_FOUND		"RTP proxy not found"
#define MI_RTP_PROXY_NOT_FOUND_LEN	(sizeof(MI_RTP_PROXY_NOT_FOUND)-1)
#define MI_PING_DISABLED			"NATping disabled from script"
#define MI_PING_DISABLED_LEN		(sizeof(MI_PING_DISABLED)-1)
#define MI_SET						"Set"
#define MI_SET_LEN					(sizeof(MI_SET)-1)
#define MI_INDEX					"index"
#define MI_INDEX_LEN				(sizeof(MI_INDEX)-1)
#define MI_DISABLED					"disabled"
#define MI_DISABLED_LEN				(sizeof(MI_DISABLED)-1)
#define MI_WEIGHT					"weight"
#define MI_WEIGHT_LEN				(sizeof(MI_WEIGHT)-1)
#define MI_RECHECK_TICKS			"recheck_ticks"
#define MI_RECHECK_T_LEN			(sizeof(MI_RECHECK_TICKS)-1)

/* param names to be stored in the dialog */
static str param1_name = str_init("rtpproxy_1");
str param1_bavp_name = str_init("$bavp(5589965)");
pv_spec_t param1_spec;
static str param2_name = str_init("rtpproxy_2");
str param2_bavp_name = str_init("$bavp(5589966)");
pv_spec_t param2_spec;
static str param3_name = str_init("rtpproxy_3");
str param3_bavp_name = str_init("$bavp(5589967)");
pv_spec_t param3_spec;
static str late_name = str_init("late_negotiation");

/* parameters name for event signaling */
static str event_name = str_init("E_RTPPROXY_STATUS");
static str socket_name = str_init("socket");
static str status_name = str_init("status");
static str status_connected = str_init("active");
static str status_disconnected = str_init("inactive");

static str rtpproxy_dtmf_event_name = str_init("E_RTPPROXY_DTMF");
struct rtpproxy_event_params {
	str name;
	evi_param_p param;
};

struct rtpproxy_event_params rtpproxy_event_params[] = {
	{ /*  0 */ str_init("digit"), NULL },
	{ /*  1 */ str_init("duration"), NULL },
	{ /*  2 */str_init("volume"), NULL },
	{ /*  3 */str_init("id"), NULL },
	{ /*  4 */str_init("is_callid"), NULL },
	{ /*  5 */str_init("stream"), NULL },
};
evi_params_p rtpproxy_dtmf_params;

static int extract_mediainfo(str *, str *, str *);
static int alter_mediaip(struct sip_msg *, str *, str *, int, str *, int, int);
static void gencookie(struct iovec *);
static int rtpp_test(struct rtpp_node*, int, int);
static int unforce_rtp_proxy_f(struct sip_msg* msg, nh_set_param_t *pset,
				pv_spec_t *var);
static int engage_rtp_proxy5_f(struct sip_msg *msg, str *param1, str *param2,
				nh_set_param_t *param3, pv_spec_t *param4, pv_spec_t *param5);
static int force_rtp_proxy(struct sip_msg* msg, char* str1, char* str2, nh_set_param_t *setid,
					pv_spec_t *var, pv_spec_t *ipvar, str *body, int offer);
static int rtpproxy_recording(struct sip_msg* msg, nh_set_param_t *setid,
	pv_spec_t *var, str *flags, str *destination, int *stream_no);
static int rtpproxy_answer6_f(struct sip_msg *msg, str *param1, str *param2,
				nh_set_param_t *param3, pv_spec_t *param4, pv_spec_t *param5, pv_spec_t *param6);
static int rtpproxy_offer6_f(struct sip_msg *msg, str *param1, str *param2,
				nh_set_param_t *param3, pv_spec_t *param4, pv_spec_t *param5, pv_spec_t *param7);
static inline int rtpproxy_stats_f(struct sip_msg *msg,
	pv_spec_t *pup, pv_spec_t *pdown, pv_spec_t *psent, pv_spec_t *pfail,
	nh_set_param_t *pset, pv_spec_t *pvar);
static inline int rtpproxy_all_stats_f(struct sip_msg *msg, pv_spec_t *pavp,
		nh_set_param_t *pset, pv_spec_t *pvar);
static int rtpp_init_extra_stats(void);

static int add_rtpproxy_socks(struct rtpp_set * rtpp_list, char * rtpproxy);
static int fixup_set_id(void ** param);
static int fixup_free_set_id(void ** param);
static int fixup_all_stats(void ** param);
static struct rtpp_set * select_rtpp_set(int id_set);

static int rtpproxy_set_store(modparam_t type, void * val);
static int rtpproxy_set_notify(modparam_t type, void * val);
static int rtpproxy_add_rtpproxy_set( char * rtp_proxies, int set_id);
static int _add_proxies_from_database();
static int unforce_rtpproxy(struct sip_msg* msg, struct rtpp_args *args, pv_spec_t *var);

static int mod_init(void);
static int mod_preinit(void);
static int child_init(int);
static void mod_destroy(void);
static int mi_child_init(void);

static int engage_force_rtpproxy(struct dlg_cell *dlg, struct sip_msg *msg);

/*mi commands*/
static mi_response_t *mi_enable_rtp_proxy_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_enable_rtp_proxy_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_show_rtpproxies(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reload_rtpproxies(const mi_params_t *params,
								struct mi_handler *async_hdl);

void free_rtpp_nodes(struct rtpp_set *);
void free_rtpp_sets();

struct dlg_binds dlg_api;
/* TM support for saving parameters */
struct tm_binds tm_api;
static int rtpproxy_api_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags);
static int rtpproxy_api_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags);
static int rtpproxy_api_delete(struct rtp_relay_session *sess, struct rtp_relay_server *server,
			str *flags, str *extra);
static int rtpproxy_api_copy_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void **_ctx, str *flags,
		unsigned int copy_flags, unsigned int streams, str *body);
static int rtpproxy_api_copy_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *_ctx, str *flags, str *body);
static int rtpproxy_api_copy_delete(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *_ctx, str *flags);
static int rtpproxy_api_copy_serialize(void *_ctx, bin_packet_t *packet);
static int rtpproxy_api_copy_deserialize(void **_ctx, bin_packet_t *packet);

int connect_rtpproxies(struct rtpp_set *filter);
int update_rtpp_proxies(struct rtpp_set *filter);

static inline void raise_rtpproxy_event(struct rtpp_node *node, int status);

#if !defined(POLLRDHUP)
#define POLLRDHUP 0
#endif

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
	{.s = "dccp/tls/rtp/savp", .len = 17, .is_rtp = 1},
	{.s = "dccp/tls/rtp/savpf", .len = 18, .is_rtp = 1},
	{.s = "udp/tls/rtp/savp", .len = 16, .is_rtp = 1},
	{.s = "udp/tls/rtp/savpf", .len = 17, .is_rtp = 1},
	{.s = "udp/bfcp",  .len = 8, .is_rtp = 0},
	{.s = NULL,        .len = 0, .is_rtp = 0}
};

static int rtpproxy_disable_tout = 60;
static int rtpproxy_retr = 5;
int rtpproxy_tout = 1000;
static char *rtpproxy_timeout = 0;
static int rtpproxy_autobridge = 0;
static pid_t mypid;
static int myrand = 0;
static unsigned int myseqn = 0;
static str nortpproxy_str = str_init("a=nortpproxy:yes");
str rtpp_notify_socket = {0, 0};
/*
 * 0 - Unix socket
 * 1 - TCP socket
 */
int rtpp_notify_socket_un = 0;

/* used in rtpproxy_set_store() */
static int rtpp_sets=0;
static char **rtpp_strings=0;
static int rtpp_set_count = 0;
/* RTP proxy balancing list */
struct rtpp_set_head ** rtpp_set_list =0;
struct rtpp_set ** default_rtpp_set=0;
static int default_rtpp_set_no = DEFAULT_RTPP_SET_ID;

/* array with the sockets used by rtpporxy (per process)*/
static int *rtpp_socks = 0;
static unsigned int *rtpp_no = 0;
static unsigned int *list_version;
static unsigned int my_version = 0;
static unsigned int rtpp_number = 0;

/* a map of reload versions for each rtpproxy set, for on-demand reconnects */
static map_t rtpp_set_versions;

/* DB support for loading proxies */
static str db_url = {NULL, 0};
static str table = str_init("rtpproxy_sockets");
static str rtpp_sock_col = str_init("rtpproxy_sock");
static str set_id_col = str_init("set_id");
static db_con_t *db_connection = NULL;
static db_func_t db_functions;

static int *rtpproxy_port;
static gen_lock_t *rtpproxy_port_lock;
static int rtpproxy_port_min = 35000;
static int rtpproxy_port_max = 65000;
static str rtpproxy_media_ip = str_init("127.0.0.1");

static int rtpproxy_gen_port(void)
{
	int port;
	lock_get(rtpproxy_port_lock);
	if ((*rtpproxy_port)++ >= rtpproxy_port_max)
		*rtpproxy_port = rtpproxy_port_min;
	port = *rtpproxy_port;
	lock_release(rtpproxy_port_lock);
	return port;
}

static event_id_t ei_id = EVI_ERROR;
static event_id_t rtpproxy_dtmf_event = EVI_ERROR;

rw_lock_t *nh_lock=NULL;

static const cmd_export_t cmds[] = {
	{"rtpproxy_unforce", (cmd_function)unforce_rtp_proxy_f, {
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_engage", (cmd_function)engage_rtp_proxy5_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_start_recording", (cmd_function)rtpproxy_recording, {
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"rtpproxy_offer", (cmd_function)rtpproxy_offer6_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_answer", (cmd_function)rtpproxy_answer6_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_stream2uac", (cmd_function)rtpproxy_stream2uac4_f, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE},
	{"rtpproxy_stream2uas", (cmd_function)rtpproxy_stream2uas4_f, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE},
	{"rtpproxy_stop_stream2uac", (cmd_function)rtpproxy_stop_stream2uac2_f, {
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE},
	{"rtpproxy_stop_stream2uas", (cmd_function)rtpproxy_stop_stream2uas2_f, {
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE},
	{"rtpproxy_stats", (cmd_function)rtpproxy_stats_f, {
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"rtpproxy_all_stats", (cmd_function)rtpproxy_all_stats_f, {
		{CMD_PARAM_VAR, fixup_all_stats, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, fixup_set_id, fixup_free_set_id},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"load_rtpproxy", (cmd_function)load_rtpproxy, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

static const param_export_t params[] = {
	{"nortpproxy_str",        STR_PARAM, &nortpproxy_str.s        },
	{"rtpproxy_sock",         STR_PARAM|USE_FUNC_PARAM,
	                         (void*)rtpproxy_set_store            },
	{"rtpproxy_disable_tout", INT_PARAM, &rtpproxy_disable_tout   },
	{"rtpproxy_retr",         INT_PARAM, &rtpproxy_retr           },
	{"rtpproxy_timeout",      STR_PARAM, &rtpproxy_timeout        },
	{"rtpproxy_autobridge",   INT_PARAM, &rtpproxy_autobridge     },
	{"default_set",           INT_PARAM, &default_rtpp_set_no     },
	{"db_url",                STR_PARAM, &db_url.s                },
	{"db_table",              STR_PARAM, &table.s                 },
	{"rtpp_socket_col",       STR_PARAM, &rtpp_sock_col.s         },
	{"set_id_col",            STR_PARAM, &set_id_col.s            },
	{"rtpp_notify_socket",    STR_PARAM|USE_FUNC_PARAM,
                             (void*)rtpproxy_set_notify            },
	{"generated_sdp_port_min",INT_PARAM, &rtpproxy_port_min },
	{"generated_sdp_port_max",INT_PARAM, &rtpproxy_port_max },
	{"generated_sdp_media_ip",STR_PARAM, &rtpproxy_media_ip.s },
	{0, 0, 0}
};

static const mi_export_t mi_cmds[] = {
	{ MI_ENABLE_RTP_PROXY, 0, 0, 0, {
		{mi_enable_rtp_proxy_1, {"url", "enable", 0}},
		{mi_enable_rtp_proxy_2, {"url", "enable", "setid", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_SHOW_RTP_PROXIES, 0, 0, 0, {
		{mi_show_rtpproxies, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_RELOAD_RTP_PROXIES, 0, 0, mi_child_init, {
		{mi_reload_rtpproxies, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const proc_export_t procs[] = {
	{"RTPP notification receiver",  0,  0, notification_listener_process, 1,
		PROC_FLAG_INITCHILD|PROC_FLAG_HAS_IPC|PROC_FLAG_NEEDS_SCRIPT},
	{0,0,0,0,0,0}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",     DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_SILENT },
		{ MOD_TYPE_DEFAULT, "rtp_relay", DEP_SILENT|DEP_REVERSE },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"rtpproxy",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	NULL,
	params,
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	0,           /* exported pseudo-variables */
	0,			 /* exported transformations */
	0,           /* extra processes */
	mod_preinit,
	mod_init,
	0,           /* reply processing */
	mod_destroy, /* destroy function */
	child_init,
	0            /* reload confirm function */
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

static int rtpproxy_set_notify(modparam_t type, void * val)
{

	char * p;

	p = (char* )val;

	if(p==0 || *p=='\0'){
		return 0;
	}

	rtpp_notify_socket.s = p;
	rtpp_notify_socket.len = strlen(p);

	exports.procs = procs;

	return 0;
}

static int add_rtpproxy_socks(struct rtpp_set * rtpp_list,
										char * rtpproxy){
	/* Make rtp proxies list. */
	char *p, *p1, *p2, *p3, *p4, *plim;
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
		/* check to see if anything was advertised */
		p3 = q_memrchr(p1, '|', p2 - p1);
		if (p3) {
			p4 = p2;
			p2 = p3;
			p3++;
			while (p3 < p2 && isspace((int)*p3))
				p3++;
			while (p2 > p1 && isspace((int)*p2))
				p2--;
		}
		pnode = shm_malloc(sizeof(struct rtpp_node) +
				(p2 - p1 + 1) /* socket */ +
				(p3 ? (p4 - p3 + 1): 0));
		if (pnode == NULL) {
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(pnode, 0, sizeof(*pnode));
		pnode->rn_url.s = (char *)(pnode + 1);
		pnode->idx = *rtpp_no;
		*rtpp_no = *rtpp_no + 1;
		pnode->rn_recheck_ticks = 0;
		pnode->rn_weight = weight;
		pnode->rn_umode = CM_UNIX;
		pnode->rn_disabled = 0;
		memcpy(pnode->rn_url.s, p1, p2 - p1);
		pnode->rn_url.s[p2 - p1] 	= '\0';
		pnode->rn_url.len 			= p2-p1;
		if (p3) {
			pnode->adv_address = pnode->rn_url.s + pnode->rn_url.len + 1;
			memcpy(pnode->adv_address, p3, p4 - p3);
			pnode->adv_address[p4 - p3] = 0;
		}

		LM_DBG("url: %s, len: %i, weight: %d, adv: [%s]\n",
		       pnode->rn_url.s, pnode->rn_url.len, weight, pnode->adv_address);
		/* Leave only address in rn_address */
		pnode->rn_address = pnode->rn_url.s;
		if (strncasecmp(pnode->rn_address, "udp:", 4) == 0) {
			pnode->rn_umode = CM_UDP;
			pnode->rn_address += 4;
		} else if (strncasecmp(pnode->rn_address, "udp6:", 5) == 0) {
			pnode->rn_umode = CM_UDP6;
			pnode->rn_address += 5;
		} else if (strncasecmp(pnode->rn_address, "tcp:", 4) == 0) {
			pnode->rn_umode = CM_TCP;
			pnode->rn_address += 4;
		} else if (strncasecmp(pnode->rn_address, "tcp6:", 5) == 0) {
			pnode->rn_umode = CM_TCP6;
			pnode->rn_address += 5;
		} else if (strncasecmp(pnode->rn_address, "unix:", 5) == 0) {
			pnode->rn_umode = CM_UNIX;
			pnode->rn_address += 5;
		} else if (strncasecmp(pnode->rn_address, "cunix:", 6) == 0) {
			pnode->rn_umode = CM_CUNIX;
			pnode->rn_address += 6;
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


/*	0-success
 *  -1 - error
 * */
static int rtpproxy_add_rtpproxy_set( char * rtp_proxies, int set_id)
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
			my_current_id = default_rtpp_set_no;
		}
	}
	else{
		rtp_proxies = p;
		my_current_id = set_id;
	}
	LM_DBG("Adding proxy in set-id %d [%s]\n", my_current_id, rtp_proxies);

	for(;*rtp_proxies && isspace(*rtp_proxies);rtp_proxies++);

	if(!(*rtp_proxies)){
		LM_ERR("script error -empty rtp_proxy list\n");
		return -1;
	}

	/*search for the current_id*/
	rtpp_list = (*rtpp_set_list) ? (*rtpp_set_list)->rset_first : 0;
	while( rtpp_list != 0 && rtpp_list->id_set!=my_current_id)
		rtpp_list = rtpp_list->rset_next;
	LM_DBG("List %sfound (%p) for id %d\n", rtpp_list ? "" : "not ",
			rtpp_list, my_current_id);

	if(rtpp_list==NULL){	/*if a new id_set : add a new set of rtpp*/
		rtpp_list = shm_malloc(sizeof(struct rtpp_set));
		if(!rtpp_list){
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(rtpp_list, 0, sizeof(struct rtpp_set));
		rtpp_list->id_set = my_current_id;
		rtpp_list->reload_ver = 0;
		rtpp_list->rtpp_socks_idx = *rtpp_no;
		new_list = 1;
	} else {
		new_list = 0;
	}

	if(add_rtpproxy_socks(rtpp_list, rtp_proxies)!= 0){
		/*if this list will not be inserted, clean it up*/
		goto error;
	}

	if (new_list) {
		if(!(*rtpp_set_list)){/*initialize the list of set -
							 executed only on the first call*/
			*rtpp_set_list = shm_malloc(sizeof(struct rtpp_set_head));
			if(!(*rtpp_set_list)){
				LM_ERR("no shm memory left\n");
				return -1;
			}
			memset(*rtpp_set_list, 0, sizeof(struct rtpp_set_head));
		}

		/*update the list of set info*/
		if(!(*rtpp_set_list)->rset_first){
			(*rtpp_set_list)->rset_first = rtpp_list;
		}else{
			(*rtpp_set_list)->rset_last->rset_next = rtpp_list;
		}

		(*rtpp_set_list)->rset_last = rtpp_list;
		rtpp_set_count++;
	}

	return 0;
error:
	return -1;
}

static int fixup_all_stats(void ** param)
{
	if (((pv_spec_t*)*param)->type != PVT_AVP) {
		LM_ERR("invalid pvar type - only AVPs are allowed!\n");
		return E_SCRIPT;
	}

	return 0;
}

static int fixup_set_id(void ** param)
{
	struct rtpp_set* rtpp_list;
	nh_set_param_t * pset;

	pset = (nh_set_param_t *) pkg_malloc(sizeof(nh_set_param_t));
	if(pset == NULL){
		LM_ERR("no more pkg memory to allocate set parameter\n");
		return E_OUT_OF_MEM;
	}
	memset(pset, 0, sizeof(nh_set_param_t));

	rtpp_list = select_rtpp_set(*(int*)*param);
	if(rtpp_list ==0){
		/* simply mark it as undefined and we search it one more time
		 * at run-time, after the database has been updated */
		pset->t = NH_VAL_SET_UNDEF;
		pset->v.int_set = *(int*)*param;
	} else {
		pset->t = NH_VAL_SET_FIXED ;
		pset->v.fixed_set = rtpp_list;
	}

	*param = (void *) pset;
	return 0;
}

static int fixup_free_set_id(void ** param)
{
	pkg_free(*param);
	return 0;
}

static mi_response_t *mi_enable_rtp_proxy(const mi_params_t *params,
											unsigned int set_id)
{
	str rtpp_url;
	int enable;
	struct rtpp_set * rtpp_list;
	struct rtpp_node * crt_rtpp;
	int found;

	found = 0;

	if(*rtpp_set_list ==NULL)
		goto end;

	if (get_mi_string_param(params, "url", &rtpp_url.s, &rtpp_url.len) < 0)
		return init_mi_param_error();
	if(rtpp_url.s == NULL || rtpp_url.len ==0)
		return init_mi_error(400, MI_SSTR("Empty url"));

	if (get_mi_int_param(params, "enable", &enable) < 0)
		return init_mi_param_error();

	for(rtpp_list = (*rtpp_set_list)->rset_first; rtpp_list != NULL;
					rtpp_list = rtpp_list->rset_next){

		/* if set_id given, check only the list with the matching set_id */
		if ( (set_id!=(unsigned int)(-1)) && set_id!=rtpp_list->id_set )
			continue;

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
					raise_rtpproxy_event(crt_rtpp, crt_rtpp->rn_disabled);
				}
			}
		}
	}

end:
	if(found)
		return init_mi_result_ok();
	return init_mi_error(404,MI_RTP_PROXY_NOT_FOUND,MI_RTP_PROXY_NOT_FOUND_LEN);
}

static mi_response_t *mi_enable_rtp_proxy_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_enable_rtp_proxy(params, (unsigned int)(-1));
}

static mi_response_t *mi_enable_rtp_proxy_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int set_id;

	if (get_mi_int_param(params, "setid", &set_id) < 0)
		return init_mi_param_error();

	return mi_enable_rtp_proxy(params, (unsigned int)set_id);
}


static mi_response_t *mi_reload_rtpproxies(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct rtpp_set *it;
	if(db_url.s == NULL) {
		LM_ERR("Dynamic loading of rtpproxies not enabled\n");
		return init_mi_error(400, MI_SSTR("Dynamic loading not enabled"));
	}

	lock_start_write( nh_lock );
	if(*rtpp_set_list) {
		LM_DBG("bumping set versions to %d [%d]\n",
		        (*rtpp_set_list)->rset_first->reload_ver + 1, rtpp_number);

		for (it = (*rtpp_set_list)->rset_first; it; it = it->rset_next) {
			free_rtpp_nodes(it);
			it->reload_ver++;
		}
	}
	*rtpp_no = 0;
	(*list_version)++;

	if(_add_proxies_from_database() < 0)
		goto error;

	if (update_rtpp_proxies(NULL))
		goto error;

	/* update pointer to default_rtpp_set*/
	*default_rtpp_set = select_rtpp_set(default_rtpp_set_no);
	if (*default_rtpp_set == NULL)
		LM_WARN("there is no rtpproxy engine in the default set %d\n",
				default_rtpp_set_no);

	/* release the readers */
	lock_stop_write( nh_lock );

	return init_mi_result_ok();
error:
	lock_stop_write( nh_lock );
	return init_mi_error(500, MI_SSTR("Internal error"));
}

static mi_response_t *mi_show_rtpproxies(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *sets_arr, *set_item, *nodes_arr, *node_item;
	struct rtpp_set * rtpp_list;
	struct rtpp_node * crt_rtpp;

	resp = init_mi_result_array(&sets_arr);
	if (!resp)
		return 0;

	if(*rtpp_set_list ==NULL)
		return resp;

	for(rtpp_list = (*rtpp_set_list)->rset_first; rtpp_list != NULL;
					rtpp_list = rtpp_list->rset_next){

		set_item = add_mi_object(sets_arr, NULL, 0);
		if (!set_item)
			goto error;

		if (add_mi_number(set_item, MI_SET, MI_SET_LEN, rtpp_list->id_set) < 0)
			goto error;

		nodes_arr = add_mi_array(set_item, MI_SSTR("Nodes"));
		if (!nodes_arr)
			goto error;

		for(crt_rtpp = rtpp_list->rn_first; crt_rtpp != NULL;
						crt_rtpp = crt_rtpp->rn_next){

			node_item = add_mi_object(nodes_arr, NULL, 0);
			if (!node_item)
				goto error;

			if (add_mi_string(node_item, MI_SSTR("url"),
				crt_rtpp->rn_url.s, crt_rtpp->rn_url.len) < 0)
				goto error;

			if (add_mi_number(node_item, MI_INDEX, MI_INDEX_LEN,
				crt_rtpp->idx) < 0)
				goto error;
			if (add_mi_number(node_item, MI_DISABLED, MI_DISABLED_LEN,
				crt_rtpp->rn_disabled) < 0)
				goto error;
			if (add_mi_number(node_item, MI_WEIGHT, MI_WEIGHT_LEN,
				crt_rtpp->rn_weight) < 0)
				goto error;
			if (add_mi_number(node_item, MI_RECHECK_TICKS, MI_RECHECK_T_LEN,
				crt_rtpp->rn_recheck_ticks) < 0)
				goto error;
		}
	}

	return resp;
error:
	if (resp)
		free_mi_response(resp);
	return 0;
}


inline static int parse_bavp(str *s, pv_spec_t *bavp)
{
	s->len = strlen(s->s);
	if (pv_parse_spec(s, bavp)==NULL) {
		LM_ERR("malformed bavp definition %s\n", s->s);
		return -1;
	}
	 /* check if there is a bavp type */
	if (bavp->type != (pv_type_t)(903 + PVT_EXTRA)) {
		LM_ERR("store parameter must be an bavp\n");
		return -1;
	}
	return 0;

}

/* hack to get the rtpproxy node used for the offer */
static pv_spec_t media_pvar;

static struct rtp_relay_hooks rtp_relay;

static int mod_preinit(void)
{
	static str rtpproxy_relay_pvar_str = str_init("$var(___rtpproxy_relay_var__)");
	struct rtp_relay_funcs binds = {
		.offer = rtpproxy_api_offer,
		.answer = rtpproxy_api_answer,
		.delete = rtpproxy_api_delete,
		.copy_offer = rtpproxy_api_copy_offer,
		.copy_answer = rtpproxy_api_copy_answer,
		.copy_delete = rtpproxy_api_copy_delete,
		.copy_serialize = rtpproxy_api_copy_serialize,
		.copy_deserialize = rtpproxy_api_copy_deserialize,
	};
	if (!pv_parse_spec(&rtpproxy_relay_pvar_str, &media_pvar))
		return -1;
	register_rtp_relay(exports.name, &binds, &rtp_relay);
	return 0;
}

static int
mod_init(void)
{
	int i;
	int tmp;
	float timeout;

	if (rtpproxy_autobridge != 0) {
		LM_WARN("Auto bridging does not properly function when doing "
			"serial/parallel forking\n");
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

	rtpp_no = (unsigned int*)shm_malloc(sizeof(unsigned int));
	list_version = (unsigned int*)shm_malloc(sizeof(unsigned int));
	if(!rtpp_no || !list_version) {
		LM_ERR("No more shared memory\n");
		return -1;
	}
	*rtpp_no = 0;
	*list_version = 0;
	my_version = 0;

	rtpp_set_versions = map_create(0);
	if (!rtpp_set_versions) {
		LM_ERR("failed to create 'versions' map\n");
		return -1;
	}

	if (!(rtpp_set_list = (struct rtpp_set_head **)
		shm_malloc(sizeof(struct rtpp_set_head *)))) {
		LM_ERR("no more shm mem\n");
		return -1;
	}
	*rtpp_set_list = 0;

	if(db_url.s == NULL)
	{
		if (rtpp_sets == 0) {
			LM_ERR("no rtpproxy set specified\n");
			return -1;
		}

		/* storing the list of rtp proxy sets in shared memory*/
		for(i=0;i<rtpp_sets;i++){
			if(rtpproxy_add_rtpproxy_set(rtpp_strings[i], -1) !=0){
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
			LM_ERR("Failed to connect to database\n");
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
	if(*rtpp_set_list) {
		*default_rtpp_set = select_rtpp_set(default_rtpp_set_no);
		if (*default_rtpp_set == NULL)
			LM_WARN("there is no rtpproxy engine in the default set %d!"
					"if you are not specifying sets in your rtpproxy_*()"
					"commands, rtpproxy will not be used!\n",
					default_rtpp_set_no);
	}

	/* configure rtpproxy timeout */
	if(rtpproxy_timeout && sscanf(rtpproxy_timeout, "%f", &timeout))
		rtpproxy_tout = (int) (timeout * 1000);

	/* load dlg api */
	memset(&dlg_api, 0, sizeof(struct dlg_binds));
	if (load_dlg_api(&dlg_api)!=0)
		LM_DBG("dialog module not loaded.\n");
	memset(&tm_api, 0, sizeof(struct tm_binds));
	if (load_tm_api(&tm_api)!=0)
		LM_DBG("TM modules was not found\n");

	if (parse_bavp(&param1_bavp_name, &param1_spec) < 0 ||
			parse_bavp(&param2_bavp_name, &param2_spec) < 0 ||
			parse_bavp(&param3_bavp_name, &param3_spec) < 0)
		LM_DBG("cannot parse bavps\n");

	if(rtpp_notify_socket.s) {
		if (strncmp("tcp:", rtpp_notify_socket.s, 4) == 0) {
				rtpp_notify_socket_un = 0;
		} else {
			if (strncmp("unix:", rtpp_notify_socket.s, 5) == 0)
				rtpp_notify_socket.s += 5;
			rtpp_notify_socket_un = 1;
		}
		/* check if the notify socket parameter is set */
		rtpp_notify_socket.len = strlen(rtpp_notify_socket.s);
		if(dlg_api.get_dlg == 0) {
			LM_ERR("You need to load dialog module if you want to use the"
				" timeout notification feature\n");
			return -1;
		}

		if (init_rtpp_notify() < 0) {
			LM_ERR("cannot init notify handlers\n");
			return -1;
		}
	}

	ei_id = evi_publish_event(event_name);
	if (ei_id == EVI_ERROR)
		LM_ERR("cannot register event\n");

	rtpp_init_extra_stats();

	rtpproxy_dtmf_event = evi_publish_event(rtpproxy_dtmf_event_name);
	if (rtpproxy_dtmf_event == EVI_ERROR) {
		LM_ERR("cannot register RTPProxy DTMF socket\n");
		return -1;
	}

	rtpproxy_dtmf_params = pkg_malloc(sizeof(evi_params_t));
	if (rtpproxy_dtmf_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(rtpproxy_dtmf_params, 0, sizeof(evi_params_t));

	for (i = 0; i < sizeof(rtpproxy_event_params)/
			sizeof(rtpproxy_event_params[0]); i++) {
		rtpproxy_event_params[i].param =
			evi_param_create(rtpproxy_dtmf_params, &rtpproxy_event_params[i].name);
		if (!rtpproxy_event_params[i].param) {
			LM_ERR("could not initiate %.*s param!\n",
					rtpproxy_event_params[i].name.len,
					rtpproxy_event_params[i].name.s);
			return -1;
		}
	}

	rtpproxy_media_ip.len = strlen(rtpproxy_media_ip.s);
	if (!rtpproxy_media_ip.len) {
		LM_ERR("invalid media ip!\n");
		return -1;
	}

	if (rtpproxy_port_min < 0 || rtpproxy_port_min > 65535) {
		LM_ERR("invalid minimum port value %d\n", rtpproxy_port_min);
		return -1;
	}
	if (rtpproxy_port_max < 0 || rtpproxy_port_max > 65535) {
		LM_ERR("invalid maximum port value %d\n", rtpproxy_port_max);
		return -1;
	}
	if (rtpproxy_port_max < rtpproxy_port_min) {
		LM_NOTICE("port_max < port_min - swapping their values!\n");
		tmp = rtpproxy_port_min;
		rtpproxy_port_min = rtpproxy_port_max;
		rtpproxy_port_max = tmp;
	}

	rtpproxy_port = shm_malloc(sizeof *rtpproxy_port);
	if (!rtpproxy_port) {
		LM_ERR("cannot alloc rtpproxy port!\n");
		return -1;
	}
	*rtpproxy_port = rtpproxy_port_min;

	rtpproxy_port_lock = lock_alloc();
	if (!rtpproxy_port_lock) {
		LM_ERR("cannot alloc rtpproxy port lock!\n");
		shm_free(rtpproxy_port);
		return -1;
	}
	lock_init(rtpproxy_port_lock);
	return 0;
}

static int mi_child_init(void)
{
	if(child_init(1) < 0)
	{
		LM_ERR("Failed to initial rtpp socks\n");
		return -1;
	}

	if(!db_url.s)
		return 0;

	if (db_functions.init==0)
	{
		LM_CRIT("database not bound\n");
		return -1;
	}

	db_connection = db_functions.init(&db_url);
	if(db_connection == NULL) {
		LM_ERR("Failed to connect to database\n");
		return -1;
	}

	LM_DBG("Database connection opened successfully\n");

	return 0;
}

static int _add_proxies_from_database(void) {

	/* select * from rtpproxy_sockets order by set_id */
	db_key_t colsToReturn[2], order_by = &str_init("set_id");
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

	if(db_functions.query(db_connection, 0, 0, 0,colsToReturn, 0, 2, order_by,
				&result) < 0) {
		LM_ERR("Error querying database\n");
		if(result)
			db_functions.free_result(db_connection, result);
		return -1;
	}

	if(result == NULL)
	{
		LM_ERR("mysql query failed - NULL result\n");
		return -1;
	}

	if (RES_ROW_N(result)<=0 || RES_ROWS(result)[0].values[0].nul != 0) {
		LM_DBG("No proxies were found\n");
		if(db_functions.free_result(db_connection, result) < 0){
			LM_ERR("Error freeing result\n");
			return -1;
		}
		return 0;
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

		if(rtpproxy_add_rtpproxy_set(rtpp_socket, set_id) == -1)
		{
			LM_ERR("failed to add rtp proxy\n");
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
	/* we need DB conn in the worker processes only */
	if (rank<1)
		return 0;

	if(*rtpp_set_list==NULL )
		return 0;

	mypid = getpid();
	myrand = rand()%10000;

	return connect_rtpproxies(NULL);
}

int connect_rtpproxies(struct rtpp_set *filter)
{
	struct rtpp_set  *rtpp_list;
	struct rtpp_node *pnode;

	LM_DBG("[RTPProxy] set list %p\n", *rtpp_set_list);
	if(!(*rtpp_set_list) )
		return 0;
	LM_DBG("[Re]connecting sockets (%d > %d)\n", *rtpp_no, rtpp_number);

	if (*rtpp_no > rtpp_number) {
		rtpp_socks = (int*)pkg_realloc(rtpp_socks, *rtpp_no * sizeof(int) );
		if (rtpp_socks==NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
	}
	rtpp_number = *rtpp_no;

	for(rtpp_list = (*rtpp_set_list)->rset_first; rtpp_list != 0;
		rtpp_list = rtpp_list->rset_next){

		if (filter && filter->id_set != rtpp_list->id_set)
			continue;

		for (pnode=rtpp_list->rn_first; pnode!=0; pnode = pnode->rn_next){
			if (pnode->rn_umode == CM_UNIX) {
				rtpp_socks[pnode->idx] = -1;
			} else {
				rtpp_socks[pnode->idx] = connect_rtpp_node(pnode);
				LM_INFO("created to %d\n", rtpp_socks[pnode->idx]);
				if (rtpp_socks[pnode->idx] == -1) {
					LM_ERR("connect_rtpp_node() failed\n");
					return -1;
				}
			}
			pnode->rn_disabled = rtpp_test(pnode, 0, 1);
		}

		/* all nodes in this set are reconnected; mark it accordingly */
		{
			void **set_version;
			str sid;

			sid.s = int2str(rtpp_list->id_set, &sid.len);
			set_version = map_get(rtpp_set_versions, sid);
			if (!set_version) {
				LM_ERR("failed to get set %d version (oom?)\n", rtpp_list->id_set);
				continue;
			}

			*set_version = (void *)(long)rtpp_list->reload_ver;
		}
	}

	LM_DBG("successfully updated proxy sets\n");
	return 0;
}

/* Reconnect all rtpproxies in a specific set, or all sets if @set is NULL */
int update_rtpp_proxies(struct rtpp_set *filter) {
	int i;

	update_rtpp_notify();
	for (i = 0; i < rtpp_number; i++) {
		if (!filter ||
		        (filter->rtpp_socks_idx <= i
		         && i < filter->rtpp_socks_idx + filter->rtpp_node_count)) {
			LM_DBG("closing rtpp_socks[%d] | filter_set: %d\n", i,
			       filter ? filter->id_set : -1);
			shutdown(rtpp_socks[i], SHUT_RDWR);
			close(rtpp_socks[i]);
		}
	}

	return connect_rtpproxies(filter);
}

void free_rtpp_nodes(struct rtpp_set *list)
{
	struct rtpp_node * crt_rtpp, *last_rtpp;

	for(crt_rtpp = list->rn_first; crt_rtpp != NULL;  ){

		last_rtpp = crt_rtpp;
		crt_rtpp = last_rtpp->rn_next;
		shm_free(last_rtpp);
	}
	list->rn_first = NULL;
	list->rtpp_node_count = 0;
}

void free_rtpp_sets(void)
{
	struct rtpp_set * crt_list, * last_list;

	for(crt_list = (*rtpp_set_list)->rset_first; crt_list != NULL; ){

		free_rtpp_nodes(crt_list);
		last_list = crt_list;
		crt_list = last_list->rset_next;
		shm_free(last_list);
	}
	(*rtpp_set_list)->rset_first = NULL;
	(*rtpp_set_list)->rset_last = NULL;
}

static void mod_destroy(void)
{
	/*free the shared memory*/
	if (default_rtpp_set)
		shm_free(default_rtpp_set);

	if(!rtpp_set_list || *rtpp_set_list == NULL)
		return;

	free_rtpp_sets();
	shm_free(*rtpp_set_list);
	shm_free(rtpp_set_list);

	if(nh_lock)
	{
		lock_destroy_rw( nh_lock );
		nh_lock = NULL;
	}

	if (rtpp_notify_socket_un) {
		if (unlink(rtpp_notify_socket.s)) {
			LM_ERR("cannot remove the notification socket(%s:%d)\n",
					strerror(errno), errno);
		}
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


static int
extract_mediainfo(str *body, str *mediaport, str *payload_types)
{
	char *cp, *cp1;
	int len, i;
	str ptype;

	cp1 = NULL;
	for (cp = body->s; (len = body->s + body->len - cp) > 0;) {
		cp1 = l_memmem(cp, "m=", len, 2);
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
	LM_INFO("unsupported ptype [%.*s]\n", ptype.len, ptype.s);
	/* Unproxyable protocol type. Generally it isn't error. */
	return 1;
}

static int alter_rtcp(struct sip_msg *msg,str * body1, str *newip, int newpf ,str* newport,
			char * line_start )
{

	static const  str field = str_init("a=rtcp:");

	str buff = {0,0} ;
	str type;
	int offset;
	struct lump* anchor;
	str body, value;

	body.s = line_start;
	body.len = body1->s + body1->len - line_start;


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

	/* check that updating media-ip is really necessary */
	/* Conditions:
	- same IP protocol format for received IP and new IP
	- null IP received
	*/
	if (oldpf == newpf && isnulladdr(oldip, oldpf))
		return 0;
	if (newip->len == oldip->len &&
	    memcmp(newip->s, oldip->s, newip->len) == 0)
		return 0;

	if (preserve != 0) {
		anchor = anchor_lump(msg, body->s + body->len - msg->buf, 0);
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

	/* check that updating media-port is really necessary */
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
		anchor = anchor_lump(msg, body->s + body->len - msg->buf, 0);
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

static void gencookie(struct iovec *cv)
{
	static char cook[34];

	cv->iov_len = sprintf(cook, "%d_%d_%u ", (int)mypid, myrand, myseqn);
	cv->iov_base = cook;
	myseqn++;
}

static int
rtpp_checkcap(struct rtpp_node *node, char *cap, int caplen)
{
	char *cp;
	struct rtpproxy_vcmd vvf;

	RTPP_VCMD_INIT(vvf, 3, {"VF", 2}, {" ", 1}, {NULL, 0});

	vvf.vu[2].iov_base = cap;
	vvf.vu[2].iov_len = caplen;

	cp = send_rtpp_command(node, &vvf, vvf.useritems);
	if (cp == NULL)
		return -1;
	if (cp[0] == 'E' || atoi(cp) != 1)
		return 0;
	return 1;
}

static inline void raise_rtpproxy_event(struct rtpp_node *node, int status)
{
	evi_params_p list = NULL;
	if (ei_id == EVI_ERROR) {
		LM_ERR("event not registered %d\n", ei_id);
		return;
	}

	if (evi_probe_event(ei_id)) {
		if (!(list = evi_get_params()))
			return;
		if (evi_param_add_str(list, &socket_name, &node->rn_url)) {
			LM_ERR("unable to add socket parameter\n");
			goto free;
		}
		if (evi_param_add_str(list, &status_name, status ?
					&status_connected : &status_disconnected)) {
			LM_ERR("unable to add status parameter\n");
			goto free;
		}
		if (evi_raise_event(ei_id, list)) {
			LM_ERR("unable to send event\n");
		}
	} else {
		LM_DBG("no event sent\n");
	}
	return;
free:
	evi_free_params(list);
}



static int
rtpp_test(struct rtpp_node *node, int isdisabled, int force)
{
	int rtpp_ver, rval;
	char *cp;
	struct rtpproxy_vcmd vver;

	RTPP_VCMD_INIT(vver, 1, {"V", 1});

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
	cp = send_rtpp_command(node, &vver, vver.useritems);
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
	if (rtpp_checkcap(node, RTP_CAP(REPACK)) > 0)
		SET_CAP(node, REPACK);
	if (rtpp_checkcap(node, RTP_CAP(CODECS)) > 0)
		SET_CAP(node, CODECS);
	if (rtpp_checkcap(node, RTP_CAP(AUTOBRIDGE)) > 0)
		SET_CAP(node, AUTOBRIDGE);
	if (rtpp_checkcap(node, RTP_CAP(NOTIFY)) > 0)
		SET_CAP(node, NOTIFY);
	if (rtpp_checkcap(node, RTP_CAP(STATS)) > 0)
		SET_CAP(node, STATS);
	if (rtpp_checkcap(node, RTP_CAP(NOTIFY_WILD)) > 0)
		SET_CAP(node, NOTIFY_WILD);
	if (rtpp_checkcap(node, RTP_CAP(STATS_EXTRA)) > 0)
		SET_CAP(node, STATS_EXTRA);
	if (rtpp_checkcap(node, RTP_CAP(TTL_CHANGE)) > 0)
		SET_CAP(node, TTL_CHANGE);
	if (rtpp_checkcap(node, RTP_CAP(RECORD)) > 0)
		SET_CAP(node, RECORD);
	if (rtpp_checkcap(node, RTP_CAP(SUBCOMMAND)) > 0)
		SET_CAP(node, SUBCOMMAND);
	raise_rtpproxy_event(node, 1);
	return 0;
error:
	LM_WARN("support for RTP proxy <%s> has been disabled%s\n", node->rn_url.s,
	    rtpproxy_disable_tout < 0 ? "" : " temporarily");
	if (rtpproxy_disable_tout >= 0)
		node->rn_recheck_ticks = get_ticks() + rtpproxy_disable_tout;
	if (cp)
		raise_rtpproxy_event(node, 0);

	return 1;
}

#define RTPPROXY_BUF_SIZE 256
#define OSIP_IOV_MAX 1024

char *
send_rtpp_command(struct rtpp_node *node, struct rtpproxy_vcmd *vcmd, int vcnt)
{
	struct sockaddr_un addr;
	int fd, len, i;
	int max_vcnt=OSIP_IOV_MAX;
	char *cp;
	static char buf[RTPPROXY_BUF_SIZE];
	struct pollfd fds[1];

	DASSERT(vcnt <= vcmd->useritems);
	DASSERT(vcmd->vu == vcmd->vs + 1);

#ifdef IOV_MAX
	if (IOV_MAX < OSIP_IOV_MAX)
		max_vcnt = IOV_MAX;
#endif

	if (rtpp_socks[node->idx] == -1 && node->rn_umode != CM_UNIX) {
		rtpp_socks[node->idx] = connect_rtpp_node(node);
		if (rtpp_socks[node->idx] == -1) {
			LM_ERR("connect_rtpp_node() failed\n");
			return (NULL);
		}
	}
	/* normalize vcntl to max_vcnt, as on some systems this limit is very low (16 on Solaris) */
	if (vcnt + 1 > max_vcnt) {
		int i, vec_len = 0;
		/* use buf if possible :) */
		for (i = max_vcnt - 1; i < (vcnt + 1); i++)
			vec_len += vcmd->vs[i].iov_len;
		/* use buf, error otherwise */
		if (vec_len > RTPPROXY_BUF_SIZE) {
			LM_ERR("Command too big %d - max %d\n", vec_len, RTPPROXY_BUF_SIZE);
			return NULL;
		}
		cp = buf;
		for (i = max_vcnt - 1; i < (vcnt + 1); i++) {
			memcpy(cp, vcmd->vs[i].iov_base, vcmd->vs[i].iov_len);
			cp += vcmd->vs[i].iov_len;
		}
		i = max_vcnt - 1;
		vcmd->vs[i].iov_len = vec_len;
		vcmd->vs[i].iov_base = buf;
		/* finally solve the problem */
		vcnt = max_vcnt;

	}

	len = 0;
	cp = buf;

	if (node->rn_umode == CM_UNIX) {
		int s_errno, nretry;

		nretry = 1;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_LOCAL;
		strncpy(addr.sun_path, node->rn_address,
		    sizeof(addr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SA_LEN
		addr.sun_len = strlen(addr.sun_path);
#endif
retry:
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
			len = writev(fd, vcmd->vs + 1, vcnt);
		} while (len == -1 && errno == EINTR);
		if (len <= 0) {
			close(fd);
			LM_ERR("can't send (#%d iovec buffers) command to a RTP proxy (%d:%s)\n",
					vcnt, errno, strerror(errno));
			goto badproxy;
		}
		do {
			len = read(fd, buf, sizeof(buf) - 1);
		} while (len == -1 && errno == EINTR);
		s_errno = (len < 0) ? errno : 0;
		close(fd);
		if (s_errno == ECONNRESET && nretry > 0) {
			LM_WARN("RTP proxy reset connection, retrying...\n");
			nretry--;
			goto retry;
		}
		if (len <= 0) {
			LM_ERR("can't read reply from a RTP proxy, e = %d\n",
                            s_errno);
			goto badproxy;
		}
	} else {
		int rtry = CM_STREAM(node) ? 1 : rtpproxy_retr;
		fds[0].fd = rtpp_socks[node->idx];
		fds[0].events = POLLIN | POLLRDHUP;
		fds[0].revents = 0;
		/* Drain input buffer */
		while ((poll(fds, 1, 0) == 1) &&
		    ((fds[0].revents & POLLIN) != 0)) {
			if (fds[0].revents & (POLLERR|POLLNVAL|POLLRDHUP)) {
				LM_ERR("error on rtpproxy socket %d!\n", rtpp_socks[node->idx]);
				break;
			}
			fds[0].revents = 0;
			if (recv(rtpp_socks[node->idx], buf, sizeof(buf) - 1, 0) < 0 &&
					errno != EINTR) {
				LM_ERR("error while draining rtpproxy %d!\n", errno);
				break;
			}
		}
		struct iovec *cv = CM_STREAM(node) ? &(vcmd->vs[1]) : &(vcmd->vs[0]);
		if (!CM_STREAM(node)) {
			gencookie(&(cv[0]));
		} else {
			cv[vcnt].iov_base = "\n";
			cv[vcnt].iov_len = 1;
		}
		for (i = 0; i < rtry; i++) {
			int buflen = sizeof(buf)-1;
			do {
				len = writev(rtpp_socks[node->idx], cv, vcnt + 1);
			} while (len == -1 && (errno == EINTR || errno == ENOBUFS));
			if (len <= 0) {
				LM_ERR("can't send (#%d iovec buffers) command to a RTP proxy (%d:%s)\n",
						vcnt + 1, errno, strerror(errno));
				goto badproxy;
			}
			while ((poll(fds, 1, rtpproxy_tout) == 1) &&
			    (fds[0].revents & POLLIN) != 0) {
				int s_errno;

				do {
					len = recv(rtpp_socks[node->idx], cp, buflen, 0);
				} while (len == -1 && errno == EINTR);
				s_errno = (len < 0) ? errno : 0;
				if (len <= 0) {
					LM_ERR("can't read reply from a RTP proxy, e = %d\n",
					    s_errno);
					goto badproxy;
				}
				if (CM_STREAM(node)) {
					char *eor = memchr(cp, '\n', len);
					if (eor != NULL) {
						if (eor != cp + len - 1) {
							LM_ERR("can't parse reply from a RTP proxy: garbage after '\\n'\n");
							goto badproxy;
						}
						len += cp - buf;
						cp = buf;
						goto out;
					}
					cp += len;
					buflen -= len;
					if (buflen == 0) {
						LM_ERR("can't parse reply from a RTP proxy: missing '\\n'\n");
						goto badproxy;
					}
				} else if (len >= (vcmd->vs[0].iov_len - 1) &&
				    memcmp(buf, vcmd->vs[0].iov_base, (vcmd->vs[0].iov_len - 1)) == 0) {
					len -= (vcmd->vs[0].iov_len - 1);
					cp += (vcmd->vs[0].iov_len - 1);
					if (len != 0) {
						len--;
						cp++;
					}
					goto out;
				}
				fds[0].revents = 0;
			}
		}
		if (i == rtry) {
			LM_ERR("timeout waiting reply from a RTP proxy\n");
			goto badproxy;
		}
	}

out:
	cp[len] = '\0';
	return cp;
badproxy:
	LM_ERR("proxy <%s> does not respond, disable it\n", node->rn_url.s);
	if (CM_STREAM(node)) {
		close(rtpp_socks[node->idx]);
		rtpp_socks[node->idx] = -1;
	}
	node->rn_disabled = 1;
	node->rn_recheck_ticks = get_ticks() + rtpproxy_disable_tout;
	raise_rtpproxy_event(node, 0);
	return NULL;
}

/*
 * select the set with the id_set id
 */

static struct rtpp_set * select_rtpp_set(int id_set){

	struct rtpp_set * rtpp_list;
	/*is it a valid set_id?*/
	LM_DBG("Looking for set_id %d\n", id_set);

	if(!rtpp_set_list || !(*rtpp_set_list) || !(*rtpp_set_list)->rset_first)
		return 0;

	for(rtpp_list=(*rtpp_set_list)->rset_first; rtpp_list!=0 &&
		rtpp_list->id_set!=id_set; rtpp_list=rtpp_list->rset_next);
	if(!rtpp_list){
		LM_DBG("no engine in set %d\n", id_set);
	}

	return rtpp_list;
}

int rtpp_check_reload_ver(struct rtpp_set *set)
{
	void **set_version;
	str sid;

	if (!set && my_version != *list_version) {
		int rc = update_rtpp_proxies(NULL);

		if (rc == 0)
			my_version = *list_version;
		return rc;
	}

	sid.s = int2str(set->id_set, &sid.len);
	set_version = map_get(rtpp_set_versions, sid);
	if (!set_version) {
		LM_ERR("failed to get set %d version (oom?)\n", set->id_set);
		return -1;
	}

	LM_DBG("set: %d | my ver: %ld | set ver: %d\n", set->id_set,
	       (long)*set_version, set->reload_ver);

	if ((long)*set_version != set->reload_ver && update_rtpp_proxies(set) < 0) {
		LM_ERR("failed to update rtpp proxies list in set %d\n", set->id_set);
		return -1;
	}

	return 0;
}


/*
 * Main balancing routine. This does not try to keep the same proxy for
 * the call if some proxies were disabled or enabled; proxy death considered
 * too rare. Otherwise we should implement "mature" HA clustering, which is
 * too expensive here.
 */
struct rtpp_node *
select_rtpp_node(struct sip_msg * msg,
		str callid, struct rtpp_set *set, pv_spec_p spec, int do_test)
{
	unsigned sum, weight_sum;
	struct rtpp_node* node;
	int was_forced, sumcut, found, constant_weight_sum;
	pv_value_t val;

	if (!set) {
		LM_ERR("no set specified\n");
		return NULL;
	}

	if (rtpp_check_reload_ver(set) != 0) {
		LM_ERR("cannot update rtpp proxies list (set: %d)\n",
		       set ? set->id_set : -1);
		return NULL;
	}

	/* Most popular case: 1 proxy, nothing to calculate */
	if (set->rtpp_node_count == 1) {
		node = set->rn_first;
		if (node->rn_disabled && node->rn_recheck_ticks <= get_ticks()) {
			node->rn_disabled = rtpp_test(node, 1, 0);
			if (node->rn_disabled)
				node->rn_recheck_ticks = get_ticks() +
				    rtpproxy_disable_tout;
		}
		if (node->rn_disabled)
			return NULL;

		goto done;
	}

	/* XXX Use quick-and-dirty hashing algo */
	for(sum = 0; callid.len > 0; callid.len--)
		sum += callid.s[callid.len - 1];
	sum &= 0xff;

	was_forced = 0;
retry:
	weight_sum = 0;
	constant_weight_sum = 0;
	found = 0;
	for (node=set->rn_first; node!=NULL; node=node->rn_next) {

		if (node->rn_disabled && node->rn_recheck_ticks <= get_ticks()){
			/* Try to enable if it's time to try. */
			node->rn_disabled = rtpp_test(node, 1, 0);
			if (node->rn_disabled)
				node->rn_recheck_ticks = get_ticks() +
				    rtpproxy_disable_tout;
		}
		constant_weight_sum += node->rn_weight;
		if (!node->rn_disabled) {
			weight_sum += node->rn_weight;
			found = 1;
		}
	}
	if (found == 0) {
		/* No proxies? Force all to be re-detected, if not yet */
		if (was_forced)
			return NULL;
		was_forced = 1;
		for(node=set->rn_first; node!=NULL; node=node->rn_next) {
			node->rn_disabled = rtpp_test(node, 1, 1);
		}
		goto retry;
	}
	sumcut = weight_sum ? sum % constant_weight_sum : -1;
	/*
	 * sumcut here lays from 0 to constant_weight_sum-1.
	 * Scan proxy list and decrease until appropriate proxy is found.
	 */
	was_forced = 0;
	for (node=set->rn_first; node!=NULL;) {
		if (sumcut < (int)node->rn_weight) {
			if (!node->rn_disabled)
				goto found;
			if (was_forced == 0) {
				/* appropriate proxy is disabled : redistribute on enabled ones */
				sumcut = weight_sum ? sum %  weight_sum : -1;
				node = set->rn_first;
				was_forced = 1;
				continue;
			}
		}
		if (!node->rn_disabled || !was_forced)
			sumcut -= node->rn_weight;
		node = node->rn_next;
	}
	/* No node list */
	return NULL;
found:
	if (do_test) {
		node->rn_disabled = rtpp_test(node, node->rn_disabled, 0);
		if (node->rn_disabled)
			goto retry;
	}
done:
	/* Store rtpproxy used */
	if (spec && msg) {
		memset(&val, 0, sizeof(pv_value_t));
		val.flags = PV_VAL_STR;
		val.rs = node->rn_url;
		if(pv_set_value(msg, spec, (int)EQ_T, &val)<0)
			LM_ERR("setting PV failed\n");
	}

	return node;
}

struct rtpp_node *get_rtpp_node_from_set(str *node, struct rtpp_set *set, int test)
{
	struct rtpp_node *rnode;

	for (rnode = set->rn_first; rnode; rnode = rnode->rn_next)
		if (node->len == rnode->rn_url.len &&
				!memcmp(node->s, rnode->rn_url.s, node->len)) {
			if (!test)
				return rnode;
			if (rnode->rn_disabled)
				rnode->rn_disabled = rtpp_test(rnode, rnode->rn_disabled, 0);
			return (rnode->rn_disabled ? NULL : rnode);
		}
	return NULL;
}

struct rtpp_node *get_rtpp_node(str *node, struct rtpp_set *filter)
{
	struct rtpp_set *set;
	struct rtpp_node *rnode;

	if (rtpp_check_reload_ver(filter) != 0) {
		LM_ERR("cannot update rtpp proxies list (set: %d)\n",
		       filter ? filter->id_set : -1);
		return NULL;
	}

	/* if chosen a specific node, use it! */
	for (set = (*rtpp_set_list)->rset_first; set; set = set->rset_next) {
		if ((rnode = get_rtpp_node_from_set(node, set, 1)) != NULL)
			return rnode;
	}
	return NULL;
}

static int
unforce_rtp_proxy_f(struct sip_msg* msg, nh_set_param_t *pset, pv_spec_t *var)
{
	int ret = -1;
	struct rtpp_args args;

	if (!msg || msg == FAKED_REPLY)
		return 1;

	memset(&args, 0, sizeof args);

	if (get_callid(msg, &args.callid) == -1 || args.callid.len == 0) {
		LM_ERR("can't get Call-Id field\n");
		return -1;
	}
	args.to_tag.s = 0;
	if (get_to_tag(msg, &args.to_tag) == -1) {
		LM_ERR("can't get To tag\n");
		return -1;
	}
	if (get_from_tag(msg, &args.from_tag) == -1 || args.from_tag.len == 0) {
		LM_ERR("can't get From tag\n");
		return -1;
	}

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	args.set = get_rtpp_set(pset);
	if (!args.set) {
		LM_ERR("could not find rtpproxy set\n");
		goto end;
	}

	args.node = select_rtpp_node(msg, args.callid, args.set, var, 1);
	if (!args.node) {
		LM_ERR("no available proxies\n");
		goto end;
	}

	ret = unforce_rtpproxy(msg, &args, var);

end:
	if (nh_lock) {
		lock_stop_read( nh_lock );
	}

	return ret;
}

static int unforce_rtpproxy(struct sip_msg* msg, struct rtpp_args *args, pv_spec_t *var)
{
	struct rtpproxy_vcmd vdel;

	RTPP_VCMD_INIT(vdel, 4 + 3, {"D", 1}, {" ", 1}, {NULL, 0}, {" ", 1},
			            /*.vu[0]*//*.vu[1]*//*.vu[2]*//*.vu[3]*/
	    {NULL, 0}, {" ", 1}, {NULL, 0});
	    /*.vu[4]*//*.vu[5]*//*.vu[6] */

	STR2IOVEC(args->callid, vdel.vu[2]);
	STR2IOVEC(args->from_tag, vdel.vu[4]);
	STR2IOVEC(args->to_tag, vdel.vu[6]);

	send_rtpp_command(args->node, &vdel,
			(args->to_tag.len > 0)?vdel.useritems:vdel.useritems - 2);
	LM_DBG("sent unforce command\n");

	return 1;
}



struct rtpp_set * get_rtpp_set(nh_set_param_t *pset)
{
	struct rtpp_set *set;

	if (!pset)
		return *default_rtpp_set;

	if (pset->t == NH_VAL_SET_FIXED)
		return pset->v.fixed_set;

	LM_DBG("Checking proxy set %d\n", pset->v.int_set);

	set = select_rtpp_set(pset->v.int_set);
	if (!set)
		LM_ERR("cannot find any available rtpproxy engine in set %d\n",
			pset->v.int_set);

	return set;
}


static inline void rtpp_get_nt_str_param(str *param, str *val, int n)
{
	#define MAX_BUF  64
	static char buf[2][MAX_BUF];

	val->s = buf[n];
	val->len = (param->len>MAX_BUF-1) ? MAX_BUF-1 : param->len;
	memcpy(val->s, param->s, val->len);
	val->s[val->len] = 0;
}

static str *rtpproxy_offer_answer_buf(struct sip_msg *msg, pv_spec_t *body_pv)
{
	pv_value_t val;
	static str body;

	if (pv_get_spec_value(msg, body_pv, &val) < 0 ||
			!(val.flags & PV_VAL_STR)) {
		LM_ERR("could not retrieve body!\n");
		return NULL;
	}

	if (pkg_str_sync(&body, &val.rs) < 0)
		return NULL;

	return &body;
}

static int rtpproxy_offer_answer_buf_ret(struct sip_msg *msg,
		pv_spec_t *body_pv, str *body)
{
	pv_value_t val;
	if(!pv_is_w(body_pv))
	{
		LM_ERR("read only PV in first parameter of pv_printf\n");
		return -1;
	}
	memset(&val, 0, sizeof val);
	val.flags = PV_VAL_STR;
	val.rs = *body;
	return pv_set_value(msg, body_pv, 0, &val)<0?-1:1;
}

static int
rtpproxy_offer_answer6_f(struct sip_msg *msg, str *param1, str *param2,
				nh_set_param_t *param3, pv_spec_t *param4, pv_spec_t *param5,
				pv_spec_t *param6, int offer)
{
	int ret;
	str *body;
	str param1_val={0,0},param2_val={0,0};

	if (param1)
		rtpp_get_nt_str_param(param1, &param1_val, 0);
	if (param2)
		rtpp_get_nt_str_param(param2, &param2_val, 1);
	if (param6) {
		body = rtpproxy_offer_answer_buf(msg, param6);
		if (!body)
			return -1;
	} else {
		body = NULL;
	}

	ret = force_rtp_proxy(msg, param1_val.s,param2_val.s, param3, param4, param5, body, offer);
	if (ret > 0 && param6)
		ret = rtpproxy_offer_answer_buf_ret(msg, param6, body);
	return ret;
}

static int
rtpproxy_offer6_f(struct sip_msg *msg, str *param1, str *param2,
				nh_set_param_t *param3, pv_spec_t *param4, pv_spec_t *param5,
				pv_spec_t *param6)
{
	if(rtpp_notify_socket.s)
	{
		if ( (!msg->to && parse_headers(msg, HDR_TO_F,0)<0) || !msg->to ) {
			LM_ERR("bad request or missing TO hdr\n");
			return -1;
		}

		/* if an initial request - create a new dialog */
		if(get_to(msg)->tag_value.s == NULL && dlg_api.create_dlg)
			dlg_api.create_dlg(msg,0);
	}
	return rtpproxy_offer_answer6_f(msg, param1, param2, param3, param4,
			param5, param6, 1);
}

static int
rtpproxy_answer6_f(struct sip_msg *msg, str *param1, str *param2,
				nh_set_param_t *param3, pv_spec_t *param4, pv_spec_t *param5,
				pv_spec_t *param6)
{
	return rtpproxy_offer_answer6_f(msg, param1, param2, param3, param4,
			param5, param6, 0);
}

static void engage_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	if (!dlg || !_params)
		return;

	/* engage */
	engage_force_rtpproxy(dlg, _params->msg);
}

static void engage_close_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	int_str value;
	struct rtpp_args args;
	static nh_set_param_t param;
	int val_type;

	if (!dlg || !_params)
		return;
	LM_DBG("engage close called\n");

	if (dlg_api.fetch_dlg_value(dlg, &param3_name, &val_type, &value, 0) < 0) {
		LM_DBG("third param not found\n");
		param.v.int_set = default_rtpp_set_no;
	} else {
		param.v.int_set = *(int *)(value.s.s);
	}
	param.t = NH_VAL_SET_UNDEF;
	args.callid = dlg->callid;
	args.from_tag = dlg->legs[DLG_CALLER_LEG].tag;
	args.to_tag = dlg->legs[callee_idx(dlg)].tag;

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	args.set = get_rtpp_set(&param);
	if (!args.set) {
		LM_ERR("could not find rtpproxy set\n");
		goto end;
	}

	args.node = select_rtpp_node(_params->msg, args.callid,
			args.set, NULL, 1);
	if (!args.node) {
		LM_ERR("no available proxies\n");
		goto end;
	}

	if (unforce_rtpproxy(_params->msg, &args, NULL) < 0)
		LM_ERR("cannot unforce rtp proxy\n");
end:
	if (nh_lock) {
		lock_stop_read( nh_lock );
	}
}

/* moves parameters from branch avps to dialog values
 * returns the values moved
 */
static int move_bavp2dlg(struct sip_msg *msg, struct dlg_cell *dlg, str *rval1, str *rval2, int *setid)
{
	unsigned int code = 0;
	unsigned int flags_found = 0;
	unsigned int ip_found = 0;
	unsigned int set_found = 0;
	pv_value_t val1, val2, val3;
	str param3_val;
	int_str isval;

	if (!msg || !dlg || msg->first_line.type != SIP_REPLY)
		goto not_moved;

	/* check to see if there are avps stored */
	if (pv_get_spec_value(msg, &param1_spec, &val1) < 0 ||
			(val1.flags & PV_VAL_NULL))
		LM_DBG("flags bavp not found!\n");
	else
		flags_found = 1;

	if (pv_get_spec_value(msg, &param2_spec, &val2) < 0 ||
			(val2.flags & PV_VAL_NULL))
		LM_DBG("ip bavp not found!\n");
	else
		ip_found = 1;

	if (pv_get_spec_value(msg, &param3_spec, &val3) < 0 ||
			(val3.flags & PV_VAL_NULL))
		LM_DBG("set bavp not found!\n");
	else
		set_found = 1;

	if ((flags_found|ip_found|set_found) == 0)
		goto not_moved;

	code = msg->first_line.u.reply.statuscode;
	/* only move branch avps if a final response has come */
	if (code >= 200 && code < 300) {
		if (flags_found) {
			isval.s = val1.rs;
			if (dlg_api.store_dlg_value(dlg, &param1_name, &isval,
				DLG_VAL_TYPE_STR) < 0) {
				LM_ERR("cannot store value\n");
				goto error;
			}
		} else {
			val1.rs.len = 0;
			val1.rs.s = 0;
		}
		if (rval1) {
			rval1->len = val1.rs.len;
			rval1->s = val1.rs.s;
		}
		if (ip_found) {
			isval.s = val2.rs;
			if (dlg_api.store_dlg_value(dlg, &param2_name, &isval,
				DLG_VAL_TYPE_STR) < 0) {
				LM_ERR("cannot store value\n");
				goto error;
			}
		} else {
			val2.rs.len = 0;
			val2.rs.s = 0;
		}
		if (rval2) {
			rval2->len = val2.rs.len;
			rval2->s = val2.rs.s;
		}

		if (set_found) {
			/* Store Set ID INT value correcty in dlg */
			param3_val.s = (char*)&val3.ri;
			param3_val.len = sizeof(unsigned int);
			isval.s = param3_val;
			if (dlg_api.store_dlg_value(dlg, &param3_name, &isval,
				DLG_VAL_TYPE_STR) < 0) {
				LM_ERR("cannot store setid value\n");
				goto error;
			}
		} else {
			val3.ri = default_rtpp_set_no;
		}
		if (setid)
			*setid = val3.ri;

		LM_DBG("moved <%s> and <%s> from branch avp list in dlg\n",
				param1_name.s,param2_name.s);
		return 1;
	} else if (code < 200) {

		if (!flags_found) {
			val1.rs.len = 0;
			val1.rs.s = 0;
		}
		if (rval1) {
			rval1->len = val1.rs.len;
			rval1->s = val1.rs.s;
		}

		if (!ip_found) {
			val2.rs.len = 0;
			val2.rs.s = 0;
		}
		if (rval2) {
			rval2->len = val2.rs.len;
			rval2->s = val2.rs.s;
		}
		if (!set_found)
			val3.ri = default_rtpp_set_no;
		if (setid)
			*setid = val3.ri;
		return 1;
	}

not_moved:
	LM_DBG("nothing moved - message type %d\n", !msg ? -1 : msg->first_line.type);
	if (rval1) rval1->len = 0;
	if (rval2) rval2->len = 0;
	if (setid) *setid = default_rtpp_set_no;
	return 0;
error:
	return -1;
}


static int engage_force_rtpproxy(struct dlg_cell *dlg, struct sip_msg *msg)
{
	int offer = 1;
	int setid;
	str param1_val,param2_val;
	int method_id, has_sdp, alloc = 0;
	int moved;
	static nh_set_param_t param = { .t = NH_VAL_SET_UNDEF };
	int_str value;
	int val_type;

	LM_DBG("engage callback called\n");

	if (!msg)
		goto done;

	if (dlg_api.get_dlg && !dlg) {
		dlg = dlg_api.get_dlg();
		if (!dlg) {
			LM_DBG("dialog not found - cannot engage rtpproxy\n");
			goto done;
		}
	}

	if (!dlg) {
		LM_ERR("null dialog\n");
		goto error;
	}

	/* parse cseq header */
	if(parse_headers(msg,HDR_CSEQ_F,0) < 0) {
		LM_ERR("cannot parse cseq header\n");
		goto error;
	}

	if(msg->cseq==NULL || msg->cseq->body.s==NULL) {
		LM_ERR("cseq header empty\n");
		goto error;
	}

	/* check to see if this is a late negotiation */
	if (dlg_api.fetch_dlg_value(dlg, &late_name, &val_type, &value, 0) < 0)
		offer = 0;
	has_sdp = has_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);

	method_id = get_cseq(msg)->method_id;
	LM_DBG("method id is %d SDP: %d\n", method_id, has_sdp);
	if (method_id == METHOD_ACK) {
		/* normal negotiation - ACK cannot have SDP */
		if (!offer && has_sdp) {
			LM_ERR("not a late negotiation - ACK cannot have SDP body\n");
			goto error;
		}
		/* late negotiation without SDP */
		if (offer && !has_sdp) {
			LM_ERR("ACK of a late negotiation that doesn't have SDP body\n");
			goto error;
		}
		/* valid normal negotiation */
		if (!offer && !has_sdp)
			goto done;
		/* late negotiation */
		/* delete the value, to make sure we don't re-engage late again */
		dlg_api.store_dlg_value(dlg, &late_name, NULL, DLG_VAL_TYPE_NONE);
	} else {
		/* sequential request without SDP */
		if (!has_sdp) {
			if (msg->first_line.type == SIP_REQUEST &&
					(method_id == METHOD_INVITE ||  method_id == METHOD_UPDATE)) {
				/* indicate there's an ongoing late negociation happening */
				value.s = late_name;
				if (dlg_api.store_dlg_value(dlg, &late_name, &value,
					DLG_VAL_TYPE_NONE) < 0) {
					LM_ERR("cannot store late_negotiation param into dialog\n");
					goto error;
				}
			}
			goto done;
		}
		/* if it is not an 200OK */
		if (msg->first_line.type == SIP_REPLY)
			LM_DBG("handling 200 OK? - %d\n", msg->first_line.u.reply.statuscode);
	}

	/* try to move values */
	if ((moved = move_bavp2dlg(msg, dlg, &param1_val, &param2_val, &setid)) < 0) {
		LM_ERR("error while moving branch avps\n");
		goto error;
	}

	/* don't have them, try to get them from the dialog */
	if (moved == 0) {
		/* nothing moved - the values should be in dialog already */
		if (dlg_api.fetch_dlg_value(dlg, &param1_name, &val_type, &value, 0) >= 0) {
			param1_val.s = pkg_malloc(value.s.len + 1);
			if (!param1_val.s) {
				LM_ERR("no more pkg mem\n");
				goto error;
			}
			alloc = 1;
			memcpy(param1_val.s, value.s.s, value.s.len);
			param1_val.s[value.s.len] = '\0';
			param1_val.len = value.s.len;
		} else {
			LM_DBG("flags param not found\n");
			param1_val.s = NULL;
		}
		if (dlg_api.fetch_dlg_value(dlg, &param2_name, &val_type, &value, 0) >= 0) {
			param2_val.s = pkg_malloc(value.s.len + 1);
			if (!param2_val.s) {
				LM_ERR("no more pkg mem\n");
				goto error;
			}
			alloc = 1;
			memcpy(param2_val.s, value.s.s, value.s.len);
			param2_val.s[value.s.len] = '\0';
			param2_val.len = value.s.len;
		} else {
			LM_DBG("ip param not found\n");
			param2_val.s = NULL;
		}

		if (dlg_api.fetch_dlg_value(dlg, &param3_name, &val_type, &value, 0) < 0) {
			LM_DBG("third param not found\n");
			setid = default_rtpp_set_no;
		} else {
			setid = *(int *)(value.s.s);
		}

		LM_DBG("fetched: param1 <%s> param2 <%s> set <%d> - offer? %s\n",
				param1_val.s ? param1_val.s : "none",
				param2_val.s ? param2_val.s : "none",
				setid, offer? "yes":"no");
	}
	param.v.int_set = setid;
	param.t = NH_VAL_SET_UNDEF;

	force_rtp_proxy(msg, param1_val.s, param2_val.s, &param, NULL, NULL, NULL, offer);

	if (alloc) {
		if (param1_val.s)
			pkg_free(param1_val.s);
		if (param2_val.s)
			pkg_free(param2_val.s);
	}
done:
	return 0;
error:
	return -1;
}

void engage_tm_reply_callback(struct cell* t, int type, struct tmcb_params *p)
{
	if (!t || !p)
		return;

	/* engage */
	engage_force_rtpproxy(NULL, p->rpl);
}


static int
engage_rtp_proxy5_f(struct sip_msg *msg, str *param1, str *param2,
				nh_set_param_t *param3, pv_spec_t *param4, pv_spec_t *param5)
{
	str param1_val={0,0},param2_val={0,0};
	struct to_body *pto;
	struct dlg_cell *dlg;
	struct rtpp_set *set = NULL;
	pv_value_t val1, val2;
	int_str isval;

	LM_DBG("engage called from script 1:%p 2:%p 3:%p 4:%p\n",
			param1, param2, param3, param4);

	if (!(msg->first_line.type == SIP_REQUEST &&
		msg->first_line.u.request.method_value == METHOD_INVITE)) {
		LM_ERR("this function can only be called from invite\n");
		return -1;
	}

	if ( (!msg->to && parse_headers(msg, HDR_TO_F, 0)<0) || !msg->to ) {
		LM_ERR("bad request or missing TO hdr\n");
		return -1;
	}

	pto = get_to(msg);
	if (pto == NULL || pto->error != PARSE_OK) {
		LM_ERR("failed to parse TO header\n");
		return -1;
	}

	/* to-tag field is empty*/
	if (!( pto->tag_value.s==NULL || pto->tag_value.len==0) ) {
		LM_ERR("function can only be called from the initial invite\n");
		return -1;
	}

	/* create dialog */
	if (dlg_api.create_dlg(msg,0) < 0) {
		LM_ERR("error creating dialog\n");
		return -1;
	}

	dlg = dlg_api.get_dlg();
	if (!dlg) {
		LM_ERR("cannot get dialog\n");
		return -1;
	}

	if (param1)
		rtpp_get_nt_str_param(param1, &param1_val, 0);
	if (param2)
		rtpp_get_nt_str_param(param2, &param2_val, 1);

	/* is this a late negotiation scenario? */
	if (has_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP)) {
		LM_DBG("message has sdp body -> forcing rtp proxy\n");
		if(force_rtp_proxy(msg,param1_val.s,param2_val.s,param3,param4, param5, NULL, 1) < 0) {
			LM_ERR("error forcing rtp proxy\n");
			return -1;
		}
	} else {
		isval.s = late_name;
		if (dlg_api.store_dlg_value(dlg, &late_name, &isval, DLG_VAL_TYPE_STR) < 0) {
			LM_ERR("cannot store late_negotiation param into dialog\n");
			return -1;
		}
	}

	if (param3) {
		/* get the set-id */
		set = get_rtpp_set(param3);
		if (!set) {
			LM_CRIT("set no longer here - forcing the default one!\n");
			set = *default_rtpp_set;
		}
	} else {
		set = *default_rtpp_set;
	}

	if (route_type & BRANCH_ROUTE) {
		/* store the value into branch avps */
		if (param1) {
			val1.flags = AVP_VAL_STR;
			val1.rs = param1_val;

			if (pv_set_value(msg, &param1_spec, EQ_T, &val1) < 0) {
				LM_ERR("cannot store <%.*s> param", param1_name.len, param1_name.s);
				return -1;
			}

			if (!val1.rs.len) {
				LM_ERR("cannot store flags parameter in branch avp\n");
				return -1;
			}
		}

		if (param2) {
			val2.flags = AVP_VAL_STR;
			val2.rs = param2_val;

			if (pv_set_value(msg, &param2_spec, EQ_T, &val2) < 0) {
				LM_ERR("cannot store <%.*s> param", param2_name.len, param2_name.s);
				return -1;
			}
		}

		if (param3) {
			val2.flags = PV_TYPE_INT;
			val2.ri = set->id_set;

			if (pv_set_value(msg, &param3_spec, EQ_T, &val2) < 0) {
				LM_ERR("cannot store set param\n");
				return -1;
			}
		}

		LM_DBG("stored values in bavp\n");
	} else {
		isval.s = param1_val;
		if ( param1 && dlg_api.store_dlg_value(dlg, &param1_name, &isval,
			DLG_VAL_TYPE_STR) < 0) {
			LM_ERR("cannot store flags param into dialog\n");
			return -1;
		}
		isval.s = param2_val;
		if ( param2 && dlg_api.store_dlg_value(dlg, &param2_name, &isval,
			DLG_VAL_TYPE_STR) < 0) {
			LM_ERR("cannot store ip param into dialog\n");
			return -1;
		}
		if (param3) {
			param2_val.s = (char*)&set->id_set;
			param2_val.len = sizeof(unsigned int);
			isval.s = param2_val;
			if (dlg_api.store_dlg_value(dlg, &param3_name, &isval,
				DLG_VAL_TYPE_STR) < 0) {
				LM_ERR("cannot store set param into dialog\n");
				return -1;
			}
		}
		LM_DBG("stored values in dialog\n");
	}
	/* callbacks setup - only once */
	if (msg->msg_flags & FL_USE_RTPPROXY) {
		LM_DBG("rtpproxy callbacks already registered\n");
		return 1;
	}
	msg->msg_flags |= FL_USE_RTPPROXY;

	/* handles the replies to the original INVITE */
	if (tm_api.register_tmcb( msg, 0, TMCB_RESPONSE_FWDED,
			engage_tm_reply_callback,0,0)!=1) {
		LM_ERR("failed to install TM callback\n");
		return -1;
	}

	if (dlg_api.register_dlgcb(dlg,
			DLGCB_RESPONSE_WITHIN|DLGCB_REQ_WITHIN,
			engage_callback, msg, 0) != 0) {
		LM_ERR("cannot register callback\n");
		return -1;
	}
	LM_DBG("registered engage_callback\n");

	if (dlg_api.register_dlgcb(dlg, DLGCB_FAILED | DLGCB_TERMINATED,
				engage_close_callback, msg, 0) != 0) {
		LM_ERR("cannot register close callback\n");
		return -1;
	}

	return 1;
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

static int
append_opts_str(struct options *op, str *s)
{
	void *p;

	if (op->s.len < op->oidx + s->len) {
		p = pkg_realloc(op->s.s, op->oidx + s->len + 32);
		if (p == NULL) {
			 return (-1);
		}
		op->s.s = p;
		op->s.len = op->oidx + s->len + 32;
	}
	memcpy(op->s.s + op->oidx, s->s, s->len);
	op->oidx += s->len;
	return (0);
}

static void
free_opts(struct options *op1, struct options *op2, struct options *op3, struct options *op4)
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
	if (op4->s.len > 0 && op4->s.s != NULL) {
		pkg_free(op4->s.s);
		op4->s.len = 0;
	}
}

static int
force_rtpproxy_body_part(struct sip_msg *msg, struct rtpp_args *args,
		pv_spec_t *var, pv_spec_t *ipvar, str *body)
{
	int ret = 0;
	struct rtpp_args *ap;
	union sockaddr_union to;
	struct ip_addr ip;
	struct cell *trans;

	if (rtpproxy_autobridge) {

		if (nh_lock)
			lock_start_read(nh_lock);

		args->node = select_rtpp_node(msg, args->callid, args->set, var, 1);
		if (args->node == NULL) {
			LM_ERR("no available proxies\n");
			goto error_with_lock;
		}

		/* XXX: here we assume that all nodes in a set should be similar */
		if (HAS_CAP(args->node, AUTOBRIDGE)) {
			if (msg->first_line.type == SIP_REQUEST) {
				ap = pkg_malloc(sizeof(*ap));
				if (ap == NULL) {
					LM_ERR("can't allocate memory\n");
					goto error_with_lock;
				}
				memcpy(ap, args, sizeof(*ap));
				if (args->arg1 != NULL) {
					ap->arg1 = pkg_strdup(args->arg1);
					if (ap->arg1 == NULL) {
						pkg_free(ap);
						LM_ERR("can't allocate memory\n");
						goto error_with_lock;
					}
				}
				if (args->arg2 != NULL) {
					ap->arg2 = pkg_strdup(args->arg2);
					if (ap->arg2  == NULL) {
						if (ap->arg1 != NULL)
							pkg_free(ap->arg1);
						pkg_free(ap);
						LM_ERR("can't allocate memory\n");
						goto error_with_lock;
					}
				}
				/* we don't remember the node, since it might not be
				 * available later when we execute the callback */
				ap->node = NULL;
				msg_callback_add(msg, REQ_PRE_FORWARD, rtpproxy_pre_fwd, ap);
				msg_callback_add(msg, MSG_DESTROY, rtpproxy_pre_fwd_free, ap);
				if (nh_lock)
					lock_stop_read(nh_lock);
				return 0;
			} else {
				/* first try to get the destination of this reply from the
				 * transaction (as the source of the request) */
				if (tm_api.t_gett && (trans=tm_api.t_gett())!=0 &&
				trans!=T_UNDEFINED && trans->uas.request ) {
					/* we have the request from the transaction this
					 * reply belongs to */
					args->raddr.s = ip_addr2a(&trans->uas.request->rcv.src_ip);
					args->raddr.len = strlen(args->raddr.s);
				} else if (parse_headers(msg, HDR_VIA2_F, 0) != -1 &&
				(msg->via2 != NULL) && (msg->via2->error == PARSE_OK) &&
				update_sock_struct_from_via(&to, msg, msg->via2)!=-1) {
					su2ip_addr(&ip, &to);
					args->raddr.s = ip_addr2a(&ip);
					args->raddr.len = strlen(args->raddr.s);
				} else {
					LM_ERR("can't extract reply destination from "
						"transaction/reply_via2\n");
				}
			}
		}
	}

	LM_DBG("Forcing body:\n[%.*s]\n",
			body?body->len:args->body.len,
			body?body->s:args->body.s);
	ret = force_rtp_proxy_body(msg, args, var, ipvar, body);

	if (rtpproxy_autobridge) {
		if (nh_lock)
			lock_stop_read(nh_lock);
		args->node = NULL;
	}

	return ret;

error_with_lock:
	if (nh_lock)
		lock_stop_read(nh_lock);
	return -1;
}

static int
force_rtp_proxy(struct sip_msg* msg, char* str1, char* str2, nh_set_param_t *setid,
											pv_spec_t *var, pv_spec_t *ipvar, str *body, int offer)
{
	int ret = 0;
	struct body_part *p;
	struct rtpp_args args;

	memset(&args, '\0', sizeof(args));

	if (!body && (parse_sip_body(msg)<0 || msg->body==NULL)) {
		LM_ERR("Unable to parse body\n");
		return -1;
	}

	LM_DBG("force rtp proxy with param1 <%s> and param2 <%s>\n",
			str1 ? str1 : "none", str2 ? str2 : "none");

	if (get_callid(msg, &args.callid) == -1 || args.callid.len == 0) {
		LM_ERR("can't get Call-Id field\n");
		return (-1);
	}

	args.arg1 = str1;
	args.arg2 = str2;
	args.offer = offer;

	/* there is not a problem if the set is not got under lock, since
	 * after we have it, we will never delete/change it */
	args.set = get_rtpp_set(setid);
	if (!args.set) {
		LM_ERR("cannot find RTPProxy set\n");
		return -1;
	}


	if (!body) {
		for (p = &msg->body->first; p != NULL; p = p->next)
		{

			/* skip body parts which were deleted or newly added */
			if (!is_body_part_received(p))
				continue;

			if (p->mime != ((TYPE_APPLICATION << 16) + SUBTYPE_SDP))
				continue;
			if (p->body.len == 0) {
				LM_WARN("empty body\n");
				continue;
			}
			args.body = p->body;

			ret = force_rtpproxy_body_part(msg, &args, var, ipvar, NULL);
			if (ret < 0)
				return ret;
		}
		ret = 1;
	} else {
		args.body = *body;
		ret = force_rtpproxy_body_part(msg, &args, var, ipvar, body);
	}

	return ret;
}

static inline int rtpp_get_error(char *command)
{
	int ret;
	str val;
	if (!command)
		return -1;
	if (command[0] != 'E')
		return 0;
	val.s = command + 1;
	val.len = strlen(val.s) - 1 /* newline */;

	if (str2sint(&val, &ret)) {
		LM_ERR("bad error received from RTPProxy: %s\n", command);
		return -1;
	}
	return ret;
}

static char _rtp_proxy_buf[IP_ADDR_MAX_STR_SIZE + 1/* : */ + 5/* port */];

#define RTPPROXY_APPEND(_a) \
	do { \
		if (body->len + (_a)->len > allocated_body) { \
			allocated_body = body->len + (_a)->len * 2; \
			body->s = pkg_realloc(body->s, allocated_body); \
			if (!body->s) \
				goto error; \
		} \
		memcpy(body->s + body->len, (_a)->s, (_a)->len); \
		body->len += (_a)->len; \
	} while(0)

#define RTPPROXY_APPEND_CONST(_c) \
	do { \
		str __s; \
		init_str(&__s, _c); \
		RTPPROXY_APPEND(&__s); \
	} while (0)

static int rtpproxy_offer_answer(struct sip_msg *msg, struct rtpp_args *args,
		pv_spec_t *var, pv_spec_t *ipvar, str *body)
{
	str body1, oldport, oldip, newport, newip ,nextport;
	str tmp, payload_types;
	int create, port, len, asymmetric, flookup, argc, proxied, real;
	int orgip, commip, enable_notification, keep_body;
	int pf, pf1, force, err, locked = 0;
	struct options opts, rep_opts, pt_opts, m_opts, t_opts, mod_opts;
	char *cp, *cp1;
	char  *cpend, *next;
	char **ap, *argv[10];
	struct lump* anchor;
	struct rtpproxy_vcmd vup;
	RTPP_VCMD_INIT(vup, 25,
		{NULL, 0},	/* command & common options */
		{NULL, 0},	/* per-media/per-node options 1 */
		{NULL, 0},	/* per-media/per-node options 2 */
		{NULL, 0},	/* per-media/per-node options 3 */
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
		{NULL, 0},	/* notify tag */
		{NULL, 0},	/* (optional) module separator */
		{NULL, 0},	/* (optional) DTMF tag */
		{NULL, 0}	/* (optional) module opts */
	);
	char *v1p, *v2p, *c1p, *c2p, *m1p, *m2p, *bodylimit, *o1p, *r2p, *newbody;
	char medianum_buf[20];
	char buf[32], dbuf[128];
	int medianum, media_multi;
	str medianum_str, tmpstr1;
	int c1p_altered;
	int enable_dtmf_catch = 0;
	int node_has_notification, node_has_dtmf_catch = 0;
	int vcnt;
	pv_value_t val;
	char *adv_address = NULL;
	struct dlg_cell * dlg;
	str dtmf_tag = {0, 0}, timeout_tag = {0, 0};
	str notification_socket = rtpp_notify_socket;
	int allocated_body = 0;
	str *did;
	int ret = -1;

	memset(&opts, '\0', sizeof(opts));
	memset(&rep_opts, '\0', sizeof(rep_opts));
	memset(&mod_opts, '\0', sizeof(mod_opts));
	memset(&pt_opts, '\0', sizeof(pt_opts));
	memset(&t_opts, '\0', sizeof(t_opts));
	/* Leave space for U/L prefix TBD later */
	if (append_opts(&opts, '?') == -1) {
		LM_ERR("out of pkg memory\n");
		goto exit;
	}
	asymmetric = flookup = force = real = orgip = commip = enable_notification = keep_body = 0;
	for (cp = args->arg1; cp != NULL && *cp != '\0'; cp++) {
		switch (*cp) {
		case 'a':
		case 'A':
			if (append_opts(&opts, 'A') == -1) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
			asymmetric = 1;
			real = 1;
			break;

		case 'd':
		case 'D':
			enable_dtmf_catch = 1;
			/* If there are any digits following D, copy them */
			if (cp[1] == '\0' || !isdigit(cp[1]))
				break;
			if (append_opts(&mod_opts, ' ') == -1) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
			for (; cp[1] != '\0' && isdigit(cp[1]); cp++) {
				if (append_opts(&mod_opts, cp[1]) == -1) {
					LM_ERR("out of pkg memory\n");
					goto exit;
				}
			}
			break;

		case 'i':
		case 'I':
			if (append_opts(&opts, 'I') == -1) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
			break;

		case 'e':
		case 'E':
			if (append_opts(&opts, 'E') == -1) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
			break;

		case 'l':
		case 'L':
			flookup=1;
			break;

		case 'k':
		case 'K':
			keep_body = 1;
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

		case 'n':
		case 'N':
			enable_notification = 1;
			/* check to see if we have a notification socket */
			if (cp[1] != '\0' && cp[1] == '<') {
				notification_socket.s = &cp[2];
				for (; cp[1] != '\0' && cp[1] != '>'; cp++);
				notification_socket.len = &cp[1] - notification_socket.s;
				cp++;
			}
			break;

		case 'w':
		case 'W':
		case 's':
		case 'S':
			if (append_opts(&opts, 'S') == -1) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
			break;

		case 't':
		case 'T':
			if (append_opts(&t_opts, *cp) == -1) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
			/* If there are any digits following T copy them into the command */
			for (; cp[1] != '\0' && isdigit(cp[1]); cp++) {
				if (append_opts(&t_opts, cp[1]) == -1) {
					LM_ERR("out of pkg memory\n");
					goto exit;
				}
			}
			break;

		case 'z':
		case 'Z':
			if (append_opts(&rep_opts, 'Z') == -1) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
			/* If there are any digits following Z copy them into the command */
			for (; cp[1] != '\0' && isdigit(cp[1]); cp++) {
				if (append_opts(&rep_opts, cp[1]) == -1) {
					LM_ERR("out of pkg memory\n");
					goto exit;
				}
			}
			break;

		default:
			LM_WARN("unknown option `%c'\n", *cp);
			if (append_opts(&opts, *cp) == -1) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
		}
	}

	if (args->raddr.s != NULL) {
		if (append_opts(&rep_opts, 'R') == -1 || \
		    append_opts_str(&rep_opts, &args->raddr) == -1) {
			LM_ERR("out of pkg memory\n");
			goto exit;
		}
	}

	if (args->offer != 0) {
		create = 1;
	} else {
		create = 0;
	}

	if (flookup != 0) {
		if (args->to_tag.len == 0)
			init_str(&args->to_tag, "dummy");
		create = 0;
		if (args->offer != 0) {
			tmp = args->from_tag;
			args->from_tag = args->to_tag;
			args->to_tag = tmp;
		}
	} else if (msg && ((msg->first_line.type==SIP_REPLY && args->offer!=0)||
	(msg->first_line.type == SIP_REQUEST && args->offer == 0) )) {
		if (args->to_tag.len == 0) {
			goto exit;
		}
		tmp = args->from_tag;
		args->from_tag = args->to_tag;
		args->to_tag = tmp;
	}
	proxied = 0;
	if (nortpproxy_str.len) {
		for ( cp=args->body.s ; (len=args->body.s+args->body.len-cp) >= nortpproxy_str.len ; ) {
			cp1 = l_memmem(cp, nortpproxy_str.s, len, nortpproxy_str.len);
			if (cp1 == NULL)
				break;
			if (cp1[-1] == '\n' || cp1[-1] == '\r') {
				proxied = 1;
				break;
			}
			cp = cp1 + nortpproxy_str.len;
		}
	}
	if (proxied != 0 && force == 0)
		goto exit;
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
	trim_leading(&args->body);
	bodylimit = args->body.s + args->body.len;
	v1p = args->body.s;
	if (args->body.len < 2 || v1p[0] != 'v' || v1p[1] != '=') {
		LM_ERR("no sessions in SDP: [%.*s]\n", args->body.len, args->body.s);
		goto exit;
	}
	v2p = find_next_sdp_line(v1p, bodylimit, 'v', bodylimit);
	media_multi = (v2p != bodylimit);
	v2p = v1p;
	medianum = 0;

	opts.s.s[0] = (create == 0) ? 'L' : 'U';
	STR2IOVEC(args->callid, vup.vu[5]);
	STR2IOVEC(args->from_tag, vup.vu[11]);
	STR2IOVEC(args->to_tag, vup.vu[15]);

	if (notification_socket.s == 0 || notification_socket.len == 0) {
		if (enable_notification)
			LM_WARN("cannot receive notifications because"
					"notification socket is not specified\n");
		enable_notification = 0;

		if (enable_dtmf_catch)
			LM_WARN("cannot receive DMTF notifications because"
					"notification socket is not specified\n");
		enable_dtmf_catch = 0;
	}

	if (opts.s.s[0] == 'U') {
		if(enable_notification && dlg_api.get_dlg) {
			dlg = dlg_api.get_dlg();
			if(dlg == NULL)
			{
				LM_ERR("Failed to get dialog\n");
				goto error;
			}
			/* construct the notify tag from dialog ids */
			did = dlg_api.get_dlg_did(dlg);
			if (!did) {
				LM_ERR("could not get the dialog did!\n");
				goto error;
			}
			if (did->len > 30) {
				LM_ERR("did too large to fit!\n");
				goto error;
			}
			timeout_tag.len= snprintf(buf, 32, "T%.*s", did->len, did->s);
			timeout_tag.s = buf;
			LM_DBG("timeout_tag= %s\n", timeout_tag.s);
		} else if (enable_dtmf_catch) {
			/* we have dtmf_catch enabled, but we are not interested in
			 * notifications - add an ignore tag */
			timeout_tag.s = "I";
			timeout_tag.len = 1;
		}
	} else
		enable_notification = 0;

	if (enable_dtmf_catch) {
		if (dlg_api.get_dlg && (dlg = dlg_api.get_dlg())) {
			LM_DBG("using DTMF dialog %p identifier\n", dlg);
			did = dlg_api.get_dlg_did(dlg);
			if (!did) {
				LM_ERR("could not get the dialog did!\n");
				goto error;
			}
			if (did->len > 30) {
				LM_ERR("did too large to fit!\n");
				goto error;
			}
			dtmf_tag.len = snprintf(dbuf, 128, "d%.*s", did->len, did->s);
		} else {
			LM_DBG("using DTMF callid %.*s identifier\n", args->callid.len, args->callid.s);
			dtmf_tag.len = snprintf(dbuf, 128, "c%.*s", args->callid.len, args->callid.s);
		}
		dtmf_tag.s = dbuf;
	}

	m_opts = opts;

	if (body) {
		body->s = pkg_malloc(args->body.len);
		if (!body->s) {
			LM_ERR("could not allocate space for new body\n");
			goto error;
		}
		allocated_body = args->body.len;
		body->len = 0;
	}

	newbody = v2p;
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
			m_opts.oidx = opts.oidx;

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
			switch (extract_mediainfo(&tmpstr1, &oldport, &payload_types)) {
				case -1:
					LM_ERR("can't extract media port from the message\n");
					goto error;
				case 0:
					break;
				case 1:
					continue;
			}
			++medianum;

			/* TODO: check if the port is allowed 0 and if the IP can be 0 */
			/* If the callee wants to neither send nor receive a stream offered by
			the caller, the callee sets the port number of that stream to zero in
			its media description - don't engage rtpproxy for such streams */
			if (oldport.s[0] == '0' && oldport.len == 1)
				continue;

			if (asymmetric != 0 || real != 0 || !msg) {
				newip = oldip;
			} else {
				newip.s = ip_addr2a(&msg->rcv.src_ip);
				newip.len = strlen(newip.s);
				/* update the AF */
				pf = msg->rcv.src_ip.af;
			}
			/* XXX must compare address families in all addresses */
			if (pf == AF_INET6) {
				if (append_opts(&m_opts, '6') == -1) {
					LM_ERR("out of pkg memory\n");
					goto error;
				}
			}
			STR2IOVEC(newip, vup.vu[7]);
			STR2IOVEC(oldport, vup.vu[9]);
			if (1 || media_multi) /* XXX netch: can't choose now*/
			{
				snprintf(medianum_buf, sizeof medianum_buf, "%d", medianum);
				medianum_str.s = medianum_buf;
				medianum_str.len = strlen(medianum_buf);
				STR2IOVEC(medianum_str, vup.vu[13]);
				STR2IOVEC(medianum_str, vup.vu[17]);
			} else {
				vup.vu[12].iov_len = vup.vu[13].iov_len = 0;
				vup.vu[16].iov_len = vup.vu[17].iov_len = 0;
			}
			if (!args->node && nh_lock) {
				locked = 1;
				lock_start_read(nh_lock);
			}
			do {

				/* if not successful choose a different rtpproxy */
				if (!args->node) {
					args->node = select_rtpp_node(msg, args->callid, args->set, var, 0);
					if (!args->node) {
						LM_ERR("no available proxies\n");
						goto error;
					}
					LM_DBG("trying new rtpproxy node %s\n", args->node->rn_address);
					adv_address = args->node->adv_address;
				}
				/* if we don't have, we should choose a new node */
				if (rep_opts.oidx > 0) {
					if (!HAS_CAP(args->node, REPACK)) {
						LM_WARN("re-packetization is requested but is not "
						    "supported by the selected RTP proxy node\n");
						vup.vu[1].iov_len = 0;
					} else {
						vup.vu[1].iov_base = rep_opts.s.s;
						vup.vu[1].iov_len = rep_opts.oidx;
					}
				}
				if (payload_types.len > 0 && HAS_CAP(args->node, CODECS)) {
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
					vup.vu[2].iov_base = pt_opts.s.s;
					vup.vu[2].iov_len = pt_opts.oidx;
				} else {
					vup.vu[2].iov_len = 0;
				}
				if (HAS_CAP(args->node, TTL_CHANGE)) {
					vup.vu[3].iov_base = t_opts.s.s;
					vup.vu[3].iov_len = t_opts.oidx;
				} else {
					vup.vu[3].iov_len = 0;
				}
				if (args->to_tag.len == 0) {
					vcnt = 14;
					vup.vu[16].iov_base = " "; /* replace ';' with ' ' */
				} else
					vcnt = 18;
				node_has_dtmf_catch = enable_dtmf_catch && HAS_CAP(args->node, SUBCOMMAND);
				node_has_notification = enable_notification && HAS_CAP(args->node, NOTIFY);
				if (node_has_dtmf_catch || node_has_notification) {
					if (opts.s.s[0] == 'U') {
						STR2IOVEC(notification_socket, vup.vu[vcnt + 1]);
						if (!HAS_CAP(args->node, NOTIFY_WILD) && !rtpp_notify_socket_un &&
								notification_socket.s == rtpp_notify_socket.s) {
							vup.vu[vcnt + 1].iov_base += 4;
							vup.vu[vcnt + 1].iov_len -= 4;
						}
						vcnt += 2;
						STR2IOVEC(timeout_tag, vup.vu[vcnt + 1]);
						vcnt += 2;
					}

					if (node_has_dtmf_catch) {
						if (HAS_CAP(args->node, SUBCOMMAND)) {
							/* separator */
							vup.vu[vcnt].iov_base = " && M3:1 D";
							vup.vu[vcnt].iov_len = 10;
							vcnt++;
							/* DTMF tag */
							STR2IOVEC(dtmf_tag, vup.vu[vcnt]);
							vcnt++;

							if (mod_opts.oidx > 0) {
								vup.vu[vcnt].iov_base = mod_opts.s.s;
								vup.vu[vcnt].iov_len = mod_opts.oidx;
								vcnt++;
							}
						} else
							LM_WARN("node does not have subcommand capability!\n");
					}
				}

				vup.vu[0].iov_base = m_opts.s.s;
				vup.vu[0].iov_len = m_opts.oidx;
				cp = send_rtpp_command(args->node, &vup, vcnt);
				if (!cp && !create) {
					LM_ERR("cannot lookup a session on a different RTPProxy\n");
					goto error;
				}
				if (cp && (err = rtpp_get_error(cp))) {
					/* check internal errors */
					if (err >= 7 && err <= 10) {
						cp = NULL;
						args->node->rn_disabled = 1;
						args->node->rn_recheck_ticks = get_ticks() +
							rtpproxy_disable_tout;
						raise_rtpproxy_event(args->node, 0);
					} else {
						LM_ERR("unhandled rtpproxy error: %d\n", err);
						goto error;
					}
				}
				args->node = NULL;
			} while (cp == NULL && args->offer);
			if (locked) {
				locked = 0;
				lock_stop_read(nh_lock);
			}
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
				goto exit;
			}
			port = atoi(argv[0]);
			if (port <= 0 || port > 65535) {
				if (port != 0 || flookup == 0)
					LM_ERR("incorrect port %i in reply "
						"from rtp proxy\n",port);
				goto exit;
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
				/* handle all possible cases properly
				 * 1) second argument w/ip passed to offer/answer (args->arg2)
				 * 2) no second argument, rtpproxy response contains ip (argv[1])
				 * 3) no ip in rtpproxy response (started using unix socket and no -l param)
				 *    must revert to default of proxy ip
				 */
				if (args->arg2)
					newip.s = args->arg2;
				else if (adv_address)
					newip.s = adv_address;
				else if (argv[1])
					newip.s = argv[1];
				else if (msg) {
					newip.s = ip_addr2a(&msg->rcv.dst_ip);
					pf1 = msg->rcv.dst_ip.af;
				}
				newip.len = strlen(newip.s);
			}
			/* marker to double check : newport goes: str -> int -> str ?!?! */
			newport.s = int2str(port, &newport.len); /* beware static buffer */

			if (ipvar) {
				val.rs.s = _rtp_proxy_buf;
				memcpy(val.rs.s, newip.s, newip.len);
				val.rs.len = newip.len;
				val.rs.s[val.rs.len++] = ':';
				memcpy(val.rs.s + val.rs.len, newport.s, newport.len);
				val.rs.len += newport.len;
				val.flags = PV_VAL_STR;
				if (pv_set_value(msg, ipvar, (int)EQ_T, &val) < 0)
					LM_ERR("cannot store rtpproxy reply: %.*s \n", val.rs.len, val.rs.s);
			}
			if (keep_body != 0)
				continue;

			if (body) {
				if (o1p) {
					tmpstr1.s = o1p;
					tmpstr1.len = v2p - tmpstr1.s;
					if (extract_mediaip(&tmpstr1, &oldip, &pf,"o=") == -1) {
						LM_ERR("can't extract media IP from the message\n");
						goto exit;
					}
					/* copy everything until oldip */
					tmp.s = newbody;
					tmp.len = oldip.s - newbody;
					RTPPROXY_APPEND(&tmp);
					/* alter the pf, if needed */
					if (pf != pf1)
						body->s[body->len - 2] = (pf1 == AF_INET6) ? '6' : '4';
					RTPPROXY_APPEND(&newip);
					newbody = oldip.s + oldip.len;
				}

				if (c1p && !c1p_altered && !c2p && commip) {
					/* we have a common IP and it was requested to change */
					/* c1p points to the common IP */
					tmpstr1.s = c1p;
					tmpstr1.len = v2p - tmpstr1.s;
					if (extract_mediaip(&tmpstr1, &oldip, &pf,"c=") == -1) {
						LM_ERR("can't extract media IP from the message\n");
						goto exit;
					}
					/* copy everything until oldip */
					tmp.s = newbody;
					tmp.len = oldip.s - newbody;
					RTPPROXY_APPEND(&tmp);
					/* alter the pf, if needed */
					if (pf != pf1)
						body->s[body->len - 2] = (pf1 == AF_INET6) ? '6' : '4';
					RTPPROXY_APPEND(&newip);
					newbody = oldip.s + oldip.len;
					c1p_altered = 1;
				}
				/* now update the port */
				if(oldport.len!=1 || oldport.s[0]!='0') {
					tmp.s = newbody;
					tmp.len = oldport.s - newbody;
					RTPPROXY_APPEND(&tmp);
					RTPPROXY_APPEND(&newport);
					newbody = oldport.s + oldport.len;
				}
				if (c2p) {
					tmpstr1.s = c2p;
					tmpstr1.len = v2p - tmpstr1.s;
					if (extract_mediaip(&tmpstr1, &oldip, &pf,"c=") == -1) {
						LM_ERR("can't extract media IP from the message\n");
						goto exit;
					}

					tmp.s = newbody;
					tmp.len = oldip.s - newbody;
					RTPPROXY_APPEND(&tmp);
					/* alter the pf, if needed */

					if (pf != pf1)
						body->s[body->len - 2] = (pf1 == AF_INET6) ? '6' : '4';
					RTPPROXY_APPEND(&newip);
					newbody = oldip.s + oldip.len;
				}
				if( r2p ) {
					nextport.s = int2str(port+1, &nextport.len);
					tmp.s = newbody;
					tmp.len = r2p - newbody;
					RTPPROXY_APPEND(&tmp);

					RTPPROXY_APPEND_CONST("a=rtcp:");
					RTPPROXY_APPEND(&nextport);
					RTPPROXY_APPEND_CONST(" IN IP4 ");
					if (pf1 == AF_INET6)
						body->s[body->len - 2] = '6';
					RTPPROXY_APPEND(&newip);
					for (newbody = r2p; *newbody != '\r'; newbody++);
				}
				tmp.s = newbody;
				tmp.len = m2p - newbody;
				RTPPROXY_APPEND(&tmp);
				newbody = m2p;
			} else {
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
						goto exit;
				}

				if( r2p ) {
					nextport.s = int2str(port+1, &nextport.len);

					if (alter_rtcp(msg, &body1, &newip, pf1, &nextport, r2p) < 0 )
						goto exit;
				}
				/*
				 * Alter IP. Don't alter IP common for the session
				 * more than once.
				 */
				if (c2p != NULL || !c1p_altered) {
					body1.s = c2p ? c2p : c1p;
					body1.len = bodylimit - body1.s;
					if (alter_mediaip(msg, &body1, &oldip, pf, &newip, pf1, 0)==-1)
						goto exit;
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
						goto exit;
					}
					body1.s = c1p;
					body1.len = bodylimit - body1.s;
					if (alter_mediaip(msg, &body1, &oldip, pf, &newip, pf1, 0)==-1)
						goto exit;
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
						goto exit;
					}
					body1.s = o1p;
					body1.len = bodylimit - body1.s;
					if (alter_mediaip(msg, &body1, &oldip, pf, &newip, pf1, 0)==-1)
						goto exit;
					o1p = 0;
				}
			}
		} /* Iterate medias in session */
	} /* Iterate sessions */

	if (proxied == 0 && nortpproxy_str.len && keep_body == 0) {
		if (body) {
			RTPPROXY_APPEND(&nortpproxy_str);
			RTPPROXY_APPEND_CONST(CRLF);
		} else {
			cp = pkg_malloc((1 + nortpproxy_str.len + CRLF_LEN) * sizeof(char));
			if (cp == NULL) {
				LM_ERR("out of pkg memory\n");
				goto exit;
			}
			/* find last CRLF and add after it */
			cp1 = args->body.s + args->body.len;
			while( cp1>args->body.s && !(*(cp1-1)=='\n' && *(cp1-2)=='\r') ) cp1--;
			if (cp1==args->body.s) cp1=args->body.s + args->body.len;

			/* XXX: ugly hack to add a string _after_ the end of the body:
			 * remove the last char and then add it in the new buffer */
			cp1--;
			cp[0] = *cp1;
			anchor = del_lump(msg, cp1 - msg->buf, 1, 0);
			if (anchor == NULL) {
				LM_ERR("del_lump failed\n");
				pkg_free(cp);
				goto exit;
			}
			memcpy(cp+1, nortpproxy_str.s, nortpproxy_str.len);
			memcpy(cp+1+nortpproxy_str.len , CRLF, CRLF_LEN);
			if (insert_new_lump_before(anchor, cp, 1 + nortpproxy_str.len + CRLF_LEN, 0) == NULL) {
				LM_ERR("insert_new_lump_after failed\n");
				pkg_free(cp);
				goto exit;
			}
		}
	}

	ret = 1;
error:
	/* we are done reading -> unref the data */
	if (locked)
		lock_stop_read( nh_lock );
	if (ret < 0 && body && allocated_body)
		pkg_free(body->s);

exit:
	free_opts(&opts, &rep_opts, &pt_opts, &mod_opts);
	return ret;
}
#undef RTPPROXY_APPEND
#undef RTPPROXY_APPEND_CONST

int force_rtp_proxy_body(struct sip_msg* msg, struct rtpp_args *args,
		pv_spec_p var, pv_spec_p ipvar, str *body)
{
	if (!args->callid.len && (get_callid(msg, &args->callid) == -1 || args->callid.len == 0)) {
		LM_ERR("can't get Call-Id field\n");
		return -1;
	}

	if (!args->to_tag.len && !args->to_tag.s) {
		args->to_tag.s = 0;
		if (get_to_tag(msg, &args->to_tag) == -1) {
			LM_ERR("can't get To tag\n");
			return -1;
		}
	}

	if (!args->from_tag.len &&
			(get_from_tag(msg, &args->from_tag) == -1 || args->from_tag.len == 0)) {
			LM_ERR("can't get From tag\n");
			return -1;
		}

	return rtpproxy_offer_answer(msg, args, var, ipvar, body);
}

static char *rtpproxy_stats_pop_int(struct sip_msg *msg, char *p,
		pv_spec_p spec, const char *varname)
{
	pv_value_t val;
	/* skip spaces */
	for (; *p != '\0' && *p == ' '; p++);
	val.rs.s = p;
	for (; *p >= '0' && *p <= '9'; p++);
	if (p == val.rs.s || (*p != ' ' && *p != '\n' && *p != '\0')) {
		LM_ERR("invalid format: cannot find %s packets [%s]\n", varname,
				val.rs.s);
		return NULL;
	}
	val.rs.len = p - val.rs.s;
	LM_DBG("%s = %.*s\n", varname, val.rs.len, val.rs.s);
	if (spec) {
		val.flags = PV_VAL_STR|PV_TYPE_INT|PV_VAL_INT;
		if (str2int(&val.rs, (unsigned int *)&val.ri) == 0) {
			if (pv_set_value(msg, (pv_spec_p)spec, (int)EQ_T, &val) < 0)
				LM_ERR("cannot store %s packets\n", varname);
		} else {
			LM_ERR("invalid %s packets %.*s\n", varname, val.rs.len, val.rs.s);
		}
	}
	return p;
}

#define RTPP_QUERY_ONCE_STATS_NO 5
static char *rtpp_stats[] = {
	"ttl",
	"npkts_ina",
	"npkts_ino",
	"nrelayed",
	"ndropped",
	"rtpa_nsent",
	"rtpa_nrcvd",
	"rtpa_ndups",
	"rtpa_nlost",
	"rtpa_perrs"};
#define RTPP_QUERY_STATS_SIZE (sizeof(rtpp_stats)/sizeof(rtpp_stats[0]))

static int rtpp_stats_no = RTPP_QUERY_STATS_SIZE;
static int rtpp_stats_chunks_no;
static struct iovec *rtpp_stats_chunks;

static int rtpp_init_extra_stats(void)
{
	char *p;
	int len, stat, chunk, stopidx;
	rtpp_stats_chunks_no = RTPP_QUERY_STATS_SIZE / RTPP_QUERY_ONCE_STATS_NO;
	if (RTPP_QUERY_STATS_SIZE % RTPP_QUERY_ONCE_STATS_NO)
		rtpp_stats_chunks_no++;
	rtpp_stats_chunks = pkg_malloc(rtpp_stats_chunks_no * sizeof(*rtpp_stats_chunks));
	if (!rtpp_stats_chunks) {
		LM_ERR("cannot allocate rtpproxy stats chunks array\n");
		return -1;
	}

	for (chunk = 0; chunk < rtpp_stats_chunks_no; chunk++) {
		stopidx = (chunk + 1) * RTPP_QUERY_ONCE_STATS_NO;
		if (stopidx > RTPP_QUERY_STATS_SIZE)
			stopidx = RTPP_QUERY_STATS_SIZE;
		len = 0;
		for (stat = chunk * RTPP_QUERY_ONCE_STATS_NO; stat < stopidx; stat++)
			len += 1 /* ' ' */ + strlen(rtpp_stats[stat]);
		rtpp_stats_chunks[chunk].iov_base = pkg_malloc(len);
		if (!rtpp_stats_chunks) {
			LM_WARN("cannot allocate %d chunk. Only %d stats out of %zu "
					"can be used!\n", chunk, chunk * RTPP_QUERY_ONCE_STATS_NO,
					RTPP_QUERY_STATS_SIZE);
			goto error;
		}
		p = rtpp_stats_chunks[chunk].iov_base;
		for (stat = chunk * RTPP_QUERY_ONCE_STATS_NO; stat < stopidx; stat++) {
			*p++ = ' ';
			len = strlen(rtpp_stats[stat]);
			memcpy(p, rtpp_stats[stat], len);
			p += len;
		}
		rtpp_stats_chunks[chunk].iov_len = p - (char *)rtpp_stats_chunks[chunk].iov_base;
		LM_INFO("%d %zu [%.*s]\n", chunk, rtpp_stats_chunks[chunk].iov_len,
				(unsigned)rtpp_stats_chunks[chunk].iov_len, (char *)rtpp_stats_chunks[chunk].iov_base);
	}
	return 0;

error:
	rtpp_stats_chunks_no = chunk;
	rtpp_stats_no = chunk * RTPP_QUERY_ONCE_STATS_NO;
	return -1;
}

static inline int rtpp_build_stats(struct sip_msg *msg, struct rtpproxy_vcmd **vret,
		int *nret, str *callid)
{
	static struct rtpproxy_vcmd vstat;

	RTPP_VCMD_INIT_STATIC(vstat, 4 + 4 + 1, {"Q", 1}, {" ", 1},
            {NULL, 0}, {" ", 1}, {NULL, 0}, {";1 ", 3}, {NULL, 0}, {";1", 2},
            /* reserved for extra stats */
            {NULL, 0});

	str from_tag = {0, 0};
	str to_tag = {0, 0};

	if (get_callid(msg, callid) == -1 || callid->len == 0) {
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

	STR2IOVEC(*callid, vstat.vu[2]);
	STR2IOVEC(from_tag, vstat.vu[4]);
	STR2IOVEC(to_tag, vstat.vu[6]);

	if (msg->first_line.type == SIP_REPLY) {
		STR2IOVEC(to_tag, vstat.vu[4]);
		STR2IOVEC(from_tag, vstat.vu[6]);
	} else {
		STR2IOVEC(from_tag, vstat.vu[4]);
		STR2IOVEC(to_tag, vstat.vu[6]);
	}

	*vret = &vstat;
	*nret = vstat.useritems - 1;

	return 0;
}

static inline int rtpproxy_stats_f(struct sip_msg *msg,
	pv_spec_t *pup, pv_spec_t *pdown, pv_spec_t *psent, pv_spec_t *pfail,
	nh_set_param_t *pset, pv_spec_t *pvar)
{
	int nitems;
	struct rtpp_node *node;
	struct rtpp_set *set;
	char *ret, *p;
	int error;
	struct rtpproxy_vcmd *vstat;
	str callid = {0, 0};

	if (rtpp_build_stats(msg, &vstat, &nitems, &callid) < 0)
		return -1;

	set = get_rtpp_set(pset);
	if (!set) {
		LM_ERR("could not find rtpproxy set\n");
		return 0;
	}

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	node = select_rtpp_node(msg, callid, set, pvar, 1);
	if (!node) {
		LM_ERR("no available proxies\n");
		goto error;
	}
	if (!HAS_CAP(node, STATS)) {
		LM_ERR("RTPProxy does not support statistics query!\n");
		goto error;
	}

	ret = send_rtpp_command(node, vstat, nitems);

	if(nh_lock)
	{
		/* we are done reading -> unref the data */
		lock_stop_read( nh_lock );
	}
	if (!ret) {
		LM_DBG("nothing returned by RTPProxy!\n");
		return -1;
	}
	error = rtpp_get_error(ret);
	switch (error) {
		case 0:
			/* success! */
			break;
		case 8:
			LM_ERR("RTPProxy cannot find session!\n");
			return -8;
		default:
			LM_ERR("RTPProxy error not handled: %s!\n", ret);
			return -error;
	}

	/* all good! parse the command */
	for (p = ret; *p != '\0' && *p != ' '; p++);
	if (*p != ' ') {
		LM_ERR("invalid format for return %s. Cannot find ttl\n", ret);
		return -2;
	}
	LM_DBG("ttl=%.*s\n", (int)(p - ret), ret);

	/* upstream */
	if (!(p = rtpproxy_stats_pop_int(msg, p+1, pup, "upstream")))
		return -2;
	if (!(p = rtpproxy_stats_pop_int(msg, p+1, pdown, "downstream")))
		return -2;
	if (!(p = rtpproxy_stats_pop_int(msg, p+1, psent, "sent")))
		return -2;
	if (!(p = rtpproxy_stats_pop_int(msg, p+1, pfail, "failed")))
		return -2;
	return 1;

error:
	if(!nh_lock)
		return -1;

	/* we are done reading -> unref the data */
	lock_stop_read( nh_lock );

	return -1;
}

static inline int rtpproxy_all_stats_f(struct sip_msg *msg, pv_spec_t *pavp,
		nh_set_param_t *pset, pv_spec_t *pvar)
{
	int nitems;
	struct usr_avp *avp;
	struct rtpp_node *node;
	struct rtpp_set *set;
	char *result, *p;
	int error;
	struct rtpproxy_vcmd *vstat;
	str callid = {0, 0};
	unsigned short type;
	int_str val;
	int avals;
	int nrstats = 0;
	str nr;
	int chunk;
	int ret = -1;

	if (pv_get_avp_name(msg, &pavp->pvp, &avals, &type) < 0) {
		LM_ERR("cannot resolve AVP!\n");
		return -1;
	}
	avp = NULL;
	do {
		if (avp) destroy_avp(avp);
		avp = search_first_avp(type, avals, NULL, NULL);
	}while(avp);

	if (rtpp_build_stats(msg, &vstat, &nitems, &callid) < 0)
		return -1;

	set = get_rtpp_set(pset);
	if (!set) {
		LM_ERR("could not find rtpproxy set\n");
		return 0;
	}

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	node = select_rtpp_node(msg, callid, set, pvar, 1);
	if (!node) {
		LM_ERR("no available proxies\n");
		goto error;
	}
	if (!HAS_CAP(node, STATS_EXTRA)) {
		LM_ERR("RTPProxy does not support all statistics query!\n");
		goto error;
	}

	ret = -2;
	for (chunk = 0; chunk < rtpp_stats_chunks_no; chunk++) {
		vstat->vu[nitems] = rtpp_stats_chunks[chunk];
		result = send_rtpp_command(node, vstat, nitems + 1);
		if (!result) {
			LM_DBG("no result from RTPProxy!\n");
			goto error;
		}

		error = rtpp_get_error(result);
		if (error) {
			LM_ERR("RTPProxy error not handled: %s!\n", result);
			goto error;
		}
		nr.s = result;
		for (p = result; *p != '\0'; p++) {
			if (*p == ' ' || *p == '\n') {
				nr.len = p - nr.s;
				if (str2sint(&nr, &val.n) < 0) {
					LM_ERR("invalid statistic value: %.*s\n", nr.len, nr.s);
					goto error;
				}
				if (add_avp_last(type, avals, val) < 0) {
					LM_ERR("cannot populate statistic %d with %d\n", nrstats, val.n);
					goto error;
				}
				nrstats++;
				nr.s = p + 1;
			}
		}
	}

	if (nrstats != rtpp_stats_no) {
		LM_ERR("unexpected number of stats %d expected %d\n",
				nrstats, rtpp_stats_no);
		goto error;
	}

	ret = 1;
error:
	if (nh_lock) {
		lock_stop_read( nh_lock );
	}
	return ret;
}

static int w_rtpproxy_recording(struct sip_msg *msg, str *callid,
		str *from_tag, str *to_tag, struct rtpp_node *node,
		pv_spec_p var, str *flags, str *destination, int medianum)
{
	int nitems;
	char cmd;
	int media_start, media_stop;
	sdp_info_t *msg_sdp;
	sdp_session_cell_t *msg_session;
	struct rtpproxy_vcmd vrec;

	RTPP_VCMD_INIT(vrec, 14,
		{&cmd, 1},	/*.vu[0] command R or C */
		{NULL, 0},	/*.vu[1] flags, if they exist */
		{" ", 1},	/*.vu[2] separator */
		{NULL, 0},	/*.vu[3] callid */
		{" ", 1},	/*.vu[4] separator */
		{" ", 0},	/*.vu[5] recording destination, if specified */
		{" ", 1},	/*.vu[6] separator */
		{NULL, 0},	/*.vu[7] from_tag */
		{";", 1},	/*.vu[8] medianum separator */
		{NULL, 0},	/*.vu[9] medianum */
		{" ", 1},	/*.vu[10] separator */
		{NULL, 0},	/*.vu[11] to_tag */
		{";", 1},	/*.vu[12] medianum separator */
		{NULL, 0}	/*.vu[13] medianum */
	);

	/* check if we support recording */
	if (!HAS_CAP(node, RECORD)) {
		LM_ERR("RTPProxy does not support recording!\n");
		goto error;
	}

	media_start = media_stop = 0;

	if (destination) {
		/* if name is specified, we need to change the command */
		cmd = 'C';
		STR2IOVEC(*destination, vrec.vu[5]);
		nitems = vrec.useritems;
		if (medianum > 0)
			media_start = media_stop = medianum;
		else if (!msg)
			media_start = media_stop = 1;
		else {
			/*
			 * we need to parse the message, if it exists, and count the
			 * number of sessions it has
			 */
			media_start = 1;
			media_stop = 0;
			msg_sdp = parse_sdp(msg);
			if (msg_sdp) {
				for (msg_session = msg_sdp->sessions; msg_session;
						msg_session = msg_session->next)
					media_stop += msg_session->streams_num;
			} else {
				LM_WARN("cannot parse message SDP! only record first stream\n");
				media_stop = 1;
			}
		}
	} else {
		cmd = 'R';
		vrec.vu[6].iov_len = 0; /* remove the separator */
		vrec.vu[8].iov_len = vrec.vu[9].iov_len = 0; /* remove medianum for caller */
		nitems = vrec.useritems - 2;;
	}

	if (flags)
		STR2IOVEC(*flags, vrec.vu[1]);

	STR2IOVEC(*callid, vrec.vu[3]);
	STR2IOVEC(*from_tag, vrec.vu[7]);
	if (to_tag)
		STR2IOVEC(*to_tag, vrec.vu[11]);

	if (!to_tag || to_tag->len <= 0) {
		if (cmd == 'C')
			nitems = vrec.useritems - 4;
		else
			nitems = vrec.useritems - 6;
	}

	if (cmd == 'R')
		send_rtpp_command(node, &vrec, nitems);
	else
		while (media_start <= media_stop) {
			vrec.vu[9].iov_base = int2str(media_start, (int *)&vrec.vu[9].iov_len);
			vrec.vu[13] = vrec.vu[9];
			send_rtpp_command(node, &vrec, nitems);
			media_start++;
		}

	return 1;

error:
	return -1;
}

static int w_rtpproxy_stop_recording(struct sip_msg *msg, str *callid,
		str *from_tag, str *to_tag, struct rtpp_node *node,
		pv_spec_p var, int medianum)
{
	struct rtpproxy_vcmd vstrec;
	RTPP_VCMD_INIT(vstrec, 10,
		{"N ", 2},	/*.vu[0] command R or C */
		{NULL, 0},	/*.vu[1] callid */
		{" ", 1},	/*.vu[2] separator */
		{NULL, 0},	/*.vu[3] from_tag */
		{";", 1},	/*.vu[4] medianum separator */
		{NULL, 0},	/*.vu[5] medianum */
		{" ", 1},	/*.vu[6] separator */
		{NULL, 0},	/*.vu[7] to_tag */
		{";", 1},	/*.vu[8] medianum separator */
		{NULL, 0}	/*.vu[9] medianum */
	);

	/* check if we support recording */
	if (!HAS_CAP(node, RECORD)) {
		LM_ERR("RTPProxy does not support recording!\n");
		goto error;
	}

	STR2IOVEC(*callid, vstrec.vu[1]);
	STR2IOVEC(*from_tag, vstrec.vu[3]);
	if (to_tag)
		STR2IOVEC(*to_tag, vstrec.vu[7]);

	vstrec.vu[5].iov_base = int2str(medianum, (int *)&vstrec.vu[5].iov_len);
	vstrec.vu[9] = vstrec.vu[5];
	send_rtpp_command(node, &vstrec, vstrec.useritems);

	return 1;

error:
	return -1;
}

static int rtpproxy_api_recording(str *callid, str *from_tag,
		str *to_tag, str *node, str *flags, str *destination, int medianum)
{
	struct rtpp_node *rnode;
	int ret = -1;

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	if (node)
		rnode = get_rtpp_node(node, NULL);
	else
		/* regular selection from the default rtpp set */
		rnode = select_rtpp_node(NULL, *callid, *default_rtpp_set, NULL, 1);

	if (!rnode) {
		LM_ERR("no available proxies\n");
		goto exit;
	}

	ret = w_rtpproxy_recording(NULL, callid, from_tag,
			to_tag, rnode, NULL, flags, destination, medianum);

exit:
	if (nh_lock) {
		lock_stop_read( nh_lock );
	}
	return ret;
}

static int rtpproxy_recording(struct sip_msg* msg, nh_set_param_t *setid,
	pv_spec_t *var, str *flags, str *destination, int *stream_no)
{
	struct rtpp_set *set;
	str callid = {0, 0};
	str from_tag = {0, 0};
	str to_tag = {0, 0};
	str aux;
	int medianum, ret;
	struct rtpp_node *node;

	if (stream_no)
		medianum = *stream_no;
	else
		medianum = -1; /* all streams */

	if (get_callid(msg, &callid) == -1 || callid.len == 0) {
		LM_ERR("can't get Call-Id field\n");
		return -1;
	}

	if (get_from_tag(msg, &from_tag) == -1 || from_tag.len == 0) {
		LM_ERR("can't get From tag\n");
		return -1;
	}

	if (get_to_tag(msg, &to_tag) == -1) {
		LM_ERR("can't get To tag\n");
		return -1;
	}

	if (msg->first_line.type == SIP_REPLY) {
		if (to_tag.len == 0)
			return -1;
		aux = to_tag;
		to_tag = from_tag;
		from_tag = aux;
	}

	if (nh_lock)
		lock_start_read( nh_lock );

	set = get_rtpp_set(setid);
	if (!set) {
		LM_ERR("could not find rtpproxy set\n");
		return -1;
	}

	node = select_rtpp_node(msg, callid, set, var, 1);
	if (!node) {
		LM_ERR("no available proxies\n");
		return -1;
	}

	ret = w_rtpproxy_recording(msg, &callid, &from_tag, &to_tag, node,
			var, flags, destination, medianum);

	if (nh_lock)
		lock_stop_read( nh_lock );
	return ret;
}

static int rtpproxy_api_stop_recording(str *callid, str *from_tag,
		str *to_tag, str *node, int medianum)
{
	struct rtpp_node *rnode;
	int ret = -1;

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	if (node)
		rnode = get_rtpp_node(node, NULL);
	else
		/* regular selection from the default rtpp set */
		rnode = select_rtpp_node(NULL, *callid, *default_rtpp_set, NULL, 1);

	if (!rnode) {
		LM_ERR("no available proxies\n");
		goto exit;
	}

	ret = w_rtpproxy_stop_recording(NULL, callid, from_tag,
			to_tag, rnode, NULL, medianum);

exit:
	if (nh_lock) {
		lock_stop_read( nh_lock );
	}
	return ret;
}

int load_rtpproxy(struct rtpproxy_binds *rtpb)
{
	rtpb->start_recording = rtpproxy_api_recording;
	rtpb->stop_recording = rtpproxy_api_stop_recording;
	return 1;
}

#define RTPPROXY_SET_EVENT_PARAM(_type, _param, _value, _idx) \
	do { \
		if (evi_param_set_##_type(rtpproxy_event_params[_idx].param, _value) < 0) { \
			LM_ERR("could not set param %.*s\n", \
					rtpproxy_event_params[_idx].name.len, \
					rtpproxy_event_params[_idx].name.s); \
			return -1; \
		} \
	} while (0)

int rtpproxy_raise_dtmf_event(struct rtpp_dtmf_event *dtmf)
{
	str digit;

	if (evi_probe_event(rtpproxy_dtmf_event)) {
		digit.s = &dtmf->digit;
		digit.len = 1;
		RTPPROXY_SET_EVENT_PARAM(str, rtpproxy_dtmf_params, &digit, 0);
		RTPPROXY_SET_EVENT_PARAM(int, rtpproxy_dtmf_params, &dtmf->duration, 1);
		RTPPROXY_SET_EVENT_PARAM(int, rtpproxy_dtmf_params, &dtmf->volume, 2);
		RTPPROXY_SET_EVENT_PARAM(str, rtpproxy_dtmf_params, &dtmf->id, 3);
		RTPPROXY_SET_EVENT_PARAM(int, rtpproxy_dtmf_params, &dtmf->is_callid, 4);
		RTPPROXY_SET_EVENT_PARAM(int, rtpproxy_dtmf_params, &dtmf->stream, 5);

		if (evi_raise_event(rtpproxy_dtmf_event, rtpproxy_dtmf_params) < 0)
			LM_ERR("cannot raise RTPProxy event\n");
	} else
		LM_DBG("nothing to do - nobody is listening!\n");
	return 0;
}

static int rtpproxy_fill_call_args(struct rtp_relay_session *sess, struct rtpp_args *args,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags)
{
	char *p;
	str b;

	if (!sess->from_tag) {
		if (get_from_tag(sess->msg, &args->from_tag) == -1 || args->from_tag.len == 0) {
			LM_ERR("can't get From tag\n");
			return 0;
		}
	} else {
		args->from_tag = *sess->from_tag;
	}
	if (!sess->to_tag) {
		if (sess->msg && get_to_tag(sess->msg, &args->to_tag) == -1) {
			LM_ERR("can't get To tag\n");
			return 0;
		}
	} else {
		args->to_tag = *sess->to_tag;
	}
	if (!sess->callid) {
		if (get_callid(sess->msg, &args->callid) == -1 || args->callid.len == 0) {
			LM_ERR("can't get Call-Id field\n");
			return 0;
		}
	} else {
		args->callid = *sess->callid;
	}
	if (sess->body)
		args->body = *sess->body;

	p = pkg_malloc((type?type->len:0) + (in_iface?in_iface->len:0) +
			(out_iface?out_iface->len:0) + (global_flags?global_flags->len:0) +
			(flags?flags->len:0) + (extra_flags?extra_flags->len:0) + 1 +
			((ip && ip->len)?ip->len + 1:0) +
			(sess->branch != -1?args->callid.len + 1 + INT2STR_MAX_LEN:0));
	if (!p) {
		LM_ERR("could not build flags!\n");
		return 0;
	}
	if (ip && ip->len) {
		args->arg2 = p;
		memcpy(p, ip->s, ip->len);
		p += ip->len;
		*p++ = '\0';
	}
	args->arg1 = p;
	if (type) {
		memcpy(p, type->s, type->len);
		p += type->len;
	}
	if (in_iface) {
		memcpy(p, in_iface->s, in_iface->len);
		p += in_iface->len;
	}
	if (out_iface) {
		memcpy(p, out_iface->s, out_iface->len);
		p += out_iface->len;
	}
	if (global_flags) {
		memcpy(p, global_flags->s, global_flags->len);
		p += global_flags->len;
	}
	if (flags) {
		memcpy(p, flags->s, flags->len);
		p += flags->len;
	}
	if (extra_flags) {
		memcpy(p, extra_flags->s, extra_flags->len);
		p += extra_flags->len;
	}
	*p++ = '\0';
	if (sess->branch != -1) {
		memcpy(p, args->callid.s, args->callid.len);
		args->callid.s = p;
		p += args->callid.len;
		*p++ = '-';
		b.s = int2str(sess->branch, &b.len);
		memcpy(p, b.s, b.len);
		args->callid.len += b.len + 1;
	}

	return 1;
}

static void rtpproxy_free_call_args(struct rtpp_args *args)
{
	if (args->arg2)
		pkg_free(args->arg2);
	else
		pkg_free(args->arg1);
}

static int fill_rtpproxy_node(struct rtp_relay_server *server,
		str *s)
{
	if (!s->len)
		return 0;
	if (server->node.s)
		shm_free(server->node.s);
	return shm_nt_str_dup(&server->node, s);
}

static int rtpproxy_api_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags)
{
	int ret = -1;
	int unlock = 0;
	pv_value_t val;
	struct rtpp_set *rset = NULL;
	struct rtpp_args args;
	struct sip_msg *msg = NULL;

	memset(&args, '\0', sizeof(args));

	if (!rtpproxy_fill_call_args(sess, &args, ip, type,
			in_iface, out_iface, global_flags, flags, extra_flags))
		return -1;

	if (!server->node.s) {
		if (server->set != -1) {
			rset = select_rtpp_set(server->set);
			if (!rset) {
				LM_WARN("RTPProxy set %d\n not available! Using default %d...\n",
						server->set, default_rtpp_set_no);
				rset = *default_rtpp_set;
			}
		} else {
			rset = *default_rtpp_set;
		}
		server->set = rset->id_set;
	} else {
		if (nh_lock)
			lock_start_read(nh_lock);

		rset = select_rtpp_set(server->set);
		args.node = get_rtpp_node(&server->node, rset);
		/* if we're not using a node, we don't need the lock */
		if (!args.node && nh_lock)
			lock_stop_read(nh_lock);
		else
			unlock = 1;
	}

	args.set = rset;
	args.offer = 1;
	msg = (sess->msg?sess->msg:get_dummy_sip_msg());

	val.rs.len = 0;
	val.rs.s = "";
	val.flags = PV_VAL_STR;
	pv_set_value(msg, &media_pvar, (int)EQ_T, &val);

	ret = rtpproxy_offer_answer(msg, &args, &media_pvar, NULL, body);
	if (nh_lock && unlock)
		lock_stop_read(nh_lock);
	if (ret < 0) {
		LM_ERR("could not engage rtpproxy offer!\n");
		goto exit;
	}
	if (pv_get_spec_value(msg, &media_pvar, &val) >= 0)
		fill_rtpproxy_node(server, &val.rs);
	else
		LM_ERR("could not retrieve the value of the used rtpproxy!\n");
exit:
	if (is_dummy_sip_msg(msg) == 0)
		release_dummy_sip_msg(msg);
	rtpproxy_free_call_args(&args);
	return ret;
}

static int rtpproxy_api_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags)
{
	int ret = -1;
	struct rtpp_set *rset = NULL;
	struct rtpp_args args;

	memset(&args, '\0', sizeof(args));

	if (!rtpproxy_fill_call_args(sess, &args, ip, type,
			in_iface, out_iface, global_flags, flags, extra_flags))
		return -1;

	if (nh_lock)
		lock_start_read(nh_lock);

	rset = select_rtpp_set(server->set);
	if (!rset) {
		LM_ERR("RTPProxy set %d\n not available!\n", server->set);
		goto exit;
	}

	args.set = rset;
	args.offer = 0;

	if (server->node.s) {
		args.node = get_rtpp_node(&server->node, rset);
		if (!args.node) {
			LM_ERR("Could not use node %.*s for reply!\n",
					server->node.len, server->node.s);
			goto exit;
		}
	}

	ret = rtpproxy_offer_answer(sess->msg, &args, NULL, NULL, body);
exit:
	if (nh_lock)
		lock_stop_read(nh_lock);
	rtpproxy_free_call_args(&args);
	return ret;

}

static int rtpproxy_api_delete(struct rtp_relay_session *sess, struct rtp_relay_server *server,
			str *flags, str *extra)
{
	int ret = -1;
	struct rtpp_set *rset = NULL;
	struct rtpp_args args;

	memset(&args, '\0', sizeof(args));
	if (!rtpproxy_fill_call_args(sess, &args, NULL, NULL,
			NULL, NULL, NULL, flags, extra))
		return -1;

	if (nh_lock) {
		lock_start_read( nh_lock );
	}

	rset = select_rtpp_set(server->set);
	if (!rset) {
		LM_ERR("RTPProxy set %d\n not available!\n", server->set);
		goto exit;
	}

	args.set = rset;

	args.node = get_rtpp_node(&server->node, rset);
	if (!args.node) {
		LM_ERR("Could not use node %.*s for delete!\n",
				server->node.len, server->node.s);
		goto exit;
	}

	ret = unforce_rtpproxy(sess->msg, &args, NULL);
exit:
	if (nh_lock) {
		lock_stop_read( nh_lock );
	}
	rtpproxy_free_call_args(&args);
	return ret;
}

struct rtpproxy_sdp_buf {
	int length;
	str buffer;
};

#define RTPPROXY_SDP_BUF_INC 512
static struct rtpproxy_sdp_buf *rtpproxy_sdp_buf_new(void)
{
	static struct rtpproxy_sdp_buf buf;
	memset(&buf, 0, sizeof buf);
	buf.buffer.s = pkg_malloc(RTPPROXY_SDP_BUF_INC);
	if (!buf.buffer.s)
		return NULL;

	return &buf;
}

#define RTPPROXY_SDP_ENSURE_SIZE(_size, _b) \
	do { \
		if ((_b)->length - (_b)->buffer.len < _size) { \
			do \
				(_b)->length += RTPPROXY_SDP_BUF_INC; \
			while ((_b)->length - (_b)->buffer.len < _size); \
			(_b)->buffer.s = pkg_realloc((_b)->buffer.s, (_b)->length); \
			if (!(_b)->buffer.s) { \
				LM_ERR("not enough pkg memory to build body!\n"); \
				return -1; \
			} \
		}\
	} while(0)
#define RTPPROXY_SDP_COPY_STR(_s, _b) \
	do { \
		RTPPROXY_SDP_ENSURE_SIZE(_s.len, _b); \
		memcpy((_b)->buffer.s + (_b)->buffer.len, _s.s, _s.len); \
		(_b)->buffer.len += _s.len; \
	} while(0)
#define RTPPROXY_SDP_COPY(_ct, _b) \
	do { \
		str tmp = str_init(_ct); \
		RTPPROXY_SDP_COPY_STR(tmp, _b); \
	} while(0)
#define RTPPROXY_SDP_COPY_INT(_i, _b); \
	do { \
		str tmp; \
		tmp.s = int2str(_i, &tmp.len); \
		RTPPROXY_SDP_COPY_STR(tmp, _b); \
	} while(0)
#define RTPPROXY_SDP_COPY_CHAR(_c, _b); \
	do { \
		RTPPROXY_SDP_ENSURE_SIZE(1, _b); \
		(_b)->buffer.s[(_b)->buffer.len++] = (_c); \
	} while(0)

#define RTPPROXY_COPY_STREAM_INACTIVE (1<<0)
#define RTPPROXY_COPY_STREAM_STARTED  (1<<1)

struct rtpproxy_copy_stream {
	unsigned short port;
	unsigned int index;
	unsigned int flags;
	unsigned int medianum;
	struct list_head list;
};

struct rtpproxy_copy_ctx {
	time_t ts;
	str media_ip;
	unsigned int flags;
	unsigned int version;
	unsigned int max_index;
	unsigned int streams_mask;
	struct list_head streams[2];
};

static struct rtpproxy_copy_ctx *rtpproxy_copy_ctx_new(
		str *media_ip, unsigned int flags)
{
	int s;
	struct rtpproxy_copy_ctx *ctx;

	ctx = shm_malloc(media_ip->len + sizeof *ctx);
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof *ctx);
	time(&ctx->ts);
	ctx->media_ip.s = (char *)(ctx + 1);
	ctx->media_ip.len = media_ip->len;
	memcpy(ctx->media_ip.s, media_ip->s, media_ip->len);
	ctx->flags = flags;
	for (s = 0; s < sizeof(ctx->streams)/sizeof(ctx->streams[0]); s++)
		INIT_LIST_HEAD(&ctx->streams[s]);
	return ctx;
}

static void rtpproxy_copy_stream_free(struct rtpproxy_copy_stream *stream)
{
	list_del(&stream->list);
	shm_free(stream);
}

static void rtpproxy_copy_ctx_free(struct rtpproxy_copy_ctx *ctx)
{
	int s;
	struct list_head *it, *safe;

	for (s = 0; s < sizeof(ctx->streams)/sizeof(ctx->streams[0]); s++) {
		list_for_each_safe(it, safe, &ctx->streams[s])
			rtpproxy_copy_stream_free(list_entry(it, struct rtpproxy_copy_stream, list));
	}
	shm_free(ctx);
}

static int rtpproxy_gen_sdp_stream(struct rtpproxy_sdp_buf *buf,
		struct rtpproxy_copy_ctx *ctx)
{
	/*
	 * SDP body format we use:
	 *
	 * v=0
	 * o=- <timestamp> <version> IN IP4 <mediaip>
	 * s=-
	 * c=IN IP4 <mediaip>
	 * t=0 0
	 * <streams*>
	 */
	str header1 = str_init("v=0" CRLF "o=- ");
	str header2 = str_init(" IN IP4 ");
	str header3 = str_init(CRLF "s=-" CRLF "c=IN IP4 ");
	str header4 = str_init("t=0 0" CRLF);
	str crlf_str = str_init(CRLF);

	RTPPROXY_SDP_COPY_STR(header1, buf);
	RTPPROXY_SDP_COPY_INT(ctx->ts, buf);
	RTPPROXY_SDP_COPY_CHAR(' ', buf);
	RTPPROXY_SDP_COPY_INT(ctx->version, buf);
	RTPPROXY_SDP_COPY_STR(header2, buf);
	RTPPROXY_SDP_COPY_STR(ctx->media_ip, buf);
	RTPPROXY_SDP_COPY_STR(header3, buf);
	RTPPROXY_SDP_COPY_STR(ctx->media_ip, buf);
	RTPPROXY_SDP_COPY_STR(crlf_str, buf);
	RTPPROXY_SDP_COPY_STR(header4, buf);

	return 1;
}

static char rtpproxy_get_sdp_line(char *start, char *end, str *line)
{
	char *p = start;

	/* eat the spaces at the beginning */
	while (p < end && is_ws(*p))
		p++;
	/* nothing here */
	if (p == end)
		return 0;
	line->s = p;
	/* search for \r or \n */
	while (p < end && *p != '\r' && *p != '\n')
		p++;
	while (p < end && is_ws(*p))
		p++;
	line->len = p - line->s;
	if (line->len)
		return *line->s;
	else
		return 0;
}

static struct rtpproxy_copy_stream *rtpproxy_get_stream(
		struct rtpproxy_copy_ctx *ctx, int leg, int medianum)
{
	struct list_head *it;
	struct rtpproxy_copy_stream *stream;

	list_for_each(it, &ctx->streams[leg]) {
		stream = list_entry(it, struct rtpproxy_copy_stream, list);
		if (stream->medianum == medianum)
			return stream;
	}
	stream = shm_malloc(sizeof *stream);
	if (!stream) {
		LM_ERR("cannot alloc new stream!\n");
		return NULL;
	}
	memset(stream, 0, sizeof *stream);
	stream->port = rtpproxy_gen_port();
	stream->index = ctx->max_index++;
	stream->medianum = medianum;

	list_add(&stream->list, &ctx->streams[leg]);
	return stream;
}

static int rtpproxy_gen_sdp_media(struct rtpproxy_sdp_buf *buf,
		struct rtpproxy_copy_ctx *ctx, str *body, int type)
{
	str tmp;
	char sdp_type;
	char *start, *end;
	int media_inactive;
	static sdp_info_t sdp;
	sdp_stream_cell_t *stream;
	struct rtpproxy_copy_stream *rtp_stream;

	memset(&sdp, 0, sizeof(sdp));
	if (parse_sdp_session(body, 0, NULL, &sdp)<0) {
		LM_ERR("failed to parse SDP, skipping\n");
		return -1;
	}

	for (stream = sdp.sessions->streams; stream; stream = stream->next) {
		/* not interested in this stream */
		if (!(ctx->streams_mask & (1 << stream->stream_num)) || !stream->is_rtp)
			continue;
		rtp_stream = rtpproxy_get_stream(ctx, type, stream->stream_num);
		if (!rtp_stream)
			continue;
		media_inactive = stream->is_on_hold ? 1: 0;
		/* m= line */
		tmp.s = stream->body.s;
		tmp.len = stream->port.s - stream->body.s;
		RTPPROXY_SDP_COPY_STR(tmp, buf);
		RTPPROXY_SDP_COPY_INT(rtp_stream->port, buf);

		tmp.s = stream->port.s + stream->port.len;
		tmp.len = stream->payloads.s + stream->payloads.len - tmp.s;
		RTPPROXY_SDP_COPY_STR(tmp, buf);
		RTPPROXY_SDP_COPY(CRLF, buf);

		/* handle session attributes */
		start = sdp.sessions->o_ip_addr.s + sdp.sessions->o_ip_addr.len;
		end = body->s + body->len;

		while ((sdp_type = rtpproxy_get_sdp_line(start, end, &tmp)) != 0) {
			/* globals are just until they reach m= line */
			if (sdp_type == 'm')
				break;
			/* XXX: we need separate buffers for each type, because they need
			 * to be all in order when we put them in the session */
			else if (sdp_type == 'b' ||sdp_type == 'z' || sdp_type == 'k' || sdp_type == 'a')
				RTPPROXY_SDP_COPY_STR(tmp, buf);
			start += tmp.len;
		}
		start = stream->payloads.s + stream->payloads.len;
		end = stream->body.s + stream->body.len;

		while ((sdp_type = rtpproxy_get_sdp_line(start, end, &tmp)) != 0) {
			switch (sdp_type) {

				case 'a':
					/* we skip a=send/recv/only and a=label attributes
					 * because they will be added later by us */
					if (tmp.len > 8 /* a=label: */ &&
							memcmp(tmp.s + 2, "label:", 6) == 0) {
						if (ctx->flags & RTP_COPY_MODE_SIPREC)
							break;
						/* if SIPREC is not enable, fallback to copy */
					} else if (tmp.len > 2 /* a= */ + 8 + 1/* \r */ &&
							(tmp.s[10] == '\r' || tmp.s[10] == '\n')) {
						if (memcmp(tmp.s + 2, "sendrecv", 8) == 0 ||
								memcmp(tmp.s + 2, "sendonly", 8) == 0) {
							media_inactive = 0;
							break;
						}
						if (memcmp(tmp.s + 2, "recvonly", 8) == 0 ||
								memcmp(tmp.s + 2, "inactive", 8) == 0) {
							media_inactive = 1;
							break;
						}
					}
					/* fallback */
				case 'b':
				case 'k':
					RTPPROXY_SDP_COPY_STR(tmp, buf);
					break;
			}
			start += tmp.len;
		}
		if (media_inactive) {
			rtp_stream->flags |= RTPPROXY_COPY_STREAM_INACTIVE;
			RTPPROXY_SDP_COPY("a=inactive" CRLF, buf);
		} else if (ctx->flags & RTP_COPY_MODE_DISABLE) {
			RTPPROXY_SDP_COPY("a=inactive" CRLF, buf);
		} else {
			rtp_stream->flags &= ~RTPPROXY_COPY_STREAM_INACTIVE;
			RTPPROXY_SDP_COPY("a=sendonly" CRLF, buf);
		}
		if (ctx->flags & RTP_COPY_MODE_SIPREC) {
			RTPPROXY_SDP_COPY("a=label:", buf);
			RTPPROXY_SDP_COPY_INT(rtp_stream->index, buf);
			RTPPROXY_SDP_COPY(CRLF, buf);
		}
	}

	free_sdp_content(&sdp);
	return 0;
}

static int rtpproxy_gen_sdp_medias(struct rtpproxy_sdp_buf *buf,
		struct rtpproxy_copy_ctx *ctx, struct rtp_relay_session *sess)
{
	str *msg_body;

	if (ctx->flags & RTP_COPY_LEG_CALLER) {
		msg_body = rtp_relay.get_sdp(sess, RTP_RELAY_CALLER);
		if (!msg_body) {
			LM_ERR("could not get caller's SDP\n");
			return -1;
		}
		if (rtpproxy_gen_sdp_media(buf, ctx, msg_body, RTP_RELAY_CALLER) < 0) {
			LM_ERR("could not push caller's SDP\n");
			return -1;
		}
	}
	if (ctx->flags & RTP_COPY_LEG_CALLEE) {
		msg_body = rtp_relay.get_sdp(sess, RTP_RELAY_CALLEE);
		if (!msg_body) {
			LM_ERR("could not get callee's SDP\n");
			return -1;
		}
		if (rtpproxy_gen_sdp_media(buf, ctx, msg_body, RTP_RELAY_CALLEE) < 0) {
			LM_ERR("could not push callee's SDP\n");
			return -1;
		}
	}

	return 0;
}

static int rtpproxy_api_copy_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void **_ctx, str *flags,
		unsigned int copy_flags, unsigned int streams, str *body)
{
	str *media_ip;
	struct rtpproxy_sdp_buf *buf;
	struct rtpproxy_copy_ctx *ctx = *_ctx;

	if (!ctx) {
		media_ip = (flags && flags->len)?flags:&rtpproxy_media_ip;
		ctx = rtpproxy_copy_ctx_new(media_ip, copy_flags);
		if (!ctx)
			return -1;
	} else {
		/* update the flags */
		ctx->flags = copy_flags;
	}
	ctx->streams_mask = streams;

	buf = rtpproxy_sdp_buf_new();

	if (rtpproxy_gen_sdp_stream(buf, ctx) < 0)
		goto error;

	if (rtpproxy_gen_sdp_medias(buf, ctx, sess) < 0)
		goto error;

	*body = buf->buffer;
	*_ctx = ctx;
	return 0;
error:
	if (*_ctx == NULL)
		rtpproxy_copy_ctx_free(ctx);
	pkg_free(buf->buffer.s);
	return -1;
}

static struct rtpproxy_copy_stream *rtpproxy_get_stream_index(
		struct rtpproxy_copy_ctx *ctx, unsigned int *leg, sdp_stream_cell_t *stream)
{
	struct rtpproxy_copy_stream *rtp_stream;
	struct list_head *it;
	unsigned int label;
	sdp_attr_t *attr;
	/* if we are in SIPREC mode, we need to search based on index */
	if (ctx->flags & RTP_COPY_MODE_SIPREC) {
		for (attr = stream->attr; attr; attr = attr->next) {
			if (attr->value.len &&
					str_match(&attr->attribute, const_str("label"))) {
				if (str2int(&attr->value, &label) < 0) {
					LM_ERR("invalid label number: %.*s - should have been numeric\n",
							attr->value.len, attr->value.s);
					continue;
				} else {
					break;
				}
			}
		}
		if (attr != NULL) {
			/* search for the proper label */
			for (*leg = RTP_RELAY_CALLER; *leg <= RTP_RELAY_CALLEE; (*leg)++) {
				list_for_each(it, &ctx->streams[*leg]) {
					rtp_stream = list_entry(it, struct rtpproxy_copy_stream, list);
					if (rtp_stream->index == label)
						return rtp_stream;
				}
			}
			LM_WARN("label %u not found - match based on media index %d\n",
					label, stream->stream_num);
		} else {
			LM_WARN("label not found - match based on media index %d\n",
					stream->stream_num);
		}
	}
	for (*leg = RTP_RELAY_CALLER; *leg <= RTP_RELAY_CALLEE; (*leg)++) {
		list_for_each(it, &ctx->streams[*leg]) {
			rtp_stream = list_entry(it, struct rtpproxy_copy_stream, list);
			if (rtp_stream->medianum == stream->stream_num)
				return rtp_stream;
		}
	}
	return NULL;
}

static int rtpproxy_handle_recording(struct rtpproxy_copy_ctx *ctx,
		struct rtpp_args *args, str *flags, str *body)
{
	int ret = -1, len;
	sdp_info_t sdp;
	sdp_stream_cell_t *stream;
	unsigned int leg;
	str *from_tag, *to_tag;
	str destination;
	struct list_head *it;
	struct rtpproxy_copy_stream *rtp_stream;

	memset(&sdp, 0, sizeof sdp);

	if (parse_sdp_session(body, 0, NULL, &sdp)<0) {
		LM_ERR("failed to parse SDP for body\n");
		return -1;
	};

	for (stream = sdp.sessions->streams; stream; stream = stream->next) {
		if (!(ctx->streams_mask & (1 << stream->stream_num)))
			continue;
		rtp_stream = rtpproxy_get_stream_index(ctx, &leg, stream);
		if (!rtp_stream) {
			LM_WARN("could not find associated stream %d\n",
					stream->stream_num);
			continue;
		}
		if (leg == RTP_RELAY_CALLER) {
			from_tag = &args->from_tag;
			to_tag = &args->to_tag;
		} else {
			from_tag = &args->to_tag;
			to_tag = &args->from_tag;
		}
		if (!stream->is_on_hold && !(ctx->flags & RTP_COPY_MODE_DISABLE) &&
				!(rtp_stream->flags & RTPPROXY_COPY_STREAM_INACTIVE)) {

			if (rtp_stream->flags & RTPPROXY_COPY_STREAM_STARTED) {
				ret++;
				continue; /* stream already started  */
			}

			len = 4/* udp: */;
			/* if there is an IP in the stream, use it, otherwise use the
			 * SDP session IP */
			if (stream->ip_addr.len)
				len += stream->ip_addr.len;
			else
				len += sdp.sessions->ip_addr.len;
			len += 1/* : */ + stream->port.len;

			/* build the socket to stream to */
			destination.s = pkg_malloc(len);
			if (!destination.s) {
				LM_ERR("cannot allocate destination buffer!\n");
				return -1;
			}
			memcpy(destination.s, "udp:", 4);
			destination.len = 4;
			if (stream->ip_addr.len) {
				memcpy(destination.s + destination.len, stream->ip_addr.s,
						stream->ip_addr.len);
				destination.len += stream->ip_addr.len;
			} else {
				memcpy(destination.s + destination.len,
						sdp.sessions->ip_addr.s,
						sdp.sessions->ip_addr.len);
				destination.len += sdp.sessions->ip_addr.len;
			}
			destination.s[destination.len++] = ':';
			memcpy(destination.s + destination.len, stream->port.s,
					stream->port.len);
			destination.len += stream->port.len;

			if (w_rtpproxy_recording(NULL, &args->callid,
					from_tag, to_tag, args->node,
					NULL, NULL, &destination, rtp_stream->medianum+1) >= 0) {
				ret++;
				rtp_stream->flags |= RTPPROXY_COPY_STREAM_STARTED;
			}
			pkg_free(destination.s);
		} else {
			if (rtp_stream->flags & RTPPROXY_COPY_STREAM_STARTED) {
				if (w_rtpproxy_stop_recording(NULL, &args->callid,
						from_tag, to_tag, args->node,
						NULL, rtp_stream->medianum+1) >= 0) {
					ret++;
					rtp_stream->flags &= ~RTPPROXY_COPY_STREAM_STARTED;
				}
			} else {
				/* media already disabled and stream not started */
				ret++;
			}
		}
	}
	/* cleanup streams that we don't know about */
	for (leg = RTP_RELAY_CALLER; leg <= RTP_RELAY_CALLEE; leg++) {
		list_for_each(it, &ctx->streams[leg]) {
			rtp_stream = list_entry(it, struct rtpproxy_copy_stream, list);
			if (ctx->streams_mask & (1 << rtp_stream->medianum))
				continue;
			if (!(rtp_stream->flags & RTPPROXY_COPY_STREAM_STARTED))
				continue;
			if (leg == RTP_RELAY_CALLER) {
				from_tag = &args->from_tag;
				to_tag = &args->to_tag;
			} else {
				from_tag = &args->to_tag;
				to_tag = &args->from_tag;
			}
			if (w_rtpproxy_stop_recording(NULL, &args->callid,
					from_tag, to_tag, args->node,
					NULL, rtp_stream->medianum+1) >= 0)
				rtp_stream->flags &= ~RTPPROXY_COPY_STREAM_STARTED;
			rtp_stream->flags |= RTPPROXY_COPY_STREAM_INACTIVE;
		}
	}
	return ret;
}

static int rtpproxy_api_copy_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *_ctx, str *flags, str *body)
{
	int ret = -1;
	struct rtpp_args args;
	struct rtpp_set *rset = NULL;

	memset(&args, '\0', sizeof(args));

	if (!rtpproxy_fill_call_args(sess, &args, NULL, NULL,
			NULL, NULL, NULL, flags, NULL))
		return -1;

	if (!server->node.s) {
		LM_ERR("no RTPProxy node to use!\n");
		return -1;
	}

	if (nh_lock)
		lock_start_read(nh_lock);

	rset = select_rtpp_set(server->set);
	args.node = get_rtpp_node(&server->node, rset);

	if (!args.node)
		args.node = select_rtpp_node(sess->msg,
				args.callid, rset, NULL, 0);
	if (!args.node) {
		LM_ERR("no available proxies\n");
		goto error;
	}

	ret = rtpproxy_handle_recording(_ctx, &args, flags, body);
error:
	if (nh_lock)
		lock_stop_read(nh_lock);
	rtpproxy_free_call_args(&args);
	return ret;
}

static int rtpproxy_stop_recording_leg(struct rtpproxy_copy_ctx *ctx,
		struct rtpp_args *args, str *flags, int leg)
{
	int ret = 0;
	str *to_tag, *from_tag;
	struct list_head *it;
	struct rtpproxy_copy_stream *rtp_stream;

	if (leg == RTP_RELAY_CALLER) {
		from_tag = &args->from_tag;
		to_tag = &args->to_tag;
	} else {
		from_tag = &args->to_tag;
		to_tag = &args->from_tag;
	}

	list_for_each(it, &ctx->streams[leg]) {
		rtp_stream = list_entry(it, struct rtpproxy_copy_stream, list);
		if (!(rtp_stream->flags & RTPPROXY_COPY_STREAM_STARTED) ||
				w_rtpproxy_stop_recording(NULL, &args->callid, from_tag,
					to_tag, args->node, NULL, rtp_stream->medianum + 1) > 0)
			ret++;
	}
	return ret;
}

static int rtpproxy_api_copy_delete(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *_ctx, str *flags)

{
	int ret = -1;
	struct rtpp_args args;
	struct rtpp_set *rset = NULL;

	memset(&args, '\0', sizeof(args));

	if (!rtpproxy_fill_call_args(sess, &args, NULL, NULL,
			NULL, NULL, NULL, flags, NULL))
		return -1;

	if (!server->node.s) {
		LM_ERR("no RTPProxy node to use!\n");
		return -1;
	}

	if (nh_lock)
		lock_start_read(nh_lock);

	rset = select_rtpp_set(server->set);
	args.node = get_rtpp_node(&server->node, rset);

	if (!args.node)
		args.node = select_rtpp_node(sess->msg,
				args.callid, rset, NULL, 0);
	if (!args.node) {
		LM_ERR("no available proxies\n");
		goto error;
	}

	ret = rtpproxy_stop_recording_leg(_ctx, &args, flags, RTP_RELAY_CALLER) +
		rtpproxy_stop_recording_leg(_ctx, &args, flags, RTP_RELAY_CALLEE);
error:
	if (nh_lock)
		lock_stop_read(nh_lock);
	rtpproxy_free_call_args(&args);
	rtpproxy_copy_ctx_free(_ctx);
	return ret <= 0?-1:1;
}

static int rtpproxy_api_copy_serialize(void *_ctx, bin_packet_t *packet)
{
	struct rtpproxy_copy_ctx *ctx = _ctx;
	str tmp;
	int leg;
	struct list_head *it;
	struct rtpproxy_copy_stream *stream;

	tmp.s = (char *)(unsigned long)&ctx->ts;
	tmp.len = sizeof(ctx->ts);
	if (bin_push_str(packet, &tmp) < 0)
		return -1;
	if (bin_push_str(packet, &ctx->media_ip) < 0)
		return -1;
	if (bin_push_int(packet, ctx->flags) < 0)
		return -1;
	if (bin_push_int(packet, ctx->version) < 0)
		return -1;
	if (bin_push_int(packet, ctx->max_index) < 0)
		return -1;
	if (bin_push_int(packet, ctx->streams_mask) < 0)
		return -1;
	for (leg = RTP_RELAY_CALLER; leg <= RTP_RELAY_CALLEE; leg++) {
		if (bin_push_int(packet, list_size(&ctx->streams[leg])) < 0)
			return -1;
		list_for_each(it, &ctx->streams[leg]) {
			stream = list_entry(it, struct rtpproxy_copy_stream, list);
			if (bin_push_int(packet, stream->port) < 0)
				return -1;
			if (bin_push_int(packet, stream->index) < 0)
				return -1;
			if (bin_push_int(packet, stream->flags) < 0)
				return -1;
			if (bin_push_int(packet, stream->medianum) < 0)
				return -1;
		}
	}
	return 0;
}

static int rtpproxy_api_copy_deserialize(void **_ctx, bin_packet_t *packet)
{
	time_t ts;
	struct rtpproxy_copy_ctx *ctx;
	struct rtpproxy_copy_stream *stream;
	str media_ip, tmp;
	unsigned int flags, medianum;
	int leg, idx, no, port;

	if (bin_pop_str(packet, &tmp) < 0)
		return -1;
	ts = (time_t)(unsigned long)tmp.s;
	if (bin_pop_str(packet, &media_ip) < 0)
		return -1;
	if (bin_pop_int(packet, &flags) < 0)
		return -1;
	ctx = rtpproxy_copy_ctx_new(&media_ip, flags);
	if (!ctx)
		return -1;
	if (bin_pop_int(packet, &ctx->version) < 0)
		return -1;
	if (bin_pop_int(packet, &ctx->max_index) < 0)
		return -1;
	if (bin_pop_int(packet, &ctx->streams_mask) < 0)
		return -1;
	ctx->ts = ts;

	for (leg = RTP_RELAY_CALLER; leg <= RTP_RELAY_CALLEE; leg++) {
		if (bin_pop_int(packet, &no) < 0)
			return -1;

		while (no--) {
			if (bin_pop_int(packet, &port) < 0)
				return -1;
			if (bin_pop_int(packet, &idx) < 0)
				return -1;
			if (bin_pop_int(packet, &flags) < 0)
				return -1;
			if (bin_pop_int(packet, &medianum) < 0)
				return -1;
			stream = rtpproxy_get_stream(ctx, leg, medianum);
			if (stream) {
				stream->port = port;
				stream->flags = flags;
				stream->index = idx;
			}
		}
	}
	*_ctx = ctx;
	return -1;
}
