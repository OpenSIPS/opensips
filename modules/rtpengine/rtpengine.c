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
 * 2014-06-17 Imported from rtpproxy module
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
#include <regex.h>

#include "../../str.h"
#include "../../flags.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../error.h"
#include "../../forward.h"
#include "../../context.h"
#include "../../mem/mem.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parser_f.h"
#include "../../parser/sdp/sdp.h"
#include "../../resolve.h"
#include "../../timer.h"
#include "../../trim.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../pvar.h"
#include "../../db/db.h"
#include "../../msg_translator.h"
#include "../../usr_avp.h"
#include "../../socket_info.h"
#include "../../mod_fix.h"
#include "../../dset.h"
#include "../../route.h"
#include "../../lib/cJSON.h"
#include "../dialog/dlg_load.h"
#include "../rtp_relay/rtp_relay.h"
#include "../tm/tm_load.h"
#include "rtpengine.h"
#include "rtpengine_funcs.h"
#include "bencode.h"
#include "../../reactor_defs.h"
#include "../../reactor_proc.h"
#include "../../io_wait.h"

#if !defined(AF_LOCAL)
#define	AF_LOCAL AF_UNIX
#endif
#if !defined(PF_LOCAL)
#define	PF_LOCAL PF_UNIX
#endif

#define DEFAULT_RTPE_SET_ID		0

#define MI_ENABLE_RTP_ENGINE			"rtpengine_enable"
#define MI_MIN_RECHECK_TICKS		0
#define MI_MAX_RECHECK_TICKS		(unsigned int)-1

#define MI_SHOW_RTP_ENGINES			"rtpengine_show"
#define MI_RELOAD_RTP_ENGINES		"rtpengine_reload"

#define MI_RTP_ENGINE_NOT_FOUND		"RTP engine not found"
#define MI_RTP_ENGINE_NOT_FOUND_LEN	(sizeof(MI_RTP_ENGINE_NOT_FOUND)-1)
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


#define	CPORT		"22222"

#define rtpe_ctx_tryget() \
	(current_processing_ctx == NULL ? NULL : \
	 ((struct rtpe_ctx *)context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, rtpe_ctx_idx)))

#define rtpe_ctx_set(_ctx) \
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, rtpe_ctx_idx, _ctx)

#define RTPE_START_READ() \
	do { \
		if (rtpe_lock) \
			lock_start_read(rtpe_lock); \
	} while (0)
#define RTPE_STOP_READ() \
	do { \
		if (rtpe_lock) \
			lock_stop_read(rtpe_lock); \
	} while (0)

#define RTPE_IO_ERROR_CLOSE(_fd) \
	do { \
		if (errno == EPIPE || errno == EBADF) { \
			LM_INFO("Closing rtpengine socket %d\n", (_fd)); \
			close((_fd)); \
			(_fd) = -1; \
		} \
	} while (0)

enum rtpe_operation {
	OP_OFFER = 1,
	OP_ANSWER,
	OP_DELETE,
	OP_START_RECORDING,
	OP_STOP_RECORDING,
	OP_PAUSE_RECORDING,
	OP_QUERY,
	OP_START_MEDIA,
	OP_STOP_MEDIA,
	OP_BLOCK_MEDIA,
	OP_UNBLOCK_MEDIA,
	OP_BLOCK_DTMF,
	OP_UNBLOCK_DTMF,
	OP_START_FORWARD,
	OP_STOP_FORWARD,
	OP_PLAY_DTMF,
	OP_SUBSCRIBE_REQUEST,
	OP_SUBSCRIBE_ANSWER,
	OP_UNSUBSCRIBE,
};

enum rtpe_stat {
	STAT_MOS_AVERAGE,	STAT_JITTER_AVERAGE,	STAT_ROUNDTRIP_AVERAGE,		STAT_PACKETLOSS_AVERAGE,
	STAT_MOS_MIN,		STAT_JITTER_MIN,		STAT_ROUNDTRIP_MIN,			STAT_PACKETLOSS_MIN,
	STAT_MOS_MIN_AT,	STAT_JITTER_MIN_AT,		STAT_ROUNDTRIP_MIN_AT,		STAT_PACKETLOSS_MIN_AT,
	STAT_MOS_MAX,		STAT_JITTER_MAX,		STAT_ROUNDTRIP_MAX,			STAT_PACKETLOSS_MAX,
	STAT_MOS_MAX_AT,	STAT_JITTER_MAX_AT,		STAT_ROUNDTRIP_MAX_AT,		STAT_PACKETLOSS_MAX_AT,
	STAT_UNKNOWN /* always keep last */
};

enum rtpe_stat_type {
	STAT_AVERAGE,
	STAT_MAX,
	STAT_MAX_AT,
	STAT_MIN,
	STAT_MIN_AT
};

enum rtpe_stat_dict {
	STAT_MOS,
	STAT_JITTER,
	STAT_ROUNDTRIP,
	STAT_PACKETLOSS
};

struct rtpe_stats {
	bencode_item_t *dict;
	bencode_buffer_t buf;
	str json;
};

struct rtpe_ctx {
	struct rtpe_stats *stats;
	struct rtpe_set *set;
} rtpe_ctx_t;


struct ng_flags_parse {
	int via, to, packetize, transport, directional;
	bencode_item_t *dict, *flags, *direction, *replace, *rtcp_mux;
	str call_id, from_tag, to_tag, received_from;
	str viabranch;
};

enum rtpe_set_var {
	RTPE_SET_NONE, RTPE_SET_FIXED
};

typedef struct rtpe_set_link {
	enum rtpe_set_var type;
	union {
		int id;
		struct rtpe_set *rset;
	} v;
} rtpe_set_link_t;

struct rtpe_ignore_node {
	struct rtpe_node *node;
	struct rtpe_ignore_node *next;
};

typedef struct rtpe_async_param_ {
        bencode_buffer_t *bencbuf;
        enum rtpe_operation op;
        struct rtpe_node *node;
        char* cookie;
        pv_spec_t *spvar;
        pv_spec_t *bpvar;
} rtpe_async_param;

static const char *command_strings[] = {
	[OP_OFFER]		= "offer",
	[OP_ANSWER]		= "answer",
	[OP_DELETE]		= "delete",
	[OP_START_RECORDING]	= "start recording",
	[OP_STOP_RECORDING]		= "stop recording",
	[OP_PAUSE_RECORDING]	= "pause recording",
	[OP_QUERY]		= "query",
	[OP_START_MEDIA]= "play media",
	[OP_STOP_MEDIA] = "stop media",
	[OP_BLOCK_MEDIA]= "block media",
	[OP_UNBLOCK_MEDIA] = "unblock media",
	[OP_BLOCK_DTMF]= "block DTMF",
	[OP_UNBLOCK_DTMF] = "unblock DTMF",
	[OP_START_FORWARD]= "start forwarding",
	[OP_STOP_FORWARD] = "stop forwarding",
	[OP_PLAY_DTMF]    = "play DTMF",
	[OP_SUBSCRIBE_REQUEST]= "subscribe request",
	[OP_SUBSCRIBE_ANSWER] = "subscribe answer",
	[OP_UNSUBSCRIBE]    = "unsubscribe",
};

static const str stat_maps[] = {
	[STAT_MOS_AVERAGE]			= str_init("mos-average"),
	[STAT_MOS_MIN]				= str_init("mos-min"),
	[STAT_MOS_MIN_AT]			= str_init("mos-min-at"),
	[STAT_MOS_MAX]				= str_init("mos-max"),
	[STAT_MOS_MAX_AT]			= str_init("mos-max-at"),
	[STAT_JITTER_AVERAGE]		= str_init("jitter-average"),
	[STAT_JITTER_MIN]			= str_init("jitter-min"),
	[STAT_JITTER_MIN_AT]		= str_init("jitter-min-at"),
	[STAT_JITTER_MAX]			= str_init("jitter-max"),
	[STAT_JITTER_MAX_AT]		= str_init("jitter-max-at"),
	[STAT_ROUNDTRIP_AVERAGE]	= str_init("roundtrip-average"),
	[STAT_ROUNDTRIP_MIN]		= str_init("roundtrip-min"),
	[STAT_ROUNDTRIP_MIN_AT]		= str_init("roundtrip-min-at"),
	[STAT_ROUNDTRIP_MAX]		= str_init("roundtrip-max"),
	[STAT_ROUNDTRIP_MAX_AT]		= str_init("roundtrip-max-at"),
	[STAT_PACKETLOSS_AVERAGE]	= str_init("packetloss-average"),
	[STAT_PACKETLOSS_MIN]		= str_init("packetloss-min"),
	[STAT_PACKETLOSS_MIN_AT]	= str_init("packetloss-min-at"),
	[STAT_PACKETLOSS_MAX]		= str_init("packetloss-max"),
	[STAT_PACKETLOSS_MAX_AT]	= str_init("packetloss-max-at")
};

static int rtpengine_offer_af(struct sip_msg *msg, async_ctx *ctx, str *flags, pv_spec_t *spvar,
                pv_spec_t *bpvar, str *body);
static int rtpengine_answer_af(struct sip_msg *msg, async_ctx *ctx, str *flags, pv_spec_t *spvar,
                pv_spec_t *bpvar, str *body);
static int rtpengine_delete_af(struct sip_msg* msg, async_ctx *ctx, str *flags, pv_spec_t *spvar);

static char *gencookie();
static int rtpe_test(struct rtpe_node*, int, int);
static int stop_recording_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int pause_recording_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int start_recording_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int rtpengine_offer_f(struct sip_msg *msg, str *flags, pv_spec_t *spvar,
		pv_spec_t *bpvar, str *body);
static int rtpengine_answer_f(struct sip_msg *msg, str *flags, pv_spec_t *spvar,
		pv_spec_t *bpvar, str *body);
static int rtpengine_manage_f(struct sip_msg *msg, str *flags, pv_spec_t *spvar,
		pv_spec_t *bpvar, str *body);
static int rtpengine_delete_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static void free_rtpe_nodes(struct rtpe_set *list);
static int rtpengine_playmedia_f(struct sip_msg* msg, str *flags,
		pv_spec_t *duration, pv_spec_t *spvar);
static int rtpengine_stopmedia_f(struct sip_msg* msg, str *flags,
		pv_spec_t *spvar, pv_spec_t *last_frame_pos);
static int rtpengine_blockmedia_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int rtpengine_unblockmedia_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int rtpengine_blockdtmf_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int rtpengine_unblockdtmf_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int rtpengine_start_forward_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int rtpengine_stop_forward_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar);
static int rtpengine_play_dtmf_f(struct sip_msg* msg, str *code, str *flags, pv_spec_t *spvar);
static void rtpengine_notify_process(int rank);

static int rtpengine_api_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags);
static int rtpengine_api_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags);
static int rtpengine_api_delete(struct rtp_relay_session *sess, struct rtp_relay_server *server,
			str *flags, str *extra);
static int rtpengine_api_copy_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void **_ctx, str *flags,
		unsigned int copy_flags, unsigned int streams, str *body,
		struct rtp_relay_streams *streams_map);
static int rtpengine_api_copy_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *_ctx, str *flags, str *body);
static int rtpengine_api_copy_delete(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *_ctx, str *flags);
static int rtpengine_api_copy_serialize(void *_ctx, bin_packet_t *packet);
static int rtpengine_api_copy_deserialize(void **_ctx, bin_packet_t *packet);
static void rtpengine_api_copy_release(void **_ctx);

static int parse_flags(struct ng_flags_parse *, struct sip_msg *, enum rtpe_operation *, const char *);

static int rtpengine_offer_answer(struct sip_msg *msg, str *flags, str *node,
		pv_spec_t *spvar, pv_spec_t *bpvar, str *body, int op);
static int add_rtpengine_socks(struct rtpe_set * rtpe_list, char * rtpengine);
static int fixup_set_id(void ** param);
static int fixup_free_set_id(void ** param);
static int set_rtpengine_set_f(struct sip_msg * msg, rtpe_set_link_t *set_param);
static int set_rtpengine_set_from_avp(struct sip_msg *msg);
static struct rtpe_set * select_rtpe_set(int id_set);
static struct rtpe_node *select_rtpe_node(str, struct rtpe_set *, struct rtpe_ignore_node *);
static struct rtpe_node *lookup_rtpe_node(struct rtpe_set * rtpe_list, str *rtpe_url);
static void free_rtpe_set(int);
static void free_rtpe_node(struct rtpe_set *, str *);
static void disconnect_rtpe_socket(int);
static void cleanup_rtpengine_versions(void);
static int add_rtpengine_version(int);
static char *send_rtpe_command(struct rtpe_node *, bencode_item_t *, int *);
static int get_extra_id(struct sip_msg* msg, str *id_str);

static int update_rtpengines(int);
static int _add_rtpengine_from_database(void);
static int rtpengine_set_store(modparam_t type, void * val);
static int rtpengine_set_notify(modparam_t type, void * val);
static int rtpengine_extra_failover(modparam_t type, void * val);
static int rtpengine_add_rtpengine_set( char * rtp_proxies, int set_id);

static int mod_init(void);
static int mod_preinit(void);
static int child_init(int);
static void mod_destroy(void);

/* Pseudo-Variables */
static int pv_get_rtpstat_f(struct sip_msg *, pv_param_t *, pv_value_t *);
static int pv_get_rtpquery_f(struct sip_msg *, pv_param_t *, pv_value_t *);

/*mi commands*/
static mi_response_t *mi_enable_rtpengine(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_show_rtpengines(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_teardown_call(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reload_rtpengines(const mi_params_t *params,
								struct mi_handler *async_hdl);


static int rtpengine_stats_used = 0;
static int rtpengine_disable_tout = 60;
static int rtpengine_retr = 5;
static int rtpengine_tout = 1;
static int rtpengine_ping_enabled = 0;
static int rtpengine_timer_interval = 5;
static pid_t mypid;
static int myrand = 0;
static int myrank = 0;
static unsigned int myseqn = 0;
static str extra_id_pv_param = {NULL, 0};
static char *setid_avp_param = NULL;
static char *err_pv_param = NULL;
static pv_spec_t err_pv;

static char ** rtpe_strings=0;
static int rtpe_sets=0; /*used in rtpengine_set_store()*/
static int rtpe_ctx_idx = -1;
struct rtpe_set_head **rtpe_set_list =0;
struct rtpe_set **default_rtpe_set=0;

static str rtpengine_notify_sock;
static short rtpengine_notify_port;
static str rtpengine_notify_event_name = str_init("E_RTPENGINE_NOTIFICATION");
static event_id_t rtpengine_notify_event = EVI_ERROR;

static str rtpengine_status_event_name = str_init("E_RTPENGINE_STATUS");
static event_id_t rtpengine_status_event = EVI_ERROR;
static evi_params_p rtpengine_status_event_params;
static str rtpengine_status_event_socket_s = str_init("socket");
static str rtpengine_status_event_status_s = str_init("status");
static str rtpengine_status_event_set_s = str_init("set");
static evi_param_p rtpengine_status_event_socket;
static evi_param_p rtpengine_status_event_status;
static evi_param_p rtpengine_status_event_set;
static inline void raise_rtpengine_status_event(struct rtpe_node *node);

/* array with the sockets used by rtpengine (per process)*/
static int *rtpe_socks = 0;
static str db_url = {NULL, 0};
static str db_table = str_init("rtpengine");
static str db_rtpe_set_col = str_init("set_id");
static str db_rtpe_sock_col = str_init("socket");
static db_con_t *db_connection = NULL;
static db_func_t db_functions;
static rw_lock_t *rtpe_lock=NULL;
static unsigned int *rtpe_no = 0;

/* version management */
struct rtpe_version_head **rtpe_versions = 0; /* chronological list of versions */
static unsigned int *list_version;            /* master version */
static unsigned int my_version = 0;           /* per process version */
static unsigned int *child_versions;          /* array of per process versions */
static unsigned int *child_versions_no;       /* number of elems */

static unsigned int rtpe_number = 0;

static int     setid_avp_type;
static int_str setid_avp;

/* tm */
static struct tm_binds tmb;

static struct dlg_binds dlgb;

static struct rtp_relay_hooks rtp_relay;

static pv_elem_t *extra_id_pv = NULL;

static acmd_export_t acmds[] = {
	{"rtpengine_offer", (acmd_function)rtpengine_offer_af, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0,0,0}}},
	{"rtpengine_answer", (acmd_function)rtpengine_answer_af, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0,0,0}}},
	{"rtpengine_delete", (acmd_function)rtpengine_delete_af, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}}},
		{0, 0, {{0, 0, 0}}}
};

static const cmd_export_t cmds[] = {
	{"rtpengine_use_set", (cmd_function)set_rtpengine_set_f, {
		{CMD_PARAM_INT, fixup_set_id, fixup_free_set_id}, {0,0,0}},
		ALL_ROUTES},
	{"rtpengine_start_recording", (cmd_function)start_recording_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rtpengine_stop_recording", (cmd_function)stop_recording_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rtpengine_pause_recording", (cmd_function)pause_recording_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rtpengine_offer",	(cmd_function)rtpengine_offer_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rtpengine_answer", (cmd_function)rtpengine_answer_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rtpengine_manage", (cmd_function)rtpengine_manage_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rtpengine_delete", (cmd_function)rtpengine_delete_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"rtpengine_play_media", (cmd_function)rtpengine_playmedia_f, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"rtpengine_stop_media", (cmd_function)rtpengine_stopmedia_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"rtpengine_block_media", (cmd_function)rtpengine_blockmedia_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"rtpengine_unblock_media", (cmd_function)rtpengine_unblockmedia_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"rtpengine_block_dtmf", (cmd_function)rtpengine_blockdtmf_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"rtpengine_unblock_dtmf", (cmd_function)rtpengine_unblockdtmf_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"rtpengine_start_forwarding", (cmd_function)rtpengine_start_forward_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"rtpengine_stop_forwarding", (cmd_function)rtpengine_stop_forward_f, {
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{"rtpengine_play_dtmf", (cmd_function)rtpengine_play_dtmf_f, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static int pv_rtpengine_stats_used(pv_spec_p sp, int param)
{
	rtpengine_stats_used = 1;
	return 0;
}

static inline enum rtpe_stat rtpe_get_stat_by_name(const str *name)
{
	enum rtpe_stat s;
	for (s = 0; s < STAT_UNKNOWN; s++) {
		if (str_strcasecmp(&stat_maps[s], name) == 0)
			return s;
	}
	return STAT_UNKNOWN;
}

static inline enum rtpe_stat_type rtpe_get_stat_by_type(enum rtpe_stat s)
{
	enum rtpe_stat_type t;
	switch (s) {
		case STAT_MOS_AVERAGE:
		case STAT_JITTER_AVERAGE:
		case STAT_ROUNDTRIP_AVERAGE:
		case STAT_PACKETLOSS_AVERAGE:
			t = STAT_AVERAGE;
			break;

		case STAT_MOS_MAX:
		case STAT_JITTER_MAX:
		case STAT_ROUNDTRIP_MAX:
		case STAT_PACKETLOSS_MAX:
			t = STAT_MAX;
			break;

		case STAT_MOS_MAX_AT:
		case STAT_JITTER_MAX_AT:
		case STAT_ROUNDTRIP_MAX_AT:
		case STAT_PACKETLOSS_MAX_AT:
			t = STAT_MAX_AT;
			break;

		case STAT_MOS_MIN:
		case STAT_JITTER_MIN:
		case STAT_ROUNDTRIP_MIN:
		case STAT_PACKETLOSS_MIN:
			t = STAT_MIN;
			break;

		case STAT_MOS_MIN_AT:
		case STAT_JITTER_MIN_AT:
		case STAT_ROUNDTRIP_MIN_AT:
		case STAT_PACKETLOSS_MIN_AT:
			t = STAT_MIN_AT;
			break;

		default:
			LM_BUG("unknown stat type %d\n", s);
			t = TYPE_UNKNOWN;
	}
	return t;
}

static inline enum rtpe_stat_dict rtpe_get_stat_by_dict(enum rtpe_stat s)
{
	enum rtpe_stat_dict d;
	switch (s) {
		case STAT_MOS_AVERAGE:
		case STAT_MOS_MAX:
		case STAT_MOS_MAX_AT:
		case STAT_MOS_MIN:
		case STAT_MOS_MIN_AT:
			d = STAT_MOS;
			break;

		case STAT_JITTER_AVERAGE:
		case STAT_JITTER_MAX:
		case STAT_JITTER_MAX_AT:
		case STAT_JITTER_MIN:
		case STAT_JITTER_MIN_AT:
			d = STAT_JITTER;
			break;

		case STAT_ROUNDTRIP_AVERAGE:
		case STAT_ROUNDTRIP_MAX:
		case STAT_ROUNDTRIP_MAX_AT:
		case STAT_ROUNDTRIP_MIN:
		case STAT_ROUNDTRIP_MIN_AT:
			d = STAT_ROUNDTRIP;
			break;

		case STAT_PACKETLOSS_AVERAGE:
		case STAT_PACKETLOSS_MAX:
		case STAT_PACKETLOSS_MAX_AT:
		case STAT_PACKETLOSS_MIN:
		case STAT_PACKETLOSS_MIN_AT:
			d = STAT_PACKETLOSS;
			break;

		default:
			LM_BUG("unknown stat dictionary %d\n", s);
			d = TYPE_UNKNOWN;
	}
	return d;
}

#define PVE_NAME_NONE		0
#define PVE_NAME_INTSTR		1
#define PVE_NAME_PVAR		2

static int pv_parse_rtpstat(pv_spec_p sp, const str *in)
{
	enum rtpe_stat s;
	pv_elem_t *format;
	if (!in || in->s == NULL || in->len == 0 || sp == NULL)
		return -1;

	LM_DBG("RTP stat name %p with name <%.*s>\n", &sp->pvp.pvn, in->len, in->s);
	if (pv_parse_format(in, &format)!=0) {
		LM_ERR("failed to parse statistic name format <%.*s> \n",
			in->len,in->s);
		return -1;
	}
	if (format->next==NULL && format->spec.type==PVT_NONE) {
		s = rtpe_get_stat_by_name(in);
		if (s == STAT_UNKNOWN) {
			LM_ERR("Unknown RTP statistic %.*s\n", in->len, in->s);
			return -1;
		}
		sp->pvp.pvn.type = PVE_NAME_INTSTR;
		sp->pvp.pvn.u.isname.type = 0;
		sp->pvp.pvn.u.isname.name.n = s;
	} else {
		sp->pvp.pvn.type = PVE_NAME_PVAR;
		sp->pvp.pvn.u.isname.type = 0;
		sp->pvp.pvn.u.isname.name.s.s = (char*)(void*)format;
		sp->pvp.pvn.u.isname.name.s.len = 0;
	}
	return 0;
}

static int pv_rtpengine_index(pv_spec_p sp, const str *in)
{
	pv_elem_t *format;
	if (!in || in->s == NULL || in->len == 0 || sp == NULL)
		return -1;

	LM_DBG("index %p with name <%.*s>\n", &sp->pvp.pvi, in->len, in->s);
	if (pv_parse_format(in, &format)!=0) {
		LM_ERR("failed to parse statistic name format <%.*s> \n",
			in->len,in->s);
		return -1;
	}
	if (format->next==NULL && format->spec.type==PVT_NONE) {
		sp->pvp.pvi.type = PVE_NAME_INTSTR;
		sp->pvp.pvi.u.dval = pkg_malloc(sizeof(str));
		if (!sp->pvp.pvi.u.dval) {
			LM_ERR("no more pkg for index!\n");
			return -1;
		}
		*(str *)(sp->pvp.pvi.u.dval) = *in;
	} else {
		sp->pvp.pvi.type = PVE_NAME_PVAR;
		sp->pvp.pvi.u.dval = (char*)(void*)format;
	}
	return 0;
}

static const pv_export_t mod_pvs[] = {
	{str_const_init("rtpstat"), /* RTP-Statistics */
		1000, pv_get_rtpstat_f, 0, pv_parse_rtpstat,
		pv_rtpengine_index, pv_rtpengine_stats_used, 0},
	{str_const_init("rtpquery"),
		1000, pv_get_rtpquery_f, 0, 0, 0, pv_rtpengine_stats_used, 0},
	{{0, 0}, 0, 0, 0, 0, 0, 0, 0}
};

static const param_export_t params[] = {
	{"rtpengine_sock",         STR_PARAM|USE_FUNC_PARAM,
				 (void*)rtpengine_set_store          },
	{"rtpengine_disable_tout", INT_PARAM, &rtpengine_disable_tout },
	{"rtpengine_retr",         INT_PARAM, &rtpengine_retr         },
	{"rtpengine_tout",         INT_PARAM, &rtpengine_tout         },
	{"rtpengine_timer_interval", INT_PARAM, &rtpengine_timer_interval},
	{"extra_id_pv",            STR_PARAM, &extra_id_pv_param.s },
	{"setid_avp",              STR_PARAM, &setid_avp_param },
	{"error_pv",               STR_PARAM, &err_pv_param },
	{"db_url",                 STR_PARAM, &db_url.s               },
	{"db_table",               STR_PARAM, &db_table.s             },
	{"socket_column",          STR_PARAM, &db_rtpe_sock_col.s        },
	{"set_column",             STR_PARAM, &db_rtpe_set_col.s         },
	{"extra_failover_error",   STR_PARAM|USE_FUNC_PARAM,
									(void *)rtpengine_extra_failover},
	{"notification_sock",      STR_PARAM|USE_FUNC_PARAM,
									(void *)rtpengine_set_notify},
	{"ping_enabled",           INT_PARAM, &rtpengine_ping_enabled    },
	{0, 0, 0}
};

static const mi_export_t mi_cmds[] = {
	{ MI_ENABLE_RTP_ENGINE, 0, 0, 0, {
		{mi_enable_rtpengine, {"url", "enable", 0}},
		{mi_enable_rtpengine, {"url", "enable", "setid", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_SHOW_RTP_ENGINES, 0, 0, 0, {
		{mi_show_rtpengines, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_RELOAD_RTP_ENGINES, 0, 0, 0, {
		{mi_reload_rtpengines, {0}},
		{mi_reload_rtpengines, {"type", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "teardown", 0, 0, 0, {
		{mi_teardown_call, {"callid", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_SILENT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_SILENT },
		{ MOD_TYPE_DEFAULT, "rtp_relay", DEP_SILENT|DEP_REVERSE },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

static const proc_export_t procs[] = {
	{"RTPEngine notification receiver",  0,  0, rtpengine_notify_process, 1,
		PROC_FLAG_INITCHILD|PROC_FLAG_HAS_IPC|PROC_FLAG_NEEDS_SCRIPT},
	{0,0,0,0,0,0}
};


struct module_exports exports = {
	"rtpengine",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	acmds,
	params,
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	mod_pvs,     /* exported pseudo-variables */
	0,			 /* exported transformations */
	0,			 /* extra processes */
	mod_preinit,
	mod_init,
	0,           /* reply processing */
	mod_destroy, /* destroy function */
	child_init,
	0            /* reload confirm function */
};

static char *rtpe_default_failover_errors[] = {
	"Parallel session limit reached",
	"Ran out of ports",
	"CPU usage limit exceeded",
	"Load limit exceeded",
	"Bandwidth limit exceeded",
};

static void rtpe_stats_free(struct rtpe_stats *stats)
{
	if (stats->json.s)
		cJSON_PurgeString(stats->json.s);
	bencode_buffer_free(&stats->buf);
}

static void rtpe_ctx_free(void *param)
{
	struct rtpe_ctx *ctx = (struct rtpe_ctx *)param;
	if (ctx) {
		if (ctx->stats) {
			rtpe_stats_free(ctx->stats);
			pkg_free(ctx->stats);
		}
		pkg_free(ctx);
	}
}

static inline struct rtpe_ctx *rtpe_ctx_get(void)
{
	struct rtpe_ctx *ctx = rtpe_ctx_tryget();
	if (!ctx) {
		if (!current_processing_ctx) {
			LM_ERR("no processing ctx found - cannot use rtpengine context!\n");
			return NULL;
		}
		ctx = pkg_malloc(sizeof(*ctx));
		if (!ctx) {
			LM_ERR("not enough pkg memory!\n");
			return NULL;
		}
		memset(ctx, 0, sizeof(*ctx));
		rtpe_ctx_set(ctx);
	}
	return ctx;
}

static inline void rtpe_ctx_set_fill(struct rtpe_set *set)
{
	struct rtpe_ctx *ctx = rtpe_ctx_get();
	if (ctx)
		ctx->set = set;
}

static inline struct rtpe_set *rtpe_ctx_set_get(void)
{
	struct rtpe_ctx *ctx = rtpe_ctx_tryget();
	return ctx ? ctx->set: NULL;
}

static inline int str_eq(const str *p, const char *q) {
	int l = strlen(q);
	if (p->len != l)
		return 0;
	if (memcmp(p->s, q, l))
		return 0;
	return 1;
}


static int rtpengine_set_store(modparam_t type, void * val){

	char * p;
	int len;

	p = (char* )val;

	if(p==0 || *p=='\0'){
		return 0;
	}

	if(rtpe_sets==0){
		rtpe_strings = (char**)pkg_malloc(sizeof(char*));
		if(!rtpe_strings){
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	} else {/*realloc to make room for the current set*/
		rtpe_strings = (char**)pkg_realloc(rtpe_strings,
										  (rtpe_sets+1)* sizeof(char*));
		if(!rtpe_strings){
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	}

	/*allocate for the current set of urls*/
	len = strlen(p);
	rtpe_strings[rtpe_sets] = (char*)pkg_malloc((len+1)*sizeof(char));

	if(!rtpe_strings[rtpe_sets]){
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memcpy(rtpe_strings[rtpe_sets], p, len);
	rtpe_strings[rtpe_sets][len] = '\0';
	rtpe_sets++;

	return 0;
}

/*
	frees any versions from list that have been applied by
	all processes
*/
static void cleanup_rtpengine_versions(void)
{
	int i, min_version=0;
	struct rtpe_version *crt_version, *prev_version;

	if (*rtpe_versions == NULL || (*rtpe_versions)->version_count == 0)
		return; // nothing to do

	for (i=0; i<*child_versions_no; i++) {
		if (!min_version || child_versions[i] < min_version)
			min_version = child_versions[i];
	}

	for (crt_version = (*rtpe_versions)->version_first; crt_version != NULL;) {
		if (crt_version->version >= min_version)
			break;
		prev_version = crt_version;
		crt_version = prev_version->version_next;

		/* first version remove */
		if ((*rtpe_versions)->version_first == prev_version)
			(*rtpe_versions)->version_first = crt_version;

		/* last version remove */
		if ((*rtpe_versions)->version_last == prev_version)
			(*rtpe_versions)->version_last = NULL;

		shm_free(prev_version);
		(*rtpe_versions)->version_count--;
	}

	return;
}

/* increments version and adds version to end of list */
static int add_rtpengine_version(int flags)
{
	struct rtpe_version *pversion;

	/* init list of versions */
	if (*rtpe_versions == NULL) {
		*rtpe_versions = shm_malloc(sizeof(struct rtpe_version_head));
		if (*rtpe_versions == NULL) {
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(*rtpe_versions, 0, sizeof(struct rtpe_version_head));
	}

	pversion = shm_malloc(sizeof(struct rtpe_version));
	if (pversion == NULL) {
		LM_ERR("no shm memory left\n");
		return -1;
	}
	memset(pversion, 0, sizeof(*pversion));
	pversion->version = ++(*list_version);
	pversion->version_flags = flags;

	if ((*rtpe_versions)->version_first == NULL) {
		(*rtpe_versions)->version_first = pversion;
	} else {
		(*rtpe_versions)->version_last->version_next = pversion;
	}
	(*rtpe_versions)->version_last = pversion;
	(*rtpe_versions)->version_count++;

	return 0;
}

static int rtpengine_set_notify(modparam_t type, void * val)
{
	char * p;

	p = (char* )val;

	if(p==0 || *p=='\0'){
		return 0;
	}
	rtpengine_notify_sock.s = p;
	rtpengine_notify_sock.len = strlen(rtpengine_notify_sock.s);
	LM_DBG("starting notification listener on %.*s\n",
			rtpengine_notify_sock.len, rtpengine_notify_sock.s);
	rtpengine_notify_event = evi_publish_event(rtpengine_notify_event_name);
	if (rtpengine_notify_event == EVI_ERROR) {
		LM_ERR("cannot register RTPEngine Notification socket\n");
		return -1;
	}
	exports.procs = procs;
	return 0;
}

static int add_rtpengine_socks(struct rtpe_set * rtpe_list,
										char * rtpengine){
	/* Make rtp proxies list. */
	char *p, *p1, *p2, *plim;
	struct rtpe_node *pnode, *tmpnode;
	int weight;

	p = rtpengine;
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
		pnode = shm_malloc(sizeof(struct rtpe_node));
		if (pnode == NULL) {
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(pnode, 0, sizeof(*pnode));
		pnode->set = rtpe_list->id_set;
		pnode->rn_recheck_ticks = 0;
		pnode->rn_weight = weight;
		pnode->rn_umode = 0;
		pnode->rn_disabled = 0;
		pnode->rn_flags = 0;
		pnode->rn_url.s = shm_malloc(p2 - p1 + 1);
		if (pnode->rn_url.s == NULL) {
			shm_free(pnode);
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memmove(pnode->rn_url.s, p1, p2 - p1);
		pnode->rn_url.s[p2 - p1]	= 0;
		pnode->rn_url.len			= p2-p1;

		LM_DBG("url is %s, len is %i\n", pnode->rn_url.s, pnode->rn_url.len);

		if ((tmpnode = lookup_rtpe_node(rtpe_list, &pnode->rn_url)) != NULL) {
			LM_DBG("node with url %s already exists in set %d, not adding new node\n", pnode->rn_url.s, rtpe_list->id_set);
			tmpnode->rn_flags &= ~RTPE_TEARDOWN_NODE;
			shm_free(pnode->rn_url.s);
			shm_free(pnode);
			return 0;
		}

		/* incr index once we've determined this is a new node */
		pnode->idx = (*rtpe_no)++;

		/* Leave only address in rn_address */
		pnode->rn_address = pnode->rn_url.s;
		if (strncasecmp(pnode->rn_address, "udp:", 4) == 0) {
			pnode->rn_umode = 1;
			pnode->rn_address += 4;
			if (pnode->rn_address[0] == '[') /* it is actually an ipv6 url */
				pnode->rn_umode = 6;
		} else if (strncasecmp(pnode->rn_address, "udp6:", 5) == 0) {
			pnode->rn_umode = 6;
			pnode->rn_address += 5;
		} else if (strncasecmp(pnode->rn_address, "unix:", 5) == 0) {
			pnode->rn_umode = 0;
			pnode->rn_address += 5;
		}

		if (rtpe_list->rn_first == NULL) {
			rtpe_list->rn_first = pnode;
		} else {
			rtpe_list->rn_last->rn_next = pnode;
		}

		rtpe_list->rn_last = pnode;
		rtpe_list->rtpe_node_count++;
	}
	return 0;
}


/*	0-succes
 *  -1 - erorr
 * */
static int rtpengine_add_rtpengine_set( char * rtp_proxies, int set_id)
{
	char *p,*p2;
	struct rtpe_set * rtpe_list;
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

	if (set_id < 0) {
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
			my_current_id = DEFAULT_RTPE_SET_ID;
		}
	} else {
		rtp_proxies = p;
		my_current_id = set_id;
	}

	for(;*rtp_proxies && isspace(*rtp_proxies);rtp_proxies++);

	if(!(*rtp_proxies)){
		LM_ERR("script error -empty rtpengine list\n");
		return -1;;
	}

	/*search for the current_id*/
	rtpe_list = (*rtpe_set_list) ? (*rtpe_set_list)->rset_first : 0;
	while( rtpe_list != 0 && rtpe_list->id_set!=my_current_id)
		rtpe_list = rtpe_list->rset_next;

	if(rtpe_list==NULL){	/*if a new id_set : add a new set of rtpe*/
		rtpe_list = shm_malloc(sizeof(struct rtpe_set));
		if(!rtpe_list){
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(rtpe_list, 0, sizeof(struct rtpe_set));
		rtpe_list->id_set = my_current_id;
		new_list = 1;
	} else {
		new_list = 0;
	}

	rtpe_list->set_flags &= ~RTPE_TEARDOWN_SET;

	if(add_rtpengine_socks(rtpe_list, rtp_proxies)!= 0){
		/*if this list will not be inserted, clean it up*/
		goto error;
	}

	if (new_list) {
		if(!(*rtpe_set_list)){/*initialize the list of set*/
			*rtpe_set_list = shm_malloc(sizeof(struct rtpe_set_head));
			if(!(*rtpe_set_list)){
				LM_ERR("no shm memory left\n");
				return -1;
			}
			memset(*rtpe_set_list, 0, sizeof(struct rtpe_set_head));
		}

		/*update the list of set info*/
		if(!(*rtpe_set_list)->rset_first){
			(*rtpe_set_list)->rset_first = rtpe_list;
		}else{
			(*rtpe_set_list)->rset_last->rset_next = rtpe_list;
		}

		(*rtpe_set_list)->rset_last = rtpe_list;
	}

	return 0;
error:
	return -1;
}


static int fixup_set_id(void ** param)
{
	struct rtpe_set* rtpe_list;
	rtpe_set_link_t *rtpl = NULL;

	rtpl = (rtpe_set_link_t*)pkg_malloc(sizeof(rtpe_set_link_t));
	if(rtpl==NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(rtpl, 0, sizeof(rtpe_set_link_t));

	if((rtpe_list = select_rtpe_set(*(int*)*param)) ==0){
		rtpl->type = RTPE_SET_NONE;
		rtpl->v.id = *(int*)*param;
	} else {
		rtpl->type = RTPE_SET_FIXED;
		rtpl->v.rset = rtpe_list;
	}

	*param = (void*)rtpl;
	return 0;
}

static int fixup_free_set_id(void **param)
{
	pkg_free(*param);
	return 0;
}

static mi_response_t *mi_enable_rtpengine(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str rtpe_url;
	int enable, set;
	struct rtpe_set * rtpe_list;
	struct rtpe_node * crt_rtpe;
	int found, disabled, prev_disabled, recheck_ticks;

	found = 0;

	if(*rtpe_set_list ==NULL)
		goto end;

	if (get_mi_string_param(params, "url", &rtpe_url.s, &rtpe_url.len) < 0)
		return init_mi_param_error();
	if(rtpe_url.s == NULL || rtpe_url.len ==0)
		return init_mi_error(400, MI_SSTR("Empty url"));

	if (get_mi_int_param(params, "enable", &enable) < 0)
		return init_mi_param_error();
	if (try_get_mi_int_param(params, "setid", &set) < 0)
		set = -1;

	RTPE_START_READ();
	for(rtpe_list = (*rtpe_set_list)->rset_first; rtpe_list != NULL;
					rtpe_list = rtpe_list->rset_next){

    if (set !=-1 && set != rtpe_list->id_set)
      continue;

		for(crt_rtpe = rtpe_list->rn_first; crt_rtpe != NULL;
						crt_rtpe = crt_rtpe->rn_next){
			/*found a matching rtpe*/

			if(crt_rtpe->rn_url.len == rtpe_url.len){

				if(strncmp(crt_rtpe->rn_url.s, rtpe_url.s, rtpe_url.len) == 0){
					/*set the enabled/disabled status*/
					found = 1;
					prev_disabled = crt_rtpe->rn_disabled;
					switch (enable) {
						case 0: /* disable */
							recheck_ticks = MI_MAX_RECHECK_TICKS;
							disabled = 1;
							break;
						case 2: /* pending */
							recheck_ticks = get_ticks() + rtpengine_disable_tout;
							disabled = 1;
							break;
						default: /* enable */
							recheck_ticks = MI_MIN_RECHECK_TICKS;
							disabled = 0;
							break;
					}
					crt_rtpe->rn_disabled = disabled;
					crt_rtpe->rn_recheck_ticks = recheck_ticks;
					if (prev_disabled != crt_rtpe->rn_disabled)
						raise_rtpengine_status_event(crt_rtpe);
				}
			}
		}
	}
	RTPE_STOP_READ();

end:
	if(found)
		return init_mi_result_ok();
	return init_mi_error(404,MI_RTP_ENGINE_NOT_FOUND,MI_RTP_ENGINE_NOT_FOUND_LEN);
}


static mi_response_t *mi_show_rtpengines(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *sets_arr, *set_item, *nodes_arr, *node_item;
	struct rtpe_set * rtpe_list;
	struct rtpe_node * crt_rtpe;

	resp = init_mi_result_array(&sets_arr);
	if (!resp)
		return 0;

	if(*rtpe_set_list ==NULL)
		return resp;

	RTPE_START_READ();
	for(rtpe_list = (*rtpe_set_list)->rset_first; rtpe_list != NULL;
					rtpe_list = rtpe_list->rset_next){

		set_item = add_mi_object(sets_arr, NULL, 0);
		if (!set_item)
			goto error;

		if (add_mi_number(set_item, MI_SET, MI_SET_LEN, rtpe_list->id_set) < 0)
			goto error;

		nodes_arr = add_mi_array(set_item, MI_SSTR("Nodes"));
		if (!nodes_arr)
			goto error;

		for(crt_rtpe = rtpe_list->rn_first; crt_rtpe != NULL;
						crt_rtpe = crt_rtpe->rn_next){

			node_item = add_mi_object(nodes_arr, NULL, 0);
			if (!node_item)
				goto error;

			if (add_mi_string(node_item, MI_SSTR("url"),
				crt_rtpe->rn_url.s, crt_rtpe->rn_url.len) < 0)
				goto error;

			if (add_mi_number(node_item, MI_INDEX, MI_INDEX_LEN,
				crt_rtpe->idx) < 0)
				goto error;
			if (add_mi_number(node_item, MI_DISABLED, MI_DISABLED_LEN,
				crt_rtpe->rn_disabled) < 0)
				goto error;
			if (add_mi_number(node_item, MI_WEIGHT, MI_WEIGHT_LEN,
				crt_rtpe->rn_weight) < 0)
				goto error;
			if (add_mi_number(node_item, MI_RECHECK_TICKS, MI_RECHECK_T_LEN,
				crt_rtpe->rn_recheck_ticks) < 0)
				goto error;
		}
	}
	RTPE_STOP_READ();

	return resp;
error:
	RTPE_STOP_READ();
	if (resp)
		free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_reload_rtpengines(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str type;
	int soft_reload = 0;
	struct rtpe_set *crt_list, *next_list;
	struct rtpe_node *crt_rtpe, *next_rtpe;

	if(db_url.s == NULL) {
		LM_ERR("Dynamic loading of rtpengines not enabled\n");
		return init_mi_error(400, MI_SSTR("Dynamic loading not enabled"));
	}

	if (try_get_mi_string_param(params, "type", &type.s, &type.len) == 0) {
		if (!str_strcmp(&type, _str("soft")))
			soft_reload = 1;
	}

	lock_start_write(rtpe_lock);

	if (soft_reload) {
		/*
			soft reload:
			- mark all nodes/sets for teardown; as nodes are added
			  from the database, this flag is cleared and sockets
			  will be reused
		*/
		if (*rtpe_set_list) {
			for(crt_list = (*rtpe_set_list)->rset_first; crt_list != NULL;
							crt_list = crt_list->rset_next){
				crt_list->set_flags |= RTPE_TEARDOWN_SET;
				for(crt_rtpe = crt_list->rn_first; crt_rtpe != NULL;
								crt_rtpe = crt_rtpe->rn_next)
					crt_rtpe->rn_flags |= RTPE_TEARDOWN_NODE;
			}
		}

		if(_add_rtpengine_from_database() < 0)
			goto error;

		/* remove old sets/nodes */
		for(crt_list = (*rtpe_set_list)->rset_first; crt_list != NULL; ){
			if (crt_list->set_flags&RTPE_TEARDOWN_SET) {
				next_list = crt_list->rset_next;
				free_rtpe_set(crt_list->id_set);
				crt_list = next_list;
				continue;
			}
			for(crt_rtpe = crt_list->rn_first; crt_rtpe != NULL; ){
				if (crt_rtpe->rn_flags&RTPE_TEARDOWN_NODE) {
					next_rtpe = crt_rtpe->rn_next;
					free_rtpe_node(crt_list, &crt_rtpe->rn_url);
					crt_rtpe = next_rtpe;
					continue;
				}
				crt_rtpe = crt_rtpe->rn_next;
			}
			crt_list = crt_list->rset_next;
		}
	} else {
		/*
			hard reload:
			- teardown all nodes and establish fresh connections
		*/
		if(*rtpe_set_list) {
			for (crt_list = (*rtpe_set_list)->rset_first; crt_list != NULL;
						crt_list = crt_list->rset_next)
				free_rtpe_nodes(crt_list);
		}
		*rtpe_no = 0;

		if(_add_rtpengine_from_database() < 0)
			goto error;
	}

	/* update pointer to default_rtpp_set*/
	*default_rtpe_set = select_rtpe_set(DEFAULT_RTPE_SET_ID);
	if (*default_rtpe_set == NULL)
		LM_WARN("there is no rtpengine in the default set %d\n",
				DEFAULT_RTPE_SET_ID);

	/* update version history */
	cleanup_rtpengine_versions();
	if (add_rtpengine_version(soft_reload ? 0 : RTPE_TEARDOWN_SOCKETS) < 0)
		goto error;

	/* release the readers */
	lock_stop_write(rtpe_lock);

	/*
		set has been updated so we can connect to nodes
		with read lock only like SIP procs; this will test node
		outside of SIP context
	*/
	RTPE_START_READ();
	if (update_rtpengines(1)) {
		RTPE_STOP_READ();
		return init_mi_error(500, MI_SSTR("Internal error"));
	}
	RTPE_STOP_READ();

	return init_mi_result_ok();
error:
	lock_stop_write(rtpe_lock);
	return init_mi_error(500, MI_SSTR("Internal error"));
}

static mi_response_t *mi_teardown_call(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str callid, *pcallid = NULL;
	unsigned int h_entry = 0, h_id = 0;

	if (dlgb.terminate_dlg == NULL)
		return init_mi_error(500, MI_SSTR("Dialog module not loaded"));

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();
	if(callid.s == NULL || callid.len ==0)
		return init_mi_error(400, MI_SSTR("Empty callid"));

	/* try to "resolve" the callid first through rtp_relay */
	if (!rtp_relay.get_dlg_ids || rtp_relay.get_dlg_ids(&callid, &h_entry, &h_id) == 0)
		pcallid = &callid; /* search for callid, if dialog was not found */
	if (dlgb.terminate_dlg(pcallid, h_entry, h_id, _str("MI Termination")) < 0)
		return init_mi_error(500, MI_SSTR("Failed to terminate dialog"));

	return init_mi_result_ok();
}

/*
 * Timer housekeeping, invoked each timer interval to check for proxy re-enablement
 */
void rtpengine_timer(unsigned int ticks, void *param)
{
  int disabled;
  struct rtpe_set *rtpe_list;
  struct rtpe_node *crt_rtpe;

  if (*rtpe_set_list == NULL)
    return;

  RTPE_START_READ();
	if (my_version != *list_version && update_rtpengines(0) < 0) {
		LM_ERR("cannot update rtpengines list\n");
		RTPE_STOP_READ();
		return;
	}
  for(rtpe_list = (*rtpe_set_list)->rset_first; rtpe_list != NULL;
					rtpe_list = rtpe_list->rset_next){
		for(crt_rtpe = rtpe_list->rn_first; crt_rtpe != NULL;
						crt_rtpe = crt_rtpe->rn_next){
      if ((crt_rtpe->rn_disabled && crt_rtpe->rn_recheck_ticks <= get_ticks()) ||
		  (rtpengine_ping_enabled && !crt_rtpe->rn_disabled &&
		   crt_rtpe->rn_last_ticks + rtpengine_timer_interval <= get_ticks())) {
		disabled = crt_rtpe->rn_disabled;
        crt_rtpe->rn_disabled = rtpe_test(crt_rtpe, disabled, 1);
		if (crt_rtpe->rn_disabled != disabled)
			raise_rtpengine_status_event(crt_rtpe);
	  }
    }
  }
  RTPE_STOP_READ();
}

/* hack to get the rtpengine node used for the offer */
static pv_spec_t media_pvar;

static int mod_preinit(void)
{
	static str rtpengine_relay_pvar_str = str_init("$var(___rtpengine_relay_var__)");
	struct rtp_relay_funcs binds = {
		.offer = rtpengine_api_offer,
		.answer = rtpengine_api_answer,
		.delete = rtpengine_api_delete,
		.copy_offer = rtpengine_api_copy_offer,
		.copy_answer = rtpengine_api_copy_answer,
		.copy_delete = rtpengine_api_copy_delete,
		.copy_serialize = rtpengine_api_copy_serialize,
		.copy_deserialize = rtpengine_api_copy_deserialize,
		.copy_release = rtpengine_api_copy_release,
	};
	if (!pv_parse_spec(&rtpengine_relay_pvar_str, &media_pvar))
		return -1;
	register_rtp_relay("rtpengine", &binds, &rtp_relay);
	return 0;
}

static int
mod_init(void)
{
	int i;
	pv_spec_t avp_spec;
	unsigned short avp_flags;
	str s;
	int count = count_child_processes();

	rtpe_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, rtpe_ctx_free);

	rtpe_no = (unsigned int*)shm_malloc(sizeof(unsigned int));
	list_version = (unsigned int*)shm_malloc(sizeof(unsigned int));
	child_versions=(unsigned int*)shm_malloc(count * sizeof(unsigned int));
	child_versions_no = (unsigned int*)shm_malloc(sizeof(unsigned int));
	rtpe_versions = (struct rtpe_version_head **)shm_malloc(sizeof(struct rtpe_version_head *));

	if(!rtpe_no || !list_version || !child_versions || !child_versions_no || !rtpe_versions) {
		LM_ERR("No more shared memory\n");
		return -1;
	}

	*rtpe_no = 0;
	*list_version = 0;
	*child_versions_no = count;
	*rtpe_versions = 0;
	my_version = 0;

	memset(child_versions, 0, *child_versions_no * sizeof(unsigned int));

	if (!(rtpe_set_list = (struct rtpe_set_head **)
		shm_malloc(sizeof(struct rtpe_set_head *)))) {
		LM_ERR("no more shm mem\n");
		return -1;
	}
	*rtpe_set_list = 0;

	rtpengine_status_event = evi_publish_event(rtpengine_status_event_name);
	if (rtpengine_status_event == EVI_ERROR) {
		LM_ERR("cannot register RTPEngine Status event\n");
		return -1;
	}

	rtpengine_status_event_params = pkg_malloc(sizeof(evi_params_t));
	if (rtpengine_status_event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(rtpengine_status_event_params, 0, sizeof(evi_params_t));
	if ((rtpengine_status_event_socket = evi_param_create(rtpengine_status_event_params,
				&rtpengine_status_event_socket_s)) == NULL) {
		LM_ERR("could not create RTPEngine Status socket param\n");
		return -1;
	}
	if ((rtpengine_status_event_status = evi_param_create(rtpengine_status_event_params,
				&rtpengine_status_event_status_s)) == NULL) {
		LM_ERR("could not create RTPEngine Status status param\n");
		return -1;
	}
	if ((rtpengine_status_event_set = evi_param_create(rtpengine_status_event_params,
				&rtpengine_status_event_set_s)) == NULL) {
		LM_ERR("could not create RTPEngine Status set param\n");
		return -1;
	}

	if(db_url.s == NULL) {
		/* storing the list of rtp proxy sets in shared memory*/
		for(i=0;i<rtpe_sets;i++){
			if(rtpengine_add_rtpengine_set(rtpe_strings[i], -1) !=0){
				for(;i<rtpe_sets;i++)
					if(rtpe_strings[i])
						pkg_free(rtpe_strings[i]);
				pkg_free(rtpe_strings);
				return -1;
			}
			if(rtpe_strings[i])
				pkg_free(rtpe_strings[i]);
		}
	} else {
		db_url.len = strlen(db_url.s);
		db_table.len = strlen(db_table.s);
		db_rtpe_sock_col.len = strlen(db_rtpe_sock_col.s);
		db_rtpe_set_col.len = strlen(db_rtpe_set_col.s);

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
		if(db_check_table_version(&db_functions, db_connection, &db_table,
					RTPENGINE_TABLE_VERSION) < 0){
				LM_ERR("error during table version check\n");
				return -1;
		}

		if(_add_rtpengine_from_database() != 0) {
			return -1;
		}

		db_functions.close(db_connection);
		db_connection = NULL;
		if ((rtpe_lock = lock_init_rw()) == NULL) {
			LM_CRIT("failed to init lock\n");
			return -1;
		}
	}

	if (extra_id_pv_param.s && *extra_id_pv_param.s) {
		extra_id_pv_param.len = strlen(extra_id_pv_param.s);
		if(pv_parse_format(&extra_id_pv_param, &extra_id_pv) < 0) {
			LM_ERR("malformed PV string: %s\n", extra_id_pv_param.s);
			return -1;
		}
	} else {
		extra_id_pv = NULL;
	}

	if (setid_avp_param) {
		s.s = setid_avp_param; s.len = strlen(s.s);
		pv_parse_spec(&s, &avp_spec);
		if (avp_spec.type != PVT_AVP) {
			LM_ERR("malformed or non AVP definition <%s>\n",
					setid_avp_param);
			return -1;
		}
		if (pv_get_avp_name(0, &(avp_spec.pvp), &(setid_avp.n),
					&avp_flags) != 0) {
			LM_ERR("invalid AVP definition <%s>\n", setid_avp_param);
			return -1;
		}
		setid_avp_type = avp_flags;
	}

	if (err_pv_param) {
		init_str(&s, err_pv_param);
		if (pv_parse_spec(&s, &err_pv) < 0) {
			LM_ERR("malformed return variable definition <%s>\n",
					err_pv_param);
			return -1;
		}
	}

	if (rtpe_strings)
		pkg_free(rtpe_strings);

	default_rtpe_set = (struct rtpe_set**)shm_malloc(sizeof(struct rtpe_set*));
	if(default_rtpe_set == NULL) {
		LM_ERR("No more shared memory\n");
		return -1;
	}
	*default_rtpe_set = NULL;

	/* any rtpengine configured? */
	if(rtpe_set_list && *rtpe_set_list) {
		*default_rtpe_set = select_rtpe_set(DEFAULT_RTPE_SET_ID);
		if (*default_rtpe_set == NULL)
			LM_WARN("there is no rtpengine engine in the default set %d!"
					"if you are not specifying sets in your rtpproxy_*()"
					"commands, rtpproxy will not be used!\n",
					DEFAULT_RTPE_SET_ID);
	}


	if (load_tm_api( &tmb ) < 0)
	{
		LM_DBG("could not load the TM-functions - answer-offer model"
				" auto-detection is disabled\n");
		memset(&tmb, 0, sizeof(struct tm_binds));
	}

	if (load_dlg_api( &dlgb ) < 0)
	{
		LM_DBG("could not load the Dialog functions - 'teardown' MI"
				" command will not work\n");
		memset(&dlgb, 0, sizeof(struct dlg_binds));
	}

  if (register_timer("rtpengine-timer", rtpengine_timer, NULL, rtpengine_timer_interval, TIMER_FLAG_DELAY_ON_DELAY) <0 ) {
    LM_ERR("could not register timer function\n");
    return -1;
  }

	return 0;
}

static inline int rtpengine_connect_node(struct rtpe_node *pnode)
{
	int n;
	char *cp, *start, *end;
	char *hostname;
	struct addrinfo hints, *res;

	if (pnode->rn_umode == 0) {
		rtpe_socks[pnode->idx] = -1;
		return 1;
	}

	start = pnode->rn_address;

	cp = strrchr(pnode->rn_address, ':');
	if (cp == NULL) {
		/* no explicit port, use the default one */
		cp = CPORT;
		end = start + strlen(pnode->rn_address);
	} else {
		end = cp++;
		if (pnode->rn_umode == 6) {
			/* if IPv6 mode, port should be right after ] */
			if (end > start && *(end - 1) != ']') {
				/* if it is not, then it is part of the address */
				cp = CPORT;
				end = start + strlen(pnode->rn_address);
			}
		}
	}
	if (pnode->rn_umode == 6 && *start == '[') {
		start++;
		if (end > start && *(end - 1) == ']')
			end--;
	}

	hostname = (char*)pkg_malloc(end - start + 1);
	if (hostname==NULL) {
		LM_ERR("no more pkg memory\n");
		return 0;
	}
	memcpy(hostname, start, end - start);
	hostname[end-start] = '\0';

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = 0;
	hints.ai_family = (pnode->rn_umode == 6) ? AF_INET6 : AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if ((n = getaddrinfo(hostname, cp, &hints, &res)) != 0) {
		LM_ERR("%s\n", gai_strerror(n));
		pkg_free(hostname);
		return 0;
	}
	pkg_free(hostname);

	rtpe_socks[pnode->idx] = socket((pnode->rn_umode == 6)
			? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if ( rtpe_socks[pnode->idx] == -1) {
		LM_ERR("can't create socket\n");
		freeaddrinfo(res);
		return 0;
	}

	if (connect(rtpe_socks[pnode->idx], res->ai_addr, res->ai_addrlen) == -1) {
		LM_ERR("can't connect to a RTP proxy\n");
		close( rtpe_socks[pnode->idx] );
		rtpe_socks[pnode->idx] = -1;
		freeaddrinfo(res);
		return 0;
	}

	pnode->ai_addrlen = res->ai_addrlen;
	memcpy(&(pnode->ai_addr), res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);
	return 1;
}

static int connect_rtpengines(int force_test)
{
	int i;
	struct rtpe_set  *rtpe_list;
	struct rtpe_node *pnode;

	LM_DBG("[RTPEngine] set list %p\n", *rtpe_set_list);
	if(!(*rtpe_set_list) )
		return 0;
	LM_DBG("[Re]connecting sockets (%d > %d)\n", *rtpe_no, rtpe_number);

	if (*rtpe_no > rtpe_number) {
		rtpe_socks = (int*)pkg_realloc(rtpe_socks, *rtpe_no * sizeof(int));
		if (rtpe_socks==NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		for (i=rtpe_number; i<*rtpe_no; i++)
			rtpe_socks[i] = -1; /* init new elems */
	}
	rtpe_number = *rtpe_no;

	for(rtpe_list = (*rtpe_set_list)->rset_first; rtpe_list != 0;
		rtpe_list = rtpe_list->rset_next){

		for (pnode=rtpe_list->rn_first; pnode!=0; pnode = pnode->rn_next){
			/* reuse socket if already initialized */
			if ((rtpe_socks[pnode->idx] != -1 || rtpengine_connect_node(pnode)) && force_test)
				pnode->rn_disabled = rtpe_test(pnode, 0, 1);
			/* else, there is an error, and we try to connect the next one */
		}
	}

	LM_DBG("successfully updated rtpengine sets\n");
	return 0;
}

static int child_init(int rank)
{
	int ret;
	mypid = getpid();
	myrand = rand()%10000;
	myrank = rank;

	/* external procs are assigned to head of version array */
	if (rank == PROC_MODULE)
		myrank = 0;

	if (db_url.s) {
		if (!db_functions.init) {
			LM_CRIT("database not bound\n");
			return -1;
		}

		db_connection = db_functions.init(&db_url);
		if (!db_connection) {
			LM_ERR("Failed to connect to database\n");
			return -1;
		}

		LM_DBG("Database connection opened successfully\n");
	}

	/* Iterate known RTP proxies - create sockets */
	RTPE_START_READ();
	ret = connect_rtpengines(1);
	RTPE_STOP_READ();
	return ret;
}

static int update_rtpengines(int force_test)
{
	int *tmp_socks;
	int i, reset=0;
	struct rtpe_set * crt_list;
	struct rtpe_node * crt_rtpe;
	struct rtpe_version * crt_version;

	LM_DBG("updating list from %d to %d [%d]\n", my_version, *list_version, rtpe_number);

	if (*rtpe_versions==NULL || (*rtpe_versions)->version_last==NULL
			|| my_version == (*rtpe_versions)->version_last->version)
		return 0; /* nothing to do or already updated */

	for (crt_version = (*rtpe_versions)->version_first; crt_version != NULL;
				crt_version = crt_version->version_next) {
		if (crt_version->version <= my_version)
			continue;
		if (crt_version->version_flags&RTPE_TEARDOWN_SOCKETS)
			reset = 1;
		my_version = crt_version->version;
	}

	if (myrank < *child_versions_no)
		child_versions[myrank] = my_version;
	else
		LM_BUG("rank overflow %d vs %d\n", myrank, *child_versions_no);

	/*
		close all sockets if any versions required
		a hard reload of rtpengine nodes
	*/
	if (reset) {
		for (i = 0; i < rtpe_number; i++)
			disconnect_rtpe_socket(i);
		return connect_rtpengines(force_test);
	}

	/*
		only close sockets that were removed from set(s)
	*/
	tmp_socks = (int*)pkg_malloc(rtpe_number * sizeof(int));
	if (tmp_socks == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memcpy(tmp_socks, rtpe_socks, rtpe_number * sizeof(int));

  for(crt_list = (*rtpe_set_list)->rset_first; crt_list != NULL;
					crt_list = crt_list->rset_next){
		for(crt_rtpe = crt_list->rn_first; crt_rtpe != NULL;
						crt_rtpe = crt_rtpe->rn_next) {
			if (crt_rtpe->idx < rtpe_number)
				tmp_socks[crt_rtpe->idx] = 0; /* mark as active */
		}
  }

	for (i = 0; i < rtpe_number; i++) {
		if (tmp_socks[i])
			disconnect_rtpe_socket(i);
	}

	pkg_free(tmp_socks);

	return connect_rtpengines(force_test);
}

/* Returns the first matching node in set */
static struct rtpe_node *lookup_rtpe_node(struct rtpe_set * rtpe_list, str *rtpe_url)
{
	struct rtpe_node * crt_rtpe;

	if (rtpe_list == NULL)
		return NULL;

	if (rtpe_url->len==0 || !rtpe_url->s)
		return NULL;

	for(crt_rtpe = rtpe_list->rn_first; crt_rtpe != NULL;
					crt_rtpe = crt_rtpe->rn_next){
		if(crt_rtpe->rn_url.len == rtpe_url->len){
			if(strncmp(crt_rtpe->rn_url.s, rtpe_url->s, rtpe_url->len) == 0){
				return crt_rtpe;
			}
		}
	}

	/* No match */
	return NULL;
}

/* finds the node based upon URL and frees it from set */
static void free_rtpe_node(struct rtpe_set *list, str *rtpe_url)
{
	struct rtpe_node *prev_rtpp=NULL, *crt_rtpp;

	for(crt_rtpp=list->rn_first; crt_rtpp!=NULL && str_strcmp(&crt_rtpp->rn_url, rtpe_url);
			crt_rtpp=crt_rtpp->rn_next)
		prev_rtpp = crt_rtpp;

	if (!crt_rtpp) {
		LM_DBG("no matching node %s\n", rtpe_url->s);
		return;
	}

	/* first node matched */
	if (!prev_rtpp) {
		list->rn_first = crt_rtpp->rn_next;
		goto free;
	}

	/* last node matched */
	if (crt_rtpp->rn_next == NULL)
		list->rn_last = prev_rtpp;

	prev_rtpp->rn_next = crt_rtpp->rn_next;

free:
	list->rtpe_node_count--;
	if (crt_rtpp->rn_url.s)
		shm_free(crt_rtpp->rn_url.s);
	shm_free(crt_rtpp);
}

static void free_rtpe_nodes(struct rtpe_set *list)
{
	struct rtpe_node * crt_rtpp, *last_rtpp;

	for(crt_rtpp = list->rn_first; crt_rtpp != NULL;  ){

		if(crt_rtpp->rn_url.s)
			shm_free(crt_rtpp->rn_url.s);

		last_rtpp = crt_rtpp;
		crt_rtpp = last_rtpp->rn_next;
		shm_free(last_rtpp);
	}
	list->rn_first = NULL;
	list->rtpe_node_count = 0;
}

/* finds the set based upon ID and frees it from list */
static void free_rtpe_set(int id_set)
{
	struct rtpe_set *prev_list=NULL, *crt_list;

	for(crt_list=(*rtpe_set_list)->rset_first; crt_list!=NULL && crt_list->id_set!=id_set;
			crt_list=crt_list->rset_next)
		prev_list = crt_list;

	if (!crt_list) {
		LM_DBG("no matching set %d\n", id_set);
		return;
	}

	/* first set matched */
	if (!prev_list) {
		(*rtpe_set_list)->rset_first = crt_list->rset_next;
		goto free;
	}

	/* last set matched */
	if (crt_list->rset_next == NULL)
		(*rtpe_set_list)->rset_last = prev_list;

	prev_list->rset_next = crt_list->rset_next;

free:
		free_rtpe_nodes(crt_list);
		shm_free(crt_list);
}

static void free_rtpe_sets(void)
{
	struct rtpe_set * crt_list, * last_list;

	for(crt_list = (*rtpe_set_list)->rset_first; crt_list != NULL; ){

		free_rtpe_nodes(crt_list);
		last_list = crt_list;
		crt_list = last_list->rset_next;
		shm_free(last_list);
	}
	(*rtpe_set_list)->rset_first = NULL;
	(*rtpe_set_list)->rset_last = NULL;
}

static void disconnect_rtpe_socket(int idx)
{
	LM_DBG("disconnect socket idx=%d\n", idx);

	shutdown(rtpe_socks[idx], SHUT_RDWR);
	close(rtpe_socks[idx]);
	rtpe_socks[idx] = -1;
}

static void mod_destroy(void)
{
	if (default_rtpe_set)
		shm_free(default_rtpe_set);

	if(!rtpe_set_list || *rtpe_set_list == NULL)
		return;

	free_rtpe_sets();
	shm_free(*rtpe_set_list);
	shm_free(rtpe_set_list);

	if (rtpe_lock) {
		lock_destroy_rw(rtpe_lock);
		rtpe_lock = NULL;
	}
}



static char * gencookie(void)
{
	static char cook[34];

	sprintf(cook, "%d_%d_%u ", (int)mypid, myrand, myseqn);
	myseqn++;
	return cook;
}



static const char *transports[] = {
	[0x00]	= "RTP/AVP",
	[0x01]	= "RTP/SAVP",
	[0x02]	= "RTP/AVPF",
	[0x03]	= "RTP/SAVPF",
	[0x04]  = "UDP/TLS/RTP/SAVP",
	[0x05]  = "UDP/TLS/RTP/SAVPF"

};

#define BCHECK(_i) \
	do { \
		if (!(_i)) {\
			err = "cannot add to bson item"; \
			goto error; \
		} \
	} while (0)

#include "rtpengine_bracket.h"

static int parse_flags(struct ng_flags_parse *ng_flags, struct sip_msg *msg,
		enum rtpe_operation *op, const char *flags_str)
{
	char *e;
	const char *err;
	str key, val;
	int delete_delay;
	bencode_item_t *bitem;
	str iniface, outiface;

	if (!flags_str)
		return 0;

	iniface.len = outiface.len = 0;
	iniface.s = outiface.s = NULL;

	while (1) {
		while (*flags_str == ' ')
			flags_str++;

		key.s = (void *) flags_str;
		val.len = key.len = -1;
		val.s = NULL;

		e = strpbrk(key.s, " =");
		if (!e)
			e = key.s + strlen(key.s);
		else if (*e == '=') {
			key.len = e - key.s;
			val.s = e + 1;
			if (*val.s == '[') {
				/* bracket value: scan forward to the matching ']',
				 * tracking nesting depth so inner brackets like
				 * key=[a=[x y] b=[z]] are consumed as a single value */
				int depth = 0;
				for (e = val.s; *e; e++) {
					if (*e == '[') depth++;
					else if (*e == ']' && --depth == 0) { e++; break; }
				}
				if (depth != 0) {
					/* set val.len before error so the error handler
					 * can safely log the partial value with %.*s */
					val.len = e - val.s;
					err = "unmatched bracket in flag value";
					goto error;
				}
			} else {
				/* non-bracket value: terminate at next space */
				e = strchr(val.s, ' ');
				if (!e)
					e = val.s + strlen(val.s);
			}
			/* e now points past the value; compute length */
			val.len = e - val.s;
		}

		if (key.len == -1)
			key.len = e - key.s;
		if (!key.len)
			break;
		flags_str = e;

		err = "unknown error";
		switch (key.len) {
			case 3:
				if (str_eq(&key, "RTP")) {
					ng_flags->transport |= 0x100;
					ng_flags->transport &= ~0x001;
				}
				else if (str_eq(&key, "AVP")) {
					ng_flags->transport |= 0x100;
					ng_flags->transport &= ~0x002;
				} else
					break;
				continue;

			case 4:
				if (str_eq(&key, "SRTP"))
					ng_flags->transport |= 0x101;
				else if (str_eq(&key, "AVPF"))
					ng_flags->transport |= 0x102;
				else
					break;
				continue;

			case 6:
				if (str_eq(&key, "to-tag")) {
					if (val.s)
						ng_flags->to_tag = val;
					ng_flags->to = 1;
				} else if (str_eq(&key, "callid") && val.s)
					ng_flags->call_id = val;
				else
					break;
				continue;

			case 7:
				if (str_eq(&key, "RTP/AVP"))
					ng_flags->transport = 0x100;
				else if (str_eq(&key, "call-id")) {
					err = "missing value";
					if (!val.s)
						goto error;
					ng_flags->call_id = val;
				} else
					break;
				continue;

			case 8:
				if (str_eq(&key, "internal")) {
					if (iniface.s)
						outiface = key;
					else
						iniface = key;
				} else if (str_eq(&key, "external")) {
					if (iniface.s)
						outiface = key;
					else
						iniface = key;
				}
				else if (str_eq(&key, "RTP/AVPF"))
					ng_flags->transport = 0x102;
				else if (str_eq(&key, "RTP/SAVP"))
					ng_flags->transport = 0x101;
				else if (str_eq(&key, "in-iface"))
					iniface = val;
				else if (str_eq(&key, "from-tag")) {
					err = "missing value";
					if (!val.s)
						goto error;
					ng_flags->from_tag = val;
					ng_flags->directional = 1;
				}
				else
					break;
				continue;

			case 9:
				if (str_eq(&key, "RTP/SAVPF"))
					ng_flags->transport = 0x103;
				else if (str_eq(&key, "out-iface"))
					outiface = val;
				else
					break;
				continue;

			case 10:
				if (str_eq(&key, "via-branch")) {
					err = "missing value";
					if (!val.s)
						goto error;
					err = "invalid value";
					if (*val.s == '1' || *val.s == '2')
						ng_flags->via = *val.s - '0';
					else if (str_eq(&val, "auto"))
						ng_flags->via = 3;
					else if (str_eq(&val, "extra"))
						ng_flags->via = -1;
					else
						goto error;
					continue;
				}
				break;

			case 11:
				if (str_eq(&key, "repacketize")) {
					err = "missing value";
					if (!val.s)
						goto error;
					ng_flags->packetize = 0;
					while (isdigit(*val.s)) {
						ng_flags->packetize *= 10;
						ng_flags->packetize += *val.s - '0';
						val.s++;
					}
					err = "invalid value";
					if (!ng_flags->packetize)
						goto error;
					BCHECK(bencode_dictionary_add_integer(ng_flags->dict, "repacketize", ng_flags->packetize));
					continue;
				} else if (str_eq(&key, "directional")) {
					ng_flags->directional = 1;
					bitem = bencode_str(bencode_item_buffer(ng_flags->flags), &key);
					if (!bitem) {
						err = "no more memory for list value";
						goto error;
					}
					BCHECK(bencode_list_add(ng_flags->flags, bitem));
					continue;
				}
				break;

			case 12:
				if (str_eq(&key, "force-answer")) {
					err = "cannot force answer in non-offer command";
					if (*op != OP_OFFER)
						goto error;
					*op = OP_ANSWER;
				} else if (str_eq(&key, "delete-delay")) {
					err = "missing value";
					if (!val.s)
						goto error;
					err = "invalid value";
					delete_delay = (int) strtol(val.s, NULL, 10);
					if (delete_delay == 0 && errno == EINVAL) {
						delete_delay = -1;
						goto error;
					} else {
						BCHECK(bencode_dictionary_add_integer(ng_flags->dict, "delete-delay", delete_delay));
					}
				} else
					break;
				continue;
			case 13:
				if (str_eq(&key, "media-address")) {
					err = "missing value";
					if (!val.s)
						goto error;
					break;
				} else if (str_eq(&key, "received-from")) {
					if (val.s)
						ng_flags->received_from = val;
				} else
					break;
				continue;

			case 14:
				if (str_eq(&key, "replace-origin")) {
					if (!ng_flags->replace)
						LM_DBG("%.*s not supported for %d op\n", key.len, key.s, *op);
					else
						BCHECK(bencode_list_add_string(ng_flags->replace, "origin"));
				} else if (str_eq(&key, "address-family")) {
					err = "missing value";
					if (!val.s)
						goto error;
					err = "invalid value";
					if (str_eq(&val, "IP4") || str_eq(&val, "IP6"))
						BCHECK(bencode_dictionary_add_str(ng_flags->dict, "address family", &val));
					else
						goto error;
				}
				else if (str_eq(&key, "rtcp-mux-demux"))
					BCHECK(!ng_flags->rtcp_mux || bencode_list_add_string(ng_flags->rtcp_mux, "demux"));
				else if (str_eq(&key, "rtcp-mux-offer"))
					BCHECK(!ng_flags->rtcp_mux || bencode_list_add_string(ng_flags->rtcp_mux, "offer"));
				else
					break;
				continue;

			case 15:
				if (str_eq(&key, "rtcp-mux-reject"))
					BCHECK(!ng_flags->rtcp_mux || bencode_list_add_string(ng_flags->rtcp_mux, "reject"));
				else if (str_eq(&key, "rtcp-mux-accept"))
					BCHECK(!ng_flags->rtcp_mux || bencode_list_add_string(ng_flags->rtcp_mux, "accept"));
				else
					break;
				continue;

			case 16:
				if (str_eq(&key, "UDP/TLS/RTP/SAVP"))
					ng_flags->transport = 0x104;
				else if (str_eq(&key, "rtcp-mux-require"))
					BCHECK(!ng_flags->rtcp_mux || bencode_list_add_string(ng_flags->rtcp_mux, "require"));
				else if (str_eq(&key, "via-branch-param")) {
					ng_flags->via = 4;
					ng_flags->viabranch = val;
				} else if (str_eq(&key, "replace-username")) {
					if (!ng_flags->replace)
						LM_DBG("%.*s not supported for %d op\n", key.len, key.s, *op);
					else
						BCHECK(bencode_list_add_string(ng_flags->replace, "username"));
				} else
					break;
				continue;

			case 17:
				if (str_eq(&key, "UDP/TLS/RTP/SAVPF"))
					ng_flags->transport = 0x105;
				else
					break;
				continue;

			case 19:
				if (str_eq(&key, "replace-SDP-version")) {
					if (!ng_flags->replace)
						LM_DBG("%.*s not supported for %d op\n", key.len, key.s, *op);
					else
						BCHECK(bencode_list_add_string(ng_flags->replace, "SDP version"));
				} else
					break;
				continue;

			case 20:
				if (str_eq(&key, "replace-zero-address")) {
					if (!ng_flags->replace)
						LM_DBG("%.*s not supported for %d op\n", key.len, key.s, *op);
					else
						BCHECK(bencode_list_add_string(ng_flags->replace, "zero address"));
				} else if (str_eq(&key, "replace-session-name")) {
					if (!ng_flags->replace)
						LM_DBG("%.*s not supported for %d op\n", key.len, key.s, *op);
					else
						BCHECK(bencode_list_add_string(ng_flags->replace, "session name"));
				} else
					break;
				continue;

			case 26:
				if (str_eq(&key, "replace-session-connection")) {
					if (!ng_flags->replace)
						LM_DBG("%.*s not supported for %d op\n", key.len, key.s, *op);
					else
						BCHECK(bencode_list_add_string(ng_flags->replace, "session-connection"));
				} else
					break;
				continue;
		}

		/* we got here if we didn't match something specific */
		if (!val.s) {
			bitem = bencode_str(bencode_item_buffer(ng_flags->flags), &key);
			if (!bitem) {
				err = "no more memory for list value";
				goto error;
			}
			BCHECK(bencode_list_add(ng_flags->flags, bitem));
		} else if (val.len >= 2 && val.s[0] == '[' && val.s[val.len - 1] == ']') {
			/* bracket-delimited list or dictionary — strip the outer
			 * '[' and ']' (val.s+1, val.len-2) and parse the inner
			 * content into a bencode list or dict */
			bitem = parse_bracket_value(val.s + 1, val.len - 2,
					bencode_item_buffer(ng_flags->dict), 0);
			if (!bitem) {
				err = "failed to parse bracket value";
				goto error;
			}
			BCHECK(bencode_dictionary_add_len(ng_flags->dict,
					key.s, key.len, bitem));
		} else {
			bitem = bencode_str(bencode_item_buffer(ng_flags->dict), &val);
			if (!bitem) {
				err = "no more memory for dict value";
				goto error;
			}
			BCHECK(bencode_dictionary_add_len(ng_flags->dict, key.s, key.len, bitem));
		}
	}

	if (iniface.len != 0 && outiface.len != 0) {
		if (ng_flags->direction) {
			bitem = bencode_str(bencode_item_buffer(ng_flags->direction), &iniface);
			if (!bitem) {
				err = iniface.s;
				goto error;
			}
			BCHECK(bencode_list_add(ng_flags->direction, bitem));
			bitem = bencode_str(bencode_item_buffer(ng_flags->direction), &outiface);
			if (!bitem) {
				err = "no more memory for direction";
				goto error;
			}
			BCHECK(bencode_list_add(ng_flags->direction, bitem));
		} else {
			LM_DBG("cannot set interfaces for non-offer/answer commands\n");
		}
	} else if (iniface.len) {
		LM_ERR("in-iface value without out-iface\n");
		return -1;
	} else if (outiface.len) {
		LM_ERR("out-iface value without in-iface\n");
		return -1;
	}

	return 0;

error:
	if (val.s)
		LM_ERR("error processing flag `%.*s' (value '%.*s'): %s\n", key.len, key.s,
				val.len, val.s, err);
	else
		LM_ERR("error processing flag `%.*s': %s\n", key.len, key.s, err);
	return -1;
}
#undef BCHECK

static struct rtpe_node *get_rtpe_node(str *node, struct rtpe_set *set)
{
	struct rtpe_node *rnode;

	/* check last list version */
	if (my_version != *list_version && update_rtpengines(0) < 0) {
		LM_ERR("cannot update rtpengines list\n");
		return NULL;
	}

	for (rnode = set->rn_first; rnode; rnode = rnode->rn_next)
		if (node->len == rnode->rn_url.len &&
				!memcmp(node->s, rnode->rn_url.s, node->len)) {
			rnode->rn_disabled = rtpe_test(rnode, rnode->rn_disabled, 0);
			return (rnode->rn_disabled?NULL:rnode);
		}
	return NULL;
}

static int rtpe_add_ignore_node(struct rtpe_ignore_node **list, struct rtpe_node *node)
{
	struct rtpe_ignore_node *new = pkg_malloc(sizeof *new);
	if (!new)
		return 0;

	new->node = node;
	new->next = *list;
	*list = new;
	LM_INFO("temporary ignoring %.*s node for this attempt\n", node->rn_url.len, node->rn_url.s);
	return 1;
}

static int rtpe_is_ignore_node(struct rtpe_ignore_node *list, struct rtpe_node *node)
{
	struct rtpe_ignore_node *it;
	for (it = list; it; it = it->next)
		if (it->node == node)
			return 1;
	return 0;
}

static void rtpe_free_ignore_node(struct rtpe_ignore_node *list)
{
	struct rtpe_ignore_node *next, *it;
	for (it = list; it; it = next) {
		next = it->next;
		pkg_free(it);
	}
}

OSIPS_LIST_HEAD(rtpe_failover_errors);
struct rtpe_failover_regex {
	regex_t re;
	struct list_head list;
};

static int rtpengine_extra_failover(modparam_t type, void * val)
{
	char *p;
	struct rtpe_failover_regex *re;

	p = (char* )val;

	if(p==0 || *p=='\0')
		return 0;
	re = pkg_malloc(sizeof(*re));
	if (!re) {
		LM_ERR("no more memory for regular expression!\n");
		return -1;
	}
	memset(re, 0, sizeof *re);
	if (regcomp(&re->re, p, (REG_EXTENDED|REG_ICASE|REG_NEWLINE))) {
		LM_ERR("could not compile regex [%s]\n", p);
		pkg_free(re);
		return -1;
	}
	list_add(&re->list, &rtpe_failover_errors);
	return 0;
}

static int rtpe_check_ignore_node(str *error)
{
	int ret;
	str error_nt;
	regmatch_t pmatch;
	struct list_head *it;
	struct rtpe_failover_regex *re;

	int i, size = sizeof(rtpe_default_failover_errors)/sizeof(rtpe_default_failover_errors[0]);
	for (i = 0; i < size; i++) {
		if (str_casematch_nt(error, rtpe_default_failover_errors[i]))
			return 1;
	}
	if (list_empty(&rtpe_failover_errors))
		return 0;
	if (pkg_nt_str_dup(&error_nt, error) < 0) {
		LM_ERR("could not duplicate error!\n");
		return 0;
	}
	ret = 1;
	list_for_each(it, &rtpe_failover_errors) {
		re = list_entry(it, struct rtpe_failover_regex, list);
		if (regexec(&re->re, error_nt.s, 1, &pmatch, 0) == 0)
			goto end;
	}
	ret = 0;
end:
	pkg_free(error_nt.s);
	return ret;
}

static int rtpe_function_call_prepare(bencode_buffer_t *bencbuf, struct sip_msg *msg, enum rtpe_operation op,
         struct ng_flags_parse *ng_flags, str *flags_str, str *body_in, bencode_item_t *extra_dict, char **err)
{
	bencode_item_t *item;
	str viabranch;
	int ret, flags_exist = 0, callid_exist = 0, from_tag_exist = 0, to_tag_exist = 0;
	str flags_nt = {0,0};

	if (bencode_buffer_init(bencbuf)) {
		LM_ERR("could not initialize bencode_buffer_t\n");
		return -1;
	}

	if (!extra_dict) {
		ng_flags->dict = bencode_dictionary(bencbuf);
	} else {
		ng_flags->dict = extra_dict;

		ng_flags->flags = bencode_dictionary_get(ng_flags->dict, "flags");
		if (ng_flags->flags)
			flags_exist = 1;
		bencode_dictionary_get_str(ng_flags->dict, "call-id", &ng_flags->call_id);
		bencode_dictionary_get_str(ng_flags->dict, "from-tag", &ng_flags->from_tag);
		bencode_dictionary_get_str(ng_flags->dict, "to-tag", &ng_flags->to_tag);
		if (ng_flags->call_id.len)
			callid_exist = 1;
		if (ng_flags->from_tag.len)
			from_tag_exist = 1;
		if (ng_flags->to_tag.len)
			to_tag_exist = 1;
	}
	if (!flags_exist)
		ng_flags->flags = bencode_list(bencbuf);
	if (op == OP_OFFER || op == OP_ANSWER) {
		ng_flags->direction = bencode_list(bencbuf);
		ng_flags->replace = bencode_list(bencbuf);
		ng_flags->rtcp_mux = bencode_list(bencbuf);

		bencode_dictionary_add_str(ng_flags->dict, "sdp", body_in);
	} else if (op == OP_SUBSCRIBE_ANSWER) {
		bencode_dictionary_add_str(ng_flags->dict, "sdp", body_in);
	}

	/*** parse flags & build dictionary ***/

	ng_flags->to = (op == OP_DELETE) ? 0 : 1;

	if (flags_str && pkg_nt_str_dup(&flags_nt, flags_str) < 0) {
		*err = "No more pkg mem";
		goto error;
	}

	if (parse_flags(ng_flags, msg, &op, flags_nt.s)) {
		*err = "could not parse flags";
		goto error;
	}

	if (!ng_flags->call_id.len &&
			(get_callid(msg, &ng_flags->call_id) == -1 || ng_flags->call_id.len == 0)) {
		*err = "can't get Call-Id field";
		goto error;
	}
	if (!ng_flags->to_tag.len &&
			get_to_tag(msg, &ng_flags->to_tag) == -1) {
		*err = "can't get To tag";
		goto error;
	}

	if (!ng_flags->from_tag.len &&
			(get_from_tag(msg, &ng_flags->from_tag) == -1 || ng_flags->from_tag.len == 0)) {
		*err = "can't get From tag";
		goto error;
	}

	/* only add those if any flags were given at all */
	if (ng_flags->direction && ng_flags->direction->child)
		bencode_dictionary_add(ng_flags->dict, "direction", ng_flags->direction);
	if (!flags_exist && ng_flags->flags && ng_flags->flags->child)
		bencode_dictionary_add(ng_flags->dict, "flags", ng_flags->flags);
	if (ng_flags->replace && ng_flags->replace->child)
		bencode_dictionary_add(ng_flags->dict, "replace", ng_flags->replace);
	if ((ng_flags->transport & 0x100))
		bencode_dictionary_add_string(ng_flags->dict, "transport-protocol",
				transports[ng_flags->transport & 0x007]);
	if (ng_flags->rtcp_mux && ng_flags->rtcp_mux->child)
		bencode_dictionary_add(ng_flags->dict, "rtcp-mux", ng_flags->rtcp_mux);

	if (!callid_exist)
		bencode_dictionary_add_str(ng_flags->dict, "call-id", &ng_flags->call_id);

	if (ng_flags->via) {
		if (ng_flags->via == 1 || ng_flags->via == 2)
			ret = get_via_branch(msg, ng_flags->via, &viabranch);
		else if (ng_flags->via == -1 && extra_id_pv)
			ret = get_extra_id(msg, &viabranch);
		else if (ng_flags->via == 4 && ng_flags->viabranch.len) {
			viabranch = ng_flags->viabranch;
			ret = 1;
		} else
			ret = -1;
		if (ret == -1 || viabranch.len == 0) {
			*err = "can't get Via branch/extra ID";
			goto error;
		}
		bencode_dictionary_add_str(ng_flags->dict, "via-branch", &viabranch);
	}

	item = bencode_list(bencbuf);
	bencode_dictionary_add(ng_flags->dict, "received-from", item);
	if (msg) {
		if (!ng_flags->received_from.len) {
			bencode_list_add_string(item, (msg->rcv.src_ip.af == AF_INET) ? "IP4" : (
					(msg->rcv.src_ip.af == AF_INET6) ? "IP6" :
					"?"
			) );
			bencode_list_add_string(item, ip_addr2a(&msg->rcv.src_ip));
		} else {
			struct ip_addr *ip_tmp = NULL;

			ip_tmp = str2ip(&ng_flags->received_from);
			if (!ip_tmp) {
				ip_tmp = str2ip6(&ng_flags->received_from);
				if (!ip_tmp) {
					*err = "received-from value is not an IP";
					goto error;
				}
			}

			bencode_list_add_string(item, (ip_tmp->af == AF_INET) ? "IP4" : (
				(ip_tmp->af == AF_INET6) ? "IP6" :
				"?"
			) );
			bencode_list_add_string(item, ip_addr2a(ip_tmp));
		}
	}

	if (op == OP_START_MEDIA || op == OP_STOP_MEDIA ||
			op == OP_BLOCK_MEDIA || op == OP_UNBLOCK_MEDIA ||
			op == OP_BLOCK_DTMF || op == OP_UNBLOCK_DTMF ||
			op == OP_START_FORWARD || op == OP_STOP_FORWARD) {
		if (ng_flags->directional && !from_tag_exist)
			bencode_dictionary_add_str(ng_flags->dict, "from-tag", &ng_flags->from_tag);
	} else if (ng_flags->directional
		|| (msg && ((msg->first_line.type == SIP_REQUEST && op != OP_ANSWER)
		|| (msg->first_line.type == SIP_REPLY && op == OP_DELETE)
		|| (msg->first_line.type == SIP_REPLY && op == OP_ANSWER))))
	{
		if (!from_tag_exist && op != OP_DELETE)
			bencode_dictionary_add_str(ng_flags->dict, "from-tag", &ng_flags->from_tag);
		if (op != OP_START_MEDIA && op != OP_STOP_MEDIA) {
			/* no need of to-tag if we are just playing media */
			if (ng_flags->to && ng_flags->to_tag.s && ng_flags->to_tag.len && !to_tag_exist && !extra_dict)
				bencode_dictionary_add_str(ng_flags->dict, "to-tag", &ng_flags->to_tag);
		}
	}
	else {
		if (!ng_flags->to_tag.s || !ng_flags->to_tag.len) {
			*err = "No to-tag present";
			goto error;
		}
		if (!from_tag_exist)
			bencode_dictionary_add_str(ng_flags->dict, "from-tag", &ng_flags->to_tag);
		if (!to_tag_exist && !extra_dict)
			bencode_dictionary_add_str(ng_flags->dict, "to-tag", &ng_flags->from_tag);
	}

	bencode_dictionary_add_string(ng_flags->dict, "command", command_strings[op]);

	if (bencbuf->error) {
		LM_ERR("bencode failed\n");
		goto error;
	}

	if (flags_nt.s)
		pkg_free(flags_nt.s);

	return 1;

error:
	if (flags_nt.s)
		pkg_free(flags_nt.s);
	return -1;
}

static bencode_item_t *rtpe_function_call(bencode_buffer_t *bencbuf, struct sip_msg *msg,
	enum rtpe_operation op, str *flags_str, str *body_in, pv_spec_t *spvar,
	struct rtpe_set *set, str *snode, bencode_item_t *extra_dict)
{
	struct ng_flags_parse ng_flags;
	bencode_item_t *resp;
	str error;
	struct rtpe_node *node, *failed_node;
	char *cp, *err = NULL;
	pv_value_t val;
	struct rtpe_ignore_node *ignore_list = NULL;
	int ret;
	memset(&ng_flags, 0, sizeof(ng_flags));
	error.len = 0;
	error.s = "";
	pv_value_t socket_val;

	/*** get & init basic stuff needed ***/
	if (rtpe_function_call_prepare(bencbuf, msg, op, &ng_flags, flags_str, body_in, extra_dict,&err) < 0)
		goto error;

	/*** set can be passed into this routine. If it is NULL, then attempt to determine it. ***/
	if (!set) {
		if ((set=rtpe_ctx_set_get())==NULL)
			set = *default_rtpe_set;
	}

	/*** If the spvar "sock_var" has been specified, parse it into a (socket_val) STR variable ***/
	if (spvar) {
		memset(&socket_val, 0, sizeof(pv_value_t));
		pv_get_spec_value(msg, spvar, &socket_val);
	}

	failed_node = NULL;

	RTPE_START_READ();
	do {
		/*
		 * Many rtpengine_* commands allow a "sock_var" to be specified by the script writer.
		 * The "sock_var" will be populated by the rtpengine_* command with the RTPEngine that
		 * was chosen for the operation.
		 *
		 * The "sock_var" can be used by subsequent rtpengine_* commands to direct the command
		 * toward a specific RTPEngine instance.
		 */
		if (spvar && (socket_val.rs.len > 0)) {
			LM_DBG("Sending command [%d] to RTPEngine socket: [%.*s] set id: [%d]\n", op, (int)(socket_val.rs.len), (char *)(socket_val.rs.s), set->id_set);
			node = lookup_rtpe_node(set, &socket_val.rs);
			if (node == NULL) {
				RTPE_STOP_READ();
				goto error;
			}

		} else if (snode && snode->s) {
			if ((node = get_rtpe_node(snode, set)) == NULL && op == OP_OFFER)
				node = select_rtpe_node(ng_flags.call_id, set, ignore_list);
			snode = NULL;

		} else {
			node = select_rtpe_node(ng_flags.call_id, set, ignore_list);
		}

		if (!node) {
			if (!err && !error.len)
				err = "no available proxies";
			RTPE_STOP_READ();
			goto error;
		}

		cp = send_rtpe_command(node, ng_flags.dict, &ret);
		if (cp) {
			/*** process reply ***/
			resp = bencode_decode_expect(bencbuf, cp, ret, BENCODE_DICTIONARY);
			if (resp) {
				if (!bencode_dictionary_get_strcmp(resp, "result", "error")) {
					if (!bencode_dictionary_get_str(resp, "error-reason", &error)) {
						LM_ERR("proxy return error but didn't give an error reason: %.*s\n", ret, cp);
						error.s = "";
						error.len = 0;
					} else {
						LM_ERR("proxy replied with error: %.*s\n", error.len, error.s);
					}
					if (rtpe_check_ignore_node(&error)) {
						cp = NULL;
						if (!rtpe_add_ignore_node(&ignore_list, node))
							LM_ERR("could not add node to ignore list!\n");
						else
							continue; /* one more loop */
					} else {
						break; /* break the loop and exit with error */
					}
				}
			} else {
				LM_ERR("failed to decode bencoded reply from proxy: %.*s\n", ret, cp);
				err = "failed to decode bencoded reply";
				cp = NULL;
			}
		}
		if (!cp) {
			if (node == failed_node) {
				/* this is the 2nd error this server generated at this round,
				 * so we should ignore it and try another one */
				if (!rtpe_add_ignore_node(&ignore_list, node)) {
					LM_ERR("could not add node to ignore list!\n");
					RTPE_STOP_READ();
					goto error;
				}
				failed_node = NULL;
			} else {
				failed_node = node;
			}
		}
	} while (cp == NULL);
	RTPE_STOP_READ();
	rtpe_free_ignore_node(ignore_list);
	LM_DBG("proxy reply: %.*s\n", ret, cp);

	/* store the value of the selected node */
	if (spvar) {
		memset(&val, 0, sizeof(pv_value_t));
		val.flags = PV_VAL_STR;
		val.rs = node->rn_url;
		if(pv_set_value(msg, spvar, (int)EQ_T, &val)<0)
			LM_ERR("setting rtpengine pvar failed\n");
	}

	return resp;

error:
	rtpe_free_ignore_node(ignore_list);
	if (err) {
		LM_ERR("%s\n", err);
		init_str(&error, err);
	}
	if (error.len && err_pv_param) {
		memset(&val, 0, sizeof(pv_value_t));
		val.flags = PV_VAL_STR;
		val.rs = error;
		if(pv_set_value(msg, &err_pv, (int)EQ_T, &val)<-1)
			LM_ERR("setting rtpengine result pvar failed\n");
	}
	if (bencbuf)
		bencode_buffer_free(bencbuf);
	return NULL;
}

static int
set_rtpengine_set_from_avp(struct sip_msg *msg)
{
	struct usr_avp *avp;
	int_str setid_val;
	struct rtpe_set *set;

	if ((setid_avp_param == NULL) ||
			(avp = search_first_avp(setid_avp_type, setid_avp.n, &setid_val, 0))
			== NULL)
		return 1;

	if (avp->flags&AVP_VAL_STR) {
		LM_ERR("setid_avp must hold an integer value\n");
		return -1;
	}

	if ((set=select_rtpe_set(setid_val.n)) == NULL) {
		LM_ERR("could not locate rtpengine set %d\n", setid_val.n);
		return -1;
	}

	rtpe_ctx_set_fill( set );
	LM_DBG("using rtpengine set %d\n", setid_val.n);

	return 1;
}


static int rtpe_function_call_simple(struct sip_msg *msg, enum rtpe_operation op,
		str *flags_str, struct rtpe_set *set, str *node, pv_spec_t *spvar)
{
	bencode_buffer_t bencbuf;
	struct rtpe_ctx *ctx;
	bencode_item_t *ret;

	if (set_rtpengine_set_from_avp(msg) == -1)
		return -1;

	ret = rtpe_function_call(&bencbuf, msg, op, flags_str, NULL, spvar, set, node, NULL);
	if (!ret)
		return -1;

	if (op == OP_DELETE && rtpengine_stats_used) {
		/* if statistics are to be used, store stats in the ctx, if possible */
		if ((ctx = rtpe_ctx_get())) {
			if (ctx->stats)
				rtpe_stats_free(ctx->stats); /* release the buffer */
			else
				ctx->stats = pkg_malloc(sizeof *ctx->stats);
			if (ctx->stats) {
				ctx->stats->buf = bencbuf;
				ctx->stats->dict = ret;
				ctx->stats->json.s = 0;
				/* return here to prevent buffer from being freed */
				return 1;
			} else
				LM_WARN("no more pkg memory - cannot cache stats!\n");
		}
	}

	bencode_buffer_free(&bencbuf);
	return 1;
}

static bencode_item_t *rtpe_function_call_ok(bencode_buffer_t *bencbuf, struct sip_msg *msg,
		enum rtpe_operation op, str *flags_str, str *body, pv_spec_t *spvar,
		struct rtpe_set *set, str *node, bencode_item_t *dict)
{
	bencode_item_t *ret;

	ret = rtpe_function_call(bencbuf, msg, op, flags_str, body, spvar, set, node, dict);
	if (!ret)
		return NULL;

	if (bencode_dictionary_get_strcmp(ret, "result", "ok")) {
		LM_ERR("proxy didn't return \"ok\" result\n");
		bencode_buffer_free(bencbuf);
		return NULL;
	}

	return ret;
}



static int
rtpe_test(struct rtpe_node *node, int isdisabled, int force)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *dict;
	bencode_item_t *resp;
	char *cp;
	int ret;

	if(node->rn_recheck_ticks == MI_MAX_RECHECK_TICKS){
	    LM_DBG("rtpe %s disabled for ever\n", node->rn_url.s);
		return 1;
	}
	if (force == 0) {
		if (isdisabled == 0)
			return 0;
		if (node->rn_recheck_ticks > get_ticks())
			return 1;
	}

	if (bencode_buffer_init(&bencbuf)) {
		LM_ERR("could not initialized bencode_buffer_t\n");
		return 1;
	}
	dict = bencode_dictionary(&bencbuf);
	bencode_dictionary_add_string(dict, "command", "ping");
	if (bencbuf.error)
		goto benc_error;

	cp = send_rtpe_command(node, dict, &ret);
	if (!cp) {
		LM_ERR("proxy did not respond to ping\n");
		goto error;
	}

	resp = bencode_decode_expect(&bencbuf, cp, ret, BENCODE_DICTIONARY);
	if (!resp || bencode_dictionary_get_strcmp(resp, "result", "pong")) {
		LM_ERR("proxy responded with invalid response\n");
		goto error;
	}

	if (isdisabled)
		LM_DBG("rtpengine <%s> found, support for it %senabled\n",
				node->rn_url.s, force == 0 ? "re-" : "");

	bencode_buffer_free(&bencbuf);
	return 0;

benc_error:
        LM_ERR("out of memory - bencode failed\n");
error:
	bencode_buffer_free(&bencbuf);
	return 1;
}

#define RTPENGINE_BUF_SIZE 0x10000
#define OSIP_IOV_MAX 1024

static char *
send_rtpe_command(struct rtpe_node *node, bencode_item_t *dict, int *outlen)
{
	struct sockaddr_un addr;
	int fd, len, i, vcnt;
	int max_vcnt=OSIP_IOV_MAX;
	char *cp;
	static char buf[RTPENGINE_BUF_SIZE];
	struct pollfd fds[1];
	struct iovec *v;

	v = bencode_iovec(dict, &vcnt, 1, 0);
	if (!v) {
		LM_ERR("error converting bencode to iovec\n");
		return NULL;
	}
#ifdef IOV_MAX
	if (IOV_MAX < OSIP_IOV_MAX)
		max_vcnt = IOV_MAX;
#endif
	vcnt++; /* add the cookie */

	if (vcnt > max_vcnt) {
		int i, vec_len = 0;
		/* use buf if possible :) */
		for (i = max_vcnt - 1; i < vcnt; i++)
			vec_len += v[i].iov_len;
		/* use buf, error otherwise */
		if (vec_len > RTPENGINE_BUF_SIZE) {
			LM_ERR("Command too big %d - max %d\n", vec_len, RTPENGINE_BUF_SIZE);
			return NULL;
		}
		cp = buf;
		for (i = max_vcnt - 1; i < vcnt; i++) {
			memcpy(cp, v[i].iov_base, v[i].iov_len);
			cp += v[i].iov_len;
		}
		i = max_vcnt - 1;
		v[i].iov_len = vec_len;
		v[i].iov_base = buf;
		/* finally solve the problem */
		vcnt = max_vcnt;
	}

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
			LM_ERR("can't send (#%d iovec buffers) command to a RTP proxy (%d:%s)\n",
					vcnt - 1, errno, strerror(errno));
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
		node->rn_last_ticks = get_ticks();
	} else {
		if (rtpe_socks[node->idx] != -1) {
			fds[0].fd = rtpe_socks[node->idx];
			fds[0].events = POLLIN;
			fds[0].revents = 0;
			/* Drain input buffer */
			while ((poll(fds, 1, 0) == 1) &&
				((fds[0].revents & POLLIN) != 0)) {
				if (fds[0].revents & (POLLERR|POLLNVAL|POLLHUP)) {
					LM_WARN("error on rtpengine socket %d!\n", rtpe_socks[node->idx]);
					RTPE_IO_ERROR_CLOSE(rtpe_socks[node->idx]);
					break;
				}
				fds[0].revents = 0;
				if (recv(rtpe_socks[node->idx], buf, sizeof(buf) - 1, 0) < 0 &&
						errno != EINTR) {
					LM_WARN("error while draining rtpengine %d!\n", errno);
					RTPE_IO_ERROR_CLOSE(rtpe_socks[node->idx]);
					break;
				}
			}
		}
		v[0].iov_base = gencookie();
		v[0].iov_len = strlen(v[0].iov_base);
		for (i = 0; i < rtpengine_retr; i++) {
			if (rtpe_socks[node->idx] == -1) {
				if (!rtpengine_connect_node(node)) {
					LM_ERR("cannot reconnect RTP engine socket!\n");
					goto badproxy;
				}
				fds[0].fd = rtpe_socks[node->idx];
			}
			do {
				len = writev(rtpe_socks[node->idx], v, vcnt);
			} while (len == -1 && (errno == EINTR || errno == ENOBUFS || errno == EMSGSIZE));
			if (len <= 0) {
				LM_ERR("can't send (#%d iovec buffers) command to a RTP proxy (%d:%s)\n",
						vcnt, errno, strerror(errno));
				RTPE_IO_ERROR_CLOSE(rtpe_socks[node->idx]);
				continue;
			}
			while ((poll(fds, 1, rtpengine_tout * 1000) == 1) &&
			    (fds[0].revents & POLLIN) != 0) {
				do {
					len = recv(rtpe_socks[node->idx], buf, sizeof(buf)-1, 0);
				} while (len == -1 && errno == EINTR);
				if (len <= 0) {
					LM_ERR("can't read reply from a RTP proxy\n");
					RTPE_IO_ERROR_CLOSE(rtpe_socks[node->idx]);
					continue;
				}
				node->rn_last_ticks = get_ticks();
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
		if (i == rtpengine_retr) {
			LM_ERR("timeout waiting reply from a RTP proxy\n");
			goto badproxy;
		}
	}

out:
	cp[len] = '\0';
	*outlen = len;
	return cp;
badproxy:
	LM_ERR("proxy <%s> does not respond, disable it\n", node->rn_url.s);
	node->rn_disabled = 1;
	node->rn_recheck_ticks = get_ticks() + rtpengine_disable_tout;
	raise_rtpengine_status_event(node);

	return NULL;
}

/*
 * select the set with the id_set id
 */

static struct rtpe_set * select_rtpe_set(int id_set )
{

	struct rtpe_set * rtpe_list;
	/*is it a valid set_id?*/

	if(!rtpe_set_list || !(*rtpe_set_list) || !(*rtpe_set_list)->rset_first)
		return 0;

	for(rtpe_list=(*rtpe_set_list)->rset_first; rtpe_list!=0 &&
		rtpe_list->id_set!=id_set; rtpe_list=rtpe_list->rset_next);
	if(!rtpe_list){
		LM_DBG("no engine in set %d\n", id_set);
	}

	return rtpe_list;
}
/*
 * Main balancing routine. This does not try to keep the same proxy for
 * the call if some proxies were disabled or enabled; proxy death considered
 * too rare. Otherwise we should implement "mature" HA clustering, which is
 * too expensive here.
 */
static struct rtpe_node *
select_rtpe_node(str callid, struct rtpe_set *set, struct rtpe_ignore_node *ignore_list)
{
	unsigned sum, weight_sum;
	struct rtpe_node* node;
	int was_forced, sumcut, found, constant_weight_sum;

	/* check last list version */
	if (my_version != *list_version && update_rtpengines(0) < 0) {
		LM_ERR("cannot update rtpengines list\n");
		return 0;
	}

	if(!set){
		LM_ERR("script error -no valid set selected\n");
		return NULL;
	}

	/* Most popular case: 1 proxy, nothing to calculate */
	if (set->rtpe_node_count == 1) {
		node = set->rn_first;
		if (node->rn_disabled || rtpe_is_ignore_node(ignore_list, node))
			return NULL;
		return node;
	}

	/* XXX Use quick-and-dirty hashing algo */
	for(sum = 0; callid.len > 0; callid.len--)
		sum += callid.s[callid.len - 1];
	sum &= 0xff;

	was_forced = 0;
	weight_sum = 0;
	constant_weight_sum = 0;
	found = 0;
	for (node=set->rn_first; node!=NULL; node=node->rn_next) {
		constant_weight_sum += node->rn_weight;
		if (!node->rn_disabled && !rtpe_is_ignore_node(ignore_list, node)) {
			weight_sum += node->rn_weight;
			found = 1;
		}
	}
	if (found == 0) {
			return NULL;
	}
	sumcut = weight_sum ? sum % constant_weight_sum : -1;
	/*
	 * sumcut here lays from 0 to constant_weight_sum-1.
	 * Scan proxy list and decrease until appropriate proxy is found.
	 */
	was_forced = 0;
	for (node=set->rn_first; node!=NULL;) {
		if (sumcut < (int)node->rn_weight) {
			if (!node->rn_disabled && !rtpe_is_ignore_node(ignore_list, node))
				return node;
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
}

static int
get_extra_id(struct sip_msg* msg, str *id_str) {
	if(msg==NULL || extra_id_pv==NULL || id_str==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}
	if (pv_printf_s(msg, extra_id_pv, id_str)<0) {
		LM_ERR("cannot print the additional id\n");
		return -1;
	}

	return 1;

}

static int rtpengine_delete(struct sip_msg *msg, str *flags,
		struct rtpe_set *set, str *node, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_DELETE, flags, set, node, spvar);
}

static int
rtpengine_delete_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpengine_delete(msg, flags, NULL, NULL, spvar);
}

static bencode_item_t *rtpe_function_call_process(bencode_buffer_t *bencbuf, char* cp, int ret)
{
        bencode_item_t *resp;
        str error;

        resp = bencode_decode_expect(bencbuf, cp, ret, BENCODE_DICTIONARY);
        if (!resp) {
                LM_ERR("failed to decode bencoded reply from proxy: %.*s\n", ret, cp);
                return NULL;
        }
        if (!bencode_dictionary_get_strcmp(resp, "result", "error")) {
                if (!bencode_dictionary_get_str(resp, "error-reason", &error))
                        LM_ERR("proxy return error but didn't give an error reason: %.*s\n", ret, cp);
                else
                        LM_ERR("proxy replied with error: %.*s\n", error.len, error.s);
                return NULL;
        }

        return resp;
}

enum async_ret_code resume_async_send_rtpe_command(int fd, struct sip_msg *msg, void *_param)
{
	int len = 0, cookielen = 0;
	static char buf[0x10000];
	char* cp = buf;
	bencode_item_t *dict;
	str oldbody = { 0, 0 };
	str newbody;
	struct lump *anchor;
	pv_value_t val;
	struct rtpe_ctx *ctx;
	rtpe_async_param *param = (rtpe_async_param *)_param;

	LM_DBG("Need to resume async rtpe call \n");

	if (param->node->rn_umode == 0) {
		do {
			len = read(fd, buf, sizeof(buf) - 1);
		} while (len == -1 && errno == EINTR);
		close(fd);
		if (len <= 0) {
			LM_ERR("can't read reply from a RTP Engine\n");
			goto error;
		}
	} else {
		/* UDP got triggered, wait for 1second max to read now */
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

		len = recv(fd, buf, sizeof(buf)-1, 0);
		if (len <= 0) {
			LM_ERR("can't read reply from a RTP Engine (%d, %d)\n", len, errno);
			RTPE_IO_ERROR_CLOSE(param->node->idx);
			goto error;
		}
		cookielen = strlen(param->cookie);
		if (len >= (cookielen - 1) &&
		memcmp(buf, param->cookie, (cookielen - 1)) == 0) {
			len -= (cookielen - 1);
			cp += (cookielen - 1);
			if (len != 0) {
				len--;
				cp++;
			}
		} else {
			LM_ERR("read reply from a RTP Ending FD %d. Cookie does NOT match (%.*s <> %.*s)\n", 
			fd, cookielen - 1, param->cookie, cookielen - 1, buf);
			goto error;
		}
	}

	/* store the value of the selected node */
	if (param->spvar) {
		memset(&val, 0, sizeof(pv_value_t));
		val.flags = PV_VAL_STR;
		val.rs = param->node->rn_url;
		if(pv_set_value(msg, param->spvar, (int)EQ_T, &val)<0)
			LM_ERR("setting rtpengine pvar failed\n");
	}

	/* process reply */
	dict = rtpe_function_call_process(param->bencbuf, cp, len);
	if(!dict) {
		goto error;
	}

	if (param->op != OP_DELETE) {
		LM_DBG("Got reply for a non-delete - yay \n");
		if (!bencode_dictionary_get_str_dup(dict, "sdp", &newbody)) {
			LM_ERR("failed to extract sdp body from proxy reply\n");
			goto error;
		}

		/* if we have a variable to store into, use it */
		if (param->bpvar) {
			memset(&val, 0, sizeof(pv_value_t));
			val.flags = PV_VAL_STR;
			val.rs = newbody;
			if(pv_set_value(msg, param->bpvar, (int)EQ_T, &val)<0)
				LM_ERR("setting PV failed\n");
			pkg_free(newbody.s);
		} else if (extract_body(msg, &oldbody) > 0) {
			/* otherwise directly set the body of the message */
			anchor = del_lump(msg, oldbody.s - msg->buf, oldbody.len, 0);
			if (!anchor) {
				LM_ERR("del_lump failed\n");
				goto error;
			}
			if (!insert_new_lump_after(anchor, newbody.s, newbody.len, 0)) {
				LM_ERR("insert_new_lump_after failed\n");
				goto error;
			}
		} else {
			LM_ERR("cannot parse old body!\n");
			goto error;
		}
	}

	if (param->op == OP_DELETE && rtpengine_stats_used) {
		/* if statistics are to be used, store stats in the ctx, if possible */
		if ((ctx = rtpe_ctx_get())) {
			if (ctx->stats) {
				rtpe_stats_free(ctx->stats); /* release the buffer */
				pkg_free(&(ctx->stats->buf));
			} else
				ctx->stats = pkg_malloc(sizeof *ctx->stats);
			if (ctx->stats) {
				ctx->stats->buf = *(param->bencbuf);
				ctx->stats->dict = dict;
				ctx->stats->json.s = 0;
				/* return here to prevent buffer from being freed */
				pkg_free(param->bencbuf);
				pkg_free(param->cookie);
				pkg_free(param);
				async_status = ASYNC_DONE_CLOSE_FD;
				return 1;
			} else
				LM_WARN("no more pkg memory - cannot cache stats!\n");
		}
	}

	pkg_free(param->cookie);
	bencode_buffer_free(param->bencbuf);
	pkg_free(param->bencbuf);
	pkg_free(param);
	async_status = ASYNC_DONE_CLOSE_FD;
	return 1;

error:
        pkg_free(param->cookie);
        bencode_buffer_free(param->bencbuf);
        pkg_free(param->bencbuf);
        pkg_free(param);
        async_status = ASYNC_DONE_CLOSE_FD;
        return -1;
}

enum async_ret_code timeout_async_send_rtpe_command(int fd, struct sip_msg *msg, void *_param)
{
	rtpe_async_param *param = (rtpe_async_param *)_param;
	LM_ERR("can't read reply from a RTP proxy - TIMEOUT on %s\n",param->node->rn_url.s);

	param->node->rn_disabled = 1;
	param->node->rn_recheck_ticks = get_ticks() + rtpengine_disable_tout;

	pkg_free(param->cookie);
	bencode_buffer_free(param->bencbuf);
	pkg_free(param->bencbuf);
	pkg_free(param);
	async_status = ASYNC_DONE_CLOSE_FD;
	return -1;
}

static int start_async_send_rtpe_command(struct rtpe_node *node, bencode_item_t *dict, char* cookie, enum async_ret_code *out_fd)
{
	struct sockaddr_un addr;
	int fd=-1, len, vcnt;
	char buf[0x10000];
	struct pollfd fds[1];
	struct iovec *v;

	v = bencode_iovec(dict, &vcnt, 1, 0);
	if (!v) {
		LM_ERR("error converting bencode to iovec\n");
		goto error;
	}

	len = 0;
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
			LM_ERR("can't create socket %d \n",errno);
			goto badproxy;
		}
		if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			LM_ERR("can't connect to RTP proxy %s (%d:%s)\n",node->rn_url.s,errno,strerror(errno));
			close(fd);
			goto badproxy;
		}

		do {
			len = writev(fd, v + 1, vcnt);
		} while (len == -1 && errno == EINTR);
		if (len <= 0) {
			LM_ERR("can't send command to RTP proxy %s (%d:%s)\n",node->rn_url.s,
			errno, strerror(errno));
			close(fd);
			goto badproxy;
		}
		*out_fd = fd;
	} else {
		if (rtpe_socks[node->idx] != -1) {
			fds[0].fd = rtpe_socks[node->idx];
			fds[0].events = POLLIN;
			fds[0].revents = 0;
			/* Drain input buffer */
			while ((poll(fds, 1, 0) == 1) &&
			((fds[0].revents & POLLIN) != 0)) {
				if (fds[0].revents & (POLLERR|POLLNVAL|POLLHUP)) {
					LM_WARN("error on rtpengine socket %d!\n", rtpe_socks[node->idx]);
					RTPE_IO_ERROR_CLOSE(rtpe_socks[node->idx]);
					break;
				}
				fds[0].revents = 0;
				if (recv(rtpe_socks[node->idx], buf, sizeof(buf) - 1, 0) < 0 &&	errno != EINTR) {
					LM_WARN("error while draining rtpengine %d!\n", errno);
					RTPE_IO_ERROR_CLOSE(rtpe_socks[node->idx]);
					break;
				}
			}
		}

		v[0].iov_base = cookie;
		v[0].iov_len = strlen(v[0].iov_base);
		if (rtpe_socks[node->idx] == -1 && !rtpengine_connect_node(node)) {
			LM_ERR("cannot reconnect RTP engine socket!\n");
			goto badproxy;
		}

		fd = socket((node->rn_umode == 6) ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			LM_ERR("can't create socket %d \n",errno);
			goto badproxy;
		}
		if (connect(fd, &(node->ai_addr), node->ai_addrlen) < 0) {
			LM_ERR("can't connect to RTP proxy %s (%d:%s)\n",node->rn_url.s,errno,strerror(errno));
			close(fd);
			goto badproxy;
		}
		do {
			len = writev(fd, v, vcnt + 1);
		} while (len == -1 && (errno == EINTR || errno == ENOBUFS || errno == EMSGSIZE));

		if (len <= 0) {
			LM_ERR("can't send command to RTP proxy %s (%d:%s)\n",node->rn_url.s,
			errno, strerror(errno));

			RTPE_IO_ERROR_CLOSE(fd);
			goto badproxy;
		}
		*out_fd = fd;
	}

	return 1;

badproxy:
	LM_ERR("proxy <%s> does not respond, disable it\n", node->rn_url.s);
	node->rn_disabled = 1;
	node->rn_recheck_ticks = get_ticks() + rtpengine_disable_tout;
error:
	if (fd>0)
		close(fd);

	*out_fd = ASYNC_NO_IO;
	return -1;
}


static int rtpe_function_call_async(struct sip_msg *msg, async_ctx *ctx, str *flags_str,
        pv_spec_t *spvar, pv_spec_t *bpvar, str *body, enum rtpe_operation op)
{
	struct ng_flags_parse ng_flags;
	str oldbody;
	struct rtpe_node *node;
	struct rtpe_set *set;
	int ret, read_fd;
	rtpe_async_param *param;
	char* cookie = NULL;
	char *err;

	bencode_buffer_t *bencbuf = pkg_malloc(sizeof(bencode_buffer_t));
	memset(&ng_flags, 0, sizeof(ng_flags));

	/*** get & init basic stuff needed ***/

	if (op != OP_DELETE) {
		if (!body) {
			if (extract_body(msg, &oldbody) == -1) {
				LM_ERR("can't extract body from the message\n");
				goto error;
			}
		} else {
			oldbody = *body;
		}
	}

	if(rtpe_function_call_prepare(bencbuf, msg, op, &ng_flags, flags_str, &oldbody, NULL,&err) < 0)
		goto error;

	/*** send it out ***/
	if ( (set=rtpe_ctx_set_get())==NULL )
		set = *default_rtpe_set;

	RTPE_START_READ();

	/* FIXME - failover logic for async is disabled for now */
	node = select_rtpe_node(ng_flags.call_id, set,NULL);
	if (!node) {
		LM_ERR("no available proxies\n");
		RTPE_STOP_READ();
		goto error;
	}

	cookie = gencookie();
	ret = start_async_send_rtpe_command(node, ng_flags.dict, cookie, &read_fd);

	RTPE_STOP_READ();
	LM_DBG("async proxy reply: %d\n", ret);

	if (read_fd == ASYNC_NO_IO) {
		ctx->resume_f = NULL;
		ctx->resume_param = NULL;
		bencode_buffer_free(bencbuf);
		pkg_free(bencbuf);
		return ret;
	} else if (read_fd == ASYNC_SYNC) {
		/* no need for async - transfer already completed! */
		async_status = ASYNC_SYNC;
		bencode_buffer_free(bencbuf);
		pkg_free(bencbuf);
		return ret;
	}

	param = pkg_malloc(sizeof(rtpe_async_param));
	if (!param) {
		LM_ERR("no more pkg mem\n");
		goto error;
	}
	memset(param, 0, sizeof(rtpe_async_param));

	param->bencbuf = bencbuf;
	param->op = op;
	param->node = node;
	param->cookie = pkg_strdup(cookie);
	param->bpvar = bpvar;
	param->spvar = spvar;

	ctx->resume_f = resume_async_send_rtpe_command;
	ctx->timeout_f = timeout_async_send_rtpe_command;
	ctx->resume_param = param;

	/* async started with success */
	async_status = read_fd;
	return 1;

error:
	bencode_buffer_free(bencbuf);
	pkg_free(bencbuf);
	return -1;
}

static int
rtpengine_offer_af(struct sip_msg *msg, async_ctx *ctx, str *flags, pv_spec_t *spvar, pv_spec_t *bpvar, str *body)
{
        LM_DBG("Async rtpengine_offer\n");

        if (set_rtpengine_set_from_avp(msg) == -1)
            return -1;

	return rtpe_function_call_async(msg, ctx, flags, spvar, bpvar, body, OP_OFFER);
}

static int
rtpengine_answer_af(struct sip_msg *msg, async_ctx *ctx, str *flags, pv_spec_t *spvar, pv_spec_t *bpvar, str *body)
{
        LM_DBG("Async rtpengine_answer\n");

        if (set_rtpengine_set_from_avp(msg) == -1)
            return -1;

        if (msg->first_line.type == SIP_REQUEST)
                if (msg->first_line.u.request.method_value != METHOD_ACK)
                        return -1;

	return rtpe_function_call_async(msg, ctx, flags, spvar, bpvar, body, OP_ANSWER);
}

static int
rtpengine_delete_af(struct sip_msg *msg, async_ctx *ctx, str *flags, pv_spec_t *spvar)
{
        LM_DBG("Async rtpengine_delete\n");

        if (set_rtpengine_set_from_avp(msg) == -1)
                return -1;

	return rtpe_function_call_async(msg, ctx, flags, spvar, NULL, NULL, OP_DELETE);
}

/* This function assumes p points to a line of requested type. */

static int
set_rtpengine_set_f(struct sip_msg * msg, rtpe_set_link_t *rtpl)
{
	struct rtpe_set *set;

	if (rtpl->type == RTPE_SET_NONE) {
		set = select_rtpe_set(rtpl->v.id);
		if(set==NULL) {
			LM_ERR("could not locate rtpengine set %d\n", rtpl->v.id);
			return -1;
		}
	} else
		set = rtpl->v.rset;

	rtpe_ctx_set_fill(set);

	return 1;
}

static int
rtpengine_manage(struct sip_msg *msg, str *flags, pv_spec_t *spvar,
		pv_spec_t *bpvar, str *body)
{
	int method;
	int nosdp;
	int op = OP_ANSWER;
	struct cell *t;

	if(msg->cseq==NULL && ((parse_headers(msg, HDR_CSEQ_F, 0)==-1)
				|| (msg->cseq==NULL)))
	{
		LM_ERR("no CSEQ header\n");
		return -1;
	}

	method = get_cseq(msg)->method_id;

	if(!(method==METHOD_INVITE || method==METHOD_ACK || method==METHOD_CANCEL
				|| method==METHOD_BYE || method==METHOD_UPDATE || method==METHOD_PRACK))
		return -1;

	if(method==METHOD_CANCEL || method==METHOD_BYE)
		return rtpengine_delete(msg, flags, NULL, NULL, spvar);

	if (body)
		nosdp = body->len != 0;
	else if(has_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP))
		nosdp = 0;
	else
		nosdp = parse_sdp(msg)?0:1;

	if(msg->first_line.type == SIP_REQUEST) {
		if(nosdp==0) {
			switch (method) {
				case METHOD_ACK:
				case METHOD_PRACK:
					op = OP_ANSWER;
					break;
				case METHOD_INVITE:
					if(route_type==FAILURE_ROUTE)
						return rtpengine_delete(msg, flags, NULL, NULL, spvar);
					/* fall through */
				case METHOD_UPDATE:
					op = OP_OFFER;
					break;
				default:
					return -1;
			}
			return rtpengine_offer_answer(msg, flags, NULL, spvar, bpvar, body, op);
		} else if (method==METHOD_INVITE) {
			msg->msg_flags |= FL_BODY_NO_SDP;
		}
	} else if(msg->first_line.type == SIP_REPLY) {
		if(msg->first_line.u.reply.statuscode>=300)
			return rtpengine_delete(msg, flags, NULL, NULL, spvar);
		if(nosdp==0) {
			if(method==METHOD_UPDATE)
				return rtpengine_offer_answer(msg, flags, NULL, spvar, bpvar, body, OP_ANSWER);
			if (tmb.t_gett != NULL) {
				t = tmb.t_gett();
				if(t && t != T_UNDEFINED && t->uas.request->msg_flags & FL_BODY_NO_SDP)
					op = OP_OFFER;
			}
			/* op defaults to OP_ANSWER */
			return rtpengine_offer_answer(msg, flags, NULL, spvar, bpvar, body, op);
		}
	}
	return -1;
}

static int
rtpengine_manage_f(struct sip_msg *msg, str *flags, pv_spec_t *spvar,
		pv_spec_t *bpvar, str *body)
{
	if (set_rtpengine_set_from_avp(msg) == -1)
	    return -1;

	return rtpengine_manage(msg, flags, spvar, bpvar, body);
}

static int
rtpengine_offer_f(struct sip_msg *msg, str *flags, pv_spec_t *spvar,
		pv_spec_t *bpvar, str *body)
{
	if (set_rtpengine_set_from_avp(msg) == -1)
	    return -1;

	return rtpengine_offer_answer(msg, flags, NULL, spvar, bpvar, body, OP_OFFER);
}

static int
rtpengine_answer_f(struct sip_msg *msg, str *flags, pv_spec_t *spvar,
		pv_spec_t *bpvar, str *body)
{
	if (set_rtpengine_set_from_avp(msg) == -1)
	    return -1;

	if (msg->first_line.type == SIP_REQUEST)
		if (msg->first_line.u.request.method_value != METHOD_ACK &&
				msg->first_line.u.request.method_value != METHOD_PRACK)
			return -1;

	return rtpengine_offer_answer(msg, flags, NULL, spvar, bpvar, body, OP_ANSWER);
}

static int
rtpengine_offer_answer_body(struct sip_msg *msg, str *flags, str *node,
		pv_spec_t *spvar, str *body, str *outbody, struct rtpe_set *set, int op)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *dict;
	str oldbody, newbody;
	struct lump *anchor;

	if (!body) {
		if (extract_body(msg, &oldbody) == -1) {
			LM_ERR("can't extract body from the message\n");
			return -1;
		}
	} else {
		oldbody = *body;
	}

	dict = rtpe_function_call_ok(&bencbuf, msg, op, flags, &oldbody, spvar, set, node, NULL);
	if (!dict)
		return -1;

	if (!bencode_dictionary_get_str_dup(dict, "sdp", &newbody)) {
		LM_ERR("failed to extract sdp body from proxy reply\n");
		goto error;
	}

	if (outbody) {
		*outbody = newbody;
	} else if (!body || (extract_body(msg, &oldbody) > 0)) {
		/* otherwise directly set the body of the message */
		anchor = del_lump(msg, oldbody.s - msg->buf, oldbody.len, 0);
		if (!anchor) {
			LM_ERR("del_lump failed\n");
			goto error_free;
		}
		if (!insert_new_lump_after(anchor, newbody.s, newbody.len, 0)) {
			LM_ERR("insert_new_lump_after failed\n");
			goto error_free;
		}
	} else {
		LM_ERR("cannot change old body!\n");
		goto error_free;
	}

	bencode_buffer_free(&bencbuf);
	return 1;

error_free:
	pkg_free(newbody.s);
error:
	bencode_buffer_free(&bencbuf);
	return -1;
}

static int
rtpengine_offer_answer(struct sip_msg *msg, str *flags, str *node,
		pv_spec_t *spvar, pv_spec_t *bpvar, str *body, int op)
{
	str newbody;
	pv_value_t val;
	int ret = rtpengine_offer_answer_body(msg, flags, node,
			spvar, body, (bpvar?&newbody:NULL), NULL, op);
	if (ret < 0)
		return -1;
	/* if we have a variable to store into, use it */
	if (bpvar) {
		memset(&val, 0, sizeof(pv_value_t));
		val.flags = PV_VAL_STR;
		val.rs = newbody;
		if(pv_set_value(msg, bpvar, (int)EQ_T, &val)<0)
			LM_ERR("setting PV failed\n");
		pkg_free(newbody.s);
	}
	return ret;
}


static int
start_recording_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_START_RECORDING, flags, NULL, NULL, spvar);
}

static int
stop_recording_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_STOP_RECORDING, flags, NULL, NULL, spvar);
}

static int
pause_recording_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_PAUSE_RECORDING, flags, NULL, NULL, spvar);
}

/**
 * Gets the rtp stats and tries to store them in a context, if that's possible
 * Returns:
 *   1: success, stored in ctx and/or taken from ctx
 *   0: query ok, but didn't get to save the buffer in ctx
 *  -1: failure
 */
static int rtpe_fetch_stats(struct sip_msg *msg, bencode_buffer_t *retbuf, bencode_item_t **retdict)
{
	/* we need a ctx */
	struct rtpe_ctx *ctx;
	bencode_item_t *dict;
	static bencode_buffer_t bencbuf;

	/* caching mechanism for statistics */
	ctx = rtpe_ctx_get();
	if (ctx) {
		/* allocate stats now */
		if (ctx->stats) {
			if (!ctx->stats->dict) /* there was a previous run and resulted in an error */
				return -1;
			*retbuf = ctx->stats->buf;
			*retdict = ctx->stats->dict;
			return 1;
		}
		ctx->stats = pkg_malloc(sizeof *ctx->stats);
		if (!ctx->stats) {
			LM_ERR("not enough pkg for stats!\n");
			/* cannot store stats */
			ctx = NULL;
		} else {
			memset(ctx->stats, 0, sizeof *ctx->stats);
		}
	}

	dict = rtpe_function_call_ok(&bencbuf, msg, OP_QUERY,
			NULL, NULL, NULL, NULL, NULL, NULL);
	if (!dict)
		return -1;

	/* if thers's no ctx, we make the request on the spot, but we don't save
	 * the reply, because we don't have where */
	if (ctx) {
		ctx->stats->buf = bencbuf;
		ctx->stats->dict = dict;
		*retbuf = bencbuf;
		*retdict = dict;
		return 1;
	} else {
		*retbuf = bencbuf;
		*retdict = dict;
		return 0;
	}
}

/*
 * Returns the current RTP-Statistics from the RTP-Proxy
 */
static inline void pv_get_rtpstat_line(bencode_item_t *dict, pv_value_t *res)
{
	static char buf[256];
	bencode_item_t *tot, *rtp, *rtcp;
	str ret;

	tot = bencode_dictionary_get_expect(dict, "totals", BENCODE_DICTIONARY);
	rtp = bencode_dictionary_get_expect(tot, "RTP", BENCODE_DICTIONARY);
	rtcp = bencode_dictionary_get_expect(tot, "RTCP", BENCODE_DICTIONARY);
	if (!rtp || !rtcp) {
		pv_get_null(NULL, NULL, res);
		return;
	}
	ret.s = buf;
	ret.len = snprintf(buf, sizeof(buf),
		"RTP: %lli bytes, %lli packets, %lli errors; "
		"RTCP: %lli bytes, %lli packets, %lli errors",
		bencode_dictionary_get_integer(rtp, "bytes", -1),
		bencode_dictionary_get_integer(rtp, "packets", -1),
		bencode_dictionary_get_integer(rtp, "errors", -1),
		bencode_dictionary_get_integer(rtcp, "bytes", -1),
		bencode_dictionary_get_integer(rtcp, "packets", -1),
		bencode_dictionary_get_integer(rtcp, "errors", -1));
	pv_get_strval(NULL, NULL, res, &ret);
}

#define BENCODE_GET_STR(_be, _s) \
	do { \
		(_s)->s = (_be)->iov[1].iov_base; \
		(_s)->len = (_be)->iov[1].iov_len; \
	} while (0)

static int bencode_dictionary_tag_has_ssrc(bencode_item_t *dict, str *ssrc, str *tag)
{
	str i;
	bencode_item_t *m, *s, *ss;
	dict = bencode_dictionary_get_expect(dict, "medias", BENCODE_LIST);
	if (!dict) {
		LM_DBG("medias list not found!\n");
		return 0;
	}
	/* go through each media */
	for (m = dict->child; m; m = m->sibling) {
		s = bencode_dictionary_get_expect(m, "streams", BENCODE_LIST);
		if (!s)
			continue;
		/* now go through each stream */
		for (s = s->child; s; s = s->sibling) {
			ss = bencode_dictionary_get_expect(s, "SSRC", BENCODE_INTEGER);
			if (!ss)
				continue;
			i.s = int2str(ss->value, &i.len);
			if (str_strcmp(&i, ssrc) == 0) {
				LM_DBG("SSRC %.*s belongs to tag %.*s\n", ssrc->len,
						ssrc->s, tag->len, tag->s);
				return 1;
			}
		}
	}
	/*LM_DBG("SSRC %.*s not for tag %.*s\n", ssrc->len, ssrc->s, tag->len, tag->s);*/
	return 0;
}

static bencode_item_t *bencode_dictionary_get_tag(bencode_item_t *dict, str *tag)
{
	str tmp;
	bencode_item_t *c;

	dict = bencode_dictionary_get_expect(dict, "tags", BENCODE_DICTIONARY);
	if (!dict) {
		LM_DBG("tags dictionary not found!\n");
		return 0;
	}
	for (c = dict->child; c; c = c->sibling)
		if (c->type == BENCODE_STRING) {
			BENCODE_GET_STR(c, &tmp);
			if (str_strcmp(&tmp, tag) != 0)
					continue;
			/* found the dictionary, it's next element! */
			c = c->sibling;
			if (!c)
				return NULL;
			if (c->type != BENCODE_DICTIONARY)
				return NULL;
			return c;
		}
	return NULL;
}

static inline void pv_handle_rtpstat(enum rtpe_stat s, str *index,
		  pv_value_t *res, bencode_item_t *dict)
{

	bencode_item_t *c, *i, *m, *tag = NULL;
	int mos, mos_no, mos_max, mos_min, mos_at;
	time_t created = 0;
	str tmp;
	char *key;
	enum rtpe_stat_type t = rtpe_get_stat_by_type(s);
	enum rtpe_stat_dict d = rtpe_get_stat_by_dict(s);

	/* init to null */
	pv_get_null(NULL, NULL, res);

	if (t == STAT_MIN_AT || t == STAT_MAX_AT) {
		/* for min and max, store when the session was created */
		c = bencode_dictionary_get_expect(dict, "created", BENCODE_INTEGER);
		if (!c) {
			LM_DBG("no created number in the dictionary!\n");
			return;
		}
		created = c->value;
	}

	if (index) {
		tag = bencode_dictionary_get_tag(dict, index);
		if (!tag) {
			LM_DBG("no session with tag %.*s\n", index->len, index->s);
			return;
		}
	}
	dict = bencode_dictionary_get_expect(dict, "SSRC", BENCODE_DICTIONARY);
	if (!dict) {
		LM_DBG("no SSRC node in response!\n");
		return;
	}

	/* search for the dictionary of this tag */
	mos = 0;
	mos_no = 0;
	mos_max = -1;
	mos_min = INT_MAX;
	mos_at = -1;
	for (c = dict->child; c; c = c->sibling) {
		/* if a tag exists, check if this SSRC belongs to it */
		if (tag) {
			if (c->type == BENCODE_STRING) {
				BENCODE_GET_STR(c, &tmp);
				if (!bencode_dictionary_tag_has_ssrc(tag, &tmp, index))
					continue;
				/* this is the SSRC we are interested in! */
				c = c->sibling;
				if (!c) {
					LM_DBG("no value for %.*s SSRC\n", tmp.len, tmp.s);
					return;
				}
			} else
				continue; /* go to the next object until we find the SSRC */
		}
		if (c->type != BENCODE_DICTIONARY)
			continue;

		switch (t) {
			case STAT_AVERAGE:
				key = "average MOS";
				break;

			case STAT_MAX:
			case STAT_MAX_AT:
				key = "highest MOS";
				break;

			case STAT_MIN:
			case STAT_MIN_AT:
				key = "lowest MOS";
				break;

			default:
				LM_BUG("unknown command %d\n", t);
				return;
		}
		m = bencode_dictionary_get_expect(c, key, BENCODE_DICTIONARY);
		if (!m)
			continue;

		switch (d) {
			case STAT_MOS:
				i = bencode_dictionary_get_expect(m, "MOS", BENCODE_INTEGER);
				break;

			case STAT_JITTER:
				i = bencode_dictionary_get_expect(m, "jitter", BENCODE_INTEGER);
				break;

			case STAT_ROUNDTRIP:
				i = bencode_dictionary_get_expect(m, "round-trip time", BENCODE_INTEGER);
				break;

			case STAT_PACKETLOSS:
				i = bencode_dictionary_get_expect(m, "packet loss", BENCODE_INTEGER);
				break;

			default:
				LM_BUG("unknown command %d\n", d);
				return;
		}
		if (!i)
			continue;

		switch (t) {
			case STAT_AVERAGE:
				mos += i->value;
				mos_no++;
				break;

			case STAT_MAX:
			case STAT_MAX_AT:
				if (i->value > mos_max) {
					mos_max = i->value;
					mos_at = -2; /* force update mos_at */
				}
				break;

			case STAT_MIN:
			case STAT_MIN_AT:
				if (i->value < mos_min) {
					mos_min = i->value;
					mos_at = -2; /* force update mos_at */
				}
				break;

			default:
				LM_BUG("unknown command %d\n", t);
				return;
		}
		if (mos_at == -2 && (t == STAT_MIN_AT || t == STAT_MAX_AT)) {
			i = bencode_dictionary_get_expect(m, "reported at", BENCODE_INTEGER);
			if (!i)
				continue;
			mos_at = i->value - created;
		}
	}
	/* wrap them up */
	switch (t) {
		case STAT_AVERAGE:
			if (mos_no == 0) {
				LM_DBG("no MOS found!\n");
				return;
			}
			mos = mos / mos_no;
			break;

		case STAT_MAX:
			if (mos_max < 0) {
				LM_DBG("max MOS not found!\n");
				return;
			}
			mos = mos_max;
			break;

		case STAT_MIN:
			if (mos_min == INT_MAX) {
				LM_DBG("min MOS not found!\n");
				return;
			}
			mos = mos_min;
			break;

		case STAT_MAX_AT:
		case STAT_MIN_AT:
			if (mos_at < 0) {
				LM_DBG("MOS at not found!\n");
				return;
			}
			mos = mos_at;
			break;

		default:
			LM_BUG("unknown command %d\n", t);
			return;
	}
	pv_get_sintval(NULL, NULL, res, mos);
}

static inline int
pv_get_rtpstat(struct sip_msg *msg, pv_param_t *param,
		  pv_value_t *res, bencode_item_t *dict)
{
	str aux;
	str *idx;
	enum rtpe_stat s;

	if (param->pvn.type == PVE_NAME_PVAR) {
		if (pv_printf_s(msg, (pv_elem_t *)param->pvn.u.isname.name.s.s, &aux) < 0) {
			LM_ERR("Cannot fetch RTP stat name!\n");
			return -1;
		}
		s = rtpe_get_stat_by_name(&aux);
		if (s == STAT_UNKNOWN) {
			LM_ERR("Unknown RTP stat %.*s\n", aux.len, aux.s);
			return -1;
		}
	} else
		s = param->pvn.u.isname.name.n;

	if (param->pvi.type == PVE_NAME_NONE)
		idx = NULL;
	else if (param->pvi.type == PVE_NAME_INTSTR)
		idx = (str *)param->pvi.u.dval;
	else {
		if (pv_printf_s(msg, (pv_elem_t *)param->pvi.u.dval, &aux) < 0) {
			LM_ERR("Cannot fetch RTP stat index!\n");
			return -1;
		}
		idx = &aux;
	}
	pv_handle_rtpstat(s, idx, res, dict);

	return 1;
}

static int
pv_get_rtpstat_f(struct sip_msg *msg, pv_param_t *param,
		  pv_value_t *res)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *dict;
	int rc;

	rc = rtpe_fetch_stats(msg, &bencbuf, &dict);
	if (rc < 0)
		return -1;

	if (param->pvn.type == PVE_NAME_NONE)
		pv_get_rtpstat_line(dict, res);
	else if (pv_get_rtpstat(msg, param, res, dict) < 0) {
		LM_ERR("cannot fetch RTP statistic!\n");
		goto error;
	}

	if (!rc)
		bencode_buffer_free(&bencbuf);
	return 0;

error:
	if (!rc)
		bencode_buffer_free(&bencbuf);
	return -1;
}

static cJSON *bson2json(bencode_item_t *i)
{
	str stmp;
	cJSON *ret, *tmp;
	bencode_item_t *c;
	switch (i->type) {
		case BENCODE_STRING:
			return cJSON_CreateStr(i->iov[1].iov_base, i->iov[1].iov_len);

		case BENCODE_INTEGER:
			return cJSON_CreateNumber(i->value);

		case BENCODE_LIST:
			ret = cJSON_CreateArray();
			for (c = i->child; c; c = c->sibling) {
				tmp = bson2json(c);
				if (!tmp) {
					cJSON_Delete(ret);
					return NULL;
				}
				cJSON_AddItemToArray(ret, tmp);
			}
			return ret;

		case BENCODE_DICTIONARY:
			ret = cJSON_CreateObject();
			for (c = i->child; c; c = c->sibling) {
				/* first is key */
				stmp.s = c->iov[1].iov_base;
				stmp.len = c->iov[1].iov_len;
				/* next is value */
				c = c->sibling;
				tmp = bson2json(c);
				if (!tmp) {
					cJSON_Delete(ret);
					return NULL;
				}
				_cJSON_AddItemToObject(ret, &stmp, tmp);
			}
			return ret;

		default:
			LM_ERR("unsupported bson type %d\n", i->type);
			return NULL;
	}
}

static int
pv_get_rtpquery_f(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	static char query_buf[512];
	bencode_buffer_t bencbuf;
	bencode_item_t *dict;
	struct rtpe_ctx *ctx;
	cJSON *out = NULL;
	str ret;

	if (rtpe_fetch_stats(msg, &bencbuf, &dict) < 0)
		return -1;
	ctx = rtpe_ctx_tryget();

	/* TODO: handle reply */
	out = bson2json(dict);
	if (!out) {
		LM_ERR("cannot convert bson to json!\n");
		goto error;
	}
	if (ctx) {
		/* we have ctx, just print it there */
		ret.s = cJSON_PrintUnformatted(out);
		if (!ret.s) {
			LM_ERR("cannot print unformatted json!\n");
			goto error;
		}
		ret.len = strlen(ret.s);
		ctx->stats->json = ret;
	} else {
		if (cJSON_PrintPreallocated(out, query_buf, sizeof(query_buf), 0) == 0) {
			LM_ERR("cannot print in preallocated buffer!\n");
			goto error;
		}
		ret.s = query_buf;
		ret.len = strlen(ret.s);
		/* also release the buffer */
		bencode_buffer_free(&bencbuf);
	}

	cJSON_Delete(out);
	return pv_get_strval(msg, param, res, &ret);

error:
	if (!ctx)
		bencode_buffer_free(&bencbuf);
	if (out)
		cJSON_Delete(out);
	return -1;
}


static int _add_rtpengine_from_database(void)
{

	/* select * from rtpproxy_sockets */
	db_key_t colsToReturn[2];
	db_res_t *result = NULL;
	int rowCount = 0;
	char *rtpe_socket;
	db_row_t *row;
	db_val_t *row_vals;
	int set_id;

	colsToReturn[0]=&db_rtpe_sock_col;
	colsToReturn[1]=&db_rtpe_set_col;

	if(db_functions.use_table(db_connection, &db_table) < 0) {
		LM_ERR("Error trying to use table\n");
		return -1;
	}

	if(db_functions.query(db_connection, 0, 0, 0,colsToReturn, 0, 2, 0,
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
		LM_DBG("No rtpengine proxies were found\n");
		if(db_functions.free_result(db_connection, result) < 0){
			LM_ERR("Error freeing result\n");
			return -1;
		}
		return 0;
	}

	for(rowCount=0; rowCount < RES_ROW_N(result); rowCount++) {

		row= &result->rows[rowCount];
		row_vals = ROW_VALUES(row);

		rtpe_socket = (char*)row_vals[0].val.string_val;
		if(rtpe_socket == NULL)
		{
			LM_ERR("NULL value for %s column\n", db_rtpe_sock_col.s);
			goto error;
		}
		set_id= row_vals[1].val.int_val;

		if(rtpengine_add_rtpengine_set(rtpe_socket, set_id) == -1)
		{
			LM_ERR("failed to add RTPEngine socket %s\n", rtpe_socket);
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

static int rtpengine_playmedia_f(struct sip_msg* msg, str *flags,
		pv_spec_t *dspec, pv_spec_t *spvar)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *dict;
	pv_value_t val;

	if (set_rtpengine_set_from_avp(msg) == -1)
		return -1;

	dict = rtpe_function_call_ok(&bencbuf, msg, OP_START_MEDIA, flags,
			NULL, spvar, NULL, NULL, NULL);
	if (!dict) {
		LM_ERR("could not start media!\n");
		return -1;
	}

	if (dspec) {
		memset(&val, 0, sizeof(pv_value_t));
		val.flags = PV_TYPE_INT|PV_VAL_INT;
		val.ri = bencode_dictionary_get_integer(dict, "duration", -1);
		if (pv_set_value(msg, dspec, 0, &val) != 0)
			LM_ERR("failed to set media file duration!\n");
	}
	bencode_buffer_free(&bencbuf);
	return 1;
}

static int rtpengine_stopmedia_f(struct sip_msg* msg, str *flags,
		pv_spec_t *spvar, pv_spec_t *last_frame_pos)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *dict;
	pv_value_t val;

	if (set_rtpengine_set_from_avp(msg) == -1)
		return -1;

	dict = rtpe_function_call_ok(&bencbuf, msg, OP_STOP_MEDIA, flags,
			NULL, spvar, NULL, NULL, NULL);
	if (!dict) {
		LM_ERR("could not stop media!\n");
		return -1;
	}

	if (last_frame_pos) {
		memset(&val, 0, sizeof(pv_value_t));
		val.flags = PV_TYPE_INT|PV_VAL_INT;
		val.ri = bencode_dictionary_get_integer(dict, "last-frame-pos", -1);
		if (pv_set_value(msg, last_frame_pos, 0, &val) != 0)
			LM_ERR("failed to set last-frame-pos after stopping media!\n");
	}
	bencode_buffer_free(&bencbuf);
	return 1;
}

static int rtpengine_blockmedia_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_BLOCK_MEDIA, flags, NULL, NULL, spvar);
}

static int rtpengine_unblockmedia_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_UNBLOCK_MEDIA, flags, NULL, NULL, spvar);
}

static int rtpengine_blockdtmf_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_BLOCK_DTMF, flags, NULL, NULL, spvar);
}

static int rtpengine_unblockdtmf_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_UNBLOCK_DTMF, flags, NULL, NULL, spvar);
}

static int rtpengine_start_forward_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_START_FORWARD, flags, NULL, NULL, spvar);
}

static int rtpengine_stop_forward_f(struct sip_msg* msg, str *flags, pv_spec_t *spvar)
{
	return rtpe_function_call_simple(msg, OP_STOP_FORWARD, flags, NULL, NULL, spvar);
}

static int rtpengine_play_dtmf_f(struct sip_msg* msg, str *code, str *flags, pv_spec_t *spvar)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *ret, *d_code;

	if (set_rtpengine_set_from_avp(msg) == -1)
	    return -1;

	if (bencode_buffer_init(&bencbuf)) {
		LM_ERR("could not initialize bencode_buffer_t\n");
		return -2;
	}
	d_code = bencode_dictionary(&bencbuf);
	if (!d_code) {
		LM_ERR("could not initialize bencode dictionary\n");
		return -2;
	}
	bencode_dictionary_add_str(d_code, "code", code);
	ret = rtpe_function_call_ok(&bencbuf, msg, OP_PLAY_DTMF,
			flags, NULL, spvar, NULL, NULL, d_code);
	if (!ret)
		return -2;

	bencode_buffer_free(&bencbuf);
	return 1;
}

static void rtpengine_raise_event(int sender, void *p)
{
	int err;
	cJSON *param;
	cJSON *jparams;
	str name, jstring;
	evi_params_p eparams = NULL;
	char *buf = (char *)p;

	jparams = cJSON_Parse(buf);
	shm_free(p);
	if (!jparams) {
		LM_ERR("could not parse json notification %s\n", buf);
		return;
	}

	if (!(jparams->type &cJSON_Object)) {
		LM_ERR("json is not an object\n");
		return;
	}

	if (!(eparams = evi_get_params())) {
		LM_ERR("cannot create parameters list\n");
		goto end;
	}

	for (param = jparams->child; param; param = param->next) {
		name.s = param->string;
		name.len = strlen(name.s);
		switch (param->type) {
			case cJSON_Number:
				err = evi_param_add_int(eparams, &name, &param->valueint);
				break;
			case cJSON_String:
				jstring.s = param->valuestring;
				jstring.len = strlen(jstring.s);
				err = evi_param_add_str(eparams, &name, &jstring);
				break;
			default:
				jstring.s = cJSON_PrintUnformatted(param);
				jstring.len = strlen(jstring.s);
				err = evi_param_add_str(eparams, &name, &jstring);
				cJSON_PurgeString(jstring.s);
				break;
		}
		if (err) {
			LM_ERR("could not add parameter %s\n", name.s);
			evi_free_params(eparams);
			goto end;
		}
	}

	/* all good: dispatch job! */
	evi_raise_event(rtpengine_notify_event, eparams);

end:
	cJSON_Delete(jparams);
}

#define RTPENGINE_DGRAM_BUF		35536

static int rtpengine_io_callback(int fd, void *fs, int was_timeout)
{
	int ret;
	char *p;
	char buffer[RTPENGINE_DGRAM_BUF];

	do
		ret = read(fd, buffer, RTPENGINE_DGRAM_BUF);
	while (ret == -1 && errno == EINTR);
	if (ret < 0) {
		LM_ERR("problem reading on socket %s:%u (%s:%d)\n",
				rtpengine_notify_sock.s, rtpengine_notify_port, strerror(errno), errno);
		return -1;
	}

	if (!evi_probe_event(rtpengine_notify_event)) {
		LM_DBG("nothing to do - nobody is listening!\n");
		return 0;
	}

	p = shm_malloc(ret + 1);
	if (!p) {
		/* coverity[string_null] - false positive CID #211356 */
		LM_ERR("could not allocate %d for buffer %.*s\n", ret, ret, buffer);
		return -1;
	}
	memcpy(p, buffer, ret);
	p[ret] = '\0';

	LM_INFO("dispatching buffer: %s\n", p);
	if (ipc_dispatch_rpc(rtpengine_raise_event, p) < 0) {
		LM_ERR("could not dispatch notification job!\n");
		shm_free(p);
	}
	return 0;
}

static void rtpengine_notify_process(int rank)
{
	int ret;
	char *p;
	str s_port;
	unsigned int port;
	static int rtpengine_notify_fd;
	union sockaddr_union ss;

	p = q_memchr(rtpengine_notify_sock.s, ':', rtpengine_notify_sock.len);
	if (!p) {
		LM_ERR("no port specified in notification socket %.*s!\n",
				rtpengine_notify_sock.len, rtpengine_notify_sock.s);
		return;
	}

	s_port.s = p + 1;
	s_port.len = rtpengine_notify_sock.s + rtpengine_notify_sock.len - s_port.s;

	if (s_port.len <= 0 || str2int(&s_port, &port) < 0 || port > 65535) {
		LM_ERR("invalid port specified in notification socket %.*s\n",
				rtpengine_notify_sock.len, rtpengine_notify_sock.s);
		return;
	}
	rtpengine_notify_sock.len -= s_port.len + 1;
	trim(&rtpengine_notify_sock);
	rtpengine_notify_sock.s[rtpengine_notify_sock.len] = '\0';

	memset(&ss, 0, sizeof(ss));
	if (rtpengine_notify_sock.s[0] == '[') {
		ss.sin6.sin6_family = AF_INET6;
		ss.sin6.sin6_port = htons(port);
		ret = inet_pton(AF_INET6, rtpengine_notify_sock.s, &ss.sin6.sin6_addr);
	} else {
		ss.sin.sin_family = AF_INET;
		ss.sin.sin_port = htons(port);
		ret = inet_pton(AF_INET, rtpengine_notify_sock.s, &ss.sin.sin_addr);
	}
	if (ret != 1) {
		LM_ERR("could not create address for %s\n", rtpengine_notify_sock.s);
		return;
	}
	rtpengine_notify_fd = socket(ss.s.sa_family, SOCK_DGRAM, 0);
	if (rtpengine_notify_fd < 0) {
		LM_ERR("could not create notification socket!\n");
		return;
	}

	if (bind(rtpengine_notify_fd, &ss.s, sizeof(ss)) == -1) {
		LM_ERR("could not bind notification socket %s:%u (%s:%d)\n",
				rtpengine_notify_sock.s, port, strerror(errno), errno);
		goto end;
	}

	if (reactor_proc_init("RTPengine events") < 0) {
		LM_ERR("failed to init the RTPengine events\n");
		goto end;
	}

	if (reactor_proc_add_fd(rtpengine_notify_fd, rtpengine_io_callback, NULL) < 0) {
		LM_CRIT("failed to add RTPengine listen socket to reactor\n");
		goto end;
	}

	reactor_proc_loop();
end:
	close(rtpengine_notify_fd);
}


static int fill_rtpengine_node(struct rtp_relay_server *server,
		str *s)
{
	if (server->node.s)
		shm_free(server->node.s);
	return shm_nt_str_dup(&server->node, s);
}

#define RTPE_APPEND_STR(_v) \
	do { \
		if (!(_v) || !(_v)->len) \
			break; \
		memcpy(p, (_v)->s, (_v)->len); \
		p += (_v)->len; \
		*p++ = ' '; \
	} while (0)

#define RTPE_APPEND_STRP(_p, _v) \
	do { \
		if (!(_v) || !(_v)->len) \
			break; \
		memcpy(p, _p "=", sizeof(_p)); \
		p += sizeof(_p); \
		RTPE_APPEND_STR(_v); \
	} while (0)

static str *rtpengine_get_call_flags(struct rtp_relay_session *sess,
		str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags)
{
	static str ret;
	char *p;
	str b;

	ret.s = pkg_malloc((sess->callid? (9/* 'call-id= ' */ + sess->callid->len): 0) +
			(sess->from_tag? (10/* 'from-tag= ' */ + sess->from_tag->len): 0) +
			(sess->to_tag? (8/* 'to-tag= ' */ + sess->to_tag->len): 0) +
			(in_iface? (10/* 'in-iface= ' */ + in_iface->len): 0) +
			(out_iface? (11/* 'out-iface= ' */ + out_iface->len): 0) +
			(type? (1/* ' ' */ + type->len): 0) +
			(global_flags? (1/* ' ' */ + global_flags->len): 0) +
			(flags? (1/* ' ' */ + flags->len): 0) +
			(extra_flags? (1/* ' ' */ + extra_flags->len): 0) +
			(sess->branch != RTP_RELAY_ALL_BRANCHES? 20/* 'via-branch-param=br ' */ + INT2STR_MAX_LEN : 0));
	if (!ret.s)
		return NULL;
	p = ret.s;
	RTPE_APPEND_STRP("call-id", sess->callid);
	RTPE_APPEND_STRP("from-tag", sess->from_tag);
	RTPE_APPEND_STRP("to-tag", sess->to_tag);
	RTPE_APPEND_STRP("in-iface", in_iface);
	RTPE_APPEND_STRP("out-iface", out_iface);
	RTPE_APPEND_STR(type);
	RTPE_APPEND_STR(global_flags);
	RTPE_APPEND_STR(flags);
	RTPE_APPEND_STR(extra_flags);
	if (sess->branch != RTP_RELAY_ALL_BRANCHES) {
		memcpy(p, "via-branch-param=br", 19);
		p += 19;

		b.s = int2str(sess->branch, &b.len);
		memcpy(p, b.s, b.len);
		p += b.len;
	}
	ret.len = p - ret.s;
	return &ret;
}
#undef RTPE_APPEND_STR
#undef RTPE_APPEND_STRP

static inline struct rtpe_set *rtpengine_get_set(int set)
{
	struct rtpe_set* rset;
	if (set != -1) {
		rset = select_rtpe_set(set);
		if (!rset) {
			LM_WARN("RTPEngine set %d\n not available! Using default %d...\n",
					set, DEFAULT_RTPE_SET_ID);
			rset = *default_rtpe_set;
		}
	} else {
		rset = *default_rtpe_set;
	}
	return rset;
}

static int rtpengine_api_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags)
{
	struct rtpe_set* rset;
	str *newflags, *node;
	pv_value_t val;
	int ret;

	RTPE_START_READ();
	if (!server->node.s) {
		node = NULL;
		rset = rtpengine_get_set(server->set);
		if (!rset) {
			LM_ERR("no rtpengine set availble!\n");
			RTPE_STOP_READ();
			return -1;
		}
		server->set = rset->id_set;
	} else {
		rset = select_rtpe_set(server->set);
		node = &server->node;
	}
	RTPE_STOP_READ();

	newflags = rtpengine_get_call_flags(sess, type, in_iface, out_iface,
			global_flags, flags, extra_flags);
	if (!newflags)
		return -1;
	ret = rtpengine_offer_answer_body(sess->msg, newflags, node,
			&media_pvar, sess->body, body, rset, OP_OFFER);
	pkg_free(newflags->s);
	if (ret >= 0) {
		if (pv_get_spec_value(sess->msg, &media_pvar, &val) >= 0)
			fill_rtpengine_node(server, &val.rs);
		else
			LM_ERR("could not retrieve the value of the used rtpengine!\n");
	}
	return ret;
}

static int rtpengine_api_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags)
{
	struct rtpe_set* rset;
	str *newflags;
	int ret;

	RTPE_START_READ();
	rset = select_rtpe_set(server->set);
	RTPE_STOP_READ();

	newflags = rtpengine_get_call_flags(sess, type, in_iface, out_iface,
			global_flags, flags, extra_flags);
	if (!newflags)
		return -1;
	ret = rtpengine_offer_answer_body(sess->msg, newflags, &server->node,
			NULL, sess->body, body, rset, OP_ANSWER);
	pkg_free(newflags->s);
	return ret;
}

static int rtpengine_api_delete(struct rtp_relay_session *sess, struct rtp_relay_server *server,
			str *flags, str *extra)
{
	struct sip_msg *msg;
	struct rtpe_set* rset;
	str *newflags;
	int ret;

	RTPE_START_READ();
	rset = select_rtpe_set(server->set);
	RTPE_STOP_READ();

	newflags = rtpengine_get_call_flags(sess, NULL, NULL, NULL, flags, extra, NULL);
	if (!newflags)
		return -1;
	msg = (sess->msg?sess->msg:get_dummy_sip_msg());
	ret = rtpengine_delete(msg, newflags, rset, &server->node, NULL);
	if (is_dummy_sip_msg(msg) == 0)
		release_dummy_sip_msg(msg);
	pkg_free(newflags->s);
	return ret;
}

static bencode_item_t *rtpengine_api_copy_op(struct rtp_relay_session *sess,
		int op, struct rtp_relay_server *server, void *copy_ctx,
		str *flags, unsigned int copy_flags, str *body)
{
	static bencode_buffer_t bencbuf;
	bencode_item_t *dict, *list = NULL;
	bencode_item_t *ret;
	struct sip_msg *msg;
	struct rtpe_set* rset;
	str viabranch;
	char viabranch_buf[2/* br */ + INT2STR_MAX_LEN];

	RTPE_START_READ();
	rset = select_rtpe_set(server->set);
	rtpe_ctx_set_fill( rset );
	RTPE_STOP_READ();

	if (bencode_buffer_init(&bencbuf)) {
		LM_ERR("could not initialize bencode_buffer_t\n");
		return NULL;
	}
	dict = bencode_dictionary(&bencbuf);

	if (sess->callid)
		bencode_dictionary_add_str(dict, "call-id", sess->callid);
	if (sess->branch != RTP_RELAY_ALL_BRANCHES) {
		viabranch.s = int2bstr(sess->branch, viabranch_buf, &viabranch.len);
		viabranch.s -= 2;
		viabranch.len += 2;
		memcpy(viabranch.s, "br", 2);
		bencode_dictionary_add_str(dict, "via-branch", &viabranch);
	}
	if (copy_ctx && ((str *)copy_ctx)->len)
		bencode_dictionary_add_str(dict, "to-tag", copy_ctx);
	if (copy_flags & RTP_COPY_MODE_SIPREC) {
		list = bencode_list(&bencbuf);
		bencode_list_add_string(list, "all");
		bencode_list_add_string(list, "siprec");
	} else if ((copy_flags & RTP_COPY_LEG_BOTH) == RTP_COPY_LEG_BOTH) {
		list = bencode_list(&bencbuf);
		bencode_list_add_string(list, "all");
	} else if (copy_flags & RTP_COPY_LEG_CALLER && sess->from_tag) {
		bencode_dictionary_add_str(dict, "from-tag", sess->from_tag);
	} else if (sess->to_tag && sess->to_tag->len) {
		bencode_dictionary_add_str(dict, "from-tag", sess->to_tag);
	}
	if (copy_flags & RTP_COPY_MODE_DISABLE) {
		if (!list)
			list = bencode_list(&bencbuf);
		bencode_list_add_string(list, "inactive");
	}
	if (list)
		bencode_dictionary_add(dict, "flags", list);
	msg = (sess->msg?sess->msg:get_dummy_sip_msg());
	ret = rtpe_function_call_ok(&bencbuf, msg, op, flags, body,
			NULL, rset, &server->node, dict);
	if (is_dummy_sip_msg(msg) == 0)
		release_dummy_sip_msg(msg);

	return ret;
}

static str *rtpengine_new_subs(str *tag)
{
	str *to_tag = shm_malloc(sizeof *to_tag + tag->len);
	if (to_tag) {
		to_tag->s = (char *)(to_tag + 1);
		to_tag->len = tag->len;
		memcpy(to_tag->s, tag->s, tag->len);
	}
	return to_tag;
}

static void rtpengine_copy_streams(bencode_item_t *streams, struct rtp_relay_streams *ret)
{
	bencode_item_t *item, *medias;
	str tmp = STR_NULL;
	struct dlg_cell *dlg;
	int leg = RTP_RELAY_CALLER, medianum, label, s;
	if (!ret || !streams)
		return;
	ret->count = 0;
	dlg = dlgb.get_dlg();
	if (!dlg)
		LM_WARN("could not fetch dialog - legs might not match\n");
	s = 0;
	for (item = streams->child; item; item = item->sibling) {
		if (dlg) {
			tmp.s = bencode_dictionary_get_string(item, "tag", &tmp.len);
			if (!tmp.s)
				LM_WARN("could not retrieve tag - placing to %s\n",
						(leg == RTP_RELAY_CALLER?"caller":"callee"));
			else if (!str_match(&tmp, &dlg->legs[DLG_CALLER_LEG].tag))
				leg = RTP_RELAY_CALLEE;
			else
				leg = RTP_RELAY_CALLER;
		} else if (leg == RTP_RELAY_CALLER) {
			/* first try caller, then callee */
			leg = RTP_RELAY_CALLEE;
		}
		medias = bencode_dictionary_get_expect(item, "medias", BENCODE_LIST);
		if (!medias)
			continue;
		for (medias = medias->child; medias; medias = medias->sibling) {
			s = ret->count;
			if (s == RTP_COPY_MAX_STREAMS) {
				LM_WARN("maximum amount of streams %d reached!\n",
						RTP_COPY_MAX_STREAMS);
				return;
			}
			medianum = bencode_dictionary_get_integer(item, "index", 0);
			tmp.s = bencode_dictionary_get_string(medias, "label", &tmp.len);
			if (str2sint(&tmp, &label) < 0) {
				LM_WARN("invalid label %.*s - not integer - skipping\n",
						tmp.len, tmp.s);
				continue;
			}
			ret->streams[s].leg = leg;
			ret->streams[s].label = label;
			ret->streams[s].medianum = medianum;
			ret->count++;
		}
	}
}

static int rtpengine_api_copy_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void **_ctx, str *flags,
		unsigned int copy_flags, unsigned int streams, str *ret_body,
		struct rtp_relay_streams *ret_streams)
{
	str tmp;
	bencode_item_t *ret;
	ret = rtpengine_api_copy_op(sess, OP_SUBSCRIBE_REQUEST,
			server, *_ctx, flags, copy_flags, NULL);
	if (!ret)
		return -1;
	if (!bencode_dictionary_get_str_dup(ret, "sdp", ret_body))
		LM_ERR("failed to extract sdp body from proxy reply\n");
	if (ret_streams)
		rtpengine_copy_streams(bencode_dictionary_get(ret, "tag-medias"), ret_streams);
	if (!bencode_dictionary_get_str(ret, "to-tag", &tmp))
		LM_ERR("failed to extract to-tag from proxy reply\n");
	else
		*_ctx = rtpengine_new_subs(&tmp);
	bencode_buffer_free(bencode_item_buffer(ret));
	return 0;
}

static int rtpengine_api_copy_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *subs, str *flags, str *body)
{
	bencode_item_t *ret;
	ret = rtpengine_api_copy_op(sess, OP_SUBSCRIBE_ANSWER,
			server, subs, flags, 0, body);
	if (!ret)
		return -1;
	bencode_buffer_free(bencode_item_buffer(ret));
	return ret != NULL;
}

static int rtpengine_api_copy_delete(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *subs, str *flags)
{
	bencode_item_t *ret;
	ret = rtpengine_api_copy_op(sess, OP_UNSUBSCRIBE,
			server, subs, flags, 0, NULL);
	if (!ret)
		return -1;
	bencode_buffer_free(bencode_item_buffer(ret));
	return ret != NULL;
}

static int rtpengine_api_copy_serialize(void *_ctx, bin_packet_t *packet)
{
	str str_empty = str_init("");
	if (!_ctx)
		return bin_push_str(packet, &str_empty);
	else
		return bin_push_str(packet, (str *)_ctx);
}

static int rtpengine_api_copy_deserialize(void **_ctx, bin_packet_t *packet)
{
	str to_tag;
	if (bin_pop_str(packet, &to_tag) < 0 || to_tag.len == 0)
		return -1;

	*_ctx = rtpengine_new_subs(&to_tag);
	if (*_ctx == NULL)
		return -1;
	else
		return 1;
}

static void rtpengine_api_copy_release(void **ctx)
{
	if (*ctx) {
		shm_free(*ctx);
		*ctx = NULL;
	}
}

static inline void raise_rtpengine_status_event(struct rtpe_node *node)
{
	static str status_connected = str_init("active");
	static str status_disconnected = str_init("inactive");

	if (rtpengine_status_event == EVI_ERROR) {
		LM_ERR("event  %.*s not registered (%d)\n", rtpengine_status_event_name.len,
				rtpengine_status_event_name.s, rtpengine_status_event);
		return;
	}
	if (!evi_probe_event(rtpengine_status_event)) {
		LM_DBG("no %.*s event subscriber!\n", rtpengine_status_event_name.len,
				rtpengine_status_event_name.s);
		return;
	}

	if (evi_param_set_str(rtpengine_status_event_socket, &node->rn_url) < 0) {
		LM_ERR("cannot set rtpengine status set parameter\n");
		return;
	}
	if (evi_param_set_str(rtpengine_status_event_status, node->rn_disabled?
					&status_disconnected:&status_connected) < 0) {
		LM_ERR("cannot set rtpengine status parameter\n");
		return;
	}
	if (evi_param_set_int(rtpengine_status_event_set, &node->set) < 0) {
		LM_ERR("cannot set rtpengine status parameter\n");
		return;
	}
	if (evi_raise_event(rtpengine_status_event, rtpengine_status_event_params))
		LM_ERR("unable to send event\n");
}
