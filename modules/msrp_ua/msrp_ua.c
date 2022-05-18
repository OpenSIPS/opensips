/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../lib/hash.h"
#include "../../socket_info.h"
#include "../../timer.h"
#include "../../parser/sdp/sdp.h"
#include "../../parser/parse_from.h"
#include "../../msg_translator.h"
#include "../../evi/evi_modules.h"
#include "../../mi/mi.h"

#include "../proto_msrp/msrp_api.h"
#include "msrp_ua.h"

#define MSRP_DEFAULT_PORT 2855

#define append_string(_d,_s,_len) \
	do{\
		memcpy((_d),(_s),(_len));\
		(_d) += (_len);\
	}while(0)

static int mod_init(void);
static void destroy(void);

mi_response_t *msrpua_mi_end(const mi_params_t *params,
	struct mi_handler *async_hdl);
mi_response_t *msrpua_mi_list(const mi_params_t *params,
	struct mi_handler *async_hdl);
mi_response_t *msrpua_mi_send_msg(const mi_params_t *params,
	struct mi_handler *async_hdl);
mi_response_t *msrpua_mi_start_session(const mi_params_t *params,
	struct mi_handler *async_hdl);

void load_msrp_ua(struct msrp_ua_binds *binds);

/* proto_msrp binds */
struct msrp_binds msrp_api;
/* proto_msrp registration handler */
void *msrp_hdl;

b2b_api_t b2b_api;

str my_msrp_uri_str;
struct msrp_url my_msrp_uri;

struct socket_info *msrp_sock;

str adv_contact;

int msrpua_sessions_hsize = 10;
gen_hash_t *msrpua_sessions;

int cleanup_interval = 60;
int max_duration = 12*3600;

static str msrpua_mod_name = str_init("msrp_ua");

gen_lock_t *sdp_id_lock;
int *next_sdp_id;

static event_id_t evi_sess_new_id = EVI_ERROR;
static event_id_t evi_sess_end_id = EVI_ERROR;

static event_id_t evi_msg_rcv_id = EVI_ERROR;

static str evi_sess_new_name = str_init("E_MSRP_SESSION_NEW");
static str evi_sess_end_name = str_init("E_MSRP_SESSION_END");

static str evi_msg_rcv_name = str_init("E_MSRP_MSG_RECEIVED");

static evi_params_p evi_sess_params;

static evi_params_p evi_msg_rcv_params;

static evi_param_p evi_sess_from_p, evi_sess_to_p, evi_sess_ruri_p,
	evi_sess_sid_p, evi_sess_types_p;

static evi_param_p evi_msg_rcv_sid_p, evi_msg_rcv_ctype_p, evi_msg_rcv_body_p;

static str evi_sess_from_pname = str_init("from_uri");
static str evi_sess_to_pname = str_init("to_uri");
static str evi_sess_ruri_pname = str_init("ruri");
static str evi_sess_sid_pname = str_init("session_id");
static str evi_sess_types_pname = str_init("content_types");

static str evi_msg_rcv_sid_pname = str_init("session_id");
static str evi_msg_rcv_ctype_pname = str_init("content_type");
static str evi_msg_rcv_body_pname = str_init("body");

static param_export_t params[] = {
	{"hash_size", INT_PARAM, &msrpua_sessions_hsize},
	{"cleanup_interval", INT_PARAM, &cleanup_interval},
	{"max_duration", INT_PARAM, &max_duration},
	{"my_uri", STR_PARAM, &my_msrp_uri_str},
	{"advertised_contact", STR_PARAM, &adv_contact.s},
};

static mi_export_t mi_cmds[] = {
	{ "msrp_ua_send_message", 0, 0, 0, {
		{msrpua_mi_send_msg, {"session_id", 0}},
		{msrpua_mi_send_msg, {"session_id", "mime", "body", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "msrp_ua_end_session", 0, 0, 0, {
		{msrpua_mi_end, {"session_id", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "msrp_ua_list_sessions", 0, 0, 0, {
		{msrpua_mi_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "msrp_ua_start_session", 0, 0, 0, {
		{msrpua_mi_start_session, {"content_types", "from_uri", "to_uri", "ruri", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static int msrpua_answer(struct sip_msg *msg, str *content_types);

static cmd_export_t cmds[]=
{
	{"msrp_ua_answer", (cmd_function)msrpua_answer, {
		{CMD_PARAM_STR, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE},
	{"load_msrp_ua", (cmd_function)load_msrp_ua, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "proto_msrp"  , DEP_ABORT  },
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"msrp_ua",       /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,      /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};

static int handle_msrp_request(struct msrp_msg *req, void *hdl_param);
static int handle_msrp_reply(struct msrp_msg *rpl, struct msrp_cell *tran,
	void *trans_param, void *hdl_param);
static void clean_msrpua_sessions(unsigned int ticks,void *param);

static int msrpua_evi_init(void)
{
	evi_sess_new_id = evi_publish_event(evi_sess_new_name);
	if (evi_sess_new_id == EVI_ERROR) {
		LM_ERR("cannot register event\n");
		return -1;
	}
	evi_sess_end_id = evi_publish_event(evi_sess_end_name);
	if (evi_sess_end_id == EVI_ERROR) {
		LM_ERR("cannot register event\n");
		return -1;
	}
	evi_msg_rcv_id = evi_publish_event(evi_msg_rcv_name);
	if (evi_msg_rcv_id == EVI_ERROR) {
		LM_ERR("cannot register event\n");
		return -1;
	}

	evi_sess_params = pkg_malloc(sizeof(evi_params_t));
	if (evi_sess_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(evi_sess_params, 0, sizeof(evi_params_t));

	evi_msg_rcv_params = pkg_malloc(sizeof(evi_params_t));
	if (evi_msg_rcv_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(evi_msg_rcv_params, 0, sizeof(evi_params_t));

	evi_sess_from_p = evi_param_create(evi_sess_params, &evi_sess_from_pname);
	if (evi_sess_from_p == NULL)
		goto error;
	evi_sess_to_p = evi_param_create(evi_sess_params, &evi_sess_to_pname);
	if (evi_sess_to_p == NULL)
		goto error;
	evi_sess_ruri_p = evi_param_create(evi_sess_params, &evi_sess_ruri_pname);
	if (evi_sess_ruri_p == NULL)
		goto error;
	evi_sess_sid_p = evi_param_create(evi_sess_params, &evi_sess_sid_pname);
	if (evi_sess_sid_p == NULL)
		goto error;
	evi_sess_types_p = evi_param_create(evi_sess_params, &evi_sess_types_pname);
	if (evi_sess_types_p == NULL)
		goto error;

	evi_msg_rcv_sid_p = evi_param_create(evi_msg_rcv_params,
		&evi_msg_rcv_sid_pname);
	if (evi_msg_rcv_sid_p == NULL)
		goto error;
	evi_msg_rcv_ctype_p = evi_param_create(evi_msg_rcv_params,
		&evi_msg_rcv_ctype_pname);
	if (evi_msg_rcv_ctype_p == NULL)
		goto error;
	evi_msg_rcv_body_p = evi_param_create(evi_msg_rcv_params,
		&evi_msg_rcv_body_pname);
	if (evi_msg_rcv_body_p == NULL)
		goto error;

	return 0;

error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

static int mod_init(void)
{
	LM_INFO("initializing...\n");
	char *p, *end;

	if (!my_msrp_uri_str.s) {
		LM_ERR("'my_uri' parameter not set\n");
		return -1;
	}

	if (adv_contact.s)
		adv_contact.len = strlen(adv_contact.s);
	
	my_msrp_uri_str.len = strlen(my_msrp_uri_str.s);

	end = my_msrp_uri_str.s + my_msrp_uri_str.len;
	p = parse_msrp_url(my_msrp_uri_str.s, end, &my_msrp_uri);
	if (!p) {
		LM_ERR("Failed to parse MSRP URI in 'my_uri' parameter\n");
		return -1;
	}

	if (my_msrp_uri.port_no == 0) {
		LM_INFO("Explicit port number not provided in 'my_uri',"
			"using default %d\n", MSRP_DEFAULT_PORT);
		my_msrp_uri.port_no = MSRP_DEFAULT_PORT;
	}

	msrp_sock = grep_sock_info(&my_msrp_uri.host, my_msrp_uri.port_no,
		my_msrp_uri.secured ? PROTO_MSRPS:PROTO_MSRP);
	if (!msrp_sock) {
		LM_ERR("non-local socket <%.*s>\n",
			my_msrp_uri.host.len, my_msrp_uri.host.s);
		return 1;
	}

	/* load MSRP API */
	if(load_msrp_api(&msrp_api)< 0){
		LM_ERR("can't load MSRP functions\n");
		return -1;
	}

	msrp_hdl = msrp_api.register_msrp_handler(&my_msrp_uri.host,
		my_msrp_uri.port_no, my_msrp_uri.secured, handle_msrp_request,
		handle_msrp_reply, NULL);
	if (!msrp_hdl) {
		LM_ERR("Failed to register MSRP handler\n");
		return -1;
	}

	if (load_b2b_api(&b2b_api) < 0) {
		LM_ERR("Failed to load b2b api\n");
		return -1;
	}

	if (msrpua_sessions_hsize < 1 || msrpua_sessions_hsize > 20) {
		LM_ERR("hash size should be between 1 and 20\n");
		return -1;
	}
	msrpua_sessions_hsize = 1 << msrpua_sessions_hsize;

	msrpua_sessions = hash_init(msrpua_sessions_hsize);
	if (!msrpua_sessions) {
		LM_ERR("Failed to init MSRP sessions table\n");
		return -1;
	}

	register_timer("msrpua-expire", clean_msrpua_sessions, NULL,
		cleanup_interval, TIMER_FLAG_DELAY_ON_DELAY);

	sdp_id_lock = lock_alloc();
	if (!sdp_id_lock) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	if (!lock_init(sdp_id_lock)) {
		LM_ERR("failed to init lock\n");
		return -1;
	}

	next_sdp_id = shm_malloc(sizeof *next_sdp_id);
	if (!next_sdp_id) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	*next_sdp_id = time(NULL);

	if (msrpua_evi_init() < 0) {
		LM_ERR("Failed to init events\n");
		return -1;
	}

	return 0;
}

static void free_msrpua_session(void *val)
{
	struct msrpua_session *sess = (struct msrpua_session *)val;

	if (sess->accept_types.s)
		shm_free(sess->accept_types.s);

	if (sess->peer_path.s)
		shm_free(sess->peer_path.s);
	free_msrp_path_shm(sess->peer_path_parsed);

	if (sess->peer_accept_types.s)
		shm_free(sess->peer_accept_types.s);

	shm_free(sess);
}

static void msrpua_delete_session(struct msrpua_session *sess)
{
	LM_DBG("Deleting session [%.*s\n", sess->session_id.len, sess->session_id.s);

	b2b_api.entity_delete(sess->b2b_type, &sess->b2b_key, NULL, 1, 1);

	hash_remove_key(msrpua_sessions, sess->session_id);
	free_msrpua_session(sess);
}

void msrpua_evi_destroy(void)
{
	evi_free_params(evi_sess_params);
}

static void destroy(void)
{
	hash_destroy(msrpua_sessions, free_msrpua_session);

	lock_destroy(sdp_id_lock);
	lock_dealloc(sdp_id_lock);

	msrpua_evi_destroy();
}

static inline int msrpua_b2b_reply(int et, str *b2b_key, int method,
	int code, str *reason, str *body)
{
	b2b_rpl_data_t rpl_data;
	static str ct_type_sdp_str = str_init("Content-Type: application/sdp\r\n");

	memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
	rpl_data.et = et;
	rpl_data.b2b_key = b2b_key;
	rpl_data.method = method;
	rpl_data.code = code;
	rpl_data.text = reason;
	rpl_data.body = body;
	if (body)
		rpl_data.extra_headers = &ct_type_sdp_str;

	return b2b_api.send_reply(&rpl_data);
}

static inline int msrpua_b2b_request(int et, str *b2b_key, str *method)
{
	b2b_req_data_t req_data;

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	req_data.et = et;
	req_data.b2b_key = b2b_key;
	req_data.method = method;

	return b2b_api.send_request(&req_data);
}

#define MESSAGE_STR "message"
#define TCP_MSRP_STR "TCP/MSRP"
#define TLS_MSRP_STR "TCP/TLS/MSRP"

static sdp_stream_cell_t *get_sdp_msrp_stream(sdp_info_t *sdp)
{
	sdp_session_cell_t* sdp_session;
	sdp_stream_cell_t* sdp_stream;
	int sdp_session_num = 0, sdp_stream_num;

	for (;;) {
		sdp_session = get_sdp_session(sdp, sdp_session_num);
		if (!sdp_session)
			break;

		sdp_stream_num = 0;
		for (;;) {
			sdp_stream = get_sdp_stream(sdp, sdp_session_num,
				sdp_stream_num);
			if (!sdp_stream)
				break;

			if (str_match(&sdp_stream->media, const_str(MESSAGE_STR)) &&
				(str_match(&sdp_stream->transport, const_str(TCP_MSRP_STR)) ||
				str_match(&sdp_stream->transport, const_str(TLS_MSRP_STR))))
				return sdp_stream;

			sdp_stream_num++;
		}

		sdp_session_num++;
	}

	return NULL;
}

static int get_sdp_peer_info(struct sip_msg *msg, str *peer_accept_types,
	str *peer_path)
{
	sdp_info_t *sdp;
	sdp_stream_cell_t *msrp_stream;

	if (!(sdp = parse_sdp(msg))) {
		LM_DBG("failed to parse SDP\n");
		return -1;
	}

	if (!(msrp_stream = get_sdp_msrp_stream(sdp))) {
		LM_ERR("No MSRP media stream in SDP\n");
		return -1;
	}

	*peer_accept_types = msrp_stream->accept_types;
	*peer_path = msrp_stream->path;

	return 0;
	}

static inline int match_mimes(str *a_type, str *a_subtype,
	str *b_type, str *b_subtype)
{
	if (a_type->len != b_type->len || memcmp(a_type->s, b_type->s, b_type->len))
		return 0;

	if (a_subtype->s[0] == '*' || b_subtype->s[0] == '*')
		return 1;
	else if (a_subtype->len != b_subtype->len ||
		memcmp(a_subtype->s, b_subtype->s, b_subtype->len))
		return 0;
	else
		return 1;
}

static int match_mime_with_list(str *mime, str *list)
{
	enum state {
		MLIST_TYPE_ST,
		MLIST_SUBTYPE_ST
	};
	enum state st;
	str src_type = STR_NULL, src_subtype = STR_NULL;
	str type = STR_NULL, subtype = STR_NULL;
	char *p;

	if (mime->len == 0)
		goto err_mime;

	if (mime->s[0] == '*') {
		if (mime->len != 1)
			goto err_mime;
		return 1;
	}

	src_type.s = mime->s;
	src_subtype.s = q_memchr(mime->s, '/', mime->len);
	if (!src_subtype.s)
		goto err_mime;
	src_type.len = src_subtype.s - src_type.s;
	src_subtype.s++;

	if (mime->len - src_type.len - 1 == 0)
		goto err_mime;

	/* ignore type params */
	p = q_memchr(src_subtype.s, ';', mime->len - src_type.len - 1);
	if (p)
		src_subtype.len = p - src_subtype.s;
	else
		src_subtype.len = mime->len - src_type.len - 1;

 	if (list->s[0] == '*') {
 		if (list->len != 1)
 			goto err_list;
 		return 1;
 	}

	p = list->s;
	st = MLIST_TYPE_ST;
	type.s = p;

	while (p < list->s + list->len) {
		switch (st) {
		case MLIST_TYPE_ST:
			switch (*p) {
			case '/':
				type.len = p - type.s;
				subtype.s = p+1;
				st = MLIST_SUBTYPE_ST;
				break;
			case ' ':
			case '*':
				goto err_list;
			}

			break;
		case MLIST_SUBTYPE_ST:
			switch (*p) {
			case '/':
				goto err_list;
			case ' ':
				subtype.len = p - subtype.s;
				if (match_mimes(&src_type, &src_subtype, &type, &subtype))
					return 1;

				type.s = p+1;
				st = MLIST_TYPE_ST;				
			}
		}

		p++;
	}

	if (st != MLIST_SUBTYPE_ST)
		goto err_list;

	subtype.len = p - subtype.s;
	if (match_mimes(&src_type, &src_subtype, &type, &subtype))
		return 1;	

	return 0;

err_mime:
	LM_ERR("Bad MIME format [%.*s]\n", mime->len, mime->s);
	return 0;
err_list:
	LM_ERR("Bad format for accept-types [%.*s]\n", list->len, list->s);
	return 0;
}

static int check_offer_types(str *accept_types, str *peer_accept_types)
{
	str mime = STR_NULL;
	char *p = accept_types->s;

	mime.s = accept_types->s;
	while (p < accept_types->s + accept_types->len) {
		if (*p == ' ') {
			mime.len = p - mime.s;
			if (match_mime_with_list(&mime, peer_accept_types))
				return 1;

			mime.s = p+1;
		} else {
			p++;
		}
	}

	mime.len = p - mime.s;
	if (match_mime_with_list(&mime, peer_accept_types))
		return 1;

	return 0;
}

#define SDP_V_LINE_STR "v=0\r\n"
#define SDP_V_LINE_STR_LEN (sizeof(SDP_V_LINE_STR) - 1)
#define SDP_S_LINE_STR "s= -\r\n"
#define SDP_S_LINE_STR_LEN (sizeof(SDP_S_LINE_STR) - 1)
#define SDP_T_LINE_STR "t=0 0\r\n"
#define SDP_T_LINE_STR_LEN (sizeof(SDP_T_LINE_STR) - 1)

#define SDP_O_STR "o=- "
#define SDP_O_STR_LEN (sizeof(SDP_O_STR) - 1)

#define SDP_IP4_STR "IN IP4 "
#define SDP_IP4_STR_LEN (sizeof(SDP_IP4_STR) - 1)
#define SDP_IP6_STR "IN IP6 "
#define SDP_IP6_STR_LEN (sizeof(SDP_IP6_STR) - 1)

#define SDP_C_STR "c="
#define SDP_C_STR_LEN (sizeof(SDP_C_STR) - 1)

#define SDP_M_STR "m=message "
#define SDP_M_STR_LEN (sizeof(SDP_M_STR) - 1)
#define SDP_M_TCP_STR " TCP/MSRP *\r\n"
#define SDP_M_TCP_STR_LEN (sizeof(SDP_M_TCP_STR) - 1)
#define SDP_M_TLS_STR " TCP/TLS/MSRP *\r\n"
#define SDP_M_TLS_STR_LEN (sizeof(SDP_M_TLS_STR) - 1)

#define SDP_A_TYPES_STR "a=accept-types:"
#define SDP_A_TYPES_STR_LEN (sizeof(SDP_A_TYPES_STR) - 1)
#define SDP_A_PATH_STR "a=path:"
#define SDP_A_PATH_STR_LEN (sizeof(SDP_A_PATH_STR) - 1)

static str *msrpua_build_sdp(struct msrpua_session *sess, str *accept_types)
{
	static str buf;
	char *p;
	str id;
	str vers;

	id.s = int2str(sess->sdp_sess_id, &id.len);
	vers.s = int2str(sess->sdp_sess_vers, &vers.len);

	buf.len = SDP_V_LINE_STR_LEN + SDP_S_LINE_STR_LEN + SDP_T_LINE_STR_LEN;
	buf.len += SDP_O_STR_LEN + id.len + 1 + vers.len + 1 +
		(msrp_sock->address.af==AF_INET ? SDP_IP4_STR_LEN:SDP_IP6_STR_LEN) +
		my_msrp_uri.host.len + CRLF_LEN;
	buf.len += SDP_C_STR_LEN +
		(msrp_sock->address.af==AF_INET ? SDP_IP4_STR_LEN:SDP_IP6_STR_LEN) + 
		my_msrp_uri.host.len + CRLF_LEN;
	buf.len += SDP_M_STR_LEN + my_msrp_uri.port.len +
		(my_msrp_uri.secured ? SDP_M_TLS_STR_LEN:SDP_M_TCP_STR_LEN);
	buf.len += SDP_A_TYPES_STR_LEN + accept_types->len + CRLF_LEN +
		SDP_A_PATH_STR_LEN + my_msrp_uri.whole.len + 1 + sess->session_id.len +
		CRLF_LEN;

	buf.s = pkg_malloc(buf.len);
	if (!buf.s) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}
	p = buf.s;

	append_string(p, SDP_V_LINE_STR, SDP_V_LINE_STR_LEN);

	append_string(p, SDP_O_STR, SDP_O_STR_LEN);
	append_string(p, id.s, id.len);
	*(p++) = ' ';
	append_string(p, vers.s, vers.len);
	*(p++) = ' ';
	if (msrp_sock->address.af==AF_INET)
		append_string(p, SDP_IP4_STR, SDP_IP4_STR_LEN);
	else
		append_string(p, SDP_IP6_STR, SDP_IP6_STR_LEN);
	append_string(p, my_msrp_uri.host.s, my_msrp_uri.host.len);
	append_string(p, CRLF, CRLF_LEN);

	append_string(p, SDP_S_LINE_STR, SDP_S_LINE_STR_LEN);

	append_string(p, SDP_C_STR, SDP_C_STR_LEN);
	if (msrp_sock->address.af==AF_INET)
		append_string(p, SDP_IP4_STR, SDP_IP4_STR_LEN);
	else
		append_string(p, SDP_IP6_STR, SDP_IP6_STR_LEN);
	append_string(p, my_msrp_uri.host.s, my_msrp_uri.host.len);
	append_string(p, CRLF, CRLF_LEN);

	append_string(p, SDP_T_LINE_STR, SDP_T_LINE_STR_LEN);

	append_string(p, SDP_M_STR, SDP_M_STR_LEN);
	append_string(p, my_msrp_uri.port.s, my_msrp_uri.port.len);
	if (my_msrp_uri.secured)
		append_string(p, SDP_M_TLS_STR, SDP_M_TLS_STR_LEN);
	else
		append_string(p, SDP_M_TCP_STR, SDP_M_TCP_STR_LEN);

	append_string(p, SDP_A_TYPES_STR, SDP_A_TYPES_STR_LEN);
	append_string(p, accept_types->s, accept_types->len);
	append_string(p, CRLF, CRLF_LEN);

	append_string(p, SDP_A_PATH_STR, SDP_A_PATH_STR_LEN);
	append_string(p, my_msrp_uri.whole.s,
		my_msrp_uri.whole.len - my_msrp_uri.params.len - 1);
	*(p++) = '/';
	append_string(p, sess->session_id.s, sess->session_id.len);
	*(p++) = ';';
	append_string(p, my_msrp_uri.params.s, my_msrp_uri.params.len);
	append_string(p, CRLF, CRLF_LEN);

	return &buf;
}

#define REASON_488_STR "Not Acceptable Here"

static int msrpua_update_session(struct msrpua_session *sess,
	struct sip_msg *msg, int etype)
{
	str peer_accept_types;
	str peer_path;
	int code;
	str reason;
	str *sdp;
	int del_sess = 0;

	if (get_sdp_peer_info(msg, &peer_accept_types, &peer_path) < 0) {
		LM_ERR("Failed to get peer info from SDP\n");
		code = 488;
		reason = str_init(REASON_488_STR);
		goto err_reply;
	}

	/* match at least one content type from our accept_types 
	 * with the peer's accept_types */
	if (!check_offer_types(&sess->accept_types, &peer_accept_types)) {
		LM_ERR("Cannot understand any content type received in the offer\n");
		code = 488;
		reason = str_init(REASON_488_STR);
		goto err_reply;
	}

	if (shm_str_sync(&sess->peer_path, &peer_path) < 0) {
		LM_ERR("No more shm memory\n");
		code = 500;
		reason = str_init("Internal Server Error");
		del_sess = 1;
		goto err_reply;
	}

	sess->peer_path_parsed = parse_msrp_path_shm(&sess->peer_path);
	if (!sess->peer_path_parsed ) {
		LM_ERR("Failed to parse MSRP peer path\n");
		code = 500;
		reason = str_init("Internal Server Error");
		del_sess = 1;
		goto err_reply;
	}

	memset(&sess->to_su, 0, sizeof sess->to_su);

	if (shm_str_sync(&sess->peer_accept_types, &peer_accept_types) < 0) {
		LM_ERR("No more shm memory\n");
		code = 500;
		reason = str_init("Internal Server Error");
		del_sess = 1;
		goto err_reply;
	}

	sess->sdp_sess_vers++;

	sdp = msrpua_build_sdp(sess, &sess->accept_types);
	if (!sdp->s) {
		LM_ERR("Failed to build SDP answer\n");
		code = 500;
		reason = str_init("Internal Server Error");
		del_sess = 1;
		goto err_reply;
	}

	if (msrpua_b2b_reply(etype, &sess->b2b_key, METHOD_INVITE,
		200, &str_init("OK"), sdp) < 0) {
		LM_ERR("Failed to send 200 OK\n");
		pkg_free(sdp->s);
		del_sess = 1;
		goto err;
	}

	sess->dlg_state = MSRPUA_DLG_CONF;

	pkg_free(sdp->s);

	return 0;

err_reply:
	if (msrpua_b2b_reply(etype, &sess->b2b_key, METHOD_INVITE,
		code, &reason, NULL) < 0) {
		LM_ERR("Failed to send error reply\n");
		del_sess = 1;
	}
err:
	if (del_sess) {
		if (msrpua_b2b_request(etype, &sess->b2b_key, &str_init("BYE")) < 0)
			LM_ERR("Failed to send BYE on error\n");
		msrpua_delete_session(sess);
	}
	return -1;
}

static int raise_sess_new_event(struct sip_msg *msg, str *sess_id,
	str *accept_types)
{
	if (parse_from_header(msg) < 0) {
		LM_ERR("cannot parse From header\n");
		return -1;
	}
	if (parse_to_header(msg) < 0) {
		LM_ERR("cannot parse To header\n");
		return -1;
	}

	if (evi_param_set_str(evi_sess_from_p, &get_from(msg)->uri) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_sess_to_p, &get_to(msg)->uri) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_sess_ruri_p, GET_RURI(msg)) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if (evi_param_set_str(evi_sess_sid_p, sess_id) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_sess_types_p, accept_types) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if (evi_raise_event(evi_sess_new_id, evi_sess_params) < 0) {
		LM_ERR("cannot raise event\n");
		return -1;
	}

	return 0;
}

static int raise_sess_end_event(str *sess_id)
{
	if (evi_param_set_str(evi_sess_sid_p, sess_id) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if (evi_raise_event(evi_sess_end_id, evi_sess_params) < 0) {
		LM_ERR("cannot raise event\n");
		return -1;
	}

	return 0;
}

static int raise_msg_rcv_event(str *sess_id, str *ctype, str *body)
{
	if (evi_param_set_str(evi_msg_rcv_sid_p, sess_id) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_msg_rcv_ctype_p, ctype) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_msg_rcv_body_p, body) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if (evi_raise_event(evi_msg_rcv_id, evi_msg_rcv_params) < 0) {
		LM_ERR("cannot raise event\n");
		return -1;
	}

	return 0;
}

static int b2b_notify_request(int etype, struct sip_msg *msg, str *key,
	void *param, int flags)
{
	struct msrpua_session *sess = (struct msrpua_session *)param;
	unsigned int hentry;
	str sess_id, accept_types;
	struct msrp_ua_notify_params cb_params = {0};
	struct msrp_ua_handler hdl;
	int raise_ev = 0;

	hentry = hash_entry(msrpua_sessions, sess->session_id);
	hash_lock(msrpua_sessions, hentry);

	LM_DBG("Received request [%.*s] for session [%.*s]\n", msg->REQ_METHOD_S.len,
		msg->REQ_METHOD_S.s, sess->session_id.len, sess->session_id.s);

	switch (msg->REQ_METHOD) {
	case METHOD_INVITE:
		if (msrpua_update_session(sess, msg, etype) < 0)
			LM_ERR("Failed to update session on reInvite\n");

		hash_unlock(msrpua_sessions, hentry);
		break;
	case METHOD_ACK:
		if (!(flags & B2B_NOTIFY_FL_ACK_NEG) &&
			/* ACK for initial INVITE */
			sess->sdp_sess_vers == sess->sdp_sess_id) {
			if (pkg_str_dup(&sess_id, &sess->session_id) < 0) {
				LM_ERR("out of pkg memory\n");
				return 0;
			}
			if (pkg_str_dup(&accept_types, &sess->peer_accept_types) < 0) {
				LM_ERR("out of pkg memory\n");
				pkg_free(sess_id.s);
				return 0;
			}

			sess->dlg_state = MSRPUA_DLG_EST;
			if (max_duration)
				sess->lifetime = max_duration + get_ticks();
			else
				sess->lifetime = 0;

			if (sess->hdl.name) {
				cb_params.event = MSRP_UA_SESS_ESTABLISHED;
				cb_params.msg = msg;
				cb_params.accept_types = &accept_types;
				cb_params.session_id = &sess_id;
				hdl = sess->hdl;
			}

			hash_unlock(msrpua_sessions, hentry);

			if (!cb_params.event) {
				if (raise_sess_new_event(msg, &sess_id, &accept_types) < 0)
					LM_ERR("Failed to raise session new event on ACK\n");
			} else {
				hdl.notify_cb(&cb_params, hdl.param);
			}

			pkg_free(sess_id.s);
			pkg_free(accept_types.s);
		} else {
			hash_unlock(msrpua_sessions, hentry);
		}
		break;
	case METHOD_CANCEL:
		if (msrpua_b2b_reply(etype, key, METHOD_INVITE,
			487, &str_init("Request Terminated"), NULL) < 0)
			LM_ERR("Failed to send error reply\n");

		if (sess->sdp_sess_vers == sess->sdp_sess_id) {
			/* CANCEL for initial INVITE */
			if (sess->hdl.name) {
				if (pkg_str_dup(&sess_id, &sess->session_id) < 0) {
					LM_ERR("out of pkg memory\n");
					return 0;
				}

				cb_params.event = MSRP_UA_SESS_FAILED;
				cb_params.session_id = &sess_id;
				cb_params.msg = msg;
				hdl = sess->hdl;
			}

			msrpua_delete_session(sess);
		}

		hash_unlock(msrpua_sessions, hentry);

		if (cb_params.event) {
			hdl.notify_cb(&cb_params, hdl.param);
			pkg_free(sess_id.s);
		}

		break;
	case METHOD_BYE:
		if (msrpua_b2b_reply(etype, key, METHOD_BYE,
			200, &str_init("OK"), NULL) < 0)
			LM_ERR("Failed to send reply\n");

		if (pkg_str_dup(&sess_id, &sess->session_id) < 0) {
			LM_ERR("out of pkg memory\n");
			return 0;
		}

		if (sess->dlg_state == MSRPUA_DLG_CONF) {
			/* should be a UAS session */
			if (sess->hdl.name) {
				cb_params.event = MSRP_UA_SESS_FAILED;
				cb_params.session_id = &sess_id;
				cb_params.msg = msg;
				hdl = sess->hdl;
			}
		} else {  /* MSRPUA_DLG_EST */
			if (sess->hdl.name) {
				cb_params.event = MSRP_UA_SESS_TERMINATED;
				cb_params.session_id = &sess_id;
				cb_params.msg = msg;
				hdl = sess->hdl;
			} else  {
				raise_ev = 1;
			}
		}

		msrpua_delete_session(sess);
		hash_unlock(msrpua_sessions, hentry);

		if (raise_ev) {
			if (raise_sess_end_event(&sess_id) < 0)
				LM_ERR("Failed to raise session end event on BYE\n");

			pkg_free(sess_id.s);
		} else if (cb_params.event) {
			hdl.notify_cb(&cb_params, hdl.param);
			pkg_free(sess_id.s);
		}

		break;
	}

	return 0;
}

static int msrpua_send_message(str *sess_id, str *mime, str *body);

static int b2b_notify_reply(int etype, struct sip_msg *msg, str *key,
	void *param, int flags)
{
	struct msrpua_session *sess = (struct msrpua_session *)param;
	unsigned int hentry;
	str peer_accept_types;
	str peer_path;
	str sess_id;
	struct msrp_ua_notify_params cb_params = {0};
	struct msrp_ua_handler hdl;

	hentry = hash_entry(msrpua_sessions, sess->session_id);
	hash_lock(msrpua_sessions, hentry);

	LM_DBG("Received reply [%d] for session [%.*s]\n", msg->REPLY_STATUS,
		sess->session_id.len, sess->session_id.s);

	if (msg->REPLY_STATUS < 200) {
		hash_unlock(msrpua_sessions, hentry);
		return 0;
	}

	if (sess->dlg_state == MSRPUA_DLG_TERM) {
		LM_DBG("Reply for terminated session, deleting entry\n");
		msrpua_delete_session(sess);

		hash_unlock(msrpua_sessions, hentry);
		return 0;
	}

	if (etype == B2B_CLIENT) {
		if (msg->REPLY_STATUS >= 300) {
			if (sess->hdl.name) {
				if (pkg_str_dup(&sess_id, &sess->session_id) < 0) {
					LM_ERR("out of pkg memory\n");
					return 0;
				}

				cb_params.event = MSRP_UA_SESS_FAILED;
				cb_params.msg = msg;
				cb_params.session_id = &sess_id;
				hdl = sess->hdl;
			}

			msrpua_delete_session(sess);
			hash_unlock(msrpua_sessions, hentry);

			if (cb_params.event) {
				hdl.notify_cb(&cb_params, hdl.param);
				pkg_free(sess_id.s);
			}
		} else { /* 2xx reply */
			if (pkg_str_dup(&sess_id, &sess->session_id) < 0) {
				LM_ERR("out of pkg memory\n");
				goto error;
			}

			if (get_sdp_peer_info(msg, &peer_accept_types, &peer_path) < 0) {
				LM_ERR("Failed to get peer info from SDP\n");
				goto error;
			}

			/* match at least one content type from our accept_types
			 * with the peer's accept_types */
			if (!check_offer_types(&sess->accept_types, &peer_accept_types)) {
				LM_ERR("Cannot understand any content type received in the offer\n");
				goto error;
			}

			if (shm_str_dup(&sess->peer_path, &peer_path) < 0) {
				LM_ERR("no more shm memory\n");
				goto error;
			}

			sess->peer_path_parsed = parse_msrp_path_shm(&sess->peer_path);
			if (!sess->peer_path_parsed ) {
				LM_ERR("Failed to parse MSRP peer path\n");
				goto error;
			}

			if (msrpua_b2b_request(etype, &sess->b2b_key, &str_init("ACK")) < 0) {
				LM_ERR("Failed to send ACK for 200 OK\n");
				goto error;
			}

			sess->dlg_state = MSRPUA_DLG_EST;
			if (max_duration)
				sess->lifetime = max_duration + get_ticks();
			else
				sess->lifetime = 0;

			if (sess->hdl.name) {
				cb_params.event = MSRP_UA_SESS_ESTABLISHED;
				cb_params.msg = msg;
				cb_params.accept_types = &peer_accept_types;
				cb_params.session_id = &sess_id;
				hdl = sess->hdl;
			}

			hash_unlock(msrpua_sessions, hentry);

			/* the initiating endpoint must issue a SEND request immediately */
			if (msrpua_send_message(&sess_id, NULL, NULL) < 0) {
				LM_ERR("Failed to send empty initial message\n");
				hash_lock(msrpua_sessions, hentry);
				goto error;
			}

			if (!cb_params.event) {
				if (raise_sess_new_event(msg, &sess_id, &peer_accept_types) < 0)
					LM_ERR("Failed to raise session new event on ACK\n");
			} else {
				hdl.notify_cb(&cb_params, hdl.param);
			}

			pkg_free(sess_id.s);
		}
	}

	return 0;
error:
	if (msrpua_b2b_request(etype, &sess->b2b_key, &str_init("BYE")) < 0)
		LM_ERR("Failed to send BYE on error\n");

	if (sess->hdl.name && sess_id.s) {
		cb_params.event = MSRP_UA_SESS_FAILED;
		cb_params.msg = msg;
		cb_params.session_id = &sess_id;
		hdl = sess->hdl;
	}

	sess->dlg_state = MSRPUA_DLG_TERM;
	sess->lifetime = MSRPUA_SESS_DEL_TOUT + get_ticks();

	hash_unlock(msrpua_sessions, hentry);

	if (cb_params.event)
		hdl.notify_cb(&cb_params, hdl.param);

	if (sess_id.s)
		pkg_free(sess_id.s);

	return -1;
}

static int b2b_server_notify(struct sip_msg *msg, str *key, int type,
		str *logic_key, void *param, int flags)
{
	if (type == B2B_REPLY)
		return b2b_notify_reply(B2B_SERVER, msg, key, param, flags);
	else
		return b2b_notify_request(B2B_SERVER, msg, key, param, flags);
}

static int b2b_client_notify(struct sip_msg *msg, str *key, int type,
		str *logic_key, void *param, int flags)
{
	if (type == B2B_REPLY)
		return b2b_notify_reply(B2B_CLIENT, msg, key, param, flags);
	else
		return b2b_notify_request(B2B_CLIENT, msg, key, param, flags);
}

static inline void msrpua_gen_id(char *dest, str *src1, str *src2)
{
	str md5_src[5];
	int l;
	int n = 4;

	md5_src[0].s = int2str(time(NULL), &l);
	md5_src[0].len = l;
	md5_src[1].s = int2str(rand(), &l);
	md5_src[1].len = l;
	md5_src[2].s = int2str(rand(), &l);
	md5_src[2].len = l;
	md5_src[3] = *src1;

	if (src2) {
		n = 5;
		md5_src[4] = *src2;
	}

	MD5StringArray(dest, md5_src, n);
}

/* if successful, returns with the session lock aquired */
static int init_msrpua_session(struct msrpua_session *new, int b2b_type,
	str *b2b_key, str *accept_types, str *peer_path, str *peer_accept_types,
	struct msrp_ua_handler *hdl)
{
	unsigned int hentry;
	void **val;

	new->b2b_key.s = (char*)(new + 1) + MD5_LEN;
	new->b2b_key.len = b2b_key->len;
	memcpy(new->b2b_key.s, b2b_key->s, b2b_key->len);

	new->b2b_type = b2b_type;

	new->lifetime = MSRPUA_SESS_SETUP_TOUT + get_ticks();
	new->dlg_state = MSRPUA_DLG_NEW;

	if (shm_str_dup(&new->accept_types, accept_types) < 0)
		return -1;

	if (peer_path) {
		if (shm_str_dup(&new->peer_path, peer_path) < 0)
			return -1;

		new->peer_path_parsed = parse_msrp_path_shm(&new->peer_path);
		if (!new->peer_path_parsed ) {
			LM_ERR("Failed to parse MSRP peer path\n");
			return -1;
		}
	}

	if (peer_accept_types &&
		shm_str_dup(&new->peer_accept_types, peer_accept_types) < 0)
		return -1;

	hentry = hash_entry(msrpua_sessions, new->session_id);
	hash_lock(msrpua_sessions, hentry);

	val = hash_get(msrpua_sessions, hentry, new->session_id);
	if (!val) {
		hash_unlock(msrpua_sessions, hentry);
		LM_ERR("Failed to allocate new hash entry\n");
		return -1;
	}
	if (*val != NULL) {
		hash_unlock(msrpua_sessions, hentry);
		LM_ERR("Generated duplicate session-id\n");
		return -1;
	}
	*val = new;

	if (hdl)
		new->hdl = *hdl;

	LM_DBG("New MSRP UA session, session_id: %.*s b2b_key: %.*s type: %d\n",
		new->session_id.len, new->session_id.s,
		new->b2b_key.len, new->b2b_key.s, b2b_type);

	return 0;
} 

static int msrpua_init_uas(struct sip_msg *msg, str *accept_types,
	struct msrp_ua_handler *hdl)
{
	str *b2b_key = NULL;
	str contact;
	unsigned int hentry;
	struct msrpua_session *sess;
	str peer_accept_types;
	str peer_path;
	int code;
	str reason;
	str *sdp;
	int del_sess = 0;
	int n;

	sess = shm_malloc(sizeof *sess + MD5_LEN + B2B_MAX_KEY_SIZE);
	if (!sess) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(sess, 0, sizeof *sess);

	sess->session_id.s = (char*)(sess + 1);
	sess->session_id.len = MD5_LEN;
	msrpua_gen_id(sess->session_id.s, b2b_key, NULL);

	if (adv_contact.s)
		contact = adv_contact;
	else
		contact.s = contact_builder(msg->rcv.bind_address, &contact.len);

	b2b_key = b2b_api.server_new(msg, &contact, b2b_server_notify,
		&msrpua_mod_name, NULL, NULL, sess, NULL);
	if (!b2b_key) {
		LM_ERR("failed to create new b2b server instance\n");
		goto err;
	}

	if (get_sdp_peer_info(msg, &peer_accept_types, &peer_path) < 0) {
		LM_ERR("Failed to get peer info from SDP\n");
		code = 488;
		reason = str_init(REASON_488_STR);
		goto err_reply;
	}

	/* match at least one content type from our accept_types 
	 * with the peer's accept_types */
	if (check_offer_types(accept_types, &peer_accept_types) < 0) {
		LM_ERR("Cannot understand any content type received in the offer\n");
		code = 488;
		reason = str_init(REASON_488_STR);
		goto err_reply;
	}

	if (init_msrpua_session(sess, B2B_SERVER, b2b_key, accept_types,
		&peer_path, &peer_accept_types, hdl) < 0) {
		LM_ERR("Failed to init MSRP UA session\n");
		code = 500;
		reason = str_init("Internal Server Error");
		goto err_reply;
	}

	lock_get(sdp_id_lock);
	n = (*next_sdp_id)++;
	lock_release(sdp_id_lock);

	sess->sdp_sess_id = n;
	sess->sdp_sess_vers = n;

	sdp = msrpua_build_sdp(sess, accept_types);
	if (!sdp->s) {
		LM_ERR("Failed to build SDP answer\n");
		code = 500;
		reason = str_init("Internal Server Error");
		del_sess = 1;
		goto err_reply;
	}

	if (msrpua_b2b_reply(B2B_SERVER, b2b_key, METHOD_INVITE,
		200, &str_init("OK"), sdp) < 0) {
		LM_ERR("Failed to send 200 OK\n");
		pkg_free(sdp->s);
		del_sess = 1;
		goto err;
	}

	sess->dlg_state = MSRPUA_DLG_CONF;

	hentry = hash_entry(msrpua_sessions, sess->session_id);
	hash_unlock(msrpua_sessions, hentry);

	pkg_free(sdp->s);
	pkg_free(b2b_key);

	return 0;

err_reply:
	if (msrpua_b2b_reply(B2B_SERVER, b2b_key, METHOD_INVITE,
		code, &reason, NULL) < 0)
		LM_ERR("Failed to send error reply\n");
	if (!del_sess)
		b2b_api.entity_delete(B2B_SERVER, b2b_key, NULL, 1, 1);
err:
	if (del_sess) {
		msrpua_delete_session(sess);
		hentry = hash_entry(msrpua_sessions, sess->session_id);
		hash_unlock(msrpua_sessions, hentry);
	} else {
		free_msrpua_session(sess);
	}
	if (b2b_key)
		pkg_free(b2b_key);
	return -1;
}

static int msrpua_answer(struct sip_msg *msg, str *content_types)
{
	if (msrpua_init_uas(msg, content_types, NULL) < 0)
		return -1;
	else
		return 1;
}

int b2b_add_dlginfo(str* key, str* entity_key, int src, b2b_dlginfo_t* dlginfo,
	void *param)
{
	return 0;
}

static int msrpua_init_uac(str *accept_types, str *from_uri, str *to_uri,
	str *ruri, struct msrp_ua_handler *hdl)
{
	str *b2b_key = NULL;
	client_info_t ci;
	static str method_invite = str_init("INVITE");
	unsigned int hentry;
	struct msrpua_session *sess;
	int n;
	str _ = STR_NULL;

	sess = shm_malloc(sizeof *sess + MD5_LEN + B2B_MAX_KEY_SIZE);
	if (!sess) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(sess, 0, sizeof *sess);

	sess->session_id.s = (char*)(sess + 1);
	sess->session_id.len = MD5_LEN;
	msrpua_gen_id(sess->session_id.s, from_uri, to_uri);

	memset(&ci, 0, sizeof ci);
	ci.method = method_invite;
	ci.to_uri = *to_uri;
	ci.from_uri = *from_uri;
	ci.req_uri = *ruri;

	if (adv_contact.s) {
		ci.local_contact = adv_contact;
	} else {
		LM_ERR("'advertised_contact' parameter required\n");
		goto error;
	}

	lock_get(sdp_id_lock);
	n = (*next_sdp_id)++;
	lock_release(sdp_id_lock);

	sess->sdp_sess_id = n;
	sess->sdp_sess_vers = n;

	ci.body = msrpua_build_sdp(sess, accept_types);
	if (!ci.body->s) {
		LM_ERR("Failed to build SDP answer\n");
		goto error;
	}

	b2b_key = b2b_api.client_new(&ci, b2b_client_notify, b2b_add_dlginfo,
		&msrpua_mod_name, &_, NULL, sess, NULL);
	if (!b2b_key) {
		LM_ERR("failed to create new b2b client instance\n");
		goto error;
	}

	if (init_msrpua_session(sess, B2B_CLIENT, b2b_key, accept_types,
		NULL, NULL, hdl) < 0) {
		LM_ERR("Failed to init MSRP UA session\n");
		goto error;
	}

	hentry = hash_entry(msrpua_sessions, sess->session_id);
	hash_unlock(msrpua_sessions, hentry);

	pkg_free(ci.body->s);
	pkg_free(b2b_key);

	return 0;
error:
	if (b2b_key)
		b2b_api.entity_delete(B2B_CLIENT, b2b_key, NULL, 1, 1);
	free_msrpua_session(sess);
	if (b2b_key)
		pkg_free(b2b_key);
	if (ci.body)
		pkg_free(ci.body->s);
	return -1;
}

static int msrpua_end_session(str *session_id)
{
	unsigned int hentry;
	struct msrpua_session *sess;
	void **val;
	int rc = -1;

	hentry = hash_entry(msrpua_sessions, *session_id);
	hash_lock(msrpua_sessions, hentry);

	val = hash_find(msrpua_sessions, hentry, *session_id);
	if (!val) {
		LM_ERR("session [%.*s] does not exist\n",
			session_id->len, session_id->s);
		rc = 1;
		goto error;
	}
	sess = *val;

	if (sess->dlg_state == MSRPUA_DLG_TERM) {
		hash_unlock(msrpua_sessions, hentry);
		return 0;
	}

	if (sess->dlg_state == MSRPUA_DLG_NEW) {
		if (msrpua_b2b_request(sess->b2b_type, &sess->b2b_key,
			&str_init("CANCEL")) < 0) {
			LM_ERR("Failed to send CANCEL\n");
			rc = -1;
			goto error;
		}
	} else {
		if (msrpua_b2b_request(sess->b2b_type, &sess->b2b_key,
			&str_init("BYE")) < 0) {
			LM_ERR("Failed to send BYE\n");
			rc = -1;
			goto error;
		}
	}

	sess->dlg_state = MSRPUA_DLG_TERM;
	sess->lifetime = MSRPUA_SESS_DEL_TOUT + get_ticks();

	hash_unlock(msrpua_sessions, hentry);
	return 0;
error:
	hash_unlock(msrpua_sessions, hentry);
	return rc;
}

#define REPORT_STATUS_OK "000 200 OK"

static int handle_msrp_request(struct msrp_msg *req, void *hdl_param)
{
	unsigned int hentry;
	struct msrpua_session *sess;
	void **val;
	struct msrp_url *to;
	int t_report = 0;
	struct msrp_ua_handler hdl;
	int run_cb = 0;
	int rc = 0;

	LM_DBG("Received MSRP request [%.*s]\n", req->fl.u.request.method.len,
		req->fl.u.request.method.s);

	/* not interested in other methods for now */
	if (req->fl.u.request.method_id != MSRP_METHOD_SEND)
		return 0;

	if (!req->failure_report || !str_match((&str_init("no")),
		&req->failure_report->body))
		t_report = 1;

	to = (struct msrp_url *)req->to_path->parsed;
	hentry = hash_entry(msrpua_sessions, to->session);

	hash_lock(msrpua_sessions, hentry);

	val = hash_find(msrpua_sessions, hentry, to->session);
	if (!val) {
		hash_unlock(msrpua_sessions, hentry);
		LM_ERR("Invalid URI, session does not exist\n");

		if (t_report && msrp_api.send_reply(msrp_hdl, req, 481, NULL,NULL,0) < 0)
			LM_ERR("Failed to send reply\n");

		return -1;
	}
	sess = *val;

	if (req->body.len && req->content_type &&
		!match_mime_with_list(&req->content_type->body, &sess->accept_types)) {
		LM_DBG("Unacceptable content type: %.*s\n",
			req->content_type->body.len, req->content_type->body.s);
		if (t_report && msrp_api.send_reply(msrp_hdl, req, 415, NULL,NULL,0) < 0)
			LM_ERR("Failed to send reply\n");

		hash_unlock(msrpua_sessions, hentry);
		return -1;
	}

	if (sess->b2b_type == B2B_SERVER)
		sess->to_su = req->rcv.src_su;

	if (sess->hdl.name) {
		run_cb = 1;
		hdl = sess->hdl;
	}

	hash_unlock(msrpua_sessions, hentry);

	if (t_report && msrp_api.send_reply(msrp_hdl, req, 200, &str_init("OK"),
		NULL, 0) < 0) {
		LM_ERR("Failed to send reply\n");
		return -1;
	}

	if (req->body.len) {
		if (run_cb) {
			rc = hdl.msrp_req_cb(req, hdl.param);
		} else {
			if (raise_msg_rcv_event(&to->session, &req->content_type->body,
				&req->body) < 0) {
				LM_ERR("Failed to raise message received event\n");
				return -1;
			}
		}
	}

	if (rc == 0 && req->success_report && str_match((&str_init("yes")),
		&req->success_report->body) && msrp_api.send_report(msrp_hdl,
		&str_init(REPORT_STATUS_OK), req, NULL) < 0) {
		LM_ERR("Failed to send REPORT\n");
		return -1;
	}

	return 0;	
}

static int handle_msrp_reply(struct msrp_msg *rpl, struct msrp_cell *tran,
	void *trans_param, void *hdl_param)
{
	struct msrpua_session *sess = (struct msrpua_session *)trans_param;
	unsigned int hentry;
	struct msrp_ua_handler hdl;
	int run_cb = 0;

	if (rpl)
		LM_DBG("Received MSRP reply [%d %.*s]\n", rpl->fl.u.reply.status_no,
			rpl->fl.u.reply.reason.len, rpl->fl.u.reply.reason.s);
	else
		LM_DBG("Timeout for ident=%.*s\n", tran->ident.len, tran->ident.s);

	hentry = hash_entry(msrpua_sessions, sess->session_id);
	hash_lock(msrpua_sessions, hentry);

	if (sess->hdl.name) {
		run_cb = 1;
		hdl = sess->hdl;
	}

	hash_unlock(msrpua_sessions, hentry);

	if (run_cb)
		hdl.msrp_rpl_cb(rpl, hdl.param);

	return 0;
}

#define MESSAGE_ID_PREFIX "Message-ID: "
#define MESSAGE_ID_PREFIX_LEN (sizeof(MESSAGE_ID_PREFIX) - 1)
#define BYTE_RANGE_PREFIX "Byte-Range: 1-"
#define BYTE_RANGE_PREFIX_LEN (sizeof(BYTE_RANGE_PREFIX) - 1)
#define FAILURE_REPORT_NO_HDR "Failure-Report: no"
#define BYTE_RANGE_PREFIX_LEN (sizeof(BYTE_RANGE_PREFIX) - 1)

#define MSRP_HDRS_NO 3

static int msrpua_send_message(str *sess_id, str *mime, str *body)
{
	unsigned int hentry;
	struct msrpua_session *sess;
	void **val;
	int rc = -1;
	str from = {0};
	str hdrs[MSRP_HDRS_NO] = {{0}};
	char *p;
	str blen;

	if (!mime || !body) {
		mime = NULL;
		body = NULL;
	}

	hentry = hash_entry(msrpua_sessions, *sess_id);
	hash_lock(msrpua_sessions, hentry);

	val = hash_find(msrpua_sessions, hentry, *sess_id);
	if (!val) {
		LM_ERR("session [%.*s] does not exist\n",
			sess_id->len, sess_id->s);
		rc = 1;
		goto error;
	}
	sess = *val;

	if (sess->dlg_state != MSRPUA_DLG_EST) {
		LM_ERR("Session not established yet\n");
		goto error;
	}

	from.len = my_msrp_uri.whole.len + 1 + sess->session_id.len;
	from.s = pkg_malloc(from.len);
	if (!from.s) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	/* build From-Path with current session_id */
	p = from.s;
	append_string(p, my_msrp_uri.whole.s,
		my_msrp_uri.whole.len - my_msrp_uri.params.len - 1);
	*(p++) = '/';
	append_string(p, sess->session_id.s, sess->session_id.len);
	*(p++) = ';';
	append_string(p, my_msrp_uri.params.s, my_msrp_uri.params.len);

	/* Message-ID */
	hdrs[0].len = MESSAGE_ID_PREFIX_LEN + MD5_LEN;
	hdrs[0].s = pkg_malloc(hdrs[0].len);
	if (!hdrs[0].s) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	p = hdrs[0].s;
	append_string(p, MESSAGE_ID_PREFIX, MESSAGE_ID_PREFIX_LEN);
	msrpua_gen_id(p, &sess->session_id, NULL);

	/* Byte-Range: 1-len/len */
	hdrs[1].len = BYTE_RANGE_PREFIX_LEN;
	if (body) {
		blen.s = int2str(body->len, &blen.len);
		hdrs[1].len += blen.len + 1 + blen.len;
	} else {
		blen = str_init("0");
		hdrs[1].len += 3;
	}
	hdrs[1].s = pkg_malloc(hdrs[1].len);
	if (!hdrs[1].s) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	p = hdrs[1].s;
	append_string(p, BYTE_RANGE_PREFIX, BYTE_RANGE_PREFIX_LEN);
	append_string(p, blen.s, blen.len);
	*(p++) = '/';
	append_string(p, blen.s, blen.len);

	hdrs[2] = str_init(FAILURE_REPORT_NO_HDR);

	if (msrp_api.send_request(msrp_hdl, MSRP_METHOD_SEND, &from,
		sess->peer_path_parsed, msrp_sock, &sess->to_su, mime, body, hdrs,
		MSRP_HDRS_NO, '$', sess) < 0) {
		LM_ERR("Failed to send MSRP message\n");
		goto error;
	}

	pkg_free(from.s);
	pkg_free(hdrs[0].s);
	pkg_free(hdrs[1].s);

	hash_unlock(msrpua_sessions, hentry);
	return 0;
error:
	hash_unlock(msrpua_sessions, hentry);
	if (from.s)
		pkg_free(from.s);
	if (hdrs[0].s)
		pkg_free(hdrs[0].s);
	if (hdrs[1].s)
		pkg_free(hdrs[1].s);
	return rc;
}

mi_response_t *msrpua_mi_send_msg(const mi_params_t *params,
	struct mi_handler *_)
{
	str sess_id;
	str mime;
	str body;
	int rc;

	if (get_mi_string_param(params, "session_id", &sess_id.s, &sess_id.len) < 0)
		return init_mi_param_error();

	switch (try_get_mi_string_param(params, "mime", &mime.s, &mime.len)) {
		case 0:
			break;
		case -1:
			mime.s = NULL;
			break;
		default:
			return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "body", &body.s, &body.len)) {
		case 0:
			break;
		case -1:
			body.s = NULL;
			break;
		default:
			return init_mi_param_error();
	}

	rc = msrpua_send_message(&sess_id, mime.s ? &mime:NULL, body.s ? &body:NULL);
	if (rc < 0)
		return init_mi_error(500, MI_SSTR("Failed to send message"));
	else if (rc == 1)
		return init_mi_error(404, MI_SSTR("Unknown session"));

	return init_mi_result_ok();
}

mi_response_t *msrpua_mi_end(const mi_params_t *params,
	struct mi_handler *_)
{
	str sess_id;
	int rc;

	if (get_mi_string_param(params, "session_id", &sess_id.s, &sess_id.len) < 0)
		return init_mi_param_error();

	rc = msrpua_end_session(&sess_id);
	if (rc < 0)
		return init_mi_error(500, MI_SSTR("Unable to end session"));
	else if (rc == 1)
		return init_mi_error(404, MI_SSTR("Unknown session"));

	return init_mi_result_ok();
}

struct mi_list_params {
	mi_item_t *resp_arr;
	int rc;
};

static int mi_print_session(void *param, str key, void *value)
{
	struct msrpua_session *sess = (struct msrpua_session *)value;
	struct mi_list_params *params = (struct mi_list_params *)param;
	mi_item_t *sess_obj;
	str hdl_str;

	sess_obj = add_mi_object(params->resp_arr, NULL, 0);
	if (!sess_obj) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_string(sess_obj, MI_SSTR("session_id"),
		sess->session_id.s, sess->session_id.len) < 0) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_string(sess_obj, MI_SSTR("b2b_key"),
		sess->b2b_key.s, sess->b2b_key.len) < 0) {
		params->rc = 1;
		return 1;
	}
	if (add_mi_string_fmt(sess_obj, MI_SSTR("type"),
		sess->b2b_type==B2B_SERVER ? "UAS" : "UAC") < 0) {
		params->rc = 1;
		return 1;
	}

	if (sess->hdl.name)
		hdl_str = *sess->hdl.name ;
	else
		hdl_str = str_init("msrp_ua");
	if (add_mi_string(sess_obj, MI_SSTR("handler"),
		hdl_str.s, hdl_str.len) < 0) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_number(sess_obj, MI_SSTR("dlg_state"), sess->dlg_state) < 0) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_string(sess_obj, MI_SSTR("peer_path"),
		sess->peer_path.s, sess->peer_path.len) < 0) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_number(sess_obj, MI_SSTR("lifetime"),
		sess->lifetime - get_ticks()) < 0) {
		params->rc = 1;
		return 1;
	}

	return 0;
}

mi_response_t *msrpua_mi_list(const mi_params_t *_,
	struct mi_handler *__)
{
	mi_response_t *resp;
	struct mi_list_params params = {0};

	resp = init_mi_result_array(&params.resp_arr);
	if (!resp)
		return NULL;

	hash_for_each_locked(msrpua_sessions, mi_print_session, &params);
	if (params.rc != 0)
		goto error;

	return resp;
error:
	free_mi_response(resp);
	return NULL;
}

mi_response_t *msrpua_mi_start_session(const mi_params_t *params,
	struct mi_handler *_)
{
	str ct_types;
	str from_uri, to_uri, ruri;

	if (get_mi_string_param(params, "content_types", &ct_types.s,
		&ct_types.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "from_uri", &from_uri.s,
		&from_uri.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "to_uri", &to_uri.s,
		&to_uri.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "ruri", &ruri.s,
		&ruri.len) < 0)
		return init_mi_param_error();

	if (msrpua_init_uac(&ct_types, &from_uri, &to_uri, &ruri, NULL) < 0)
		return init_mi_error(500, MI_SSTR("Failed to start session"));

	return init_mi_result_ok();
}

static int timer_clean_session(void *param, str key, void *value)
{
	struct msrpua_session *sess = (struct msrpua_session *)value;
	str sess_id;
	int raise_ev = 0;
	struct msrp_ua_notify_params cb_params = {0};
	struct msrp_ua_handler hdl;

	if (sess->lifetime > 0 && sess->lifetime < get_ticks()) {
		if (sess->dlg_state == MSRPUA_DLG_NEW) {
			if (msrpua_b2b_request(sess->b2b_type, &sess->b2b_key,
				&str_init("CANCEL")) < 0)
				LM_ERR("Failed to send CANCEL on timeout\n");

			if (sess->hdl.name) {
				if (pkg_str_dup(&sess_id, &sess->session_id) < 0) {
					LM_ERR("no more pkg memory\n");
					goto del_session;
				}

				cb_params.event = MSRP_UA_SESS_FAILED;
				cb_params.session_id = &sess_id;
				hdl = sess->hdl;
			}
		} else if (sess->dlg_state < MSRPUA_DLG_TERM) {
			if (msrpua_b2b_request(sess->b2b_type, &sess->b2b_key,
				&str_init("BYE")) < 0) {
				LM_ERR("Failed to send BYE on timeout\n");
				goto del_session;
			}

			if (sess->dlg_state == MSRPUA_DLG_EST) {
				if (pkg_str_dup(&sess_id, &sess->session_id) < 0) {
					LM_ERR("no more pkg memory\n");
					goto del_session;
				}

				if (sess->hdl.name) {
					cb_params.event = MSRP_UA_SESS_TERMINATED;
					cb_params.session_id = &sess_id;
					hdl = sess->hdl;
				} else {
					raise_ev = 1;
				}
			} else if (sess->hdl.name) {  /* MSRPUA_DLG_CONF */
				/* this should be a UAS session for which we have not received
				 * the ACK in time */
				if (pkg_str_dup(&sess_id, &sess->session_id) < 0) {
					LM_ERR("no more pkg memory\n");
					goto del_session;
				}

				cb_params.event = MSRP_UA_SESS_FAILED;
				cb_params.session_id = &sess_id;
				hdl = sess->hdl;
			}
		}

del_session:
		hash_remove_key(msrpua_sessions, key);
		free_msrpua_session(sess);
	}

	if (raise_ev) {
		/* TODO: don't raise event/run callback under lock */
		if (raise_sess_end_event(&sess_id) < 0)
			LM_ERR("Failed to raise session end event on timeout\n");

		pkg_free(sess_id.s);
	} else if (cb_params.event) {
		hdl.notify_cb(&cb_params, hdl.param);

		pkg_free(sess_id.s);
	}

	return 0;
}

static void clean_msrpua_sessions(unsigned int ticks,void *param)
{
	hash_for_each_locked(msrpua_sessions, timer_clean_session, NULL);
}

void load_msrp_ua(struct msrp_ua_binds *binds)
{
	binds->init_uas = msrpua_init_uas;
	binds->init_uac = msrpua_init_uac;
	binds->end_session = msrpua_end_session;
	binds->send_message = msrpua_send_message;
}
