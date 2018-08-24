/*
 * Copyright (C) 2015 - OpenSIPS Foundation
 * Copyright (C) 2001-2003 FhG Fokus
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
 *
 * History:
 * -------
 *  2017-09-**  first version (victor.ciurel)
 */
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../pt.h"
#include "../../ut.h"
#include "../../resolve.h"
#include "../../forward.h"
#include "../../ipc.h"
#include "../../db/db.h"
#include "../../receive.h"
#include "../tm/tm_load.h"
#include "../../parser/parse_from.h"

#include "db.h"
#include "proto_smpp.h"
#include "utils.h"

extern int proto_tcp_read(struct tcp_connection* ,struct tcp_req* );

static int mod_init(void);
static int child_init(int rank);
static int smpp_init(struct proto_info *pi);
static int smpp_init_listener(struct socket_info *si);
static int smpp_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to, int id);
static int smpp_read_req(struct tcp_connection* conn, int* bytes_read);
static int smpp_write_async_req(struct tcp_connection* con,int fd);
static int smpp_conn_init(struct tcp_connection* c);
static void smpp_conn_clean(struct tcp_connection* c);
static int recv_smpp_msg(smpp_header_t *header, smpp_deliver_sm_t *body, struct tcp_connection *conn);
static int send_smpp_msg(struct sip_msg* msg);
static void send_enquire_link_request(smpp_session_t *session);

static void build_smpp_sessions_from_db(void);
static void rpc_bind_sessions(int sender_id, void *param);
static int register_enquire_link_timer(void);

static uint32_t increment_sequence_number(smpp_session_t *session);

void enquire_link(unsigned int ticks, void *param);

/** TM bind */
struct tm_binds tmb;

static unsigned smpp_port = 2775;
static smpp_session_t **g_sessions = NULL;
static struct tcp_req smpp_current_req;

char _ip_addr_A_buff[IP_ADDR_MAX_STR_SIZE];

str msg_type = str_init("MESSAGE");

str outbound_uri;


str db_url = {NULL, 0};
int db_mode = 0;			/* Database usage mode: 0 = no cache, 1 = cache */
str smpp_table = {"smpp", 4}; /* Name of smpp table */
str ip_col = {"ip", 2};       /* Name of domain column */
str port_col = {"port", 4}; /* Name of attributes column */
str system_id_col = {"system_id", 9};
str password_col = {"password", 8};
str system_type_col = {"system_type", 11};
str ton_col = {"ton", 3};
str npi_col = {"npi", 3};

static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)smpp_init, 0, 0, 0, 0},
	{"send_smpp_message", (cmd_function)send_smpp_msg, 0, 0, 0, REQUEST_ROUTE},
	{0,0,0,0,0,0}
};

static param_export_t params[] = {
	{"smpp_port", INT_PARAM, &smpp_port},
	{"db_url", STR_PARAM, &db_url},
	{"outbound_uri", STR_PARAM, &outbound_uri},
	{0, 0, 0}
};

struct module_exports exports = {
	PROTO_PREFIX "smpp",	/* module name*/
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	NULL,			/* OpenSIPS module dependencies */
	cmds,			/* exported functions */
	0,			/* exported async functions */
	params,			/* module parameters */
	0,			/* exported statistics */
	0,			/* exported MI functions */
	0,			/* exported pseudo-variables */
	0,			/* exported transformations */
	0,			/* extra processes */
	mod_init,		/* module initialization function */
	0,			/* response function */
	0,			/* destroy function */
	child_init,		/* per-child init function */
};

static int smpp_init(struct proto_info *pi)
{
	pi->id			= PROTO_SMPP;
	pi->name		= "smpp";
	pi->default_port	= smpp_port;

	pi->tran.init_listener	= smpp_init_listener;
	pi->tran.send		= smpp_send;
	pi->tran.dst_attr	= tcp_conn_fcntl;

	pi->net.flags		= PROTO_NET_USE_TCP;
	pi->net.read		= (proto_net_read_f)smpp_read_req;
	pi->net.write		= (proto_net_write_f)smpp_write_async_req;

	pi->net.conn_init	= smpp_conn_init;
	pi->net.conn_clean	= smpp_conn_clean;

	return 0;
}

static int mod_init(void)
{
	LM_INFO("initializing SMPP protocol\n");

	db_url.len = strlen(db_url.s);
	outbound_uri.len = strlen(outbound_uri.s);

	if (smpp_db_bind(&db_url) < 0) {
		return -1;
	}
	if (smpp_db_init(&db_url) < 0) {
		return -1;
	}

	build_smpp_sessions_from_db();

	smpp_db_close();

	if (register_enquire_link_timer() < 0) {
	    LM_ERR("could not register timer\n");
	    return -1;
	}

	/* load the TM API */
	if (load_tm_api(&tmb)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}


	return 0;
}

static uint32_t get_payload_from_header(char *payload, smpp_header_t *header)
{
	if (!payload || !header) {
		LM_ERR("NULL params");
		return 0;
	}

	char *p = payload;
	p += copy_u32(p, header->command_length);
	p += copy_u32(p, header->command_id);
	p += copy_u32(p, header->command_status);
	p += copy_u32(p, header->sequence_number);

	return p - payload;
}

static uint32_t get_payload_from_bind_transceiver_body(char *body, smpp_bind_transceiver_t *transceiver)
{
	if (!body || !transceiver) {
		LM_ERR("NULL params");
		return 0;
	}

	char *p = body;
	p += copy_var_str(p, transceiver->system_id);
	p += copy_var_str(p, transceiver->password);
	p += copy_var_str(p, transceiver->system_type);
	p += copy_u8(p, transceiver->interface_version);
	p += copy_u8(p, transceiver->addr_ton);
	p += copy_u8(p, transceiver->addr_npi);
	p += copy_var_str(p, transceiver->address_range);

	return p - body;
}

uint32_t get_payload_from_submit_sm_body(char *body, smpp_submit_sm_t *submit_sm)
{
	if (!body || !submit_sm) {
		LM_ERR("NULL params");
		return 0;
	}

	char *p = body;
	p += copy_var_str(p, submit_sm->service_type);
	p += copy_u8(p, submit_sm->source_addr_ton);
	p += copy_u8(p, submit_sm->source_addr_npi);
	p += copy_var_str(p, submit_sm->source_addr);
	p += copy_u8(p, submit_sm->dest_addr_ton);
	p += copy_u8(p, submit_sm->dest_addr_npi);
	p += copy_var_str(p, submit_sm->destination_addr);
	p += copy_u8(p, submit_sm->esm_class);
	p += copy_u8(p, submit_sm->protocol_id);
	p += copy_u8(p, submit_sm->protocol_flag);
	p += copy_var_str(p, submit_sm->schedule_delivery_time);
	p += copy_var_str(p, submit_sm->validity_period);
	p += copy_u8(p, submit_sm->registered_delivery);
	p += copy_u8(p, submit_sm->replace_if_present_flag);
	p += copy_u8(p, submit_sm->data_coding);
	p += copy_u8(p, submit_sm->sm_default_msg_id);
	p += copy_u8(p, submit_sm->sm_length);
	p += copy_fixed_str(p, submit_sm->short_message, submit_sm->sm_length);

	return p - body;
}

uint32_t get_payload_from_deliver_sm_body(char *body, smpp_deliver_sm_resp_t *deliver_sm_resp)
{
	if (!body || !deliver_sm_resp) {
		LM_ERR("NULL params");
		return 0;
	}

	body[0] = deliver_sm_resp->message_id[0];
	return 1;
}

static int build_bind_transceiver_request(smpp_bind_transceiver_req_t **preq, smpp_bind_transceiver_t *transceiver, uint32_t seq_no)
{
	if (!preq || !transceiver) {
		LM_ERR("NULL params");
		goto err;
	}

	/* request allocations */
	smpp_bind_transceiver_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header");
		goto header_err;
	}

	smpp_bind_transceiver_t *body = pkg_malloc(sizeof(*body));
	if (!body) {
		LM_ERR("malloc error for body");
		goto body_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(BIND_RECEIVER));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload");
		goto payload_err;
	}

	req->header = header;
	req->body = body;

	/* copy body fields */
	copy_var_str(body->system_id, transceiver->system_id);
	copy_var_str(body->password, transceiver->password);
	copy_var_str(body->system_type, transceiver->system_type);
	body->interface_version = transceiver->interface_version;
	body->addr_ton = transceiver->addr_ton;
	body->addr_npi = transceiver->addr_npi;
	copy_var_str(body->address_range, transceiver->address_range);

	uint32_t body_len = get_payload_from_bind_transceiver_body(req->payload.s + HEADER_SZ, transceiver);
	header->command_length = HEADER_SZ + body_len;
	header->command_id = BIND_TRANSCEIVER_CID;
	header->command_status = 0;
	header->sequence_number = seq_no;

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(body);
body_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}

static int build_submit_sm_request(smpp_submit_sm_req_t **preq, char *src, char *dst, str *message, uint32_t sequence_number)
{
	if (!preq || !src || !dst || !message) {
		LM_ERR("NULL params");
		goto err;
	}

	/* request allocations */
	smpp_submit_sm_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header");
		goto header_err;
	}

	smpp_submit_sm_t *body = pkg_malloc(sizeof(*body));
	if (!body) {
		LM_ERR("malloc error for body");
		goto body_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(SUBMIT_SM));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload");
		goto payload_err;
	}

	req->header = header;
	req->body = body;

	memset(body, 0, sizeof(*body));
	body->source_addr_ton = 0x02;
	body->source_addr_npi = 0x01;
	strcpy(body->source_addr, src);
	body->dest_addr_ton = 0x02;
	body->dest_addr_npi = 0x01;
	strcpy(body->destination_addr, dst);
	body->sm_length = message->len;
	strncpy(body->short_message, message->s, message->len);

	uint32_t body_len = get_payload_from_submit_sm_body(req->payload.s + HEADER_SZ, body);

	header->command_length = HEADER_SZ + body_len;
	header->command_id = SUBMIT_SM_CID;
	header->command_status = 0;
	header->sequence_number = sequence_number;

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(body);
body_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}

static int build_deliver_sm_resp_request(smpp_deliver_sm_resp_req_t **preq, uint32_t command_status, uint32_t sequence_number)
{
	if (!preq) {
		LM_ERR("NULL param");
		goto err;
	}

	/* request allocations */
	smpp_deliver_sm_resp_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header");
		goto header_err;
	}

	smpp_deliver_sm_resp_t *body = pkg_malloc(sizeof(*body));
	if (!body) {
		LM_ERR("malloc error for body");
		goto body_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(DELIVER_SM_RESP));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload");
		goto payload_err;
	}

	req->header = header;
	req->body = body;

	memset(body, 0, sizeof(*body));

	uint32_t body_len = get_payload_from_deliver_sm_body(req->payload.s + HEADER_SZ, body);
	header->command_length = HEADER_SZ + body_len;
	header->command_id = DELIVER_SM_RESP_CID;
	header->command_status = command_status;
	header->sequence_number = sequence_number;

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(body);
body_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}


static struct tcp_connection* smpp_sync_connect(struct socket_info* send_sock,
		union sockaddr_union* server, int *fd)
{
	int s;
	union sockaddr_union my_name;
	socklen_t my_name_len;
	struct tcp_connection* con;

	s=socket(AF2PF(server->s.sa_family), SOCK_STREAM, 0);
	if (s==-1){
		LM_ERR("socket: (%d) %s\n", errno, strerror(errno));
		goto error;
	}
	if (tcp_init_sock_opt(s)<0){
		LM_ERR("tcp_init_sock_opt failed\n");
		goto error;
	}
	my_name_len = sockaddru_len(send_sock->su);
	memcpy( &my_name, &send_sock->su, my_name_len);
	su_setport( &my_name, 0);
	if (bind(s, &my_name.s, my_name_len )!=0) {
		LM_ERR("bind failed (%d) %s\n", errno,strerror(errno));
		goto error;
	}

	if (tcp_connect_blocking(s, &server->s, sockaddru_len(*server))<0){
		LM_ERR("tcp_blocking_connect failed\n");
		goto error;
	}
	con = tcp_conn_create(s, server, send_sock, S_CONN_OK);
	if (con==NULL){
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		goto error;
	}
	*fd = s;
	return con;
	/*FIXME: set sock idx! */
error:
	/* close the opened socket */
	if (s!=-1) close(s);
	return 0;
}

static uint32_t get_sequence_number(smpp_session_t *session)
{
	uint32_t seq_no;
	lock_get(&session->sequence_number_lock);
	seq_no = session->sequence_number;
	lock_release(&session->sequence_number_lock);
	return seq_no;
}

static uint32_t increment_sequence_number(smpp_session_t *session)
{
	uint32_t seq_no;
	lock_get(&session->sequence_number_lock);
	seq_no = session->sequence_number++;
	lock_release(&session->sequence_number_lock);
	return seq_no;
}

static void rpc_bind_sessions(int sender_id, void *param)
{
	smpp_session_t *session_it = (smpp_session_t*)param;
	while (session_it) {
		LM_INFO("bindin session with system_id \"%s\"\n",
				session_it->bind.transceiver.system_id);
		bind_session(session_it);
		session_it = session_it->next;
	}
}

static void bind_session(smpp_session_t *session)
{
	if (!session)
		LM_ERR("NULL param\n");

	smpp_bind_transceiver_req_t *req = NULL;
	uint32_t seq_no = increment_sequence_number(session);

	if (build_bind_transceiver_request(&req, &session->bind.transceiver, seq_no)) {
		LM_ERR("error creating request\n");
		return;
	}

	union sockaddr_union to;
	if (init_su(&to, session->ip, session->port)) {
		LM_ERR("error creating su from ipaddr and port\n");
		goto free_req;
	}
	struct socket_info *send_socket = get_send_socket(NULL, &to, PROTO_SMPP);
	if (!send_socket) {
		LM_ERR("error getting send socket\n");
		goto free_req;
	}
	union sockaddr_union server;
	if (init_su(&server, session->ip, session->port)) {
		LM_ERR("error creating su from ipaddr and port\n");
		goto free_req;
	}
	int fd;
	smpp_sync_connect(send_socket, &server, &fd);
	int n = tsend_stream(fd, req->payload.s, req->payload.len, 1000);

	LM_INFO("received connection with return code %d\n", n);

free_req:
	pkg_free(req);
}

static int child_init(int rank)
{
	LM_INFO("initializing child #%d\n", rank);

	if ((rank == 1) && ipc_dispatch_rpc(rpc_bind_sessions, *g_sessions) < 0) {
		LM_CRIT("failed to RPC the data loading\n");
		return -1;
	}

	return 0;
}

static void build_smpp_sessions_from_db(void)
{
	db_key_t cols[7];
	db_res_t* res = NULL;
	db_row_t* row;
	db_val_t* val;

	int i;

	cols[0] = &ip_col;
	cols[1] = &port_col;
	cols[2] = &system_id_col;
	cols[3] = &password_col;
	cols[4] = &system_type_col;
	cols[5] = &ton_col;
	cols[6] = &npi_col;

	if (smpp_query(&smpp_table, cols, 7, &res) < 0) {
		return;
	}

	row = RES_ROWS(res);

	LM_DBG("Number of rows in domain table: %d\n", RES_ROW_N(res));

	g_sessions = shm_malloc(sizeof(smpp_session_t*));
	if (!g_sessions) {
		LM_CRIT("failed to allocate shared memory for sessions pointer\n");
		return;
	}
	smpp_session_t *sessions = shm_malloc(RES_ROW_N(res) * sizeof(smpp_session_t));
	if (!sessions) {
		LM_CRIT("failed to allocate shared memory for session\n");
		return;
	}
	memset(sessions, 0, RES_ROW_N(res) * sizeof(smpp_session_t));
	for (i = 0; i < RES_ROW_N(res); i++) {
		val = ROW_VALUES(row + i);
		sessions[i].session_status = SMPP_CLOSED;
		sessions[i].session_type = BIND_TRANSCEIVER;
		char *ip = strdup(VAL_STRING(val));
		str ip_str = {ip, strlen(ip)};
		sessions[i].ip = str2ip(&ip_str);
		sessions[i].port = VAL_INT(val + 1);
		strncpy(sessions[i].bind.transceiver.system_id, VAL_STRING(val + 2), 16);
		strncpy(sessions[i].bind.transceiver.password, VAL_STRING(val + 3), 16);
		strncpy(sessions[i].bind.transceiver.system_type, VAL_STRING(val + 4), 16);
		sessions[i].bind.transceiver.interface_version = SMPP_VERSION;
		sessions[i].bind.transceiver.addr_ton = VAL_INT(val + 5);
		sessions[i].bind.transceiver.addr_npi = VAL_INT(val + 6);
		lock_init(&sessions[i].sequence_number_lock);
	}
	*g_sessions = sessions;
	smpp_free_results(res);
}

static int register_enquire_link_timer(void)
{
	if (register_timer("enquire-link-timer", enquire_link, NULL, 5,
	TIMER_FLAG_DELAY_ON_DELAY)<0 ) {
		return -1;
	}
	return 0;
}

void enquire_link(unsigned int ticks, void *params)
{
	LM_INFO("%u ticks\n", ticks);
	send_enquire_link_request();
}

static int smpp_conn_init(struct tcp_connection* c)
{
	LM_INFO("smpp_conn_init called\n");
	return 0;
}

static void smpp_conn_clean(struct tcp_connection* c)
{
	LM_INFO("smpp_conn_clean called\n");
}

static int smpp_init_listener(struct socket_info *si)
{
	/* we do not do anything particular, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}

static int smpp_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to, int id)
{
	LM_INFO("smpp_send called\n");

	return 0;
}

static void smpp_parse_headers(struct tcp_req *req)
{
	if (req->content_len == 0 && req->pos - req->buf < HEADER_SZ){
		req->parsed = req->pos;
		return;
	}
	//validity ? TODO

	uint32_t *px = (uint32_t*)req->buf;
	req->content_len = ntohl(*px);
	if (req->pos - req->buf == req->content_len) {
		LM_DBG("received a complete message\n");
		req->complete = 1;
		req->parsed = req->buf +req->content_len;
	} else if (req->pos - req->buf > req->content_len) {
		LM_DBG("received more then a message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else {
		LM_DBG("received only part of a message\n");
		req->parsed = req->pos;
	}
}


static void smpp_parse_header(smpp_header_t *header, char *buffer)
{
	if (!header || !buffer)
		LM_ERR("NULL params");

	uint32_t *p = (uint32_t*)buffer;

	header->command_length = ntohl(*p++);
	header->command_id = ntohl(*p++);
	header->command_status = ntohl(*p++);
	header->sequence_number = ntohl(*p++);
}

void parse_deliver_sm_body(smpp_deliver_sm_t *body, smpp_header_t *header, char *buffer)
{
	if (!body || !header || !buffer) {
		LM_ERR("NULL params\n");
		return;
	}

	char *p = buffer;
	p += copy_var_str(body->service_type, p);
	body->source_addr_ton = *p++;
	body->source_addr_npi = *p++;
	p += copy_var_str(body->source_addr, p);
	body->dest_addr_ton = *p++;
	body->dest_addr_npi = *p++;
	p += copy_var_str(body->destination_addr, p);
	body->esm_class = *p++;
	body->protocol_id = *p++;
	body->protocol_flag = *p++;
	body->schedule_delivery_time[0] = *p++;
	body->validity_period[0] = *p++;
	body->registered_delivery = *p++;
	body->replace_if_present_flag = *p++;
	body->data_coding = *p++;
	body->sm_default_msg_id = *p++;
	body->sm_length = *p++;
	copy_fixed_str(body->short_message, p, body->sm_length);
}

void parse_bind_transceiver_resp_body(smpp_bind_transceiver_resp_t *body, smpp_header_t *header, char *buffer)
{
	if (!body || !header || !buffer) {
		LM_ERR("NULL params\n");
		return;
	}

	copy_var_str(body->system_id, buffer);
}

void parse_submit_sm_resp_body(smpp_submit_sm_resp_t *body, smpp_header_t *header, char *buffer)
{
	if (!body || !header || !buffer) {
		LM_ERR("NULL params\n");
		return;
	}

	copy_var_str(body->message_id, buffer);
}

void send_deliver_sm_resp(smpp_deliver_sm_req_t *req, struct receive_info *rcv)
{
	if (!req || !rcv) {
		LM_ERR("NULL params\n");
		return;
	}

	smpp_deliver_sm_resp_req_t *resp;
	uint32_t command_status = 0;
	uint32_t seq_no = req->header->sequence_number;
	if (build_deliver_sm_resp_request(&resp, command_status, seq_no)) {
		LM_ERR("error creating request\n");
		return;
	}

	struct tcp_connection *conn;
	int fd;
	int ret = tcp_conn_get(rcv->proto_reserved1, &rcv->src_ip, rcv->src_port, rcv->proto, &conn, &fd);
	if (ret < 0) {
		LM_ERR("return code %d\n", ret);
		goto free_req;
	}
	int n = tsend_stream(fd, resp->payload.s, resp->payload.len, 1000);
	LM_INFO("send %d bytes\n", n);

free_req:
	pkg_free(resp);
}

void handle_generic_nack_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	LM_DBG("Received generic_nack command\n");
}
void handle_bind_receiver_resp_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	LM_DBG("Received bind_receiver_resp command\n");
}
void handle_bind_transmitter_resp_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	LM_DBG("Received bind_transmitter_resp command\n");
}
void handle_submit_sm_resp_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	if (!header || !buffer || !rcv) {
		LM_ERR("NULL params\n");
		return;
	}
	LM_DBG("Received submit_sm_resp command\n");
	if (header->command_status) {
		LM_ERR("Error in submit_sm_resp %08x\n", header->command_status);
		return;
	}
	smpp_submit_sm_resp_t body;
	memset(&body, 0, sizeof(body));
	parse_submit_sm_resp_body(&body, header, buffer);
	LM_INFO("Successfully submitted message \"%s\"\n", body.message_id);
}
void handle_deliver_sm_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	if (!header || !buffer || !rcv) {
		LM_ERR("NULL params\n");
		return;
	}

	LM_DBG("Received deliver_sm command\n");
	if (header->command_status) {
		LM_ERR("Error in deliver_sm %08x\n", header->command_status);
		return;
	}
	smpp_deliver_sm_t body;
	memset(&body, 0, sizeof(body));
	parse_deliver_sm_body(&body, header, buffer);
	LM_DBG("Received SMPP message\n"
			"FROM:\t%02x %02x %s\n"
			"TO:\t%02x %02x %s\n%.*s\n",
			body.source_addr_ton, body.source_addr_npi, body.source_addr,
			body.dest_addr_ton, body.dest_addr_npi, body.destination_addr,
			body.sm_length, body.short_message);
	smpp_deliver_sm_req_t req;
	req.header = header;
	req.body = &body;
	send_deliver_sm_resp(&req, rcv);
}
void handle_unbind_resp_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	LM_DBG("Received unbind_resp command\n");
}
void handle_bind_transceiver_resp_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	if (!header || !buffer || !rcv) {
		LM_ERR("NULL params\n");
		return;
	}
	LM_DBG("Received bind_transceiver_resp command\n");
	if (header->command_status) {
		LM_ERR("Error in bind_transceiver_resp %08x\n", header->command_status);
		return;
	}
	smpp_bind_transceiver_resp_t body;
	memset(&body, 0, sizeof(body));
	parse_bind_transceiver_resp_body(&body, header, buffer);
	LM_INFO("Successfully bound transceiver \"%s\"\n", body.system_id);
}
void handle_data_sm_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	LM_DBG("Received data_sm command\n");
}
void handle_data_sm_resp_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	LM_DBG("Received data_sm_resp command\n");
}

void handle_enquire_link_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	LM_DBG("Received enquire_link command\n");
}

void handle_enquire_link_resp_cmd(smpp_header_t *header, char *buffer, struct receive_info *rcv)
{
	LM_DBG("Received enquire_link_resp command\n");
}

static void handle_smpp_msg(char* buffer, struct receive_info *rcv)
{
	smpp_header_t header;
	smpp_parse_header(&header, buffer);
	buffer += HEADER_SZ;

	LM_DBG("Received SMPP command %08x\n", header.command_id);

	switch (header.command_id) {
		case GENERIC_NACK_CID:
			handle_generic_nack_cmd(&header, buffer, rcv);
			break;
		case BIND_RECEIVER_RESP_CID:
			handle_bind_receiver_resp_cmd(&header, buffer, rcv);
			break;
		case BIND_TRANSMITTER_RESP_CID:
			handle_bind_transmitter_resp_cmd(&header, buffer, rcv);
			break;
		case SUBMIT_SM_RESP_CID:
			handle_submit_sm_resp_cmd(&header, buffer, rcv);
			break;
		case DELIVER_SM_CID:
			handle_deliver_sm_cmd(&header, buffer, rcv);
			break;
		case UNBIND_RESP_CID:
			handle_unbind_resp_cmd(&header, buffer, rcv);
			break;
		case BIND_TRANSCEIVER_RESP_CID:
			handle_bind_transceiver_resp_cmd(&header, buffer, rcv);
			break;
		case DATA_SM_CID:
			handle_data_sm_cmd(&header, buffer, rcv);
			break;
		case DATA_SM_RESP_CID:
			handle_data_sm_resp_cmd(&header, buffer, rcv);
			break;
		case ENQUIRE_LINK_CID:
			handle_enquire_link_cmd(&header, buffer, rcv);
			break;
		case ENQUIRE_LINK_RESP_CID:
			handle_enquire_link_resp_cmd(&header, buffer, rcv);
			break;
		default:
			LM_WARN("Unknown or unsupported command received %08X\n", header.command_id);
	}
}

static int smpp_handle_req(struct tcp_req *req,
							struct tcp_connection *con, int _max_msg_chunks)
{
	long size;

	if (req->complete){
		/* update the timeout - we successfully read the request */
		tcp_conn_set_lifetime( con, tcp_con_lifetime);
		con->timeout = con->lifetime;

		LM_DBG("completely received a message\n");
		/* rcv.bind_address should always be !=0 */
		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		con->rcv.proto_reserved1=con->id; /* copy the id */

		/* prepare for next request */
		size=req->pos - req->parsed;

		if (!size) {
			/* did not read any more things -  we can release
			 * the connection */
			LM_DBG("Nothing more to read on TCP conn %p, currently in state %d \n",
				con,con->state);
			if (req != &smpp_current_req) {
				/* we have the buffer in the connection tied buff -
				 *	detach it , release the conn and free it afterwards */
				con->con_req = NULL;
			}
		} else {
			LM_DBG("We still have things on the pipe - "
				"keeping connection \n");
		}
		
		/* give the message to the registered functions */
		handle_smpp_msg(req->buf, &con->rcv);


		if (!size && req != &smpp_current_req) {
			/* if we no longer need this tcp_req
			 * we can free it now */
			pkg_free(req);
		}

		if (size)
			memmove(req->buf, req->parsed, size);

		init_tcp_req(req, size);
		con->msg_attempts = 0;

		/* if we still have some unparsed bytes, try to  parse them too*/
		if (size) 
			return 1;
	} 

	return 0;
}

static int smpp_read_req(struct tcp_connection* con, int* bytes_read)
{
	int bytes;
	int total_bytes;
	struct tcp_req *req;

	bytes = -1;
	total_bytes = 0;

	if (con->con_req) {
		req = con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		init_tcp_req(&smpp_current_req, 0);
		req = &smpp_current_req;
	}

	again:
	if(req->error == TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed < req->pos){
			bytes=0;
		} else {
			bytes=proto_tcp_read(con,req);
			if (bytes < 0) {
				LM_ERR("failed to read \n");
				goto error;
			}
		}

		smpp_parse_headers(req);

		total_bytes+=bytes;
		/* eof check:
		 * is EOF if eof on fd and req.  not complete yet,
		 * if req. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((con->state==S_CONN_EOF) && (req->complete==0)) {
			LM_DBG("EOF received\n");
			goto done;
		}
	}

	if (req->error!=TCP_REQ_OK){
		LM_ERR("bad request, state=%d, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->error,
				  (int)(req->pos-req->buf), req->buf,
				  (int)(req->parsed-req->start), req->start);
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ",&con->rcv.src_ip, "\n");
		goto error;
	}

	//TODO max_msg_chunks
	switch (smpp_handle_req(req, con, 32) ) {
		case 1:
			goto again;
		case -1:
			goto error;
	}

	LM_DBG("tcp_read_req end\n");
done:
	if (bytes_read) *bytes_read=total_bytes;
	/* connection will be released */
		return 0;
error:
	/* connection will be released as ERROR */
		return -1;
}

static int smpp_write_async_req(struct tcp_connection* con,int fd)
{
	LM_INFO("smpp_write_async_req called\n");
	return 0;
}


void send_submit_sm_request(str *msg)
{
	smpp_submit_sm_req_t *req;
	if (build_submit_sm_request(&req, "444", "555", msg, 0)) {
		LM_ERR("error creating submit_sm request\n");
		return;
	}
	struct tcp_connection *conn;
	int fd;
	int ret = tcp_conn_get(0, (*g_sessions)->ip, (*g_sessions)->port, PROTO_SMPP, &conn, &fd);
	if (ret < 0) {
		LM_ERR("return code %d\n", ret);
		goto free_req;
	}
	int n = tsend_stream(fd, req->payload.s, req->payload.len, 1000);
	LM_INFO("send %d bytes\n", n);

free_req:
	pkg_free(req);
}

static int build_enquire_link_request(smpp_enquire_link_req_t **preq, int32_t sequence_number)
{
	if (!preq) {
		LM_ERR("NULL param");
		goto err;
	}

	/* request allocations */
	smpp_enquire_link_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header");
		goto header_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(ENQUIRE_LINK));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload");
		goto payload_err;
	}

	req->header = header;

	header->command_length = HEADER_SZ;
	header->command_id = ENQUIRE_LINK_CID;
	header->command_status = 0;
	header->sequence_number = sequence_number;

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}

static void send_enquire_link_request(void)
{
	smpp_enquire_link_req_t *req;
	if (build_enquire_link_request(&req, 0)) {
		LM_ERR("error creating enquire_link_sm request\n");
		return;
	}

	struct tcp_connection *conn;
	int fd;
	int ret = tcp_conn_get(0, (*g_sessions)->ip, (*g_sessions)->port, PROTO_SMPP, &conn, &fd);
	if (ret < 0) {
		LM_ERR("return code %d\n", ret);
		goto free_req;
	}
	int n = tsend_stream(fd, req->payload.s, req->payload.len, 1000);
	LM_INFO("send %d bytes\n", n);

free_req:
	pkg_free(req);
}

static int send_smpp_msg(struct sip_msg *msg)
{
	LM_INFO("send_smpp_msg called\n");
	if(msg->parsed_uri_ok==0)
	    parse_sip_msg_uri(msg);

	str body;
	get_body(msg, &body);
	send_submit_or_deliver_request(&body, &parse_from_uri(msg)->user, &msg->parsed_uri.user, *g_sessions);
	return 0;
}

static int recv_smpp_msg(smpp_header_t *header, smpp_deliver_sm_t *body, struct tcp_connection *conn)
{
	char hdrs[1024];
	char *p = hdrs;
	char src[128];
	sprintf(src, "sip:%s@%s:%d", body->source_addr, ip_addr2a(&conn->rcv.src_ip), conn->rcv.src_port);
	char dst[128];
	sprintf(dst, "sip:%s@%s:%d", body->destination_addr, ip_addr2a(&conn->rcv.dst_ip), conn->rcv.dst_port);
	p += sprintf(p, "Content-Type:text/plain\r\n");

	str hdr_str;
	hdr_str.s = hdrs;
	hdr_str.len = p - hdrs;

	str src_str;
	src_str.s = src;
	src_str.len = strlen(src);

	str dst_str;
	dst_str.s = dst;
	dst_str.len = strlen(dst);

	str body_str;
	body_str.s = body->short_message;
	body_str.len = body->sm_length;

	tmb.t_request(&msg_type, /* Type of the message */
		      &dst_str,            /* Request-URI */
		      &dst_str,            /* To */
		      &src_str,     /* From */
		      &hdr_str,         /* Optional headers including CRLF */
		      &body_str, /* Message body */
		      &outbound_uri,
		      /* outbound uri */
		      NULL,
		      NULL,
		      NULL
		     );
	return 0;
}
