/*
 * sca logic module
 *
 * Copyright (C) 2010 VoIP Embedded, Inc.
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
 * --------
 *  2010-11-21  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <stdlib.h>

#include "../../ut.h"
#include "../../trim.h"
#include "../../strcommon.c"
#include "../../parser/parse_from.h"
#include "../../parser/sdp/sdp.h"
#include "../../usr_avp.h"
#include "../../parser/parse_call_info.h"
#include "../pua/pua.h"
#include "../pua/pua_bind.h"
#include "../b2b_logic/b2b_load.h"
#include "sca_records.h"
#include "sca_db_handler.h"
#include "sca_logic.h"

#define APPEARANCE_INDEX_STR "appearance-index"
#define APPEARANCE_INDEX_LEN strlen(APPEARANCE_INDEX_STR)

#define APPEARANCE_STATE_STR "appearance-state"
#define APPEARANCE_STATE_LEN strlen(APPEARANCE_STATE_STR)

#define AUDIO_STR "audio"
#define AUDIO_STR_LEN 5

extern pua_api_t pua_api;
extern b2bl_api_t b2bl_api;
extern str presence_server;
//extern int watchers_avp_name;
extern unsigned short watchers_avp_type;

int get_hash_index_and_shared_line(struct sip_msg* msg, unsigned int *hash_index, str **shared_line);
struct to_body* get_appearance_name_addr(struct sip_msg* msg);

#define CALL_INFO_APPEARANCE_URI_LEN	64
static char call_info_apperance_uri_buf[CALL_INFO_APPEARANCE_URI_LEN];

#define CALL_INFO_URI		"sip:"
#define CALL_INFO_URI_LEN	64
static char call_info_uri_buf[CALL_INFO_URI_LEN] = CALL_INFO_URI;

#define CALL_INFO_HDR			"Call-Info: <"
#define INVITE_CALL_INFO_HDR_LEN	128
#define PUBLISH_CALL_INFO_HDR_LEN	512
static char invite_call_info_hdr_buf[INVITE_CALL_INFO_HDR_LEN] = CALL_INFO_HDR;
static char publish_call_info_hdr_buf[PUBLISH_CALL_INFO_HDR_LEN] = CALL_INFO_HDR;

static const str callinfo_id=str_init("CALLINFO_PUBLISH");
static const str callinfo_appuri_prefix=str_init(">;appearance-uri=\"");
static const str callinfo_appindex=str_init(";appearance-index=");
static const str callinfo_appstate=str_init(";appearance-state=");
static const str callinfo_hdr_postfix=str_init("*;appearance-state=idle\r\n");
static const str callinfo_default_uri=str_init("sip:127.0.0.1>");

static unsigned int b2b_sca_shutdown_completed = 0;

#define APP_STATE_IDLE		""
#define APP_STATE_ALERTING	"alerting"
#define APP_STATE_ACTIVE	"active"
#define APP_STATE_HELD		"held"
#define APP_STATE_HELD_PRIVATE	"held-private"

const str app_state[]={
	str_init(APP_STATE_IDLE),
	str_init(APP_STATE_ALERTING),
	str_init(APP_STATE_ACTIVE),
	str_init(APP_STATE_HELD),
	str_init(APP_STATE_HELD_PRIVATE),
};

static str scenario = str_init("top hiding");


void destroy_b2b_sca_handlers(void)
{
	b2b_sca_shutdown_completed = 1;
}


unsigned int get_app_index(struct sip_msg* msg)
{
	unsigned int appearance;
	struct hdr_field *call_info;
	struct call_info_body *callinfo_b;
	struct to_body *call_info_b;
	struct to_param *param;

	if (0 == parse_call_info_header(msg)) {
		call_info = msg->call_info;
		while (call_info) {
			//LM_DBG("BODY=[%p]->[%.*s] sibling=[%p]\n", call_info,
			//	call_info->body.len, call_info->body.s,
			//	call_info->sibling);
			callinfo_b = call_info->parsed;
			while (callinfo_b) {
				call_info_b = &(callinfo_b->call_info_body);
				//LM_DBG(". body=[%.*s] param_lst=[%p] "
				//	"last_param=[%p]\n",
				//	call_info_b->body.len, call_info_b->body.s,
				//	call_info_b->param_lst,
				//	call_info_b->last_param);
				param = call_info_b->param_lst;
				while (param) {
					//LM_DBG(".. [%p]->[%d] "
					//	"[%.*s]=[%.*s]->[%p]\n",
					//	param, param->type,
					//	param->name.len, param->name.s,
					//	param->value.len, param->value.s,
					//	param->next);
					if (param->name.len==APPEARANCE_INDEX_LEN &&
						strncmp(APPEARANCE_INDEX_STR,
							param->name.s,
							APPEARANCE_INDEX_LEN)==0) {
						if (strno2int(&param->value,
								&appearance)<0) {
							LM_ERR("bad appearance-index"
								" [%.*s]\n",
								param->value.len,
								param->value.s);
							return 0;
						}
						LM_DBG("*** GOT APP-INDEX [%d]\n",
								appearance);
						return appearance;
					}
					param=param->next;
				}
				callinfo_b = callinfo_b->next;
			}
			call_info = call_info->sibling;
		}
	} else {
		LM_ERR("Unable to parse Call-Info header\n");
		return 0;
	}

	LM_ERR("appearance index not found\n");
	return 0;
}


int build_publish_call_info_header(b2b_sca_record_t *rec, str *publish_hdr)
{
	unsigned int i;
	unsigned int size = sizeof(CALL_INFO_HDR);
	b2b_sca_call_t *call = NULL;
	char *p;

	size += callinfo_default_uri.len +
		callinfo_appindex.len + callinfo_hdr_postfix.len;

	if (rec == NULL) {
		/* we need to build an idle Call-Info header */
		publish_hdr->s = publish_call_info_hdr_buf;
		p = &publish_call_info_hdr_buf[sizeof(CALL_INFO_HDR) - 1];
		goto default_hdr;
	}
	rec->expires = 30;

	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		if (rec->call[i]) {
			call = rec->call[i];
			if (call->call_state > ALERTING_STATE)
				rec->expires = 36000;
			size += call->call_info_uri.len +
				callinfo_appuri_prefix.len +
				call->call_info_apperance_uri.len +
				callinfo_appindex.len +
				call->appearance_index_str.len +
				callinfo_appstate.len +
				app_state[call->call_state].len + 2;
		}
	}

	if (size > PUBLISH_CALL_INFO_HDR_LEN) {
		LM_WARN("buffer overflow for PUBLISH Call-Info"
			" header: size [%d]\n", size);
		p = (char *)pkg_malloc(size);
		if (p == NULL) {
			LM_ERR("OOM\n");
			return -1;
		}
		publish_hdr->s = p;
		memcpy(p, publish_call_info_hdr_buf, sizeof(CALL_INFO_HDR) - 1);
		p += sizeof(CALL_INFO_HDR) - 1;
	} else {
		publish_hdr->s = publish_call_info_hdr_buf;
		p = &publish_call_info_hdr_buf[sizeof(CALL_INFO_HDR) - 1];
	}

	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		if (rec->call[i]) {
			call = rec->call[i];

			memcpy(p, call->call_info_uri.s, call->call_info_uri.len);
			p += call->call_info_uri.len;

			memcpy(p, callinfo_appuri_prefix.s,
				callinfo_appuri_prefix.len);
			p += callinfo_appuri_prefix.len;

			memcpy(p, call->call_info_apperance_uri.s,
					call->call_info_apperance_uri.len);
			p += call->call_info_apperance_uri.len;
			*p = '\"'; p++;

			memcpy(p, callinfo_appindex.s, callinfo_appindex.len);
			p += callinfo_appindex.len;

			memcpy(p, call->appearance_index_str.s,
				call->appearance_index_str.len);
			p += call->appearance_index_str.len;

			memcpy(p, callinfo_appstate.s, callinfo_appstate.len);
			p += callinfo_appstate.len;

			memcpy(p, app_state[call->call_state].s, app_state[call->call_state].len);
			p += app_state[call->call_state].len;

			*p = ','; p++;
			*p = '<'; p++;
		}
	}

default_hdr:
	memcpy(p, callinfo_default_uri.s, callinfo_default_uri.len);
	p += callinfo_default_uri.len;

	memcpy(p, callinfo_appindex.s, callinfo_appindex.len);
	p += callinfo_appindex.len;

	memcpy(p, callinfo_hdr_postfix.s, callinfo_hdr_postfix.len);
	p += callinfo_hdr_postfix.len;

	publish_hdr->len = p - publish_hdr->s;

	LM_DBG("publish_hdr [%d:%d] [%.*s]\n", size, publish_hdr->len,
						publish_hdr->len, publish_hdr->s);
	return 0;
}

int build_invite_call_info_header(b2b_sca_call_t *call,
					str* call_info_uri, str *custom_hdr)
{
	unsigned int size;
	char *p;

	size = sizeof(CALL_INFO_HDR) + call_info_uri->len + 1 +
		callinfo_appindex.len + call->appearance_index_str.len + CRLF_LEN;
	if (size >= INVITE_CALL_INFO_HDR_LEN) {
		LM_WARN("buffer overflow on INVITE Call-Info header: size [%d]\n", size);
		p = (char *)pkg_malloc(size);
		if (p == NULL) {
			LM_ERR("OOM\n");
			return -1;
		}
		custom_hdr->s = p;
		memcpy(p, invite_call_info_hdr_buf, sizeof(CALL_INFO_HDR) - 1);
		p += sizeof(CALL_INFO_HDR) - 1;
	} else {
		custom_hdr->s = invite_call_info_hdr_buf;
		p = &invite_call_info_hdr_buf[sizeof(CALL_INFO_HDR) - 1];
	}

	memcpy(p, call_info_uri->s, call_info_uri->len);
	p += call_info_uri->len;
	*p = '>'; p++;

	memcpy(p, callinfo_appindex.s, callinfo_appindex.len);
	p += callinfo_appindex.len;

	memcpy(p, call->appearance_index_str.s, call->appearance_index_str.len);
	p += call->appearance_index_str.len;

	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	custom_hdr->len = p - custom_hdr->s;
	LM_DBG("custom_hdr [%d:%d] [%.*s]\n", size, custom_hdr->len,
						custom_hdr->len, custom_hdr->s);
	return 0;
}

int build_appearanceURI(str *display, str *uri, str *call_info_apperance_uri)
{
	unsigned int size;
	int escaped_display_size;
	char *p;
	char escaped_display[256];

	size = display->len + 5 + uri->len + 2;
	if (size > CALL_INFO_APPEARANCE_URI_LEN) {
		LM_WARN("buffer overflow on appearance URI param: size [%d]\n", size);
		p = (char *)pkg_malloc(size);
		if (p == NULL) {
			LM_ERR("OOM\n");
			return -1;
		}
		call_info_apperance_uri->s = p;
	} else {
		p = call_info_apperance_uri->s = call_info_apperance_uri_buf;
	}
	if (display->len<80) {
		escaped_display_size = escape_common(escaped_display, display->s, display->len);
		if (escaped_display_size) {
			memcpy(p, escaped_display, escaped_display_size);
			p += escaped_display_size;
			*p = ' '; p++;
		}
	}
	*p = '<'; p++;
	memcpy(p, uri->s, uri->len);
	p += uri->len;
	*p = '>'; p++;
	call_info_apperance_uri->len = p - call_info_apperance_uri->s;
	/*
	LM_DBG("call_info_apperance_uri [%d:%d][%.*s]\n",
			size, call_info_apperance_uri->len,
			call_info_apperance_uri->len, call_info_apperance_uri->s);
	*/
	return 0;
}

int build_absoluteURI(str *host, str *port, str *call_info_uri)
{
	unsigned int size;
	char *p;

	size = sizeof(CALL_INFO_URI) - 1 + host->len + port->len;
	if (size > CALL_INFO_URI_LEN) {
		LM_WARN("buffer overflow on absoluteURI: size [%d]\n", size);
		p = (char *)pkg_malloc(size);
		if (p == NULL) {
			LM_ERR("OOM\n");
			return -1;
		}
		call_info_uri->s = p;
		memcpy(p, call_info_uri_buf, sizeof(CALL_INFO_URI) - 1);
		p += sizeof(CALL_INFO_URI) - 1;
	} else {
		call_info_uri->s = call_info_uri_buf;
		p = &call_info_uri_buf[sizeof(CALL_INFO_URI) - 1];
	}
	memcpy(p, host->s, host->len);
	p += host->len;
	if (port->s && port->len) {
		*p = ':'; p++;
		memcpy(p, port->s, port->len);
		p += port->len;
	}
	call_info_uri->len = p - call_info_uri->s;
	/*
	LM_DBG("call_info_uri [%d:%d][%.*s]\n",
			size, call_info_uri->len,
			call_info_uri->len, call_info_uri->s);
	*/
	return 0;
}


b2bl_cb_ctx_t* build_cb_params(unsigned int hash_index,
		str *shared_line, unsigned int appearance_index)
{
	unsigned int size;
	char *p;
	b2bl_cb_ctx_t *cb_params;

	/* Prepare b2b_logic callback params. */
	size = sizeof(b2bl_cb_ctx_t) + shared_line->len;
	cb_params = (b2bl_cb_ctx_t *)shm_malloc(size);
	if (cb_params == NULL) {
		LM_ERR("OOM\n");
		return NULL;
	}
	memset(cb_params, 0, size);
	cb_params->hash_index = hash_index;
	cb_params->appearance = appearance_index;

	p = (char *)(cb_params + 1);
	cb_params->shared_line.len = shared_line->len;
	cb_params->shared_line.s = p;
	memcpy(p, shared_line->s, shared_line->len);
	p += shared_line->len;

	return cb_params;
}


void sca_publish(b2b_sca_record_t *record, str *extra_hdr)
{
	str_lst_t *new_watcher;
	publ_info_t publ;

	/* TESTING */
	//return;

	memset(&publ, 0, sizeof(publ_info_t));

	publ.id = callinfo_id;
	publ.body = NULL;

	publ.expires = record->expires;

	publ.flag|= UPDATE_TYPE;
	publ.source_flag|= CALLINFO_PUBLISH;
	publ.event|= CALLINFO_EVENT;

	publ.content_type.s = NULL;
	publ.content_type.len = 0;

	publ.etag = NULL;

	publ.extra_headers= extra_hdr;

	publ.outbound_proxy = presence_server;
	publ.cb_param = NULL;

	new_watcher = record->watchers;
	while (new_watcher) {
		publ.pres_uri = &new_watcher->watcher;
		if(pua_api.send_publish(&publ)< 0) {
			LM_ERR("sending publish failed\n");
		}
		new_watcher = new_watcher->next;
	}

	return;
}


int sca_logic_notify(b2bl_cb_params_t *params, unsigned int b2b_event)
{
	int on_hold = 0;
	int sdp_session_num = 0, sdp_stream_num;
	sdp_info_t *sdp;
	sdp_session_cell_t* sdp_session;
	sdp_stream_cell_t* sdp_stream;
	struct sip_msg *msg;
	b2bl_cb_ctx_t *cb_params;
	str *shared_line;
	unsigned int hash_index, appearance;
	b2b_sca_record_t *record;
	b2b_sca_call_t *call = NULL;
	str publish_hdr;
	unsigned int call_info_appearance;
	unsigned int call_info_appearance_state = 0;
	struct hdr_field *call_info;
	struct call_info_body *callinfo_b;
	struct to_body *call_info_b;
	struct to_param *param;

	if (b2b_sca_shutdown_completed) return B2B_FOLLOW_SCENARIO_CB_RET;
	if (params == NULL) {
		LM_ERR("callback event [%d] without cb params\n", b2b_event);
		return B2B_DROP_MSG_CB_RET;
	}
	msg = params->msg;
	cb_params = params->param;

	shared_line = &cb_params->shared_line;
	hash_index = cb_params->hash_index;
	appearance = cb_params->appearance;

	LM_DBG("*** GOT NOTIFICATION TYPE [%d] WITH cb_params [%p]->[%.*s] appearance [%d] on hash index [%d]"
			" for b2bl entity [%d]\n",
			b2b_event, cb_params, shared_line->len, shared_line->s,
			appearance, hash_index, params->entity);


	if (msg && msg->call_info) {
		if (0 == parse_call_info_header(msg)) {
			call_info = msg->call_info;
			if (call_info) {
				LM_DBG("BODY=[%p]->[%.*s] sibling=[%p]\n", call_info,
					call_info->body.len, call_info->body.s, call_info->sibling);
				callinfo_b = call_info->parsed;
				while (callinfo_b) {
					call_info_b = &(callinfo_b->call_info_body);
					LM_DBG(". body=[%.*s] param_lst=[%p] last_param=[%p]\n",
						call_info_b->body.len, call_info_b->body.s,
						call_info_b->param_lst, call_info_b->last_param);
					param = call_info_b->param_lst;
					while (param) {
						LM_DBG(".. [%p]->[%d] [%.*s]=[%.*s]->[%p]\n",
							param, param->type, param->name.len, param->name.s,
							param->value.len, param->value.s, param->next);
						if (param->name.len==APPEARANCE_INDEX_LEN &&
							strncmp(APPEARANCE_INDEX_STR,
							param->name.s, APPEARANCE_INDEX_LEN)==0) {
							if (strno2int(&param->value,&call_info_appearance)<0) {
								LM_ERR("bad appearance-index [%.*s]\n",
									param->value.len, param->value.s);
								return -1;
							}
							if (appearance != call_info_appearance) {
								LM_ERR("got appearance[%d] while expecting[%d]\n",
									call_info_appearance, appearance);
								goto next_callinfo_b;
							} else {
								LM_DBG("*** GOT APP-INDEX [%d]\n",
									call_info_appearance);
							}
						} else if (param->name.len==APPEARANCE_STATE_LEN &&
							strncmp(APPEARANCE_STATE_STR,
							param->name.s, APPEARANCE_STATE_LEN)==0) {
							LM_DBG("*** GOT APP-STATE [%.*s]\n",
								param->value.len, param->value.s);
							if (param->value.len == strlen(APP_STATE_HELD_PRIVATE) &&
								strncmp(param->value.s,
									app_state[HELD_PRIVATE_STATE].s,
									param->value.len)==0) {
								call_info_appearance_state = HELD_PRIVATE_STATE;
							}
						}
						param=param->next;
					}
					goto handle_appearance;
next_callinfo_b:
					callinfo_b = callinfo_b->next;
				}
				call_info = call_info->sibling;
			}
		} else {
			LM_ERR("Unable to parse Call-Info header\n");
			return B2B_DROP_MSG_CB_RET;
		}
	}

handle_appearance:
	lock_get(&b2b_sca_htable[hash_index].lock);
	record = b2b_sca_search_record_safe(hash_index, shared_line);
	if (record == NULL) {
		lock_release(&b2b_sca_htable[hash_index].lock);
		LM_ERR("record not found for shared line [%.*s] on hash index [%d]\n",
			shared_line->len, shared_line->s, hash_index);
		return B2B_DROP_MSG_CB_RET;
	}

	b2b_sca_print_record(record);

	switch(b2b_event){
	case B2B_DESTROY_CB:
		/* Destroy the sca index record */
		shm_free(params->param);
		b2b_sca_delete_call_record(hash_index, record, appearance);
		break;
	case B2B_RE_INVITE_CB:
	case B2B_CONFIRMED_CB:
		call = b2b_sca_search_call_safe(record, appearance);
		if (call == NULL) {
			LM_ERR("call record not found for shared line [%.*s] with index [%d]\n",
						shared_line->len, shared_line->s, appearance);
			lock_release(&b2b_sca_htable[hash_index].lock);
			return B2B_DROP_MSG_CB_RET;
		}
		if ( msg && (sdp=parse_sdp(msg)) != NULL ) {
			sdp_session = get_sdp_session(sdp, sdp_session_num);
			if(!sdp_session) break;
			sdp_stream_num = 0;
			for(;;) {
				sdp_stream = get_sdp_stream(sdp, sdp_session_num,
					sdp_stream_num);
				if(!sdp_stream) break;
				if(sdp_stream->media.len==AUDIO_STR_LEN &&
					strncmp(sdp_stream->media.s,AUDIO_STR,AUDIO_STR_LEN)==0 &&
					sdp_stream->is_on_hold) {
					on_hold = 1;
					break;
				}
				sdp_stream_num++;
			}
			sdp_session_num++;
		}

		if (on_hold) {
			if (call_info_appearance_state)
				call->call_state = HELD_PRIVATE_STATE;
			else
				call->call_state = HELD_STATE;
		} else {
			call->call_state = ACTIVE_STATE;
		}
		break;
	default:
		LM_ERR("Unexpected event\n");
	}

	/* Prepare PUBLISH Call-Info header.  */
	if (build_publish_call_info_header(record, &publish_hdr) != 0) {
		lock_release(&b2b_sca_htable[hash_index].lock);
		LM_ERR("Unable to build PUBLISH Call-Info header\n");
		return B2B_FOLLOW_SCENARIO_CB_RET;
	}

	/* Save the record to db. */
	if (push_sca_info_to_db(record, appearance, 1) != 0)
		LM_ERR("DB out of synch\n");

	/* Notify the watchers. */
	sca_publish(record, &publish_hdr);

	b2b_sca_delete_record_if_empty(record, hash_index);

	lock_release(&b2b_sca_htable[hash_index].lock);

	if (publish_hdr.s != publish_call_info_hdr_buf)
		pkg_free(publish_hdr.s);

	return B2B_FOLLOW_SCENARIO_CB_RET;
}


int sca_init_request(struct sip_msg* msg, int *shared_entity)
{
	int method_value, ret;
	//unsigned int size, hash_index, shared_entity;
	unsigned int hash_index, app_index;
	str *b2bl_key, *host, *port, *display, *uri, *shared_line;
	//char *p;
	//uri_type scheme;
	struct to_body *appearance_name_addr_body;
	b2b_sca_record_t *record = NULL;
	b2b_sca_call_t *call = NULL;
	b2bl_cb_ctx_t *cb_params;

	str publish_hdr = {NULL, 0};
	str custom_hdr = {NULL, 0};
	str call_info_uri = {NULL, 0};
	str call_info_apperance_uri = {NULL, 0};

	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse message\n");
		return -1;
	}
	method_value = msg->first_line.u.request.method_value;
	if (method_value != METHOD_INVITE) {
		LM_ERR("nonINVITE [%d] cannot initiate a call\n", method_value);
		return -1;
	}
	ret = tmb.t_newtran(msg);
	if(ret < 1) {
		if(ret == 0) {
			LM_DBG("It is a retransmission, drop\n");
		} else {
			LM_ERR("Error when creating tm transaction\n");
		}
		return 0;
	}

	switch (*shared_entity) {
	case 0:
		LM_DBG("Incoming call from shared line\n");
		break;
	case 1:
		LM_DBG("Outgoing call via a shared line\n");
		break;
	default:
		LM_ERR("shared line entity should be 0 or 1\n");
		return -1;
	}

	/* Get the hash index for the shared line.  */
	if (get_hash_index_and_shared_line(msg, &hash_index, &shared_line)<0)
		return -1;
	LM_DBG("got hash_index=[%d] for shared line [%.*s]\n",
			hash_index, shared_line->len, shared_line->s);

	/* Get the appearance name-addr for this call.  */
	appearance_name_addr_body = get_appearance_name_addr(msg);
	if (appearance_name_addr_body == NULL) {
		LM_ERR("unable to get apperance of this call\n");
		return -1;
	}
	//scheme = appearance_name_addr_body->parsed_uri.type;
	host = &appearance_name_addr_body->parsed_uri.host;
	port = &appearance_name_addr_body->parsed_uri.port;
	display = &appearance_name_addr_body->display;
	uri = &appearance_name_addr_body->uri;
	LM_DBG("display uri [%.*s][%.*s] from host:port [%.*s]:[%.*s]\n",
			display->len, display->s, uri->len, uri->s,
			host->len, host->s, port->len, port->s);


	/* Prepare absoluteURI for Call-Info header.
	 */
	if (build_absoluteURI(host, port, &call_info_uri) != 0)
		goto error1;

	/* Prepare appearanceURI param for Call-Info header.  */
	if (build_appearanceURI(display, uri, &call_info_apperance_uri) != 0)
		goto error1;

	/* Extract required appearance from the received request */
	app_index = get_app_index(msg);

	/* Adding call to the sca_table.  */
	lock_get(&b2b_sca_htable[hash_index].lock);
	if (b2b_sca_add_call_record(hash_index, shared_line, *shared_entity, app_index,
			&call_info_uri, &call_info_apperance_uri, &record, &call) != 0) {
		LM_ERR("unable to add record to sca htable\n");
		goto error2;
	}

	/* Prepare INVITE Call-Info header.  */
	if (build_invite_call_info_header(call, &call_info_uri, &custom_hdr) != 0)
		goto error2;

	/* Prepare PUBLISH Call-Info header.  */
	if (build_publish_call_info_header(record, &publish_hdr) != 0) {
		LM_ERR("Unable to build PUBLISH Call-Info header\n");
		goto error2;
	}

	/* Prepare b2b_logic callback params. */
	cb_params = build_cb_params(hash_index, shared_line, call->appearance_index);
	if (cb_params == NULL)
		goto error2;

	LM_DBG("*** INITIALIZING \"top hiding\" SCENARIO with cb_params [%p]\n", cb_params);
	/* release the lock here to avoid deadlock while getting callback notifications */
	lock_release(&b2b_sca_htable[hash_index].lock);
	b2bl_key = b2bl_api.init(msg, &scenario, NULL, &sca_logic_notify, (void *)cb_params,
			B2B_RE_INVITE_CB|B2B_CONFIRMED_CB|B2B_DESTROY_CB, &custom_hdr);
	lock_get(&b2b_sca_htable[hash_index].lock);

	if (!b2bl_key || !b2bl_key->s || !b2bl_key->len)
		goto error2;
	else if (b2b_sca_update_call_record_key(call, b2bl_key) != 0)
		goto error3;

	/* Save the record to db. */
	if (push_sca_info_to_db(record, call->appearance_index, 0) != 0)
		goto error3;

	/* Notify the watchers. */
	sca_publish(record, &publish_hdr);

	lock_release(&b2b_sca_htable[hash_index].lock);


	if (publish_hdr.s != publish_call_info_hdr_buf)
		pkg_free(publish_hdr.s);
	if (custom_hdr.s != invite_call_info_hdr_buf)
		pkg_free(custom_hdr.s);
	if (call_info_uri.s != call_info_uri_buf)
		pkg_free(call_info_uri.s);
	if (call_info_apperance_uri.s != call_info_apperance_uri_buf)
		pkg_free(call_info_apperance_uri.s);

	return 1;

error3:
	/* Release the call */
	b2bl_api.terminate_call(b2bl_key);
error2:
	lock_release(&b2b_sca_htable[hash_index].lock);
error1:
	if (publish_hdr.s != publish_call_info_hdr_buf)
		pkg_free(publish_hdr.s);
	if (custom_hdr.s != invite_call_info_hdr_buf)
		pkg_free(custom_hdr.s);
	if (call_info_uri.s != call_info_uri_buf)
		pkg_free(call_info_uri.s);
	if (call_info_apperance_uri.s != call_info_apperance_uri_buf)
		pkg_free(call_info_apperance_uri.s);

	return -1;
}


int sca_bridge_request(struct sip_msg* msg, str* shared_line)
{
	str publish_hdr = {NULL, 0};
	int method_value, ret;
	//int entity_no;
	unsigned int hash_index;
	b2b_sca_record_t *record = NULL;
	b2b_sca_call_t *call;

	unsigned int appearance;

	/* Get the hash index for the shared line. */
	hash_index = core_hash(shared_line, NULL, b2b_sca_hsize);
	LM_DBG("got hash_index=[%d] for shared line [%.*s]\n",
			hash_index, shared_line->len, shared_line->s);

	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse message\n");
		return -1;
	}
	method_value = msg->first_line.u.request.method_value;
	if (method_value != METHOD_INVITE) {
		LM_ERR("nonINVITE [%d] cannot bridge a call\n", method_value);
		return -1;
	}
	ret = tmb.t_newtran(msg);
	if(ret < 1) {
		if(ret == 0) {
			LM_DBG("It is a retransmission, drop\n");
		} else {
			LM_ERR("Error when creating tm transaction\n");
		}
		return 0;
	}

	if (!msg->call_info) {
		LM_ERR("No 'Call-Info' header\n");
		return -1;
	}

	/* Extract required appearance from the received request */
	appearance = get_app_index(msg);
	if (appearance==0) return -1;

	lock_get(&b2b_sca_htable[hash_index].lock);
	record = b2b_sca_search_record_safe(hash_index, shared_line);
	if (record == NULL) {
		lock_release(&b2b_sca_htable[hash_index].lock);
		LM_ERR("record not found for shared line [%.*s] on hash index [%d]\n",
			shared_line->len, shared_line->s, hash_index);
		// FIXME:
		/* Build an empty PUBLISH header */
		//if (build_publish_call_info_header(NULL, &publish_hdr) != 0) {
		//	LM_ERR("Unable to build PUBLISH Call-Info header\n");
		//}
		goto error;
	}

	b2b_sca_print_record(record);

	call = b2b_sca_search_call_safe(record, appearance);
	if (call == NULL) goto error;
	if (call->call_state != HELD_STATE) {
		LM_ERR("Improper call state [%d] for bridging\n", call->call_state);
		goto error;
	}

	/* What will happen if the b2b_logic entity doesn't exist anymore? */
	LM_DBG("*** BRIDGING THE REQUEST to entity [%d] on tuple [%.*s]\n",
			call->shared_entity, call->b2bl_key.len, call->b2bl_key.s);
	ret = b2bl_api.bridge_msg(msg, &call->b2bl_key, call->shared_entity);
	if (ret != 0) {
		/* FIXME:
		 * handle the error here */
		LM_ERR("*** got ret [%d]\n", ret);
		goto error;
	}
	LM_DBG("*** got ret [%d]\n", ret);

	/* Set the state back to active */
	call->call_state = ACTIVE_STATE;

	/* Reset the shared_entity */
	call->shared_entity = 0;

	/* Prepare PUBLISH Call-Info header.  */
	if (build_publish_call_info_header(record, &publish_hdr) != 0) {
		lock_release(&b2b_sca_htable[hash_index].lock);
		LM_ERR("Unable to build PUBLISH Call-Info header\n");
		return B2B_FOLLOW_SCENARIO_CB_RET;
	}

	/* Save the record to db. */
	if (push_sca_info_to_db(record, appearance, 1) != 0)
		LM_ERR("db out of synch\n");

	/* Notify the watchers. */
	sca_publish(record, &publish_hdr);

	lock_release(&b2b_sca_htable[hash_index].lock);

	return 1;
error:
	lock_release(&b2b_sca_htable[hash_index].lock);

	if (publish_hdr.s && publish_hdr.s != publish_call_info_hdr_buf)
		pkg_free(publish_hdr.s);

	return -1;
}

