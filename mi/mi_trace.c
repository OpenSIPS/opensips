/*
 * Copyright (C) 2016 - OpenSIPS Solutions
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
 *
 * History:
 * -------
 *  2016-09-19  first version (Ionut Ionita)
 */
#include "../ut.h"

#include "mi_trace.h"

#define TRACE_API_MODULE "proto_hep"
#define MI_ID_S "mi"
#define MI_TRACE_BUF_SIZE (1 << 10)

/* CORR - magic for internally generated correltion id */
#define MI_CORR_COOKIE "MICORR"

trace_proto_t* mi_trace_api=NULL;
int mi_message_id;

static char* correlation_name = "correlation_id";
str correlation_value;
int correlation_id=-1, correlation_vendor=-1;
str mi_trpl;
struct mi_trace_req mi_treq;
struct mi_trace_param mi_tparam;


void try_load_trace_api(void)
{
	/* already loaded */
	if ( mi_trace_api )
		return;

	mi_trace_api = pkg_malloc(sizeof(trace_proto_t));
	if (mi_trace_api == NULL)
		return;

	memset(mi_trace_api, 0, sizeof(trace_proto_t));
	if (trace_prot_bind(TRACE_API_MODULE, mi_trace_api) < 0) {
		LM_DBG("No tracing module used!\n");
		return;
	}

	mi_message_id = mi_trace_api->get_message_id(MI_ID_S);
}

struct mi_trace_req* build_mi_trace_request( str* cmd,
						mi_item_t *params, str* backend)
{
	int len=0, new=0;
	mi_item_t *p;

	if ( !cmd || !backend )
		return 0;

	mi_treq.cmd = *cmd;
	mi_treq.backend = *backend;
	memset( mi_treq.params, 0, MAX_TRACE_FIELD);

	p = params;
	if (!p)
		return &mi_treq;

	for(p = p->child; p && new < MAX_TRACE_FIELD - len; p = p->next) {
		switch ((p->type) & 0xFF) {
			case cJSON_Number:
				new = snprintf(mi_treq.params + len, MAX_TRACE_FIELD - len,
						"%s%d", (p->prev ? "," : ""), p->valueint);
				if (new < 0) {
					LM_ERR("snprintf failed!\n");
					return 0;
				}

				len += new;
				break;
			case cJSON_String:
				new = snprintf(mi_treq.params + len, MAX_TRACE_FIELD - len,
						"%s%s", (p->prev ? "," : ""), p->valuestring);
				if (new < 0) {
					LM_ERR("snprintf failed!\n");
					return 0;
				}

				len += new;
				break;
			default:
				continue;
		}
	}

	return &mi_treq;
}

str *build_mi_trace_reply(str *rpl_msg)
{
	mi_trpl.s = rpl_msg->s;
	mi_trpl.len = rpl_msg->len > MAX_TRACE_FIELD ?
					MAX_TRACE_FIELD : rpl_msg->len;

	return &mi_trpl;
}

char* generate_correlation_id(int* len)
{
	char *ret;

	ret = (char *)mi_trace_api->generate_guid(MI_CORR_COOKIE);
	*len = strlen(ret);

	return (char *)ret;
}


int trace_mi_message(union sockaddr_union* src, union sockaddr_union* dst,
		struct mi_trace_param* pld_param, str* correlation_val, trace_dest trace_dst)
{
	/* FIXME is this the case for all mi impelementations?? */
	const int proto = IPPROTO_TCP;
	str tmp_value = { 0, 0};

	trace_message message;

	if (mi_trace_api->create_trace_message == NULL ||
			mi_trace_api->send_message == NULL) {
		LM_DBG("trace api not loaded!\n");
		return 0;
	}

	message = mi_trace_api->create_trace_message(src, dst,
			proto, 0, mi_message_id, trace_dst);
	if (message == NULL) {
		LM_ERR("failed to create trace message!\n");
		return -1;
	}

	if ( correlation_val ) {
		if ( correlation_id < 0 || correlation_vendor < 0 ) {
			if ( load_correlation_id() < 0 ) {
				LM_ERR("can't load correlation id!\n");
				goto error;
			}
		}

		if ( mi_trace_api->add_chunk( message, correlation_val->s,
				correlation_val->len, TRACE_TYPE_STR,
					correlation_id, correlation_vendor) < 0 ) {
			LM_ERR("can't set the correlation id!\n");
			goto error;
		}
	}

	if ( pld_param->type == MI_TRACE_REQ ) {
		mi_trace_api->add_payload_part(message, "command", &pld_param->d.req->cmd);
		mi_trace_api->add_payload_part(message, "backend", &pld_param->d.req->backend);
		if ( pld_param->d.req->params[0] ) {
			tmp_value.s = pld_param->d.req->params;
			tmp_value.len = strlen( tmp_value.s );
			mi_trace_api->add_payload_part(message, "parameters", &tmp_value );
		}
	} else {
		mi_trace_api->add_payload_part(message,
				"reply", pld_param->d.rpl);
	}

	if (mi_trace_api->send_message(message, trace_dst, 0) < 0) {
		LM_ERR("failed to send trace message!\n");
		goto error;
	}

	mi_trace_api->free_message(message);

	return 0;
error:
	mi_trace_api->free_message(message);
	return -1;
}

int load_correlation_id(void)
{
	/* already looked for them */
	if (correlation_id > 0 && correlation_vendor > 0)
		return 0;

	return mi_trace_api->get_data_id(correlation_name, &correlation_vendor, &correlation_id);
}



static int mi_mods_no=0;

static int is_id_valid(int id)
{
	/* mask is currently char, we might need to expand it to offer more space */
	if (id < 0 || id >= 8 * sizeof( *(((struct mi_cmd *)0)->trace_mask) ))
		return 0;

	return 1;
}

/**
 * returns an id that should internally be stored by each module implementing
 * the mi interface
 */
int register_mi_trace_mod(void)
{
	if ( !is_id_valid(mi_mods_no) ) {
		LM_BUG("can't register any more mods; change trace mask data type"
				" from struct mi_cmd!\n");
		return -1;
	}

	return mi_mods_no++;
}

/**
 *
 * initialise mask to 0 or 1 depending on list type
 * if whitelist all mi cmds will be initially set to 0
 * if blacklist all mi cmds will be initially set to 1
 *
 */
int init_mod_trace_cmds(int id, int white)
{
	int idx, len;
	struct mi_cmd* mi_cmds;

	if ( !is_id_valid(id) ) {
		LM_BUG("Invalid module id!\n");
		return -1;
	}

	get_mi_cmds(&mi_cmds, &len);

	for ( idx = 0; idx < len; idx++) {
		if (white) {
			*mi_cmds[idx].trace_mask &= ~(1 << id);
		} else {
			*mi_cmds[idx].trace_mask |= (1 << id);
		}
	}

	return 0;
}

/**
 *
 * block an mi command having its name
 *
 */
int block_mi_cmd_trace(int id, char* name, int len)
{
	struct mi_cmd* cmd;

	if ( !is_id_valid(id) ) {
		LM_BUG("Invalid module id!\n");
		return -1;
	}

	if ( !(cmd = lookup_mi_cmd(name, len)) ) {
		LM_ERR("command (%.*s) not found!\n", len, name);
		return -1;
	}

	*cmd->trace_mask &= ~(1 << id);

	return 0;
}

/**
 *
 * allow an mi command having its name
 *
 */
int allow_mi_cmd_trace(int id, char* name, int len)
{
	struct mi_cmd* cmd;

	if ( !is_id_valid(id) ) {
		LM_BUG("Invalid module id!\n");
		return -1;
	}

	if ( !(cmd = lookup_mi_cmd(name, len)) ) {
		LM_ERR("command (%.*s) not found!\n", len, name);
		return -1;
	}

	*cmd->trace_mask |= (1 << id);

	return 0;
}

unsigned char is_mi_cmd_traced(int id, struct mi_cmd* cmd)
{
	return (id < 0)? 0 : (1 << id) & *cmd->trace_mask;
}

/**
 *
 * all mi modules that trace their commands must use this functions to parse
 * their blacklist
 *
 */
int parse_mi_cmd_bwlist(int id, char* bw_string, int len)
{

	char* tok_end;

	str token, list;

	int white;

	static const char type_delim = ':';
	static const char list_delim = ',';

	struct mi_cmd* cmd;

	if ( bw_string == NULL || len == 0 ) {
		LM_ERR("empty mi command list!\n");
		return -1;
	}

	tok_end = q_memchr(bw_string, type_delim, len);
	if ( !tok_end ) {
		LM_ERR("missing list type: either blacklist( b ) or whitelist ( w )!\n");
		return -1;
	}

	token.s = bw_string;
	token.len = tok_end - bw_string;
	str_trim_spaces_lr(token);

	if ( token.len != 1 ) {
		goto invalid_list;
	} else if ( token.s[0] == 'w' || token.s[0] == 'W' ) {
		white = 1;
	} else if ( token.s[0] == 'b' || token.s[0] == 'B' ) {
		white = 0;
	} else {
		goto invalid_list;
	}

	if ( init_mod_trace_cmds(id, white) < 0 ) {
		LM_ERR("failed to initialise trace mask for mi commands!\n");
		return -1;
	}

	if ( (tok_end - bw_string) >= len || tok_end + 1 == 0) {
		LM_ERR("no command in list!\n");
		return -1;
	}

	list.s = tok_end + 1;
	list.len = len - ((tok_end + 1) - bw_string);


	while ( list.s != NULL && list.len > 0 ) {
		tok_end = q_memchr( list.s, list_delim, list.len );
		if ( tok_end ) {
			token.s = list.s;
			token.len = tok_end - list.s;

			list.s = tok_end + 1;
			list.len -= token.len + 1;
		} else {
			token = list;
			list.s = NULL;
			list.len = 0;
		}

		str_trim_spaces_lr( token );

		cmd = lookup_mi_cmd( token.s, token.len );
		if ( cmd == NULL ) {
			LM_ERR("can't find mi command [%.*s]!\n", token.len, token.s);
			return -1;
		}

		if ( !cmd->trace_mask ) {
			LM_ERR("command <%.*s> doesn't have it's trace mask allocated!\n",
					token.len, token.s);
			continue;
		}

		if ( white ) {
			*cmd->trace_mask |= ( 1 << id );
		} else {
			*cmd->trace_mask &= ~( 1 << id );
		}
	}

	return 0;

invalid_list:
	LM_ERR("Invalid list type <%.*s>! Either b (blacklist) or w (whitelist)!\n",
			token.len, token.s);
	return -1;
}


