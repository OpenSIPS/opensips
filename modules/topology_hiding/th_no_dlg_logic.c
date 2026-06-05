/*
 *
 * Copyright (C) 2026 Genesys Cloud Services, Inc.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "th_no_dlg_logic.h"
#include "thinfo_codec.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../forward.h"
#include "../dialog/dlg_hash.h"
#include "../tm/tm_load.h"
#include "../rr/loose.h"
#include "../rr/api.h"
#include "../../data_lump.h"

#include <stdint.h>
#include <string.h>

#define START_THINFO_BUF_SZ 1000
#define THINFO_MAX_BUFFER_SIZE 10000

#define TOPOH_MATCH_TAG_MATCH            2
#define TOPOH_MATCH_SUCCESS              1
#define TOPOH_MATCH_FAILURE             -1
#define TOPOH_MATCH_UNSUPPORTED_METHOD  -2

#define ROUTE_STR "Route: "
#define ROUTE_LEN (sizeof(ROUTE_STR) - 1)
#define ROUTE_PREF "Route: <"
#define ROUTE_PREF_LEN (sizeof(ROUTE_PREF) -1)
#define ROUTE_SUFF ">\r\n"
#define ROUTE_SUFF_LEN (sizeof(ROUTE_SUFF) -1)

#define ROUTE_SUCCESS   (1<<0)
#define ROUTE_LOOSE     (1<<1)
#define ROUTE_SELF      (1<<2)
#define ROUTE_DOUBLE_RR (1<<3)
#define ROUTE_STRICT    (1<<4)
#define ROUTE_FAILURE   (1<<5)

#define RR_PREFIX "Record-Route: "
#define RR_PREFIX_LEN (sizeof(RR_PREFIX)-1)

#define RR_URI_PREFIX "<sip:"
#define RR_URI_PREFIX_LEN (sizeof(RR_URI_PREFIX)-1)

#define RR_LR ";lr"
#define RR_LR_LEN (sizeof(RR_LR)-1)

#define RR_LR_FULL ";lr=on"
#define RR_LR_FULL_LEN (sizeof(RR_LR_FULL)-1)

#define RR_FROMTAG ";ftag="
#define RR_FROMTAG_LEN (sizeof(RR_FROMTAG)-1)

#define RR_R2 ";r2=on"
#define RR_R2_LEN (sizeof(RR_R2)-1)

#define RR_TERM ">"
#define RR_TERM_LEN (sizeof(RR_TERM)-1)

#define RR_SEPARATOR ","
#define RR_SEPARATOR_LEN (sizeof(RR_SEPARATOR)-1)

#define BUILD_RR_HEADER_BUFFER(hdr_buf, hdr_len, uri_str) \
    do { \
        hdr_len = RR_PREFIX_LEN + (uri_str).len + CRLF_LEN; \
        hdr_buf = pkg_malloc(hdr_len); \
        if (hdr_buf) { \
            memcpy(hdr_buf, RR_PREFIX, RR_PREFIX_LEN); \
            memcpy(hdr_buf + RR_PREFIX_LEN, (uri_str).s, (uri_str).len); \
            memcpy(hdr_buf + RR_PREFIX_LEN + (uri_str).len, CRLF, CRLF_LEN); \
        } \
    } while(0)

extern struct tm_binds tm_api;

static thinfo_encoded_t encoded_uri_buf = { 0 };
static thinfo_encoded_t decoded_uri_buf = { 0 };

struct th_no_dlg_param {
	str routes;
	str username;
	uint16_t flags;
};

static char decoded_uri_str[MAX_ENCODED_URI_SIZE * 3];
static char dec_buf_legacy[4096];

extern int th_ct_enc_scheme;
extern str th_internal_trusted_tag;
extern str th_external_socket_tag;
extern str th_is_self_socket_tag;
extern int auto_route_on_trusted_socket;

extern struct th_ct_params *th_param_list;
extern struct th_ct_params *th_hdr_param_list;

static int param_password_count = 0;
static char *buffers[TH_INFO_PASSWORD_ROTATION_SIZE] = { 0 };
static thinfo_options_t param_passwords[TH_INFO_PASSWORD_ROTATION_SIZE] = {
	{
		.param_name = DEFAULT_PARAM,
		.param_password = DEFAULT_PW,
		.compact_encoding = 1
	}
};

static thinfo_options_t *encoding_options = NULL;

typedef struct {
	unsigned int delete_count;
	unsigned int skip_encode_count;
} route_count_t;

enum info_buffer_state {
    HAS_CONTACT        = 1 << 0,
    HAS_ROUTES         = 1 << 1,
    HAS_SOCK           = 1 << 2,
    INVALID_BUF        = 1 << 3,
};

typedef struct {
	str routes;
	str contact;
	const struct socket_info *sock;
	uint16_t flags;
	enum info_buffer_state state;
} decoded_info_buffer_t;

#define FINALIZE_DECODED_BUF_STATE(db) \
    do { \
        if ((db).contact.s && (db).contact.len > 0) \
            (db).state |= HAS_CONTACT; \
        if ((db).routes.s && (db).routes.len > 0) \
            (db).state |= HAS_ROUTES; \
        if ((db).sock) \
            (db).state |= HAS_SOCK; \
    } while(0)

typedef decoded_info_buffer_t (*decode_info_fn)(str *, const thinfo_options_t *);
static decoded_info_buffer_t decode_info_buffer(str *, const thinfo_options_t *);
static decoded_info_buffer_t decode_info_buffer_legacy(str *, const thinfo_options_t *);

static int th_no_dlg_encode_contact(struct sip_msg *, uint16_t, str, str *);

static inline int th_no_dlg_onrequest(struct sip_msg *, uint16_t, str *);
static void th_no_dlg_onreply(struct cell *, int, struct tmcb_params *);
static int th_no_dlg_seq_handling(struct sip_msg *, str *, decode_info_fn, const thinfo_options_t *);
static inline int th_no_dlg_one_way_hiding(const struct socket_info *);
static struct lump* th_no_dlg_add_auto_record_route(struct sip_msg *, uint16_t, struct lump *);
static route_count_t th_no_dlg_match_record_route_or_route_uris(struct sip_msg *, struct sip_msg *, hdr_types_t, int);

static char* build_encoded_thinfo_suffix(struct sip_msg *, str, int *, uint16_t, int);
static char* build_encoded_contact_suffix_legacy(struct sip_msg *, str, int *, int);

static thinfo_options_t *th_get_options(const str *);

int topo_hiding_no_dlg(struct sip_msg *req, struct cell* t, unsigned int extra_flags, struct th_params *params) {
	struct th_no_dlg_param *p = NULL;
	str *username = NULL;
	size_t param_size = 0;

	if (extra_flags & TOPOH_HIDE_CALLID)
		LM_WARN("Cannot hide callid when dialog support is not engaged!\n");
	if (extra_flags & TOPOH_DID_IN_USER)
		LM_WARN("Cannot store DID in user when dialog support is not engaged!\n");

	if (!(extra_flags & TOPOH_KEEP_USER) && params && params->ct_callee_user.len) {
		param_size = sizeof *p + params->ct_callee_user.len;
	} else {
		param_size = sizeof *p;
	}

	p = shm_malloc(param_size);
	if (p == NULL) {
		LM_ERR("Failed to allocate params\n");
		return -1;
	}

	memset(p, 0, sizeof *p);
	
	if (!(extra_flags & TOPOH_KEEP_USER)) {
		if (params && params->ct_callee_user.len) {
			p->username.s = (char *)(p + 1);
			p->username.len =  params->ct_callee_user.len;
			memcpy(p->username.s,  params->ct_callee_user.s,
					params->ct_callee_user.len);
			username = &params->ct_callee_user;
		}
	}

	p->flags = extra_flags;

    if (th_no_dlg_onrequest(req, extra_flags, username) < 0) {
        LM_ERR("Failed to do topology_hiding on request\n");
        goto error;
    }

    if (tm_api.register_tmcb(req, 0, TMCB_RESPONSE_FWDED, th_no_dlg_onreply, p, shm_free_wrap) < 0) {
        LM_ERR("failed to register TMCB\n");
        goto error;
    }

    return 1;
error:
	shm_free_wrap(p);
	return -1;
}

static int th_no_dlg_auto_route_seq_handling(struct sip_msg *msg, rr_t auto_route[static 1], str thinfo[static 1], int self_route, const thinfo_options_t *options) {
	struct th_no_dlg_param *p = NULL;
	rr_t *after_auto = NULL;
	const struct socket_info *sock = NULL;
	str host = STR_NULL;
	str route_s = STR_NULL;
	char *route_free_str = NULL;
	int max_size = 0, dec_len = 0, proto = 0, i = 0;
	uint16_t flags;
	unsigned short port = 0;
	
	max_size = th_ct_enc_scheme == ENC_BASE64 ?
		calc_max_word64_decode_len(thinfo->len) :
		calc_max_word32_decode_len(thinfo->len);
	
	if (max_size > MAX_THINFO_BUFFER_SIZE) {
		return -1;
	}

	if (th_ct_enc_scheme == ENC_BASE64)
		dec_len = word64decode(decoded_uri_buf.buf, (unsigned char *) thinfo->s, thinfo->len);
	else
		dec_len = word32decode(decoded_uri_buf.buf, (unsigned char *) thinfo->s, thinfo->len);

	if (dec_len <= 0) {
		LM_ERR("Failed to decode\n");
		return TOPOH_MATCH_FAILURE;
	}

	LM_DBG("Size of base64 decoded length %d and size of param len %d\n", dec_len, thinfo->len);

	for (i = 0; i < dec_len; i++)
		decoded_uri_buf.buf[i] ^= options->param_password.s[i % options->param_password.len];

	if (thinfo_get_uri_count(&decoded_uri_buf) != 0) {
		LM_ERR("Encoded URI count is invalid, can only be 0 in auto Route\n");
		return TOPOH_MATCH_FAILURE;
	}

	flags = thinfo_get_flags(&decoded_uri_buf);

	decoded_uri_buf.len = dec_len;
	decoded_uri_buf.pos = 0;

	if (thinfo_decode_socket(&decoded_uri_buf, &proto, &host, &port) <= 0) {
		LM_ERR("Failed to decode socket 0\n");
		return -1;
	}

	LM_DBG("Decoded socket host [%.*s] - Port - %d - Proto %d\n", host.len, host.s, port, proto);

	if (self_route) {
		sock = grep_sock_info(&host, port, proto);
	} else if (th_external_socket_tag.len > 0) {
		sock = grep_internal_sock_info(&th_external_socket_tag, 0, proto);
	} else {
		LM_ERR("No external socket tag defined\n");
		return TOPOH_MATCH_FAILURE;
	}

	if (sock != NULL) {
		msg->force_send_socket = sock;
	} else if (sock == NULL) {
		LM_ERR("No socket found encoded in the auto Route\n");
		return TOPOH_MATCH_FAILURE;
	}

	if (topo_delete_record_route_uris(msg, 0) < 0) {
		LM_ERR("Failed to remove Record Route header \n");
		return TOPOH_MATCH_FAILURE;
	}

	if (topo_delete_vias(msg) < 0) {
		LM_ERR("Failed to remove via headers\n");
		return TOPOH_MATCH_FAILURE;
	}

	if (msg->record_route) {
		if (print_rr_body(msg->record_route, &route_s, 0, 0, NULL) != 0){
			LM_ERR("failed to print route records \n");
			if (route_s.s != NULL) {
				pkg_free(route_s.s);
			}
			return TOPOH_MATCH_FAILURE;
		}
		route_free_str = route_s.s;
	}

	if (th_no_dlg_encode_contact(msg, flags, route_s, NULL) < 0) {
		LM_ERR("Failed to encode contact header\n");
		if (route_free_str != NULL) {
			pkg_free(route_free_str);
		}
		return TOPOH_MATCH_FAILURE;
	}

	if (route_free_str != NULL) {
		pkg_free(route_free_str);
	}

	after_auto = auto_route->next;

	if (topo_delete_route_uris(msg, 1) < 0) {
		LM_ERR("Failed to Auto Route URI\n");
		return -1;
	}

	if (after_auto != NULL && set_dst_uri(msg, &after_auto->nameaddr.uri) !=0) {
		LM_ERR("Error set_dst_uri\n");
		return TOPOH_MATCH_FAILURE;
	}

	p = shm_malloc(sizeof *p);
	if (p == NULL) {
		LM_ERR("Failed to allocate params\n");
		return -1;
	}

	memset(p, 0, sizeof *p);

	p->flags = flags;

	if (tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED, th_no_dlg_onreply, p, shm_free_wrap) < 0) {
		LM_ERR("failed to register TMCB\n");
		shm_free(p);
		return TOPOH_MATCH_FAILURE;
	}

	p = NULL;

	return TOPOH_MATCH_SUCCESS;
}

int topo_hiding_match_no_dlg(struct sip_msg *msg) {
	struct sip_uri *request_uri;
	struct sip_uri route_uri = { 0 };
	str *thinfo = NULL;
	rr_t *auto_route = NULL;
	int i, self_route, tag_match;
	thinfo_options_t *thinfo_decode = NULL;

	if (parse_sip_msg_uri(msg) < 0) {
		LM_ERR("Failed to parse request URI\n");
		return -1;
	}

	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse route headers\n");
	}

	request_uri = &msg->parsed_uri;

	if (msg->route == NULL && check_self(&request_uri->host, request_uri->port_no ? request_uri->port_no : SIP_PORT, 0)) {
		/* topology_hiding_match with thinfo and request domain is us
		 * needs to have a thinfo to continue otherwise we cannot match */
		for (i = 0; i < request_uri->u_params_no; i++) {
			thinfo_decode = th_get_options(&request_uri->u_name[i]);
			if (thinfo_decode != NULL) {
				if (thinfo_decode->compact_encoding) {
					LM_DBG("We found param in R-URI with value of %.*s\n",
						request_uri->u_val[i].len, request_uri->u_val[i].s);
					return th_no_dlg_seq_handling(msg, &request_uri->u_val[i], decode_info_buffer, thinfo_decode);
				} else {
					LM_DBG("We found legacy param in R-URI with value of %.*s\n",
						request_uri->u_val[i].len, request_uri->u_val[i].s);
					return th_no_dlg_seq_handling(msg, &request_uri->u_val[i], decode_info_buffer_legacy, thinfo_decode);
				}
			}
		}
	} else if (msg->route != NULL && auto_route_on_trusted_socket) {
		LM_DBG("Route header found, checking params\n");

		if (!msg->route->parsed && parse_rr(msg->route) != 0) {
			LM_ERR("failed to parse Route header\n");
			return -1;
		}

		auto_route = (rr_t *) msg->route->parsed;

		if (parse_uri(auto_route->nameaddr.uri.s, auto_route->nameaddr.uri.len, &route_uri) < 0) {
			LM_ERR("Bad Route URI\n");
			return TOPOH_MATCH_FAILURE;
		}

		LM_DBG("Auto Route header has '%d' params\n", route_uri.u_params_no);

		self_route = check_self(&route_uri.host, route_uri.port_no ? route_uri.port_no : SIP_PORT, 0);
		tag_match = th_no_dlg_one_way_hiding(msg->rcv.bind_address);
		
		if (self_route || tag_match) {
			if (!tag_match) {
				LM_ERR("Inbound socket is not a trusted internal socket or tag matching disable\n");
				return TOPOH_MATCH_FAILURE;
			}

			for (i = 0; i < route_uri.u_params_no; i++) {
				// encoding the socket uses the compact encoding regardless of the option
				// reuse the same param name and password but with compact encoding
				thinfo_decode = th_get_options(&route_uri.u_name[i]);
				if (thinfo_decode != NULL) {
					LM_DBG("We found param in Route header with value of %.*s\n",
						route_uri.u_val[i].len, route_uri.u_val[i].s);
					thinfo = &route_uri.u_val[i];
					break;
				}
			}

			if (thinfo == NULL) {
				LM_ERR("No known th_contact_encode_param_password param in auto Route\n");
				return TOPOH_MATCH_FAILURE;
			}

			return th_no_dlg_auto_route_seq_handling(msg, auto_route, thinfo, self_route, thinfo_decode);
		}
	}

	LM_DBG("Topology hiding did not match\n");
	return TOPOH_MATCH_FAILURE;
}

static int free_msg_rrs(struct sip_msg *msg) {
	struct hdr_field *hdr;

	for (hdr = msg->record_route; hdr; hdr = hdr->sibling) {
		if (hdr->parsed) {
			free_rr((rr_t **)&hdr->parsed);
			hdr->parsed = NULL;
		}
	}

	return 0;
}

static struct lump *anchor_after_last_record_route(struct sip_msg *msg) {
    struct hdr_field *last_rr = msg->record_route;
    unsigned int offset;

    if (last_rr) {
        while (last_rr->sibling)
            last_rr = last_rr->sibling;
        offset = last_rr->name.s + last_rr->len - msg->buf;
    } else {
        offset = msg->headers->name.s - msg->buf;
    }

    return anchor_lump(msg, offset, HDR_RECORDROUTE_T);
}

static void th_no_dlg_onreply(struct cell *t, int type, struct tmcb_params *param) {
	struct th_no_dlg_param *p = *(param->param);
	str route_s = STR_NULL;
	str *username = &p->username;
	str *rpl_original_rrs = NULL;
    str *additional_rrs = NULL;
	struct sip_msg *req = param->req;
	struct sip_msg *rpl = param->rpl;
	struct lump *lmp = NULL, *rr_lmp = NULL;
	char *suffix = NULL, *req_rr_buf = NULL, *rpl_rr_buf = NULL, *rr_free_str = NULL;
	int req_rr_count = 0, rpl_rr_count = 0, req_rr_buf_len = 0, rpl_rr_buf_len = 0;
	unsigned int flags = p->flags;
	int is_sequential = 0;
	int rebuild_req_rrs = 0;
	int one_way_hiding = th_no_dlg_one_way_hiding(t->uas.response.dst.send_sock);
	int req_one_way_hiding = th_no_dlg_one_way_hiding(t->uac[t->first_branch]->request.dst.send_sock);
	route_count_t route_count = { 0 };

	LM_DBG("Response callback with flags %u \n", flags);

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(rpl, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return;
	}

	if (parse_to_header(req) < 0 || req->to == NULL || get_to(req) == NULL) {
		LM_ERR("cannot parse TO header\n");
		return;
	}

	/* do_rr determined by if the request has a tag, don't add them on sequential */
	is_sequential = get_to(req)->tag_value.len > 0 && get_to(req)->tag_value.s != NULL;

	LM_DBG("Original request trusted send sock '%d' reply is trusted send sock '%d'\n", req_one_way_hiding, one_way_hiding);

	if (!req_one_way_hiding && (lmp = restore_vias_from_req(req, rpl)) == NULL) {
		LM_ERR("Failed to restore VIA headers from request \n");
		return;
	}

	if (!is_sequential && req_one_way_hiding) {
		route_count = th_no_dlg_match_record_route_or_route_uris(req, rpl, HDR_RECORDROUTE_T, auto_route_on_trusted_socket && req_one_way_hiding);

		if (topo_delete_record_route_uris(rpl, route_count.delete_count) < 0) {
			LM_ERR("Failed to remove '%d' Record-Route URIs\n", route_count.delete_count);
			goto cleanup;
		}
	} else if (!is_sequential && one_way_hiding) {
		// Rebuild the Record-Routes for consistency into single uri per single header
		if ((rpl_rr_count = list_rr_body(rpl->record_route, &rpl_original_rrs)) < 0 ){
			LM_ERR("failed to print route records \n");
			goto cleanup;
		}

		if (rpl_rr_count > 0) {
			if (topo_delete_record_route_uris(rpl, 0) < 0) {
				LM_ERR("Failed to remove all Record-Route URIs\n");
				goto cleanup;
			}

			if (rr_lmp == NULL) {
				rr_lmp = anchor_lump(rpl, rpl->headers->name.s - rpl->buf, HDR_RECORDROUTE_T);
			}

			for (int i = 0; i < rpl_rr_count; i++) {
				BUILD_RR_HEADER_BUFFER(rpl_rr_buf, rpl_rr_buf_len, rpl_original_rrs[i]);

				if (!rpl_rr_buf) {
					LM_ERR("no more pkg memory\n");
					goto cleanup;
				}

				if (!(rr_lmp = insert_new_lump_after(rr_lmp, rpl_rr_buf, rpl_rr_buf_len, 0))) {
					LM_ERR("failed to insert prefix\n");
					pkg_free(rpl_rr_buf);
					goto cleanup;
				}
			}
		}

		if (auto_route_on_trusted_socket) {
            rr_lmp = th_no_dlg_add_auto_record_route(rpl, flags, rr_lmp);
            if (rr_lmp == NULL) {
                LM_ERR("Failed to add Record-Route header\n");
				if (suffix)
                	pkg_free(suffix);
                goto cleanup;
            }
		}

		rebuild_req_rrs = req->record_route != NULL;
    } else {
		rebuild_req_rrs = req->record_route != NULL;

		if (topo_delete_record_route_uris(rpl, 0) < 0) {
			LM_ERR("Failed to remove all Record-Route URIs\n");
			goto cleanup;
		}
	}

	if (rebuild_req_rrs) {
		if (one_way_hiding && (lmp = restore_vias_from_req(req, rpl)) == NULL) {
			LM_ERR("Failed to restore VIA headers from request \n");
			return;
		}

		if (rr_lmp == NULL) {
			rr_lmp = anchor_after_last_record_route(rpl);
		}

		if ((req_rr_count = list_rr_body(req->record_route, &additional_rrs)) < 0 ) {
			LM_ERR("failed to print route records \n");
			goto cleanup;
		}

		for (int i = 0; i < req_rr_count; i++) {
			BUILD_RR_HEADER_BUFFER(req_rr_buf, req_rr_buf_len, additional_rrs[i]);

			if (!req_rr_buf) {
				LM_ERR("no more pkg memory\n");
				goto cleanup;
			}

			if (!(rr_lmp = insert_new_lump_after(rr_lmp, req_rr_buf, req_rr_buf_len, 0))) {
				LM_ERR("failed to insert prefix\n");
				pkg_free(req_rr_buf);
				goto cleanup;
			}
		}
	}
	if (!one_way_hiding && !(rpl->REPLY_STATUS >= 300 && rpl->REPLY_STATUS < 400)) {
		if (p->routes.s != NULL) {
			route_s = p->routes;
		} else if (rpl->record_route) {
			if (print_rr_body(rpl->record_route, &route_s, 1, 0, &route_count.skip_encode_count) != 0){
				LM_ERR("failed to print route records \n");
				goto cleanup;
			}

			rr_free_str = route_s.s;
		}

        if (th_no_dlg_encode_contact(rpl, flags, route_s, username) < 0) {
            LM_ERR("Failed to encode contact header \n");
        }
    }
cleanup:
	/* We parse the record-routes in the request from the transaction 
	 * they need to be cleaned up as it's in pkg memory
	 * this request can used from a transaction timeout to generate a response
	 * if they're parsed and not nulled it will crash
	 */
	free_msg_rrs(req);
	if (rr_free_str != NULL)
		pkg_free(rr_free_str);
}

static inline int th_no_dlg_onrequest(struct sip_msg *req, uint16_t flags, str *username) {
	int one_way_hiding = 0;
    int do_rr = 0;
	str route_s = STR_NULL;

	LM_DBG("Request callback with flags %u\n", flags);

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(req, HDR_EOH_F, 0) >= 0) {
		one_way_hiding = th_no_dlg_one_way_hiding(req->force_send_socket != NULL ? req->force_send_socket : req->rcv.bind_address);
        do_rr = get_to(req)->tag_value.len == 0 || get_to(req)->tag_value.s == NULL;
		if (!one_way_hiding) {
			if (topo_delete_vias(req) < 0) {
				LM_ERR("Failed to remove via headers\n");
				return -1;
            }

			if (req->record_route) {
				if (print_rr_body(req->record_route, &route_s, 0, 0, NULL) != 0){
					LM_ERR("failed to print route records \n");
					goto error;
				}
			}

            if (th_no_dlg_encode_contact(req, flags, route_s, username) < 0) {
                LM_ERR("Failed to encode contact header\n");
                goto error;
            }

			if (topo_delete_record_route_uris(req, 0) < 0) {
				LM_ERR("Failed to remove Record Route header \n");
				goto error;
			}
		} else if (do_rr && auto_route_on_trusted_socket) {
			if (th_no_dlg_add_auto_record_route(req, flags, NULL) == NULL) {
                LM_ERR("Failed to add Record-Route header\n");
                return -1;
            }
        }
	} else {
		LM_ERR("Failed to parse request\n");
		return -1;
	}

	if (route_s.s != NULL)
		pkg_free(route_s.s);

	return 1;
error:
	if (route_s.s != NULL) {
		pkg_free(route_s.s);
	}

	return -1;
}

#define HAS_NO_CONTACT_BODY(_m) (((contact_body_t *) ((_m)->contact->parsed))->star == 1 || \
							    ((contact_body_t *) ((_m)->contact->parsed))->contacts == NULL || \
                                ((contact_body_t *) ((_m)->contact->parsed))->contacts->next != NULL)

static char* build_encoded_contact_suffix_legacy(struct sip_msg* msg, str rr_set, int *suffix_len, int flags) {
	short rr_len,ct_len,addr_len,flags_len,enc_len;
	char *suffix_plain = NULL, *suffix_enc = NULL, *p = NULL, *s = NULL;
	char *rr_set_free_str = NULL;
	str contact;
	str flags_str;
	int i,total_len;
	struct sip_uri ctu, rr_uri;
	struct th_ct_params* el;
	param_t *it;
	rr_t *head = NULL;
	const struct socket_info *rr_sock = NULL;
	int params_len = 0;
	int local_len = sizeof(short) /* RR length */ +
					sizeof(short) /* Contact length */ +
					sizeof(short) /* RR length */ +
					sizeof(short) /* bind addr */;

	/* parse all headers as we can have multiple
	   RR headers in the same message */
	if (parse_headers(msg,HDR_EOH_F,0)<0 ){
		LM_ERR("failed to parse all headers\n");
		return NULL;
	}

	if (parse_contact(msg->contact) < 0 || HAS_NO_CONTACT_BODY(msg)) {
		LM_ERR("bad Contact HDR\n");
		goto error;
	} else {
		contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
		ct_len = (short)contact.len;
	}

	rr_len = rr_set.len;

	flags_str.s = int2str(flags, &flags_str.len);
	flags_len = (short)flags_str.len;
	
	addr_len = (short)msg->rcv.bind_address->sock_str.len;
	local_len += rr_len + ct_len + flags_len + addr_len; 
	enc_len = th_ct_enc_scheme == ENC_BASE64 ?
		calc_word64_encode_len(local_len) : calc_word32_encode_len(local_len);
	total_len = enc_len +
		1 /* ; */ +
		encoding_options->param_name.len +
		1 /* = */  +
		params_len + /* URI and header params */
		1 /* > */;	 

	if (th_param_list) {
		if (parse_contact(msg->contact) < 0 || HAS_NO_CONTACT_BODY(msg)) {
			LM_ERR("bad Contact HDR\n");
		} else {
			contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
			if(parse_uri(contact.s, contact.len, &ctu) < 0) {
				LM_ERR("Bad Contact URI\n");
			} else {
				for (el=th_param_list;el;el=el->next) {
					/* we just iterate over the unknown params */
					for (i=0;i<ctu.u_params_no;i++) {
						if (str_match(&el->param_name, &ctu.u_name[i]))
							params_len += topo_ct_param_len(&ctu.u_name[i], &ctu.u_val[i], 0);
					}
				}
			}
		}
	}

	if (th_hdr_param_list) {
		if (parse_contact(msg->contact) < 0 || HAS_NO_CONTACT_BODY(msg)) {
			LM_ERR("bad Contact HDR\n");
		} else {
			for (el=th_hdr_param_list;el;el=el->next) {
				for (it=((contact_body_t *)msg->contact->parsed)->contacts->params;it;it=it->next) {
					if (str_match(&el->param_name, &it->name))
						params_len += topo_ct_param_len(&it->name, &it->body, 1);
				}
			}
		}
	}

	if (rr_set.len > 0) {
        if (parse_rr_body(rr_set.s, rr_set.len, &head) != 0) {
            LM_ERR("failed parsing route set\n");
            goto error;
        }

        if (parse_uri(head->nameaddr.uri.s, head->nameaddr.uri.len, &rr_uri) < 0) {
            LM_ERR("Failed to parse SIP uri\n");
            goto error;
        }

		rr_sock = grep_sock_info(&rr_uri.host, rr_uri.port_no ? rr_uri.port_no : SIP_PORT, rr_uri.proto);

        if (th_no_dlg_one_way_hiding(rr_sock)) {
			rr_set.s = rr_set.s + head->nameaddr.uri.len + 1;
			rr_set.len = rr_set.len - (head->nameaddr.uri.len + 1);
        }
    }

	if (head != NULL) {
		free_rr(&head);
		head = NULL;
	}

	total_len += params_len;

	suffix_enc = pkg_malloc(total_len+1);
	if (!suffix_enc) {
		LM_ERR("no more pkg\n");
		goto error;
	}
	suffix_plain = pkg_malloc(local_len+1);
	if (!suffix_plain) {
		LM_ERR("no more pkg\n");
		goto error;
	}

	p = suffix_plain;
	memcpy(p,&rr_len,sizeof(short));
	p+= sizeof(short);
	if (rr_len) {
		memcpy(p,rr_set.s,rr_set.len);
		p+= rr_set.len;
	}
	memcpy(p,&ct_len,sizeof(short));
	p+= sizeof(short);
	if (ct_len) {
		memcpy(p,contact.s,contact.len);
		p+= contact.len;
	}
	memcpy(p,&flags_len,sizeof(short));
	p+= sizeof(short);
	memcpy(p,flags_str.s, flags_str.len);
	p+= flags_str.len;
	memcpy(p,&addr_len,sizeof(short));
	p+= sizeof(short);
	memcpy(p,msg->rcv.bind_address->sock_str.s,msg->rcv.bind_address->sock_str.len);
	p+= msg->rcv.bind_address->sock_str.len;
	for (i=0;i<(int)(p-suffix_plain);i++)
		suffix_plain[i] ^= encoding_options->param_password.s[i % encoding_options->param_password.len];

	s = suffix_enc;
	*s++ = ';';
	memcpy(s, encoding_options->param_name.s, encoding_options->param_name.len);
	s += encoding_options->param_name.len;
	*s++ = '=';
	if (th_ct_enc_scheme == ENC_BASE64)
		word64encode((unsigned char*)s,(unsigned char *)suffix_plain,p-suffix_plain);
	else
		word32encode((unsigned char*)s,(unsigned char *)suffix_plain,p-suffix_plain);
	s = s+enc_len;
	
	if (th_param_list) {
		for (el=th_param_list;el;el=el->next) {
			/* we just iterate over the unknown params */
			for (i=0;i<ctu.u_params_no;i++) {
				if (str_match(&el->param_name, &ctu.u_name[i]))
					s = topo_ct_param_copy(s, &ctu.u_name[i], &ctu.u_val[i], 0);
			}
		}
	}
	*s++ = '>';
	if (th_hdr_param_list) {
		if ( parse_contact(msg->contact)<0 ||
			((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
			((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
			LM_ERR("bad Contact HDR\n");
		} else {
			for (el=th_hdr_param_list;el;el=el->next) {
				for (it=((contact_body_t *)msg->contact->parsed)->contacts->params;it;it=it->next) {
					if (str_match(&el->param_name, &it->name))
						s = topo_ct_param_copy(s, &it->name, &it->body, 1);
				}
			}
		}
	}

	if (rr_set_free_str)
		pkg_free(rr_set_free_str);
	pkg_free(suffix_plain);
	*suffix_len = total_len;
	return suffix_enc;
error:
	if (suffix_enc)
		pkg_free(suffix_enc);
	if (suffix_plain)
		pkg_free(suffix_plain);
	if (rr_set_free_str)
		pkg_free(rr_set_free_str);
	if (head)
		free_rr(&head);
	return NULL;
}

static int th_binary_encode_record_route(rr_t *record_route, rr_t **out_rr, int encode_self) {
	struct sip_uri rr_uri = { 0 }, rr_uri_r2 = { 0 };
	const struct socket_info *rr_sock = NULL;

	if (record_route == NULL) {
		LM_DBG("Record-Route to encode is NULL, skipping\n");
		return -1;
	}

	if (parse_uri(record_route->nameaddr.uri.s, record_route->nameaddr.uri.len, &rr_uri) < 0) {
		LM_ERR("Failed to parse SIP uri\n");
		return -1;
	}

	rr_sock = grep_sock_info(&rr_uri.host, rr_uri.port_no ? rr_uri.port_no : SIP_PORT, rr_uri.proto);

	if (th_no_dlg_one_way_hiding(rr_sock) && !encode_self) {
		LM_DBG("Route header is self, skipping encode\n");
		return 1;
	}

	if (!is_2rr(&rr_uri.params)) {
		if (thinfo_encode_uri(&encoded_uri_buf, &rr_uri, 0, NULL, 1) == -1) {
			LM_ERR("Error encoding Route URI\n");
			return -1;
		}
	} else {
		record_route = record_route->next;
		if (record_route != NULL) {
			if (parse_uri(record_route->nameaddr.uri.s, record_route->nameaddr.uri.len, &rr_uri_r2) < 0) {
				LM_ERR("Failed to parse SIP uri\n");
				return -1;
			}

			if (is_2rr(&rr_uri_r2.params) && str_match(&rr_uri.host, &rr_uri_r2.host)) {
				if (thinfo_encode_dual_uri(&encoded_uri_buf, &rr_uri, &rr_uri_r2) == -1) {
					LM_ERR("Error encoding Route URI\n");
					return -1;
				}
			} else {
				if (thinfo_encode_uri(&encoded_uri_buf, &rr_uri, 0, NULL, 1) == -1) {
					LM_ERR("Error encoding Route URI\n");
					return -1;
				}

				if (thinfo_encode_uri(&encoded_uri_buf, &rr_uri_r2, 0, NULL, 1) == -1) {
					LM_ERR("Error encoding Route URI\n");
					return -1;
				}
			}
		} else {
			if (thinfo_encode_uri(&encoded_uri_buf, &rr_uri, 0, NULL, 1) == -1) {
				LM_ERR("Error encoding Route URI\n");
				return -1;
			}
			LM_WARN("Previous Route has r2=on but no next Route\n");
		}
	}

	*out_rr = record_route != NULL ? record_route->next : NULL;
	return 0;
}

static char* build_encoded_thinfo_suffix(struct sip_msg* msg, str rr_set, int *suffix_len, uint16_t flags, int socket_only) {
	uint16_t enc_len = 0;
	char *suffix_enc = NULL, *s = NULL;
    rr_t *next = NULL, *head = NULL;
	int i, x, params_len = 0;
	struct sip_uri ctu = { 0 };
	struct th_ct_params* el;
	param_t *it;
	str contact = STR_NULL;
	char *rr_set_free_str = NULL;
	str ct_uri_params_skip[URI_MAX_U_PARAMS];
	int param_count = 0;
	int encode_self_rr = 0, encode_ret_code = 0;

	/* parse all headers as we can have multiple
	   RR headers in the same message */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse all headers\n");
		return NULL;
	}

    thinfo_buffer_reset(&encoded_uri_buf);

    if (socket_only == 1) {
		goto socket_only;
	}

	if (parse_contact(msg->contact) < 0 || HAS_NO_CONTACT_BODY(msg)) {
		LM_ERR("bad Contact HDR\n");
		goto error;
	} else {
		contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
		if (parse_uri(contact.s, contact.len, &ctu) < 0) {
			LM_ERR("Bad Contact URI\n");
			goto error;
		} 
	}

	if (th_param_list) {
		for (el = th_param_list; el; el = el->next) {
			/* we just iterate over the unknown params */
			for (i = 0; i < ctu.u_params_no; i++) {
				if (str_match(&el->param_name, &ctu.u_name[i])) {
					ct_uri_params_skip[param_count++] = ctu.u_name[i];
					params_len += topo_ct_param_len(&ctu.u_name[i], &ctu.u_val[i], 0);
				}
			}
		}
	}

	if (th_hdr_param_list) {
		for (el = th_hdr_param_list; el; el = el->next) {
			for (it = ((contact_body_t *)msg->contact->parsed)->contacts->params; it; it = it->next) {
				if (str_match(&el->param_name, &it->name))
					params_len += topo_ct_param_len(&it->name, &it->body, 1);
			}
		}
	}

	if (thinfo_encode_uri(&encoded_uri_buf, &ctu, param_count, ct_uri_params_skip, !(flags & TOPOH_KEEP_USER)) == -1) {
		LM_ERR("Error encoding Contact URI\n");
		goto error;
	}

    if (rr_set.len > 0) {
        if (parse_rr_body(rr_set.s, rr_set.len, &head) != 0) {
            LM_ERR("failed parsing route set\n");
            goto error;
        }

        next = head;
    }

	while (next != NULL) {
		encode_ret_code = th_binary_encode_record_route(next, &next, encode_self_rr);
		if (encode_ret_code < 0) {
			goto error;
		} else if (encode_ret_code == 1) {
			// Found first occurence of self Record-Route, need to encode the rest
			encode_self_rr = 1;
		}
	}

	if (head != NULL) {
		free_rr(&head);
		head = NULL;
	}

socket_only:
    if (thinfo_encode_socket(&encoded_uri_buf, msg->rcv.bind_address) < 0) {
        LM_ERR("Error encoding socket\n");
        goto error;
    }

    enc_len = th_ct_enc_scheme == ENC_BASE64 ?
		calc_word64_encode_len(encoded_uri_buf.len) : calc_word32_encode_len(encoded_uri_buf.len);
    
    thinfo_buffer_finalize(&encoded_uri_buf, flags);

	for (i = 0; i < encoded_uri_buf.len; i++)
    	encoded_uri_buf.buf[i] ^= encoding_options->param_password.s[i % encoding_options->param_password.len];

    suffix_enc = pkg_malloc(1 + encoding_options->param_name.len + 1 + enc_len + params_len + 1);
    if (!suffix_enc) {
        LM_ERR("no more pkg\n");
        goto error;
    }

    s = suffix_enc;
    *s++ = ';';
    memcpy(s, encoding_options->param_name.s, encoding_options->param_name.len);
    s += encoding_options->param_name.len;
    *s++ = '=';

    if (th_ct_enc_scheme == ENC_BASE64)
        word64encode((unsigned char*)s, encoded_uri_buf.buf, encoded_uri_buf.len);
    else
        word32encode((unsigned char*)s, encoded_uri_buf.buf, encoded_uri_buf.len);

    s += enc_len;

	if (param_count > 0) {
		for (x = 0; x < param_count; x++) {
			/* we just iterate over the unknown params */
			for (i = 0; i < ctu.u_params_no; i++) {
				if (str_match(&ct_uri_params_skip[x], &ctu.u_name[i]))
					s = topo_ct_param_copy(s, &ctu.u_name[i], &ctu.u_val[i], 0);
			}
		}
	}

	if (!socket_only)
		*s++ = '>';

	if (socket_only != 1 && th_hdr_param_list) {
		for (el = th_hdr_param_list; el; el = el->next) {
			for (it = ((contact_body_t *)msg->contact->parsed)->contacts->params; it; it = it->next) {
				if (str_match(&el->param_name, &it->name))
					s = topo_ct_param_copy(s, &it->name, &it->body, 1);
			}
		}
	}

	if (rr_set_free_str)
    	pkg_free(rr_set_free_str);

	*suffix_len = s - suffix_enc;

	return suffix_enc;
error:
	if (rr_set_free_str)
		pkg_free(rr_set_free_str);
	if (head)
		free_rr(&head);
	if (suffix_enc)
		pkg_free(suffix_enc);
	return NULL;
}

static int th_no_dlg_encode_contact(struct sip_msg *msg, uint16_t flags, str routes, str *ct_user) {
	struct lump* lump;
	char *prefix = NULL,*suffix = NULL,*ct_username = NULL;
	int prefix_len, suffix_len = 0, ct_username_len = 0;
	struct sip_uri ctu;
	str contact;

	if (!msg->contact) {
		if(parse_headers(msg, HDR_CONTACT_F, 0) < 0) {
			LM_ERR("Failed to parse headers\n");
			return -1;
		}
		if (!msg->contact)
			return 0;
	}

	if (!(lump = delete_existing_contact(msg, 0))) {
		LM_ERR("Failed to delete existing contact \n");
		goto error;
	}

	LM_DBG("Flags '%d' passed for encoding Contact\n", flags);

	prefix_len = 5; /* <sip: */

	if (ct_user && ct_user->len) {
		ct_username = ct_user->s;
		ct_username_len = ct_user->len;
		prefix_len += 1 + /* @ */ + ct_username_len;
	} else if (flags & TOPOH_KEEP_USER) {
		if (parse_contact(msg->contact) < 0 || HAS_NO_CONTACT_BODY(msg)) {
			LM_ERR("bad Contact HDR\n");
		} else {
			contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
			if (parse_uri(contact.s, contact.len, &ctu) < 0) {
				LM_ERR("Bad Contact URI\n");
			} else {
				ct_username = ctu.user.s;
				ct_username_len = ctu.user.len;
				LM_DBG("Trying to propagate username [%.*s]\n", ct_username_len,
									ct_username);
				if (ct_username_len > 0)
					prefix_len += 1 + /* @ */ + ct_username_len;
			}
		}
	}

	prefix = pkg_malloc(prefix_len);
	if (!prefix) {
		LM_ERR("no more pkg\n");
		goto error;
	}

	memcpy(prefix, "<sip:", 5);
	if (flags & TOPOH_KEEP_USER && ct_username_len > 0) {
		memcpy(prefix + 5, ct_username, ct_username_len);
		prefix[prefix_len - 1] = '@';
	}

	if (!(lump = insert_new_lump_after(lump, prefix, prefix_len,0))) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}

	/* make sure we do not free this string in case of a further error */
	prefix = NULL;

	if (encoding_options->compact_encoding) {
		if (!(suffix = build_encoded_thinfo_suffix(msg, routes, &suffix_len, flags, 0))) {
			LM_ERR("Failed to build suffix \n");
			goto error;
		}
	} else {
		if (!(suffix = build_encoded_contact_suffix_legacy(msg, routes, &suffix_len, flags))) {
			LM_ERR("Failed to build suffix \n");
			goto error;
		}
	}

    if (!(lump = insert_subst_lump_after(lump, SUBST_SND_ALL, 0))) {
        LM_ERR("failed inserting SUBST_SND buf\n");
        goto error;
    }

    if (!(lump = insert_new_lump_after(lump, suffix,suffix_len, 0))) {
        LM_ERR("failed inserting '<sip:'\n");
        goto error;
    }

	return 0;
error:
    // Need to add this lump in on error to stop the process from blocking
	if (lump != NULL) {
		if (!(lump = insert_subst_lump_after(lump, SUBST_SND_ALL, 0))) {
			LM_ERR("failed inserting SUBST_SND buf\n");
		}
	}
	if (prefix) pkg_free(prefix);
	if (suffix) pkg_free(suffix);
	return -1;
}

static inline int topo_no_dlg_route(struct sip_msg *msg, str rr_buf[static 1]) {
	rr_t *head = NULL, *rrp = NULL;
	struct sip_uri rr_uri;
	char *route = NULL, *hdrs = NULL;
	int size = 0, start_index = 0;
	int route_flags = 0;
	struct lump *lmp = NULL;

	if (parse_rr_body(rr_buf->s, rr_buf->len, &head) != 0) {
		LM_ERR("failed parsing route set\n");
		route_flags = ROUTE_FAILURE;
		goto cleanup;
	}

	rrp = head;

	if (parse_uri(head->nameaddr.uri.s, head->nameaddr.uri.len, &rr_uri) < 0) {
		LM_ERR("Failed to parse SIP uri\n");
		route_flags = ROUTE_FAILURE;
		goto cleanup;
	}

	if (!is_strict(&rr_uri.params)) {
		route_flags |= ROUTE_LOOSE;
	} else {
		route_flags |= ROUTE_STRICT;
	}

	if (is_2rr(&rr_uri.params)) {
		route_flags |= ROUTE_DOUBLE_RR;
	}

	if (route_flags & (ROUTE_STRICT | ROUTE_SELF)) {
		LM_DBG("First Route header is a strict router\n");

		if (route_flags & ROUTE_STRICT && set_ruri(msg, &rrp->nameaddr.uri) != 0) {
			LM_ERR("failed setting new dst uri\n");
			route_flags = ROUTE_FAILURE;
			goto cleanup;
		}

		start_index = rrp->nameaddr.uri.len + 3; /* 3 = <>,*/	
		rrp = head->next;
	}

	hdrs = rr_buf->s + start_index;

	if (rrp != NULL && start_index < rr_buf->len) {
		size = rr_buf->len - start_index + ROUTE_LEN + CRLF_LEN;
		route = pkg_malloc(size);
		if (route == 0) {
			LM_ERR("no more pkg memory\n");
			route_flags = ROUTE_FAILURE;
			goto cleanup;
		}

		memcpy(route, ROUTE_STR, ROUTE_LEN);
		memcpy(route + ROUTE_LEN, hdrs, rr_buf->len - start_index);
		memcpy(route + ROUTE_LEN + rr_buf->len - start_index, CRLF, CRLF_LEN);

		LM_DBG("Adding Route header: [%.*s] \n", size, route);

		lmp = anchor_lump(msg, msg->headers->name.s - msg->buf, HDR_RECORDROUTE_T);

		if (lmp == NULL || insert_new_lump_after(lmp, route, size, HDR_ROUTE_T) == NULL) {
			LM_ERR("failed inserting new route set\n");
			pkg_free(route);
			route_flags = ROUTE_FAILURE;
			goto cleanup;
		}

		msg->msg_flags |= FL_HAS_ROUTE_LUMP;
		rr_buf->len = rr_buf->len - start_index;
		rr_buf->s = memcpy(rr_buf->s, hdrs, rr_buf->len);

		LM_DBG("setting dst_uri to <%.*s> \n", rrp->nameaddr.uri.len, rrp->nameaddr.uri.s);

		if (route_flags & ROUTE_LOOSE && set_dst_uri(msg, &rrp->nameaddr.uri) !=0 ) {
			route_flags = ROUTE_FAILURE;
			LM_ERR("Error set_dst_uri\n");
		}
	}

cleanup:
	if (head != NULL)
		free_rr(&head);

	return route_flags;
}

static inline int topo_no_dlg_rewrite_contact_as_next_route(struct sip_msg *msg, const str contact_buf[static 1]) {
	char *remote_contact = NULL;
	struct lump *lmp = NULL;
	int size = 0;

	size = contact_buf->len + ROUTE_PREF_LEN + ROUTE_SUFF_LEN;
	remote_contact = pkg_malloc(size);
	if (remote_contact == NULL) {
		LM_ERR("no more pkg \n");
		return -1;
	}

	memcpy(remote_contact, ROUTE_PREF,ROUTE_PREF_LEN);
	memcpy(remote_contact + ROUTE_PREF_LEN, contact_buf->s, contact_buf->len);
	memcpy(remote_contact + ROUTE_PREF_LEN + contact_buf->len,
			ROUTE_SUFF, ROUTE_SUFF_LEN);

	LM_DBG("Adding remote contact route header : [%.*s]\n",
			size, remote_contact);

	lmp = anchor_lump(msg, msg->headers->name.s - msg->buf, HDR_ROUTE_T);

	if (insert_new_lump_after(lmp, remote_contact, size, HDR_ROUTE_T) == 0) {
		LM_ERR("failed inserting remote contact route\n");
		pkg_free(remote_contact);
		return -1;
	}

	msg->msg_flags |= FL_HAS_ROUTE_LUMP;
	return 1;
}

static decoded_info_buffer_t decode_info_buffer(str *info, const thinfo_options_t *options) {
	int max_size, dec_len, decoded_uri_buf_len, i;
	uint8_t uri_count;
	int proto = 0;
	str host = STR_NULL;
	unsigned short port = 0;
	decoded_info_buffer_t decoded_buffer = { 0 };

	max_size = th_ct_enc_scheme == ENC_BASE64 ?
		calc_max_word64_decode_len(info->len) :
		calc_max_word32_decode_len(info->len);
	
	LM_DBG("Size of decoded length %d\n", max_size);
	if (max_size > MAX_THINFO_BUFFER_SIZE) {
		LM_ERR("Size of decoded buffer %d larger than max size %d\n", max_size, MAX_THINFO_BUFFER_SIZE);
		goto error;
	}

	if (th_ct_enc_scheme == ENC_BASE64)
		dec_len = word64decode(decoded_uri_buf.buf, (unsigned char *)info->s, info->len);
	else
		dec_len = word32decode(decoded_uri_buf.buf, (unsigned char *)info->s, info->len);

	if (dec_len <= 0) {
		LM_ERR("Decoded length less than zero, decoded len %d\n", dec_len);
		goto error;
	}

	for (i = 0; i < dec_len; i++)
		decoded_uri_buf.buf[i] ^= options->param_password.s[i % options->param_password.len];

    decoded_uri_buf.len = dec_len;
    decoded_uri_buf.pos = 0;

    uri_count = thinfo_get_uri_count(&decoded_uri_buf);
    if (uri_count == 0 || uri_count > MAX_ENCODED_SIP_URIS) {
        LM_ERR("Decoded URI count %d less than zero or larger than max size %d\n", uri_count, MAX_ENCODED_SIP_URIS);
		goto error;
    }

	LM_DBG("Decoded URI count %u\n", uri_count);

    decoded_buffer.flags = thinfo_get_flags(&decoded_uri_buf);
    decoded_uri_buf_len = thinfo_decode_uris(&decoded_uri_buf, decoded_uri_str, uri_count, decoded_uris);

	if (decoded_uri_buf_len < 0) {
        LM_ERR("Decoded len less than 0\n");
		goto error;
    }

    if (thinfo_decode_socket(&decoded_uri_buf, &proto, &host, &port) <= 0) {
		LM_ERR("Failed to decode socket\n");
		goto error;
	}

    if (host.len > 0 && host.s != NULL) {
		decoded_buffer.sock = grep_sock_info(&host, port, proto);

		if (!decoded_buffer.sock && th_internal_trusted_tag.len > 0) {
			decoded_buffer.sock = grep_internal_sock_info(&th_internal_trusted_tag, 0, proto);
		} else if (decoded_buffer.sock && th_internal_trusted_tag.len == 0) {
			LM_WARN("non-local socket <%.*s:%d>...ignoring\n", host.len, host.s, port);
		}

		if (decoded_buffer.sock) {
			decoded_buffer.state |= HAS_SOCK;
		}
    }

	if (decoded_uris[0].s != NULL && decoded_uris[0].len > 0) {
		decoded_buffer.contact = (str) { .s = decoded_uris[0].s, .len = decoded_uris[0].len };
		decoded_buffer.state |= HAS_CONTACT;
	}
    
    if (uri_count > 1) {
		decoded_buffer.routes = (str) { .s = decoded_uris[1].s, .len = decoded_uri_buf_len - decoded_buffer.contact.len - 1 };
		decoded_buffer.state |= HAS_ROUTES;
    }

	decoded_buffer.contact.s++; // Removing <
	decoded_buffer.contact.len -= 2; // Removing <>

	decoded_uris_count = uri_count;
	ctx_decoded_routes_set_valid();

	LM_DBG("Extracted routes [%.*s], contact [%.*s], flags [%u] and bind socket address [%.*s:%d] and proto %d\n",
		decoded_buffer.routes.len, decoded_buffer.routes.s,decoded_buffer.contact.len, decoded_buffer.contact.s,
		decoded_buffer.flags, host.len, host.s, port, proto);

	FINALIZE_DECODED_BUF_STATE(decoded_buffer);
	return decoded_buffer;
error:
	return (decoded_info_buffer_t) { .state = INVALID_BUF };
}

static decoded_info_buffer_t decode_info_buffer_legacy(str *info, const thinfo_options_t *options) {
    str flags_buf = STR_NULL, bind_buf = STR_NULL, host = STR_NULL;
    int max_size, port = 0, proto = 0;
    char *p;
    int i, dec_len, size;
    unsigned int parsed_flags;
	decoded_info_buffer_t decoded_buffer = { 0 };
    
    max_size = th_ct_enc_scheme == ENC_BASE64 ?
        calc_max_word64_decode_len(info->len) :
        calc_max_word32_decode_len(info->len);
    
    if (max_size > sizeof(dec_buf_legacy)) {
        LM_ERR("Decoded size %d exceeds buffer size %zu\n", max_size, sizeof(dec_buf_legacy));
		goto error;
    }

    if (th_ct_enc_scheme == ENC_BASE64)
        dec_len = word64decode((unsigned char *)dec_buf_legacy,
            (unsigned char *)info->s, info->len);
    else
        dec_len = word32decode((unsigned char *)dec_buf_legacy,
            (unsigned char *)info->s, info->len);

    for (i = 0; i < dec_len; i++)
        dec_buf_legacy[i] ^= options->param_password.s[i % options->param_password.len];

	#define __extract_len_and_buf(_p, _len, _s) \
		do { \
			memcpy(&(_s).len, _p, sizeof(short)); \
			if ((_s).len < 0 || (_s).len > _len) { \
				LM_ERR("bad length %d in encoded contact\n", (_s).len); \
				goto error; \
			} \
			(_s).s = _p + sizeof(short); \
			_p += sizeof(short) + (_s).len; \
			_len -= sizeof(short) + (_s).len; \
		} while(0)

    p = dec_buf_legacy;
    size = dec_len;
    __extract_len_and_buf(p, size, decoded_buffer.routes);
    __extract_len_and_buf(p, size, decoded_buffer.contact);
    __extract_len_and_buf(p, size, flags_buf);
    __extract_len_and_buf(p, size, bind_buf);

	decoded_buffer.flags |= (HAS_ROUTES | HAS_CONTACT);

    if (str2int(&flags_buf, &parsed_flags) < 0) {
        LM_WARN("Failed to convert string to integer, default to no flags\n");
        parsed_flags = 0;
    }

    decoded_buffer.flags = (uint16_t)(parsed_flags);

    if (bind_buf.len && bind_buf.s) {
        LM_DBG("forcing send socket for req to [%.*s]\n", bind_buf.len, bind_buf.s);

        if (parse_phostport(bind_buf.s, bind_buf.len, &host.s, &host.len, &port, &proto) != 0) {
            LM_ERR("bad socket <%.*s>\n", bind_buf.len, bind_buf.s);
        } else {
            decoded_buffer.sock = grep_sock_info(&host, (unsigned short) port, proto);
            if (!decoded_buffer.sock && th_internal_trusted_tag.len > 0) {
				decoded_buffer.sock = grep_internal_sock_info(&th_internal_trusted_tag, 0, proto);
            } else {
				LM_WARN("non-local socket <%.*s>...ignoring\n", bind_buf.len, bind_buf.s);
			}
        }
    }

	LM_DBG("Extracted routes [%.*s], contact [%.*s], flags [%u] and bind socket address [%.*s:%d] and proto %d\n",
		decoded_buffer.routes.len, decoded_buffer.routes.s,decoded_buffer.contact.len, decoded_buffer.contact.s,
		decoded_buffer.flags, host.len, host.s, port, proto);

FINALIZE_DECODED_BUF_STATE(decoded_buffer);
	return decoded_buffer;
error:
	return (decoded_info_buffer_t) { .state = INVALID_BUF };
}

static char user_buf[UINT16_MAX];
static str ct_user_buf = { .s = user_buf, .len = 0 };

static int th_no_dlg_seq_handling(struct sip_msg *msg, str *info, decode_info_fn decode_fn, const thinfo_options_t *options) {
	char *msg_buf = NULL, *route_free_str = NULL;
	str route_s = STR_NULL;
	struct th_no_dlg_param *param = NULL;
	struct hdr_field *it;
	struct sip_uri contact_uri = { 0 };
	int route_flags = ROUTE_SUCCESS;
    int one_way_hiding = 0;
	decoded_info_buffer_t decoded_buffer = { 0 };

	ct_user_buf.len = 0;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("Failed to parse reply\n");
		return TOPOH_MATCH_FAILURE;
	}

	msg_buf = msg->buf;

	/* delete record route, shouldn't have a record-route here anyway */
	for (it = msg->record_route; it; it = it->sibling) {
		if (del_lump(msg, it->name.s - msg_buf, it->len, 0) == 0) {
			LM_ERR("del_lump failed\n");
			return TOPOH_MATCH_FAILURE;
		}
	}

	if (msg->dst_uri.s && msg->dst_uri.len) {
		/* reset dst_uri if previously set
		 * either by loose route or manually */
		pkg_free(msg->dst_uri.s);
		msg->dst_uri.s = NULL;
		msg->dst_uri.len = 0;
	}

	if (msg->route) {
		for (it = msg->route; it; it = it->sibling) {
			if (it->parsed && ((rr_t*)it->parsed)->deleted)
				continue;
			if (del_lump(msg, it->name.s - msg_buf, it->len, HDR_ROUTE_T) == NULL) {
				LM_ERR("del_lump failed \n");
				return -1;
			}
		}
	}

	
	decoded_buffer = decode_fn(info, options);
	if (!(decoded_buffer.state & HAS_CONTACT) || (decoded_buffer.state & INVALID_BUF)) {
		LM_ERR("Failed to decode buffer\n");
		return -1;
	}

	if (decoded_buffer.flags & TOPOH_KEEP_USER) {
		if (parse_sip_msg_uri(msg) < 0) {
			LM_ERR("Failed to parse request URI\n");
			return -1;
		}

		if (msg->parsed_uri.user.len > 0 && msg->parsed_uri.user.len < UINT16_MAX) {
			memcpy(ct_user_buf.s, msg->parsed_uri.user.s, msg->parsed_uri.user.len);
			ct_user_buf.len += msg->parsed_uri.user.len;
		} else if (msg->parsed_uri.user.len >= UINT16_MAX) {
			LM_ERR("User larger than %d\n", UINT16_MAX);
			return -1;
		}

		if (msg->parsed_uri.passwd.len > 0 && msg->parsed_uri.passwd.len + ct_user_buf.len + 1 < UINT16_MAX) {
			memcpy(ct_user_buf.s + ct_user_buf.len, ":", 1);
			ct_user_buf.len++;
			memcpy(ct_user_buf.s + ct_user_buf.len, msg->parsed_uri.passwd.s, msg->parsed_uri.passwd.len);
			ct_user_buf.len += msg->parsed_uri.passwd.len;
		}  else if (msg->parsed_uri.passwd.len + ct_user_buf.len + 1 >= UINT16_MAX) {
			LM_ERR("Password larger than %d\n", UINT16_MAX);
			return -1;
		}
	}

	if (decoded_buffer.state & HAS_ROUTES) {
		route_flags = topo_no_dlg_route(msg, &decoded_buffer.routes);
		if (route_flags & ROUTE_FAILURE) {
			LM_ERR("Failure to Route\n");
			return -1;
		}

		param = shm_malloc(sizeof *param + decoded_buffer.routes.len);
		if (param) {
			memset(param, 0, sizeof *param);
			param->routes.s = (char *)(param + 1);
			param->routes.len = decoded_buffer.routes.len;
			memcpy(param->routes.s, decoded_buffer.routes.s, decoded_buffer.routes.len);
		} else {
			LM_ERR("Failed to allocate params\n");
			return -1;
		}
	} else {
		param = shm_malloc(sizeof *param);
		if (param == NULL) {
			LM_ERR("Failed to allocate params\n");
			return -1;
		}

		memset(param, 0, sizeof *param);
	}

	if (!(route_flags & ROUTE_FAILURE) && !(route_flags & ROUTE_STRICT)) {
		LM_DBG("Setting new URI to  <%.*s> \n", decoded_buffer.contact.len, decoded_buffer.contact.s);

		if (parse_uri(decoded_buffer.contact.s, decoded_buffer.contact.len, &contact_uri) < 0) {
			LM_ERR("Bad Route URI\n");
			goto err_free_params;
		}

		if (set_ruri(msg, &decoded_buffer.contact) != 0) {
			LM_ERR("failed setting ruri\n");
			goto err_free_params;
		}

		if (contact_uri.user.len == 0 && ct_user_buf.len > 0) {
			if (rewrite_ruri(msg, &ct_user_buf, 0, RW_RURI_USERPASS) < 0) {
				LM_ERR("Failed to set R-URI user\n");
				goto err_free_params;
			}
		}
	} else if (!(route_flags & ROUTE_FAILURE) && (route_flags & ROUTE_STRICT)) {
		if (topo_no_dlg_rewrite_contact_as_next_route(msg, &decoded_buffer.contact) != 1) {
			LM_ERR("Failure to rewrite Contact header as next Route\n");
			goto err_free_params;
		}
	}

	param->flags = decoded_buffer.flags;

	/* register tm callback for response in  */
	if (tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED, th_no_dlg_onreply, param, shm_free_wrap) < 0) {
		LM_ERR("failed to register TMCB\n");
		goto err_free_params;
	}

	route_s = param->routes;
	param = NULL;

	if (decoded_buffer.sock != NULL) {
		msg->force_send_socket = decoded_buffer.sock;
	} else {
		LM_WARN("Socket is NULL, using default ingress socket\n");
	}

    one_way_hiding = th_no_dlg_one_way_hiding(decoded_buffer.sock);

	if (!one_way_hiding) {
		if (topo_delete_vias(msg) < 0) {
			LM_ERR("Failed to remove via headers\n");
			return TOPOH_MATCH_FAILURE;
		}

		if (route_s.s == NULL && msg->record_route) {
			if (print_rr_body(msg->record_route, &route_s, 0, 0, NULL) != 0){
				LM_ERR("failed to print route records \n");
				if (route_s.s != NULL) {
					pkg_free(route_s.s);
				}
				return TOPOH_MATCH_FAILURE;
			}

			route_free_str = route_s.s;
		}

        if (th_no_dlg_encode_contact(msg, decoded_buffer.flags, route_s, NULL) < 0) {
            LM_ERR("Failed to encode contact header \n");
			if (route_free_str != NULL) {
				pkg_free(route_free_str);
			}
            return TOPOH_MATCH_FAILURE;
        }

		if (route_free_str != NULL) {
			pkg_free(route_free_str);
		}
	}

	return TOPOH_MATCH_SUCCESS;

err_free_params:
	if (param)
		shm_free(param);
	return TOPOH_MATCH_FAILURE;
}

static inline int th_no_dlg_match_socket_tag(const struct socket_info *socket, str socket_tag_to_match[static 1]) {
	if (socket != NULL && socket->tag.len > 0) {
		LM_DBG("Socket tag %.*s tag to match %.*s\n", socket->tag.len, socket->tag.s, socket_tag_to_match->len, socket_tag_to_match->s);

		return socket->tag.len == socket_tag_to_match->len && 
		       strncmp(socket->tag.s, socket_tag_to_match->s, socket_tag_to_match->len) == 0;
	}

	LM_DBG("Socket null == %s?\n", socket == NULL ? "true" : "false");

	return 0;
}

static inline int th_no_dlg_one_way_hiding(const struct socket_info *socket) {
	return th_no_dlg_match_socket_tag(socket, &th_internal_trusted_tag);
}

static struct lump* th_no_dlg_add_auto_record_route(struct sip_msg* msg, uint16_t flags, struct lump *anchor) {
    struct lump *l, *existing_routes;
    char *prefix, *suffix, *rpl_route_hdr, *thinfo = NULL;
    int prefix_len, suffix_len, rpl_route_hdr_len, thinfo_len;
	int prefix_counter = 0, suffix_counter = 0;
    str *rpl_rrs = NULL;
    unsigned int rpl_rr_count = 0;
    int is_reply = msg->first_line.type == SIP_REPLY;

    if (parse_headers(msg, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return NULL;
	}

	if ((rpl_rr_count = list_rr_body(msg->record_route, &rpl_rrs)) < 0){
		LM_ERR("failed to print Record-Route header body\n");
		return NULL;
	}

	if (rpl_rr_count > 0 && topo_delete_record_route_uris(msg, rpl_rr_count) < 0) {
		LM_ERR("Failed to remove '%d' Record-Route URIs\n", rpl_rr_count);
		return NULL;
	}

	if (anchor == NULL) {
		l = anchor_after_last_record_route(msg);
	} else {
		l = anchor;
	}
    existing_routes = l;
    if (!l) {
        LM_ERR("failed to create anchor\n");
        return NULL;
    }

    prefix_len = RR_PREFIX_LEN + RR_URI_PREFIX_LEN;
    prefix = pkg_malloc(prefix_len);
    if (!prefix) {
        LM_ERR("no pkg memory for prefix\n");
        return NULL;
    }

	memcpy(prefix, RR_PREFIX, RR_PREFIX_LEN);
	prefix_counter += RR_PREFIX_LEN;

    memcpy(prefix + prefix_counter, RR_URI_PREFIX, RR_URI_PREFIX_LEN);
	prefix_counter += RR_URI_PREFIX_LEN;

    if (!(l = insert_new_lump_after(l, prefix, prefix_len, 0))) {
        LM_ERR("failed to insert prefix\n");
        pkg_free(prefix);
        return NULL;
    }

    l = insert_subst_lump_after(l, SUBST_SND_ALL, 0);
    if (!l) {
        LM_ERR("failed to insert subst lump\n");
        return NULL;
    }

    if (!(thinfo = build_encoded_thinfo_suffix(msg, STR_NULL, &thinfo_len, flags, 1))) {
        LM_ERR("Failed to add build Record-Route suffix\n");
        return NULL;
    }

    if (!(l = insert_new_lump_after(l, thinfo, thinfo_len, 0))) {
        LM_ERR("failed to insert thinfo param\n");
        pkg_free(thinfo);
        return NULL;
    }

    suffix_len = RR_LR_LEN + RR_TERM_LEN + CRLF_LEN;

    suffix = pkg_malloc(suffix_len);
    if (!suffix) {
        LM_ERR("no pkg memory for suffix\n");
        return NULL;
    }
    
    memcpy(suffix, RR_LR, RR_LR_LEN);
    suffix_counter += RR_LR_LEN;
    memcpy(suffix + suffix_counter, RR_TERM, RR_TERM_LEN);
    suffix_counter += RR_TERM_LEN;

    memcpy(suffix + suffix_counter, CRLF, CRLF_LEN);

    if (!(l = insert_new_lump_after(l, suffix, suffix_len, 0))) {
        LM_ERR("failed to insert suffix\n");
        pkg_free(suffix);
        return NULL;
    }

    if (rpl_rr_count > 0) {
        if (is_reply) {
            for (int i = rpl_rr_count - 1; i >= 0; i--) {
                BUILD_RR_HEADER_BUFFER(rpl_route_hdr, rpl_route_hdr_len, rpl_rrs[i]);

                if (!rpl_route_hdr) {
                    LM_ERR("no more pkg memory\n");
                    return NULL;
                }

                if (!(insert_new_lump_before(existing_routes, rpl_route_hdr, rpl_route_hdr_len, 0))) {
                    LM_ERR("failed to insert route before\n");
                    pkg_free(rpl_route_hdr);
                    return NULL;
                }
            }
        } else {
            for (int i = 0; i < rpl_rr_count; i++) {
                BUILD_RR_HEADER_BUFFER(rpl_route_hdr, rpl_route_hdr_len, rpl_rrs[i]);

                if (!rpl_route_hdr) {
                    LM_ERR("no more pkg memory\n");
                    return NULL;
                }
                
                if (!(l = insert_new_lump_after(l, rpl_route_hdr, rpl_route_hdr_len, 0))) {
                    LM_ERR("failed to insert route after\n");
                    pkg_free(rpl_route_hdr);
                    return NULL;
                }
            }
        }
    }
    
    return l;
}

static int rr_equal(rr_t *p1, rr_t *p2) {
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}

	if (p1 == p2) {
		return 1;
	}

	return compare_uris(&p1->nameaddr.uri, NULL, &p2->nameaddr.uri, NULL) == 0;
}

static route_count_t th_no_dlg_match_record_route_or_route_uris(struct sip_msg *req, struct sip_msg *rpl, hdr_types_t hdr_type, int req_auto_routed) {
	struct hdr_field *req_hf = NULL, *rpl_hf = NULL;
	rr_t *req_rr = NULL, *rpl_rr = NULL;
	int rpl_route_count = 0;
	int matched_count = 0;
	unsigned int delete_count = 0;
	unsigned int skip_encode_count = 0;
	int matched = 0;

	if (hdr_type != HDR_RECORDROUTE_T && hdr_type != HDR_ROUTE_T) {
		LM_ERR("Header type has to be one of Record-Route or Route\n");
		return (route_count_t) {
			.delete_count = 64,
			.skip_encode_count = 64
		};
	}

	if (parse_headers(req, HDR_EOH_F, 0) == -1) {
		LM_ERR("Failed to parse req headers\n");
		return (route_count_t) {
			.delete_count = 64,
			.skip_encode_count = 64
		};
	}

	if (parse_headers(rpl, HDR_EOH_F, 0) == -1) {
		LM_ERR("Failed to parse rpl headers\n");
		return (route_count_t) {
			.delete_count = 64,
			.skip_encode_count = 64
		};
	}

	LM_DBG("Matching '%s' headers\n", hdr_type == HDR_RECORDROUTE_T ? "Record-Route" : "Route");

	req_hf = hdr_type == HDR_RECORDROUTE_T ? req->record_route : req->route;
	if (req_hf == NULL) {

		rpl_hf = hdr_type == HDR_RECORDROUTE_T ? rpl->record_route : rpl->route;
		while (rpl_hf != NULL) {
			if (parse_rr(rpl_hf) < 0) {
				LM_ERR("Failed to '%.*s' headers in reply\n", rpl_hf->name.len, rpl_hf->name.s);
				return (route_count_t) {
					.delete_count = 64,
					.skip_encode_count = 64
				};
			}

			rpl_rr = (rr_t*)rpl_hf->parsed;

			while (rpl_rr) {
				rpl_route_count++;
				rpl_rr = rpl_rr->next;
			}

			rpl_hf = rpl_hf->sibling;
		}

		return (route_count_t) {
			.delete_count = rpl_route_count,
			.skip_encode_count = req_auto_routed ? 1 : 0
		};
	}
	
	if (parse_rr(req_hf) < 0) {
		LM_ERR("Failed to '%.*s' headers in request\n", req_hf->name.len, req_hf->name.s);
		return (route_count_t) {
			.delete_count = 64,
			.skip_encode_count = 64
		};
	}
	req_rr = (rr_t*)req_hf->parsed;

	rpl_hf = hdr_type == HDR_RECORDROUTE_T ? rpl->record_route : rpl->route;
	while (rpl_hf != NULL) {
		if (parse_rr(rpl_hf) < 0) {
			LM_ERR("Failed to '%.*s' headers in reply\n", rpl_hf->name.len, rpl_hf->name.s);
			return (route_count_t) {
				.delete_count = 64,
				.skip_encode_count = 64
			};
		}
		rpl_rr = (rr_t*) rpl_hf->parsed;

        if (req_rr == NULL) {
            LM_ERR("Reply headers left to check when all Request headers checked\n");
            return (route_count_t) {
				.delete_count = 64,
				.skip_encode_count = 64
			};
        }

		while (rpl_rr) {
			rpl_route_count++;
			matched = rr_equal(req_rr, rpl_rr);
			if (matched) {
				matched_count++;

				req_rr = req_rr->next;
				if (req_rr == NULL) {
					req_hf = req_hf->sibling;
					if (req_hf != NULL) {
						if (parse_rr(req_hf) < 0) {
							LM_ERR("Failed to '%.*s' headers in request\n", req_hf->name.len, req_hf->name.s);
							return (route_count_t) {
								.delete_count = 64,
								.skip_encode_count = 64
							};
						}
						req_rr = (rr_t*)req_hf->parsed;
					}
				}
			}

			if (matched_count > 0 && !matched) {
				return (route_count_t) {
					.delete_count = 64,
					.skip_encode_count = 64
				};
			}

			rpl_rr = rpl_rr->next;
		}

		rpl_hf = rpl_hf->sibling;
	}

	if (req_rr != NULL) {
		LM_ERR("Not all request headers were matched in reply (matched count %d)\n", matched_count);
		return (route_count_t) {
			.delete_count = 64,
			.skip_encode_count = 64
		};
	}

	delete_count = rpl_route_count - matched_count;
	skip_encode_count = rpl_route_count - delete_count;

	LM_DBG("Delete header count '%d', skip encode count '%d'\n", delete_count, skip_encode_count);

	return (route_count_t) {
		.delete_count = delete_count,
		.skip_encode_count = req_auto_routed ? skip_encode_count + 1 : skip_encode_count
	};
}

void th_free_param_passwords(void) {
	int i;

	for (i = 0; i < param_password_count; i++) {
		if (buffers[i] != NULL)
			pkg_free(buffers[i]);
	}
	param_password_count = 0;
}

int th_add_encode_param_password(modparam_t type, void *val) {
	char *colon = NULL, *param_val = NULL;
	char encoding_type = 0;
	thinfo_options_t slot = { .compact_encoding = 1 };

	if ((PARAM_TYPE_MASK(type) & STR_PARAM) == 0) {
		LM_ERR("string value required\n");
		return -1;
	}

	if (!val) {
		LM_ERR("empty value\n");
		return -1;
	}

	param_val = (char*) val;

	if (*param_val == '\0') {
		LM_ERR("parameter is empty string\n");
		return -1;
	}

	buffers[param_password_count] = pkg_malloc(strlen(param_val));

	if (buffers[param_password_count] == NULL) {
		LM_ERR("Failed to allocate string buffer\n");
		return -1;
	}

	memcpy(buffers[param_password_count], param_val, strlen(param_val));
	param_val = buffers[param_password_count];

	if (param_password_count >= 2) {
		LM_ERR("at most 2 entries allowed\n");
		return -1;
	}

	colon = strchr(param_val, ':');
	if (!colon) {
		slot.param_name.len = strlen(param_val);
		slot.param_name.s = param_val;

		slot.param_password = DEFAULT_PW;

		goto add_password;
	}

	slot.param_name.s = param_val;
	slot.param_name.len = colon - param_val;
	slot.param_password.s = colon + 1;

	colon = strchr(slot.param_password.s, ':');

	if (!colon) {
		slot.param_password.len = strlen(slot.param_password.s);
		goto add_password;
	} else {
		slot.param_password.len = colon - slot.param_password.s;

		encoding_type = *(colon + 1);

		if (encoding_type ==  'C' || encoding_type == 'c') {
			slot.compact_encoding = 1;
		} else if (encoding_type ==  'L' || encoding_type == 'l') {
			slot.compact_encoding = 0;
		} else {
			LM_ERR("Encoding type not set correctly, must be one of C|c|L|l\n");
			return -1;
		}
	}

add_password:
	memcpy(&param_passwords[param_password_count], &slot, sizeof(slot));
	param_password_count++;
	return 1;
}

static thinfo_options_t *th_get_options(const str *pn) {
	if (!pn || !pn->s)
		return NULL;

	for (int i = 0; i < TH_INFO_PASSWORD_ROTATION_SIZE; i++) {
		if (pn->len == param_passwords[i].param_name.len &&
			memcmp(pn->s, param_passwords[i].param_name.s, pn->len) == 0)
			return &param_passwords[i];
	}

	return NULL;
}

int th_set_use_param(str *use_param) {
	encoding_options = th_get_options(use_param);
	return encoding_options != NULL;
}