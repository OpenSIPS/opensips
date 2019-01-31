/*
 * Copyright (C) 2007 SOMA Networks, Inc.
 * Written by Ovidiu Sas (osas)
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 *
 * History:
 * --------
 * 2007-07-16 initial version (osas)
 */


#include "../../ut.h"
#include "../../dprint.h"
#include "../../mi/mi.h"
#include "qos_handlers.h"
#include "qos_ctx_helpers.h"


int add_mi_sdp_payload_nodes(mi_item_t *payload_item, int index,
						sdp_payload_attr_t* sdp_payload)
{
	if (add_mi_number(payload_item, MI_SSTR("index"), index) < 0)
		return 1;
	
	if (add_mi_string(payload_item, MI_SSTR("rtpmap"), 
		sdp_payload->rtp_payload.s, sdp_payload->rtp_payload.len) < 0)
		return 1;

	if (sdp_payload->rtp_enc.s!=NULL && sdp_payload->rtp_enc.len!=0) {
		if (add_mi_string(payload_item, MI_SSTR("codec"), 
			sdp_payload->rtp_enc.s, sdp_payload->rtp_enc.len) < 0)
			return 1;
	}

	return 0;
}

int add_mi_stream_nodes(mi_item_t *stream_item, int index, sdp_stream_cell_t* stream)
{
	mi_item_t *payload_arr, *payload_item;
	sdp_payload_attr_t* sdp_payload;
	int i;

	if (add_mi_number(stream_item, MI_SSTR("index"), index) < 0)
		return 1;

	if (add_mi_string(stream_item, MI_SSTR("media"),
		stream->media.s, stream->media.len) < 0)
		return 1;

	if (add_mi_string(stream_item, MI_SSTR("IP"),
		stream->ip_addr.s, stream->ip_addr.len) < 0)
		return 1;

	if (add_mi_string(stream_item, MI_SSTR("port"),
		stream->port.s, stream->port.len) < 0)
		return 1;

	if (add_mi_string(stream_item, MI_SSTR("transport"),
		stream->transport.s, stream->transport.len) < 0)
		return 1;

	if (stream->sendrecv_mode.s!=NULL && stream->sendrecv_mode.len!=0) {
		if (add_mi_string(stream_item, MI_SSTR("sendrecv"),
			stream->sendrecv_mode.s, stream->sendrecv_mode.len) < 0)
			return 1;
	}

	if (stream->ptime.s!=NULL && stream->ptime.len!=0) {
		if (add_mi_string(stream_item, MI_SSTR("transport"),
			stream->ptime.s, stream->ptime.len) < 0)
			return 1;
	}

	if (add_mi_number(stream_item, MI_SSTR("payloads_num"),
		stream->payloads_num) < 0)
		return 1;

	payload_arr = add_mi_array(stream_item, MI_SSTR("payload"));
	if (!payload_arr)
		return 1;

	sdp_payload = stream->payload_attr;
	for(i=stream->payloads_num-1;i>=0;i--){
		if (!sdp_payload) {
			LM_ERR("got NULL sdp_payload\n");
			return 1;
		}
		payload_item = add_mi_object(payload_arr, NULL, 0);
		if (!payload_item)
			return 1;

		if (0!=add_mi_sdp_payload_nodes(payload_item, i, sdp_payload)){
			return 1;
		}
		sdp_payload = sdp_payload->next;
	}

	return 0;
}

int add_mi_session_nodes(mi_item_t *sess_item, int index, sdp_session_cell_t* session)
{
	sdp_stream_cell_t* stream;
	int i;

	mi_item_t *streams_arr, *stream_item;

	switch (index) {
		case 0:
			if (add_mi_string(sess_item, MI_SSTR("entity"), MI_SSTR("caller")) < 0)
				return 1;
			break;
		case 1:
			if (add_mi_string(sess_item, MI_SSTR("entity type"), MI_SSTR("callee")) < 0)
				return 1;
			break;
		default:
			return 1;
	}

	if (add_mi_string(sess_item, MI_SSTR("cnt_disp"),
		session->cnt_disp.s, session->cnt_disp.len) < 0)
		return 1;

	if (add_mi_string(sess_item, MI_SSTR("bw_type"),
		session->bw_type.s, session->bw_type.len) < 0)
		return 1;

	if (add_mi_string(sess_item, MI_SSTR("bw_width"),
		session->bw_width.s, session->bw_width.len) < 0)
		return 1;

	if (add_mi_number(sess_item, MI_SSTR("no. streams"), 
		session->streams_num) < 0)
		return 1;

	streams_arr = add_mi_array(sess_item, MI_SSTR("streams"));
	if (!streams_arr)
		return 1;

	stream = session->streams;
	for(i=session->streams_num-1;i>=0;i--){
		if (!stream) {
			LM_ERR("got NULL stream\n");
			return 1;
		}
		stream_item = add_mi_object(streams_arr, NULL, 0);
		if (!stream_item)
			return 1;

		if (0!=add_mi_stream_nodes(stream_item, i, stream)){
			return 1;
		}
		stream = stream->next;
	}

	return 0;
}

int add_mi_sdp_nodes(mi_item_t *item, qos_sdp_t* qos_sdp)
{
	int i;
	sdp_session_cell_t* session;

	mi_item_t *sdp_arr, *sdp_item, *sess_arr, *sess_item;

	if ( qos_sdp->prev != NULL ) LM_ERR("got qos_sdp->prev=%p\n", qos_sdp->prev);

	sdp_arr = add_mi_array(item, MI_SSTR("sdp"));
	if (!sdp_arr)
		return 1;

	while (qos_sdp) {
		sdp_item = add_mi_object(sdp_arr, NULL, 0);
		if (!sdp_item)
			return 1;

		if (add_mi_number(sdp_item, MI_SSTR("m_dir"), qos_sdp->method_dir) < 0)
			return 1;

		if (add_mi_number(sdp_item, MI_SSTR("m_id"), qos_sdp->method_id) < 0)
			return 1;

		if (add_mi_string(sdp_item, MI_SSTR("method"),
			qos_sdp->method.s, qos_sdp->method.len) < 0)
			return 1;

		if (add_mi_string(sdp_item, MI_SSTR("cseq"),
			qos_sdp->cseq.s, qos_sdp->cseq.len) < 0)
			return 1;

		if (add_mi_number(sdp_item, MI_SSTR("negotiation"), qos_sdp->negotiation) < 0)
			return 1;

		sess_arr = add_mi_array(item, MI_SSTR("sessions"));
		if (!sess_arr)
			return 1;

		for (i=1;i>=0;i--){
			session = qos_sdp->sdp_session[i];
			if (session) {
				sess_item = add_mi_object(sess_arr, NULL, 0);
				if (!sess_item)
					return 1;

				if (0 != add_mi_session_nodes(sess_item, i, session))
					return 1;
			}
		}

		qos_sdp = qos_sdp->next;
	}
	return 0;
}

void qos_dialog_mi_context_CB(struct dlg_cell* did, int type, struct dlg_cb_params * params)
{
	mi_item_t *context_item = (mi_item_t *)(params->dlg_data);
	mi_item_t *pend_sdp, *neg_sdp;
	qos_ctx_t* qos_ctx = (qos_ctx_t*)*(params->param);
	qos_sdp_t* qos_sdp;

	qos_sdp = qos_ctx->pending_sdp;
	if (qos_sdp) {
		pend_sdp = add_mi_object(context_item, MI_SSTR("qos_pending_sdp"));
		if (!pend_sdp) {
			LM_ERR("Failed to add MI item\n");
			return;
		}

		if (0 != add_mi_sdp_nodes(pend_sdp, qos_sdp))
			return;
	}


	qos_sdp = qos_ctx->negotiated_sdp;
	if (qos_sdp) {
		neg_sdp = add_mi_object(context_item, MI_SSTR("qos_negotiated_sdp"));
		if (!neg_sdp) {
			LM_ERR("Failed to add MI item\n");
			return;
		}

		if (0 != add_mi_sdp_nodes( neg_sdp, qos_sdp))
			return;
	}


	return;
}

