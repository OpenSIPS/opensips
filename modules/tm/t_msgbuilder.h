/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2004-02-11  FIFO/CANCEL + alignments (hash=f(callid,cseq)) (uli+jiri)
 */


#ifndef _MSGBUILDER_H
#define _MSGBUILDER_H

#include "../../ip_addr.h"
#include "../../receive.h"
#include "dlg.h"


#define CSEQ "CSeq: "
#define CSEQ_LEN (sizeof(CSEQ)-1)
#define TO "To: "
#define TO_LEN (sizeof(TO)-1)
#define CALLID "Call-ID: "
#define CALLID_LEN (sizeof(CALLID)-1)
#define FROM "From: "
#define FROM_LEN (sizeof(FROM)-1)
#define FROMTAG ";tag="
#define FROMTAG_LEN (sizeof(FROMTAG)-1)
#define TOTAG ";tag="
#define TOTAG_LEN (sizeof(TOTAG)-1)
#define LOCAL_MAXFWD_VALUE "70"

char *build_local(struct cell *Trans, unsigned int branch,
	str *method, str *extra, struct sip_msg *rpl, unsigned int *len);

char *build_uac_request(  str msg_type, str dst, str from,
	str fromtag, int cseq, str callid, str headers,
	str body, int branch,
	struct cell *t, unsigned int *len);

/*
 * The function creates an ACK to 200 OK. Route set will be created
 * and parsed. The function is used by tm when it generates
 * local ACK to 200 OK (on behalf of applications using uac
 */
char *build_dlg_ack(struct sip_msg* rpl, struct cell *Trans, unsigned int branch,
		str* to, unsigned int *len);


/*
 * Create a request
 */
char* build_uac_req(str* method, str* headers, str* body, dlg_t* dialog,
		int branch, struct cell *t, int* len);


int t_calc_branch(struct cell *t,
	int b, char *branch, int *branch_len);

/* exported minimum functions for use in t_cancel */
char* print_callid_mini(char* target, str callid);
char* print_cseq_mini(char* target, str* cseq, str* method);


static inline struct sip_msg* buf_to_sip_msg(char *buf, unsigned int len,
															dlg_t *dialog)
{
	static struct sip_msg req;

	memset( &req, 0, sizeof(req) );
	req.id = get_next_msg_no();
	req.buf = buf;
	req.len = len;
	if (parse_msg(buf, len, &req)!=0) {
		LM_CRIT("BUG - buffer parsing failed!");
		return NULL;
	}
	/* parse all headers, to be sure they get cloned in shm */
	if (parse_headers(&req, HDR_EOH_F, 0 )<0) {
		LM_ERR("parse_headers failed\n");
		free_sip_msg(&req);
		return NULL;
	}
	/* check if we have all necessary headers */
	if (check_transaction_quadruple(&req)==0) {
		LM_ERR("too few headers\n");
		free_sip_msg(&req);
		/* stop processing */
		return NULL;
	}

	/* populate some special fields in sip_msg */
	req.force_send_socket = dialog->send_sock;
	if (set_dst_uri(&req, dialog->hooks.next_hop)) {
		LM_ERR("failed to set dst_uri");
		free_sip_msg(&req);
		return NULL;
	}
	req.rcv.proto = dialog->send_sock->proto;
	req.rcv.src_ip = req.rcv.dst_ip = dialog->send_sock->address;
	req.rcv.src_port = req.rcv.dst_port = dialog->send_sock->port_no;
	req.rcv.bind_address = dialog->send_sock;

	return &req;
}

#endif
