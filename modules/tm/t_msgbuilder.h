/*
 * Copyright (C) 2010-2014 OpenSIPS Solutions
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
 * History:
 * --------
 *  2004-02-11  FIFO/CANCEL + alignments (hash=f(callid,cseq)) (uli+jiri)
 */


#ifndef _MSGBUILDER_H
#define _MSGBUILDER_H

#include "../../ip_addr.h"
#include "../../receive.h"
#include "../../dset.h"
#include "../../msg_callbacks.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
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
		LM_ERR("failed to set dst_uri\n");
		free_sip_msg(&req);
		return NULL;
	}
	req.rcv.proto = dialog->send_sock->proto;
	req.rcv.src_ip = req.rcv.dst_ip = dialog->send_sock->address;
	req.rcv.src_port = req.rcv.dst_port = dialog->send_sock->port_no;
	req.rcv.bind_address = dialog->send_sock;

	return &req;
}


static inline int fake_req(struct sip_msg *faked_req, struct sip_msg *shm_msg,
		struct ua_server *uas, struct ua_client *uac, int with_dst)
{
	/* on_negative_reply faked msg now copied from shmem msg (as opposed
	 * to zero-ing) -- more "read-only" actions (exec in particular) will
	 * work from reply_route as they will see msg->from, etc.; caution,
	 * rw actions may append some pkg stuff to msg, which will possibly be
	 * never released (shmem is released in a single block) */
	memcpy( faked_req, shm_msg, sizeof(struct sip_msg));

	/* if we set msg_id to something different from current's message
	 * id, the first t_fork will properly clean new branch URIs */
	faked_req->id = get_next_msg_no();
	/* msg->parsed_uri_ok must be reset since msg_parsed_uri is
	 * not cloned (and cannot be cloned) */
	faked_req->parsed_uri_ok = 0;

	faked_req->msg_flags |= FL_TM_FAKE_REQ;

	/* new_uri can change -- make a private copy */
	faked_req->new_uri.s=pkg_malloc( uac->uri.len+1 );
	if (!faked_req->new_uri.s) {
		LM_ERR("no uri/pkg mem\n");
		return 0;
	}
	faked_req->new_uri.len = uac->uri.len;
	memcpy( faked_req->new_uri.s, uac->uri.s, uac->uri.len);
	faked_req->new_uri.s[faked_req->new_uri.len]=0;
	faked_req->parsed_uri_ok = 0;

	/* duplicate the dst_uri, advertised address and port into private mem
	 * so that they can be changed at script level */
	if (with_dst) {
		if (shm_msg->dst_uri.s) {
			faked_req->dst_uri.s = pkg_malloc(shm_msg->dst_uri.len);
			if (!faked_req->dst_uri.s) {
				LM_ERR("out of pkg mem\n");
				goto out;
			}
			memcpy(faked_req->dst_uri.s, shm_msg->dst_uri.s,
				shm_msg->dst_uri.len);
		}
	} else {
		faked_req->dst_uri.s = NULL;
		faked_req->dst_uri.len = 0;
	}

	if (shm_msg->set_global_address.s) {
		faked_req->set_global_address.s = pkg_malloc
			(shm_msg->set_global_address.len);
		if (!faked_req->set_global_address.s) {
			LM_ERR("out of pkg mem\n");
			goto out;
		}
		memcpy(faked_req->set_global_address.s, shm_msg->set_global_address.s,
			shm_msg->set_global_address.len);
	}

	if (shm_msg->set_global_port.s) {
		faked_req->set_global_port.s=pkg_malloc(shm_msg->set_global_port.len);
		if (!faked_req->set_global_port.s) {
			LM_ERR("out of pkg mem\n");
			goto out1;
		}
		memcpy(faked_req->set_global_port.s, shm_msg->set_global_port.s,
			shm_msg->set_global_port.len);
	}

	if (shm_msg->path_vec.s) {
		faked_req->path_vec.s = pkg_malloc(shm_msg->path_vec.len);
		if (!faked_req->path_vec.s) {
			LM_ERR("out of pkg mem\n");
			goto out2;
		}
		memcpy(faked_req->path_vec.s, shm_msg->path_vec.s,
			   shm_msg->path_vec.len);
	}

	if (clone_sip_msg_body( shm_msg, faked_req, &faked_req->body, 0)!=0) {
		LM_ERR("out of pkg mem - cannot clone body\n");
		goto out3;
	}

	/* set as flags the global flags and the branch flags from the
	 * elected branch */
	faked_req->flags = uas->request->flags;
	setb0flags( faked_req, uac->br_flags);

	return 1;
out3:
	pkg_free(faked_req->path_vec.s);
out2:
	pkg_free(faked_req->set_global_port.s);
out1:
	pkg_free(faked_req->set_global_address.s);
out:
	pkg_free(faked_req->new_uri.s);

	return 0;
}


inline static void free_faked_req(struct sip_msg *faked_req, struct cell *t)
{
	if (faked_req->new_uri.s) {
		pkg_free(faked_req->new_uri.s);
		faked_req->new_uri.s = NULL;
	}
	if (faked_req->dst_uri.s) {
		pkg_free(faked_req->dst_uri.s);
		faked_req->dst_uri.s = NULL;
	}
	if (faked_req->path_vec.s) {
		pkg_free(faked_req->path_vec.s);
		faked_req->path_vec.s = NULL;
	}
	if (faked_req->set_global_address.s) {
		pkg_free(faked_req->set_global_address.s);
		faked_req->set_global_address.s = NULL;
	}
	if (faked_req->set_global_port.s) {
		pkg_free(faked_req->set_global_port.s);
		faked_req->set_global_port.s = NULL;
	}

	/* clean the pkg copy of the body */
	if (faked_req->body) {
		free_sip_body(faked_req->body);
		faked_req->body = NULL;
	}

	if (faked_req->msg_cb) {
		msg_callback_process(faked_req, MSG_DESTROY, NULL);
	}

	/* free all types of lump that were added in failure handlers */
	del_notflaged_lumps( &(faked_req->add_rm), LUMPFLAG_SHMEM );
	del_notflaged_lumps( &(faked_req->body_lumps), LUMPFLAG_SHMEM );
	del_nonshm_lump_rpl( &(faked_req->reply_lump) );

	if (faked_req->add_rm && faked_req->add_rm != t->uas.request->add_rm)
		shm_free(faked_req->add_rm);
	if (faked_req->body_lumps
	&& faked_req->body_lumps != t->uas.request->body_lumps)
		shm_free(faked_req->body_lumps);
	if (faked_req->reply_lump
	&& faked_req->reply_lump != t->uas.request->reply_lump)
		shm_free(faked_req->reply_lump);

	clean_msg_clone( faked_req, t->uas.request, t->uas.end_request);
}


#endif
