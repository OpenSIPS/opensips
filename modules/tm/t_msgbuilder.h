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
#include "../../parser/contact/parse_contact.h"
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
	struct sip_msg *req;

	req = (struct sip_msg*)pkg_malloc( sizeof(struct sip_msg));
	if (req==NULL) {
		LM_ERR("no more pkg mem, needed %zu\n",sizeof(struct sip_msg));
		return NULL;
	}
	memset( req, 0, sizeof(struct sip_msg) );
	req->id = get_next_msg_no();
	req->buf = buf;
	req->len = len;
	if (parse_msg(buf, len, req)!=0) {
		LM_CRIT("BUG - buffer parsing failed!\n");
		goto error;
	}
	/* parse all headers, to be sure they get cloned in shm */
	if (parse_headers(req, HDR_EOH_F, 0 )<0) {
		LM_ERR("parse_headers failed\n");
		goto error1;
	}
	/* check if we have all necessary headers */
	if (check_transaction_quadruple(req)==0) {
		LM_ERR("too few headers\n");
		/* stop processing */
		goto error1;
	}

	/* populate some special fields in sip_msg */
	req->force_send_socket = dialog->send_sock;
	if (set_dst_uri(req, dialog->hooks.next_hop)) {
		LM_ERR("failed to set dst_uri\n");
		goto error1;
	}
	req->rcv.proto = dialog->send_sock->proto;
	req->rcv.src_ip = req->rcv.dst_ip = dialog->send_sock->address;
	req->rcv.src_port = req->rcv.dst_port = dialog->send_sock->port_no;
	req->rcv.bind_address = dialog->send_sock;

	return req;

error1:
	free_sip_msg(req);
error:
	pkg_free(req);
	return NULL;
}

static inline int fix_fake_req_headers(struct sip_msg *req)
{
	struct hdr_field *hdr;
	struct lump *ld, *la;
	contact_t *c;

	if (clone_headers(req, req) < 0) {
		LM_ERR("could not clone headers list!\n");
		return -1;
	}
	/*
	 * the fix_nated_contact() function in the nathelper module changes the
	 * contact to point to a buffer stored in a lump; the following code
	 * restores the pointer so that functions that use the contact header body
	 * to see the "fixed" contact, rather than the original header
	 */
	for (hdr = req->contact; hdr; hdr = hdr->sibling) {

		/* not something critical right now, so we can pass the error */
		if (parse_contact(hdr) < 0 || !hdr->parsed)
			continue;

		for (c = ((contact_body_t *)hdr->parsed)->contacts; c; c = c->next) {
			/* search for the lump */
			for (ld = req->add_rm; ld; ld = ld->next) {
				if (ld->op != LUMP_DEL)
					continue;
				for (la = ld->after; la; la = la->after) {
					/* LM_DBG("matching contact lump op=%d type=%d offset=%d"
							"len = %d c.offset=%d c.len=%d\n", la->op,
							la->type, ld->u.offset, ld->len,
							(int)(c->uri.s-req->buf), c->uri.len); */
					if (la->op == LUMP_ADD && la->type == HDR_CONTACT_T &&
							ld->u.offset == c->uri.s-req->buf &&
							ld->len == c->uri.len) {
						/* if enclosed, skip enclosing */
						if (la->u.value[0] == '<') {
							c->uri.s = la->u.value + 1;
							c->uri.len = la->len - 2;
						} else {
							c->uri.s = la->u.value;
							c->uri.len = la->len;
						}
						LM_DBG("buffer found <%.*s>\n", c->uri.len, c->uri.s);
						goto next_contact;
					}
				}
			}
next_contact:
			;
		}
	}
	return 0;
}


static inline int fake_req(struct sip_msg *faked_req, struct sip_msg *shm_msg,
								struct ua_server *uas, struct ua_client *uac)
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

	if (uac) {

		/* duplicate some values into private mem
		 * so that they can be visible and changed at script level */
		/* RURI / new URI */
		faked_req->new_uri.s=pkg_malloc( uac->uri.len+1 );
		if (!faked_req->new_uri.s) {
			LM_ERR("no uri/pkg mem\n");
			goto out0;
		}
		faked_req->new_uri.len = uac->uri.len;
		memcpy( faked_req->new_uri.s, uac->uri.s, uac->uri.len);
		faked_req->new_uri.s[faked_req->new_uri.len]=0;

		/* duplicate the dst_uri and path_vec into private mem
		 * so that they can be visible and changed at script level */
		if (uac->duri.s) {
			faked_req->dst_uri.s = pkg_malloc(uac->duri.len);
			if (!faked_req->dst_uri.s) {
				LM_ERR("out of pkg mem\n");
				goto out1;
			}
			memcpy(faked_req->dst_uri.s, uac->duri.s, uac->duri.len);
		} else {
			faked_req->dst_uri.s = NULL;
			faked_req->dst_uri.len = 0;
		}
		if (uac->path_vec.s) {
			faked_req->path_vec.s = pkg_malloc(uac->path_vec.len);
			if (!faked_req->path_vec.s) {
				LM_ERR("out of pkg mem\n");
				goto out2;
			}
			memcpy(faked_req->path_vec.s, uac->path_vec.s, uac->path_vec.len);
		} else {
			faked_req->path_vec.s = NULL;
			faked_req->path_vec.len = 0;
		}

		/* set the branch flags from the elected branch */
		setb0flags( faked_req, uac->br_flags);
		/* Q and force_send_socket values were already copied
		 * as part of the sip_msg struct */

		/* duplicate advertised address and port from UAC into
		 * private mem so that they can be changed at script level */
		if (uac->adv_address.s) {
			faked_req->set_global_address.s = pkg_malloc(uac->adv_address.len);
			if (!faked_req->set_global_address.s) {
				LM_ERR("out of pkg mem\n");
				goto out3;
			}
			memcpy(faked_req->set_global_address.s,
				uac->adv_address.s, uac->adv_address.len);
		} else {
			faked_req->set_global_address.s = NULL;
			faked_req->set_global_address.len = 0;
		}
		if (uac->adv_port.s) {
			faked_req->set_global_port.s=pkg_malloc(uac->adv_port.len);
			if (!faked_req->set_global_port.s) {
				LM_ERR("out of pkg mem\n");
				goto out4;
			}
			memcpy(faked_req->set_global_port.s,
				uac->adv_port.s, uac->adv_port.len);
		} else {
			faked_req->set_global_port.s = NULL;
			faked_req->set_global_port.len = 0;
		}

	} else {

		/* reset new URI value */
		faked_req->new_uri.s = NULL;
		faked_req->new_uri.len = 0;

		/* reset DST URI, PATH vector and Q value */
		faked_req->dst_uri.s = NULL;
		faked_req->dst_uri.len = 0;
		faked_req->path_vec.s = NULL;
		faked_req->path_vec.len = 0;
		faked_req->ruri_q = Q_UNSPECIFIED;

		/* reset force_send_socket and the per-branch flags */
		faked_req->force_send_socket = NULL;
		setb0flags( faked_req, 0);

		/* duplicate advertised address and port from SIP MSG into
		 * private mem so that they can be changed at script level */
		if (shm_msg->set_global_address.s) {
			faked_req->set_global_address.s = pkg_malloc
				(shm_msg->set_global_address.len);
			if (!faked_req->set_global_address.s) {
				LM_ERR("out of pkg mem\n");
				goto out3;
			}
			memcpy(faked_req->set_global_address.s,
				shm_msg->set_global_address.s,
				shm_msg->set_global_address.len);
		}
		if (shm_msg->set_global_port.s) {
			faked_req->set_global_port.s=pkg_malloc
				(shm_msg->set_global_port.len);
			if (!faked_req->set_global_port.s) {
				LM_ERR("out of pkg mem\n");
				goto out4;
			}
			memcpy(faked_req->set_global_port.s, shm_msg->set_global_port.s,
				shm_msg->set_global_port.len);
		}

	}

	if (fix_fake_req_headers(faked_req) < 0) {
		LM_ERR("could not fix request headers!\n");
		goto out5;
	}

	if (clone_sip_msg_body( shm_msg, faked_req, &faked_req->body, 0)!=0) {
		LM_ERR("out of pkg mem - cannot clone body\n");
		goto out6;
	}

	/* set as flags the global flags */
	faked_req->flags = uas->request->flags;

	return 1;

out6:
	if (faked_req->headers)
		pkg_free(faked_req->headers);
out5:
	if (faked_req->set_global_port.s)
		pkg_free(faked_req->set_global_port.s);
out4:
	if (faked_req->set_global_address.s)
		pkg_free(faked_req->set_global_address.s);
out3:
	if (faked_req->path_vec.s)
		pkg_free(faked_req->path_vec.s);
out2:
	if (faked_req->dst_uri.s)
		pkg_free(faked_req->dst_uri.s);
out1:
	if (faked_req->new_uri.s)
		pkg_free(faked_req->new_uri.s);
out0:
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

	/* remove the headers' list */
	if (faked_req->headers) {
		pkg_free(faked_req->headers);
		faked_req->headers = 0;
	}
}


#endif
