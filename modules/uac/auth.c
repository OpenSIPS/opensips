/*
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * UAC OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * UAC OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2005-01-31  first version (ramona)
 *  2006-03-02  UAC authentication looks first in AVPs for credential (bogdan)
 */


#include <ctype.h>
#include <string.h>

#include "../../str.h"
#include "../../dprint.h"
#include "../../pvar.h"
#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "../../md5global.h"
#include "../../md5.h"
#include "../../parser/parse_authenticate.h"
#include "../../parser/msg_parser.h"
#include "../tm/tm_load.h"
#include "../uac_auth/uac_auth.h"
#include "../dialog/dlg_load.h"
#include "auth.h"



extern struct tm_binds uac_tmb;
extern uac_auth_api_t uac_auth_api;
extern str rr_uac_cseq_param;
extern struct rr_binds uac_rrb;
extern struct dlg_binds dlg_api;

static inline int apply_urihdr_changes( struct sip_msg *req,
													str *uri, str *hdr)
{
	struct lump* anchor;

	/* add the uri - move it to branch directly FIXME (bogdan)*/
	if (req->new_uri.s)
	{
		pkg_free(req->new_uri.s);
		req->new_uri.len=0;
	}
	req->parsed_uri_ok=0;
	req->new_uri.s = (char*)pkg_malloc(uri->len+1);
	if (req->new_uri.s==0)
	{
		LM_ERR("no more pkg\n");
		goto error;
	}
	memcpy( req->new_uri.s, uri->s, uri->len);
	req->new_uri.s[uri->len]=0;
	req->new_uri.len=uri->len;

	/* add the header */
	if (parse_headers(req, HDR_EOH_F, 0) == -1)
	{
		LM_ERR("failed to parse message\n");
		goto error;
	}

	anchor = anchor_lump(req, req->unparsed - req->buf, 0);
	if (anchor==0)
	{
		LM_ERR("failed to get anchor\n");
		goto error;
	}

	if (insert_new_lump_before(anchor, hdr->s, hdr->len, 0) == 0)
	{
		LM_ERR("faield to insert lump\n");
		goto error;
	}

	return 0;
error:
	pkg_free( hdr->s );
	return -1;
}


int force_master_cseq_change(struct sip_msg *msg, int new_cseq)
{
	int offset,len,olen;
	struct lump *tmp;
	char *obuf;
	str pkg_cseq;

	/* it should be already parsed, but anyhow.... */
	if(parse_headers(msg, HDR_CSEQ_F, 0) <0 ) {
		LM_ERR("failed to parse headers \n");
		return -1;
	}

	obuf = int2str(new_cseq,&olen);
	if (obuf == NULL) {
		LM_ERR("Failed to convert new integer to string \n");
		return -1;
	}

	pkg_cseq.s = pkg_malloc(2+olen+1+REQ_LINE(msg).method.len);
	if (!pkg_cseq.s) {
		LM_ERR("No more pkg mem \n");
		return -1;
	}

	pkg_cseq.s[0] = ':';
	pkg_cseq.s[1] = ' ';
	memcpy(2+pkg_cseq.s,obuf,olen);
	pkg_cseq.len = 2+olen;
	pkg_cseq.s[pkg_cseq.len++] = ' ';
	memcpy(pkg_cseq.s+pkg_cseq.len,REQ_LINE(msg).method.s,REQ_LINE(msg).method.len);
	pkg_cseq.len += REQ_LINE(msg).method.len;

	len = (msg->cseq->body.s + msg->cseq->body.len) - (msg->cseq->name.s + msg->cseq->name.len);
	offset = msg->cseq->name.s + msg->cseq->name.len - msg->buf;

	if ((tmp = del_lump(msg,offset,len,0)) == 0) {
		LM_ERR("failed to remove the existing CSEQ\n");
		pkg_free(pkg_cseq.s);
		return -1;
	}

	if (insert_new_lump_after(tmp,pkg_cseq.s,pkg_cseq.len,0) == 0) {
		LM_ERR("failed to insert new CSEQ\n");
		pkg_free(pkg_cseq.s);
		return -1;
	}

	LM_DBG("Cseq handling - replaced [%.*s] with [%.*s]\n",
		len, msg->buf+offset, pkg_cseq.len, pkg_cseq.s);

	return 0;
}


int apply_cseq_op(struct sip_msg *msg,int val)
{
	int offset,len,olen;
	struct lump *tmp;
	char *buf,*obuf;
	unsigned int cseq_no;
	str pkg_cseq;

	if (!msg) {
		LM_ERR("null pointer provided\n");
		return -1;
	}

	if(parse_headers(msg, HDR_CSEQ_F, 0) <0 ) {
		LM_ERR("failed to parse headers \n");
		return -1;
	}

	if (str2int(&(((struct cseq_body *)msg->cseq->parsed)->number),&cseq_no) < 0) {
		LM_ERR("Failed to convert cseq to integer \n");
		return -1;
	}

	cseq_no=cseq_no+val;
	obuf = int2str(cseq_no,&olen);
	if (obuf == NULL) {
		LM_ERR("Failed to convert new integer to string \n");
		return -1;
	}

	pkg_cseq.s = pkg_malloc(olen);
	if (!pkg_cseq.s) {
		LM_ERR("No more pkg mem \n");
		return -1;
	}

	memcpy(pkg_cseq.s,obuf,olen);
	pkg_cseq.len = olen;
	
	buf = msg->buf;
	len = ((struct cseq_body *)msg->cseq->parsed)->number.len;
	offset = ((struct cseq_body *)msg->cseq->parsed)->number.s - buf;

	if ((tmp = del_lump(msg,offset,len,0)) == 0)
	{
		LM_ERR("failed to remove the existing CSEQ\n");
		pkg_free(pkg_cseq.s);
		return -1;
	}

	if (insert_new_lump_after(tmp,pkg_cseq.s,pkg_cseq.len,0) == 0)
	{
		LM_ERR("failed to insert new CSEQ\n");
		pkg_free(pkg_cseq.s);
		return -1;
	}

	LM_DBG("Message CSEQ translated from [%.*s] to [%.*s]\n",
			((struct cseq_body *)msg->cseq->parsed)->number.len,
			((struct cseq_body *)msg->cseq->parsed)->number.s,pkg_cseq.len,
			pkg_cseq.s);
	
	return cseq_no;
}

void apply_cseq_decrement(struct cell* t, int type, struct tmcb_params *p)
{
	struct sip_msg *req;
	struct sip_msg *rpl;
	unsigned int cseq_req, cseq_rpl;

	if ( !t || !t->uas.request || !p->rpl )
		return;

	req = t->uas.request;
	rpl = p->rpl;
	if (req == FAKED_REPLY || rpl == FAKED_REPLY)
		return;

	if (str2int( &(get_cseq(req)->number),&cseq_req) < 0
	|| str2int( &(get_cseq(rpl)->number),&cseq_rpl) < 0 ||
	cseq_req==cseq_rpl )
		return;

	apply_cseq_op(rpl, (int)cseq_req-(int)cseq_rpl);
}

int uac_auth( struct sip_msg *msg)
{
	struct authenticate_body *auth = NULL;
	str msg_body;
	static struct authenticate_nc_cnonce auth_nc_cnonce;
	struct uac_credential *crd;
	int code, branch;
	int new_cseq;
	struct sip_msg *rpl;
	struct cell *t;
	HASHHEX response;
	str *new_hdr;
	str param, ttag;
	char *p;
	struct dlg_cell *dlg;

	/* get transaction */
	t = uac_tmb.t_gett();
	if (t==T_UNDEFINED || t==T_NULL_CELL)
	{
		LM_CRIT("no current transaction found\n");
		goto error;
	}

	/* get the selected branch */
	branch = uac_tmb.t_get_picked();
	if (branch<0) {
		LM_CRIT("no picked branch (%d)\n",branch);
		goto error;
	}

	rpl = t->uac[branch].reply;
	code = t->uac[branch].last_received;
	LM_DBG("picked reply is %p, code %d\n",rpl,code);

	if (rpl==0)
	{
		LM_CRIT("empty reply on picked branch\n");
		goto error;
	}
	if (rpl==FAKED_REPLY)
	{
		LM_ERR("cannot process a FAKED reply\n");
		goto error;
	}

	if (code==WWW_AUTH_CODE) {
		parse_www_authenticate_header(rpl, &auth);
	} else if (code==PROXY_AUTH_CODE) {
		parse_proxy_authenticate_header(rpl, &auth);
	}

	if (auth == NULL) {
		LM_ERR("Unable to extract authentication info\n");
		goto error;
	}

	/* can we authenticate this realm? */
	/* look into existing credentials */
	crd = uac_auth_api._lookup_realm( &auth->realm );
	/* found? */
	if (crd==0)
	{
		LM_DBG("no credential for realm \"%.*s\"\n",
			auth->realm.len, auth->realm.s);
		goto error;
	}

	if ((auth->flags & QOP_AUTH_INT) && get_body(msg, &msg_body) < 0) {
		LM_ERR("Failed to get message body\n");
		goto error;
	}

	/* do authentication */
	uac_auth_api._do_uac_auth(&msg_body, &msg->first_line.u.request.method,
			&t->uac[branch].uri, crd, auth, &auth_nc_cnonce, response);

	/* build the authorization header */
	new_hdr = uac_auth_api._build_authorization_hdr( code, &t->uac[branch].uri,
		crd, auth, &auth_nc_cnonce, response);
	if (new_hdr==0)
	{
		LM_ERR("failed to build authorization hdr\n");
		goto error;
	}

	/* so far, so good -> add the header and set the proper RURI */
	if (apply_urihdr_changes( msg, &t->uac[branch].uri, new_hdr)<0)
	{
		LM_ERR("failed to apply changes\n");
		pkg_free(new_hdr->s);
		new_hdr->s = NULL; new_hdr->len = 0;
		goto error;
	}
	/* the Authorization hdr was already pushed into the message as a lump
	 * along with the buffer, so detach the buffer from new_hdr var */
	new_hdr->s = NULL; new_hdr->len = 0;

	/* gather some information about the context of this request,
	 * like if initial or sequential, if dialog support is on */
	get_totag(msg, &ttag);
	if (dlg_api.get_dlg)
		dlg = dlg_api.get_dlg();
	else
		dlg = NULL;

	if (ttag.s==NULL || dlg==NULL || (dlg->flags&DLG_FLAG_CSEQ_ENFORCE)==0) {

		/* initial request or no dialog support
		 * => do the changes over cseq from here */
		if ( (new_cseq = apply_cseq_op(msg,1)) < 0) {
			LM_WARN("Failure to increment the CSEQ header - continue \n");
			goto error;
		}

		/* only register the TMCB once per transaction */
		if (!(msg->msg_flags & FL_USE_UAC_CSEQ || 
		t->uas.request->msg_flags & FL_USE_UAC_CSEQ)) {
			if (uac_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_FWDED,
			apply_cseq_decrement,0,0)!=1) {
				LM_ERR("Failed to register TMCB response fwded - continue \n");
				goto error;
			}
		}

		/* marking of the call (with or without dialog support) for further
		 * CSEQ handling must be done only for intial request */
		if (ttag.s==NULL) {
			if (dlg) {
				/* dlg->legs[dlg->legs_no[DLG_LEGS_USED]-1].last_gen_cseq = new_cseq; */
				dlg->flags |= DLG_FLAG_CSEQ_ENFORCE;
			} else {
				param.len=rr_uac_cseq_param.len+3;
				param.s=pkg_malloc(param.len);
				if (!param.s) {
					LM_ERR("No more pkg mem \n");
					goto error;
				}

				p = param.s;
				*p++=';';
				memcpy(p,rr_uac_cseq_param.s,rr_uac_cseq_param.len);
				p+=rr_uac_cseq_param.len;
				*p++='=';
				*p++='1';

				if (uac_rrb.add_rr_param( msg, &param)!=0) {
					LM_ERR("add_RR_param failed\n");
					pkg_free(param.s);
					goto error;
				}

				pkg_free(param.s);
			}
		}

	} else {

		/* this is a sequential with dialog support, so the dialog module
		 * is already managing the cseq => tell directly the dialog module
		 * about the cseq increasing */
		new_cseq = ++dlg->legs[dlg->legs_no[DLG_LEGS_USED]-1].last_gen_cseq;

		/* as we expect to have the request already altered (by the dialog 
		 * module) with a new cseq, to invalidate that change, we do a trick
		 * by adding a new set of lumps (del+add) to cover the old one
		 * (as start+len), so let's change the whole cseq hdr - anyhow
		 * this is a per-branch change, so it will be discarded afterwards */
		if ( (force_master_cseq_change( msg, new_cseq)) < 0) {
			LM_ERR("failed to forced new in-dialog cseq\n");
			goto error;
		}

	}

	msg->msg_flags |= FL_USE_UAC_CSEQ;
	t->uas.request->msg_flags |= FL_USE_UAC_CSEQ;

	return 0;
error:
	return -1;
}

void rr_uac_auth_checker(struct sip_msg *msg, str *r_param, void *cb_param)
{
	str param_val;

	LM_DBG("getting '%.*s' Route param\n",
		rr_uac_cseq_param.len,rr_uac_cseq_param.s);

	/* do we have the uac auth marker ? */
	if (uac_rrb.get_route_param( msg, &rr_uac_cseq_param, &param_val)!=0) {
		LM_DBG("route param '%.*s' not found\n",
			rr_uac_cseq_param.len,rr_uac_cseq_param.s);
		return;
	}

	/* we don't change anything upstream */
	if (uac_rrb.is_direction( msg, RR_FLOW_UPSTREAM)==0)
		return;

	if (apply_cseq_op(msg,1) < 0) {
		LM_WARN("Failure to increment the CSEQ header - continue \n");
		return;
	}

	if (uac_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_FWDED,
	apply_cseq_decrement,0,0)!=1) {
		LM_ERR("Failed to register TMCB response fwded - continue \n");
		return;
	}
}
