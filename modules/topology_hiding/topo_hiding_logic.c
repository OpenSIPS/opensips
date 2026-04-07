/**
* Topology Hiding Module
*
* Copyright (C) 2015 OpenSIPS Foundation
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
 * History
 * -------
 *  2015-02-17  initial version (Vlad Paiu)
*/

#include "../../ut.h"
#include "topo_hiding_logic.h"
#include "th_no_dlg_logic.h"

extern int force_dialog;
extern struct tm_binds tm_api;
extern struct dlg_binds dlg_api;

extern str topo_hiding_prefix;
extern str topo_hiding_seed;

extern struct th_ct_params *th_param_list;
extern struct th_ct_params *th_hdr_param_list;

static int topo_hiding_with_dlg(struct sip_msg *req,struct cell* t,
		struct dlg_cell* dlg,int extra_flags,struct th_params *params);
static int topo_dlg_replace_contact(struct sip_msg* msg, struct dlg_cell* dlg,
		int leg, str *ct_user);
static void topo_dlg_onroute (struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params);
static void topo_dlg_initial_reply (struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params);
static void th_down_onreply(struct cell* t, int type,struct tmcb_params *param);
static void th_up_onreply(struct cell* t, int type, struct tmcb_params *param);
static int dlg_th_onreply(struct dlg_cell *dlg, struct sip_msg *rpl, struct sip_msg *req,
		int init_req, int dir, int dst_leg);
static int dlg_th_callid_pre_parse(struct sip_msg *msg,int want_from);
static int dlg_th_needs_decoding(struct sip_msg *msg);
static int dlg_th_decode_callid(struct sip_msg *msg);
static int dlg_th_encode_callid(struct sip_msg *msg);
static inline char *dlg_th_rebuild_req(struct sip_msg *msg,int *len);
static inline char *dlg_th_rebuild_rpl(struct sip_msg *msg,int *len);
static struct th_params *th_params_dup(struct th_params *params);

/* exposed logic below */

int topology_hiding(struct sip_msg *req,int extra_flags, struct th_params *params)
{
	struct dlg_cell *dlg;
	struct cell* t;
	int is_sequential = 0;

	/* we should only initialize topology hiding for initial requests */
	if (!req->to && parse_headers(req, HDR_TO_F,0) == -1) {
		LM_ERR("To parsing failed\n");
		return -1;
	}

	if (!req->to) {
		LM_ERR("no To\n");
		return -1;
	}

	/* one way hiding will fail topology hiding match when going out the untrusted side */
	is_sequential = get_to(req)->tag_value.len > 0;

	t = tm_api.t_gett();
	if (t == T_UNDEFINED)
		t=NULL;

	if (dlg_api.get_dlg) {
		/* we have dialog module loaded */
		dlg = dlg_api.get_dlg();
		if (!dlg) {
			if (force_dialog) {
				if(dlg_api.create_dlg(req, 0) < 0) {
					LM_ERR("Failed to create dialog\n");
					return -1;
				}
				/* double check if the dialog can be retrieved */
				if (!(dlg = dlg_api.get_dlg())) {
					LM_ERR("failed to get dialog\n");
					return -1;
				}

			}
		}

		if (dlg) {
			if (is_sequential) {
				LM_WARN("SCRIPT ERROR - trying to initialize topology hiding for sequential request in dialog mode \n");
				return -1;
			}

			return topo_hiding_with_dlg(req, t, dlg, extra_flags, params);
		} else {
			return topo_hiding_no_dlg(req, t, extra_flags, params);
		}
	}

	return topo_hiding_no_dlg(req, t, extra_flags, params);
}

int topo_callid_pre_raw(str *data, struct sip_msg* foo)
{
	struct sip_msg msg;

	memset(&msg,0,sizeof(struct sip_msg));
	msg.buf=data->s;
	msg.len=data->len;
	if (dlg_th_callid_pre_parse(&msg,0) < 0)
		goto done;

	if (msg.first_line.type==SIP_REQUEST) {
		if (get_to(&msg)->tag_value.len>0) {
			/* sequential request, check if callid needs to be unmasked */
			if (dlg_th_needs_decoding(&msg)) {
				if (dlg_th_decode_callid(&msg) < 0) {
					LM_ERR("Failed to decode callid for sequential request\n");
					goto error;
				}
				goto rebuild_msg;
			}
		} else {
			/* initial request, don't do anything
			callid masking will be done on the out side */
		}
	} else if (msg.first_line.type==SIP_REPLY) {
		/* we might need to decode callid if mangled */
		if (dlg_th_needs_decoding(&msg)) {
			if (dlg_th_decode_callid(&msg) < 0) {
				LM_ERR("Failed to decode callid for reply\n");
				goto error;
			}
			goto rebuild_rpl;
		} else {
			/* encoding will be done on the out side */
		}
	} else {
		/* non sip, most likely, let it through */
		return 0;
	}

done:
	free_sip_msg(&msg);
	return 0;

rebuild_msg:
	data->s = dlg_th_rebuild_req(&msg,&data->len);
	free_sip_msg(&msg);
	return 0;

rebuild_rpl:
	data->s = dlg_th_rebuild_rpl(&msg,&data->len);
	free_sip_msg(&msg);
	return 0;
error:
	free_sip_msg(&msg);
	return -1;
}

int topo_callid_post_raw(str *data, struct sip_msg* foo)
{
	struct sip_msg msg;
	struct dlg_cell *dlg;

	if (dlg_api.get_dlg == NULL || (dlg = dlg_api.get_dlg()) == NULL || 
	!dlg_api.is_mod_flag_set(dlg,TOPOH_HIDE_CALLID)) {
		/* dialog module not involved or not callid topo hiding
		 - let is pass freely */
		return 0;
	}

	memset(&msg,0,sizeof(struct sip_msg));
	msg.buf=data->s;
	msg.len=data->len;
	if (dlg_th_callid_pre_parse(&msg,1) < 0) {
		LM_ERR("could not parse resulted sip message: %.*s\n", data->len, data->s);
		goto done;
	}

	if (msg.first_line.type==SIP_REQUEST) {
		if (get_to(&msg)->tag_value.len>0) {
			/* sequential request, check if callid needs to be unmasked */
			if (get_from(&msg)->tag_value.len != 0) {
				/* FIXME - we need to know the direction for non-dialog here */
				if (memcmp(get_from(&msg)->tag_value.s,
				dlg->legs[0].tag.s,dlg->legs[0].tag.len) == 0) {
					/* request from caller -  need to encode callid */
					if (dlg_th_encode_callid(&msg) < 0) {
						LM_ERR("Failed to mask callid for initial request\n");
						goto error;
					}
					goto rebuild_req;
				} else {
					/* let request go through - was decoded on the in side */
				}
			} else {
				/* no from tag in request - kinda foobar ? - let it through */
				goto done;
			}
		} else {
			/* initial request, mask callid */
			if (dlg_th_encode_callid(&msg) < 0) {
				LM_ERR("Failed to mask callid for initial request\n");
				goto error;
			}
			goto rebuild_req;
		}
	} else if (msg.first_line.type==SIP_REPLY) {
		/* we need to look at the direction */
		if (get_from(&msg)->tag_value.len != 0) {
			if (memcmp(get_from(&msg)->tag_value.s,
			dlg->legs[0].tag.s,dlg->legs[0].tag.len) == 0) {
				/* reply going to caller -
				decode was done on the receiving end, let it unchanged */
			} else {
				/* reply going to callee , need to encode callid */
				if (dlg_th_encode_callid(&msg) < 0) {
					LM_ERR("Failed to decode callid for reply\n");
					goto error;
				}
				goto rebuild_rpl;
			}
		} else {
			/* no from tag in reply - kinda foobar ? - let it through */
			goto done;
		}
	}

done:
	free_sip_msg(&msg);
	return 0;

rebuild_req:
	data->s = dlg_th_rebuild_req(&msg,&data->len);
	free_sip_msg(&msg);
	return 0;
rebuild_rpl:
	data->s = dlg_th_rebuild_rpl(&msg,&data->len);
	free_sip_msg(&msg);
	return 0;

error:
	free_sip_msg(&msg);
	return -1;
}

/* Internal dialog topology hiding functionality */
static int topo_hiding_with_dlg(struct sip_msg *req,struct cell* t,
		struct dlg_cell* dlg,int extra_flags,struct th_params *params)
{
	int already_engaged = dlg_api.is_mod_flag_set(dlg,TOPOH_ONGOING);
	struct th_params *saved_params = NULL;
	int_str isval;

	dlg_api.set_mod_flag(dlg, TOPOH_ONGOING | extra_flags );
	if (already_engaged) {
		LM_DBG("topology hiding already engaged!\n");
		return 1;
	}

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(req, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}

	if (params && (params->ct_caller_user.len || params->ct_callee_user.len)) {
		if (params->ct_caller_user.len) {
			isval.s = params->ct_caller_user;
			if (dlg_api.store_dlg_value(dlg,
					&th_contact_caller_var, &isval, DLG_VAL_TYPE_STR) < 0) {
				LM_ERR("Failed to store caller dialog var\n");
				return -1;
			}
			LM_DBG("advertising caller user <%.*s> in contact\n",
					isval.s.len, isval.s.s);
		}
		if (params->ct_callee_user.len) {
			isval.s = params->ct_callee_user;
			if (dlg_api.store_dlg_value(dlg,
					&th_contact_callee_var, &isval, DLG_VAL_TYPE_STR) < 0) {
				LM_ERR("Failed to store callee dialog var\n");
				return -1;
			}
			LM_DBG("advertising callee user <%.*s> in contact\n",
					isval.s.len, isval.s.s);
		}
		saved_params = th_params_dup(params);
		if (!saved_params) {
			LM_ERR("could not dup contact user\n");
			return -1;
		}
	}

	if (topo_delete_record_routes(req) < 0) {
		LM_ERR("Failed to remove Record Route header \n");
		goto error;
	}

	if(topo_delete_vias(req) < 0) {
		LM_ERR("Failed to remove via headers\n");
		goto error;
	}

	if(topo_dlg_replace_contact(req, dlg, -1, (params?&params->ct_callee_user:NULL)) < 0) {
		LM_ERR("Failed to replace contact\n");
		goto error;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, topo_dlg_initial_reply,
			NULL, NULL)) {
		LM_ERR("cannot register callback for fwded replies in dialog\n");
		goto error;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_REQ_WITHIN,
	topo_dlg_onroute, saved_params, (saved_params?shm_free_wrap:NULL))) {
		LM_ERR("cannot register callback for sequential requests\n");
		goto error;
	}

	return 1;
error:
	if (saved_params)
		shm_free(saved_params);
	return -1;
}

static int topo_dlg_replace_contact(struct sip_msg* msg, struct dlg_cell* dlg,
		int leg, str *ct_user)
{
	char *prefix=NULL,*suffix=NULL,*p,*p_init,*ct_username=NULL;
	int prefix_len,suffix_len,ct_username_len=0,n,i;
	struct sip_uri ctu;
	str contact;
	struct th_ct_params* el;
	param_t *it;
	str *rr_param;
	struct lump* lump;
	str *ct;

	if(!msg->contact)
	{
		if(parse_headers(msg, HDR_CONTACT_F, 0)< 0)
		{
			LM_ERR("Failed to parse headers\n");
			return -1;
		}
		if(!msg->contact)
			return 0;
	}

	if (leg >= 0) {
		if (dlg->legs[leg].adv_contact.len)
			ct = &dlg->legs[leg].adv_contact;
		else
			ct = &dlg->legs[leg].contact;

		prefix = pkg_malloc(ct->len);
		if (!prefix) {
			LM_ERR("could not allocate prefix!\n");
			return -1;
		}
		memcpy(prefix, ct->s, ct->len);

		if (!(lump = delete_existing_contact(msg, 1))){
			LM_ERR("Failed removing existing contact \n");
			goto error;
		}

		if ((lump = insert_new_lump_after(lump, prefix, ct->len, 0)) == 0) {
			LM_ERR("failed inserting '%.*s'\n", ct->len, prefix);
			goto error;
		}
		return 0;
	}

	prefix_len = 5; /* <sip: */

	memset(&ctu, 0, sizeof(ctu));
	if (ct_user && ct_user->len) {
		ct_username = ct_user->s;
		ct_username_len = ct_user->len;
		prefix_len += 1 + /* @ */ + ct_username_len;
	} else if (dlg_api.is_mod_flag_set(dlg,TOPOH_KEEP_USER)) {
		if ( parse_contact(msg->contact)<0 ||
			((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
			((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
				LM_ERR("bad Contact HDR\n");
		} else {
			contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
			if(parse_uri(contact.s, contact.len, &ctu) < 0) {
				LM_ERR("Bad Contact URI\n");
				if (dlg_api.is_mod_flag_set(dlg,TOPOH_DID_IN_USER))
					prefix_len += RR_DLG_PARAM_SIZE + 1;
			} else {
				ct_username = ctu.user.s;
				ct_username_len = ctu.user.len;
				LM_DBG("Trying to propagate username [%.*s]\n",ct_username_len,
									ct_username);
				if (ct_username_len > 0) {
					prefix_len += 1 + /* @ */ + ct_username_len;
				}
			}
		}
	}
	if (dlg_api.is_mod_flag_set(dlg,TOPOH_DID_IN_USER))
		prefix_len += RR_DLG_PARAM_SIZE + 1;

	prefix = pkg_malloc(prefix_len);
	if (!prefix) {
		LM_ERR("no more pkg\n");
		goto error;
	}

	if (dlg_api.is_mod_flag_set(dlg,TOPOH_DID_IN_USER))
		suffix_len = 1; /* > */
	else
		suffix_len = RR_DLG_PARAM_SIZE+1; /* > */
	if (th_param_list) {
		if ( parse_contact(msg->contact)<0 ||
			((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
			((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
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
							suffix_len += topo_ct_param_len(&ctu.u_name[i], &ctu.u_val[i], 0);
					}
				}
			}
		}
	}

	if (th_hdr_param_list) {
		if ( parse_contact(msg->contact)<0 ||
			((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
			((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
			LM_ERR("bad Contact HDR\n");
		} else {
			for (el=th_hdr_param_list;el;el=el->next) {
				for (it=((contact_body_t *)msg->contact->parsed)->contacts->params;it;it=it->next) {
					if (str_match(&el->param_name, &it->name))
						suffix_len += topo_ct_param_len(&it->name, &it->body, 1);
				}
			}
		}
	}

	suffix = pkg_malloc(suffix_len);
	if (!suffix) {
		LM_ERR("no more pkg\n");
		goto error;
	}

	rr_param = dlg_api.get_rr_param();

	p = prefix;
	memcpy( p, "<sip:", 5);
	p += 5;
	if (dlg_api.is_mod_flag_set(dlg,TOPOH_KEEP_USER) && ct_username_len > 0) {
		memcpy( p, ct_username, ct_username_len);
		p += ct_username_len;
	}
	if (dlg_api.is_mod_flag_set(dlg,TOPOH_DID_IN_USER)) {
		if (p==prefix+5)
			*(p++) = 'X';
		/* add '.' */
		*(p++) = DLG_SEPARATOR;
		/* add "did" */
		memcpy(p,rr_param->s,rr_param->len);
		p+=rr_param->len;
		/* add '.' */
		*(p++) = DLG_SEPARATOR;
		/* add hash entry as hexa */
		n = (prefix_len-1)/*len without @*/ - (p-prefix);
		if (int2reverse_hex( &p, &n, dlg->h_entry)==-1) {
			LM_ERR("int2reverse_hex on entry failed with buf size %d\n",n);
			return -1;
		}
		/* add '.' */
		*(p++) = DLG_SEPARATOR;
		/* add hash entry as hexa */
		n = (prefix_len-1)/*len without @*/ - (p-prefix);
		if (int2reverse_hex( &p, &n, dlg->h_id)==-1) {
			LM_ERR("int2reverse_hex on id failed with buf size %d\n",n);
			return -1;
		}
	}
	if (p!=prefix+5)
		*(p++) = '@';

	prefix_len = p - prefix;

	p_init = p = suffix;

	if (!dlg_api.is_mod_flag_set(dlg,TOPOH_DID_IN_USER)) {
		*p++ = ';';
		memcpy(p,rr_param->s,rr_param->len);
		p+=rr_param->len;
		*p++ = '=';

		n = RR_DLG_PARAM_SIZE - (p-p_init);
		if (int2reverse_hex( &p, &n, dlg->h_entry)==-1)
			return -1;

		*(p++) = DLG_SEPARATOR;

		n = RR_DLG_PARAM_SIZE - (p-p_init);
		if (int2reverse_hex( &p, &n, dlg->h_id)==-1)
			return -1;
	}

	if (th_param_list) {
		for (el=th_param_list;el;el=el->next) {
			/* we just iterate over the unknown params */
			for (i=0;i<ctu.u_params_no;i++) {
				if (str_match(&el->param_name, &ctu.u_name[i]))
					p = topo_ct_param_copy(p, &ctu.u_name[i], &ctu.u_val[i], 0);
			}
		}
	}

	*p++ = '>';
	if (th_hdr_param_list) {
		if ( parse_contact(msg->contact)<0 ||
			((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
			((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
			LM_ERR("bad Contact HDR\n");
		} else {
			for (el=th_hdr_param_list;el;el=el->next) {
				for (it=((contact_body_t *)msg->contact->parsed)->contacts->params;it;it=it->next) {
					if (str_match(&el->param_name, &it->name))
						p = topo_ct_param_copy(p, &it->name, &it->body, 1);
				}
			}
		}
	}
	suffix_len = p - p_init;

	if (!(lump = delete_existing_contact(msg, 0))){
		LM_ERR("Failed removing existing contact \n");
		goto error;
	}

	if ((lump = insert_new_lump_after(lump,prefix,prefix_len,0)) == 0) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}
	/* make sure we do not free this string in case of a further error */
	prefix = NULL;

	if ((lump = insert_subst_lump_after(lump, SUBST_SND_ALL, 0)) == 0) {
		LM_ERR("failed inserting SUBST_SND buf\n");
		goto error;
	}

	if ((lump = insert_new_lump_after(lump,suffix,suffix_len,0)) == 0) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}

	return 0;
error:
	if (prefix) pkg_free(prefix);
	if (suffix) pkg_free(suffix);
	return -1;
}

static struct th_params *th_params_dup(struct th_params *params)
{
	struct th_params *ret;
	if (!params || (!params->ct_caller_user.len && !params->ct_callee_user.len))
		return NULL;
	ret = shm_malloc(sizeof *ret +
			params->ct_caller_user.len + params->ct_callee_user.len);
	if (!ret) {
		LM_ERR("oom for username dup\n");
		return NULL;
	}
	ret->ct_caller_user.s = (char *)(ret + 1);
	memcpy(ret->ct_caller_user.s, params->ct_caller_user.s, params->ct_caller_user.len);
	ret->ct_caller_user.len = params->ct_caller_user.len;
	ret->ct_callee_user.s = ret->ct_caller_user.s;
	memcpy(ret->ct_callee_user.s, params->ct_callee_user.s, params->ct_callee_user.len);
	ret->ct_callee_user.len = params->ct_callee_user.len;
	return ret;
}

/* restore callbacks */
void th_loaded_callback(struct dlg_cell *dlg, int type,
			struct dlg_cb_params *_params)
{
	int_str isval;
	int val_type;
	struct th_params params, *pparams = NULL;

	if (!dlg) {
		LM_ERR("null dialog - cannot fetch message flags\n");
		return;
	}

	if (!dlg_api.is_mod_flag_set(dlg,TOPOH_ONGOING)) {
		LM_DBG("no topo hiding for dlg %p\n", dlg);
		return;
	}
	memset(&params, 0, sizeof params);

	if (dlg_api.fetch_dlg_value(dlg, &th_contact_caller_var,
			&val_type, &isval, 0) >= 0)
		params.ct_caller_user = isval.s;
	if (dlg_api.fetch_dlg_value(dlg, &th_contact_callee_var,
			&val_type, &isval, 0) >= 0)
		params.ct_callee_user = isval.s;
	if (params.ct_caller_user.len || params.ct_callee_user.len)
		pparams = th_params_dup(&params);

	if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, topo_dlg_initial_reply,
			NULL, NULL)) {
		LM_ERR("cannot register callback for fwded replies in dialog\n");
		goto error;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_REQ_WITHIN,
	topo_dlg_onroute, pparams, (pparams?shm_free_wrap:NULL))) {
		LM_ERR("cannot register callback for sequential requests\n");
		goto error;
	}
	return;
error:
	if (pparams)
		shm_free(pparams);
}

static void topo_unref_dialog(void *dialog)
{
	dlg_api.dlg_unref((struct dlg_cell*)dialog, 1);
}

static void topo_dlg_initial_reply (struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params)
{
	struct cell *t;

	if (dlg==0)
		return;
	if (params->msg==FAKED_REPLY)
		return;

	t = tm_api.t_gett();
	if (t == T_UNDEFINED || t == NULL)
		return;

	if(dlg_th_onreply(dlg, params->msg, t->uas.request, 1, DLG_DIR_UPSTREAM, params->dst_leg) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}


static void topo_dlg_onroute (struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params)
{
	int dir = params->direction;
	struct sip_msg *req = params->msg;
	int adv_leg = -1, leg;
	str *ct_user = (str *)(*params->param);

	if (!req) {
		LM_ERR("Called with NULL SIP message \n");
		return;
	}

	/* we also may end up here via TERMINATE event triggered by internal
	 * dlg termination -> the requests we have here are dummy, so nothing
	 * to be done */
	if ((req->flags&FL_IS_LOCAL)!=0 || is_dummy_sip_msg(req)==0) {
		LM_DBG("dummy request identified, skipping...\n");
		return;
	}

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(req, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return;
	}

	/* delete vias */
	if(topo_delete_vias(req) < 0) {
		LM_ERR("Failed to remove via headers\n");
		return;
	}

	/* delete record route */
	if (topo_delete_record_routes(req) < 0) {
		LM_ERR("Failed to remove record route headers \n");
		return;
	}

	/* add route headers */
	if (dlg_api.fix_route_dialog(req, dlg) < 0) {
		LM_ERR("Failed to fix the SIP request according to dialog info \n");
		return;
	}

	leg = (params->dst_leg < 0?DLG_CALLER_LEG:params->dst_leg);
	req->force_send_socket = dlg->legs[leg].bind_addr;
	switch (dir) {
	case DLG_DIR_UPSTREAM:
		if (dlg_api.is_mod_flag_set(dlg, TOPOH_KEEP_ADV_A))
			adv_leg = leg;
		break;
	case DLG_DIR_DOWNSTREAM:
		if (dlg_api.is_mod_flag_set(dlg, TOPOH_KEEP_ADV_B))
			adv_leg = leg;
		break;
	}

	/* replace contact*/
	if(topo_dlg_replace_contact(req, dlg, adv_leg, ct_user) < 0) {
		LM_ERR("Failed to replace contact\n");
		return;
	}

	/* register tm callback for response in  */
	dlg_api.dlg_ref(dlg,1);
	if (tm_api.register_tmcb( req, 0, TMCB_RESPONSE_FWDED,
	(dir==DLG_DIR_UPSTREAM)?th_down_onreply:th_up_onreply,
	(void*)dlg, topo_unref_dialog)<0 ) {
		LM_ERR("failed to register TMCB\n");
		dlg_api.dlg_unref(dlg,1);
		return;
	}
}

static int dlg_th_onreply(struct dlg_cell *dlg, struct sip_msg *rpl,
								struct sip_msg *req, int init_req, int dir, int dst_leg)
{
	struct lump* lmp;
	int size;
	char* route;
	struct dlg_leg* leg;
	int adv_leg = -1;
	str *ct_user, *ct_var;
	int val_type;
	int_str value;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(rpl, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}
	if (dst_leg < 0) {
		if (dir == DLG_DIR_DOWNSTREAM)
			dst_leg = callee_idx(dlg);
		else
			dst_leg = DLG_CALLER_LEG;
	}

	if (!init_req) {
		if (dir == DLG_DIR_UPSTREAM) {
			if (dlg_api.is_mod_flag_set(dlg, TOPOH_KEEP_ADV_A))
				adv_leg = dst_leg;
		} else {
			if (dlg_api.is_mod_flag_set(dlg, TOPOH_KEEP_ADV_B))
				adv_leg = dst_leg;
		}
	}

	/* replace contact, but not if a redirect reply for initial INVITE */
	if ( !(init_req && dir == DLG_DIR_UPSTREAM &&
	rpl->REPLY_STATUS>=300 && rpl->REPLY_STATUS<400) ) {
		if (dst_leg == DLG_CALLER_LEG)
			ct_var = &th_contact_caller_var;
		else
			ct_var = &th_contact_callee_var;
		if (dlg_api.fetch_dlg_value(dlg, ct_var, &val_type, &value, 0) < 0)
			ct_user = NULL;
		else
			ct_user = &value.s;

		if(topo_dlg_replace_contact(rpl, dlg, adv_leg, ct_user) < 0) {
			LM_ERR("Failed to replace contact\n");
			return -1;
		}
	}

	leg = &dlg->legs[dst_leg];

	if (topo_delete_record_routes(rpl) < 0) {
		LM_ERR("Failed to remove Record Route header \n");
		return -1;
	}

	if (!(lmp = restore_vias_from_req(req,rpl))) {
		LM_ERR("Failed to restore VIA headers from request \n");
		return -1;
	}

	/* if dialog not confirmed and 200OK for Invite */
	/* pass the record route headers for this leg */
	if(init_req && dir == DLG_DIR_UPSTREAM && leg->route_set.s) {

		/* changed here for contact
		 * (take care to insert the routes after own) */

		/* pass record route headers */
		size = leg->route_set.len + RECORD_ROUTE_LEN + CRLF_LEN;
		route = pkg_malloc(size);
		if (route == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}

		memcpy(route, RECORD_ROUTE, RECORD_ROUTE_LEN);
		memcpy(route+RECORD_ROUTE_LEN, leg->route_set.s, leg->route_set.len);
		memcpy(route+RECORD_ROUTE_LEN+leg->route_set.len, CRLF, CRLF_LEN);

		/* put after Via */
		if ((lmp =
		insert_new_lump_after(lmp, route, size, HDR_RECORDROUTE_T)) == 0) {
			LM_ERR("failed inserting new route set\n");
			pkg_free(route);
			return -1;
		}
		LM_DBG("Added record route [%.*s]\n", size, route);
	}

	return 0;
}

static void th_down_onreply(struct cell* t, int type,struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (dlg==0)
		return;

	if(dlg_th_onreply(dlg, param->rpl, param->req,0, DLG_DIR_DOWNSTREAM, -1) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}

static void th_up_onreply(struct cell* t, int type, struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (dlg==0)
		return;

	if(dlg_th_onreply(dlg, param->rpl, param->req, 0, DLG_DIR_UPSTREAM, -1) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}

static int dlg_th_decode_callid(struct sip_msg *msg)
{
	struct lump *del;
	str new_callid;
	int i,max_size;

	if (msg->callid == NULL) {
		LM_ERR("Message with no callid\n");
		return -1;
	}

	max_size = calc_max_word64_decode_len(msg->callid->body.len - topo_hiding_prefix.len);
	new_callid.s = pkg_malloc(max_size);
	if (new_callid.s==NULL) {
		LM_ERR("No more pkg\n");
		return -1;
	}

	new_callid.len = word64decode((unsigned char *)(new_callid.s),
			(unsigned char *)(msg->callid->body.s + topo_hiding_prefix.len),
			msg->callid->body.len - topo_hiding_prefix.len);
	
	for (i=0;i<new_callid.len;i++)
		new_callid.s[i] ^= topo_hiding_seed.s[i%topo_hiding_seed.len];

	del=del_lump(msg, msg->callid->body.s-msg->buf, msg->callid->body.len, HDR_CALLID_T);
	if (del==NULL) {
		LM_ERR("Failed to delete old callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	if (insert_new_lump_after(del,new_callid.s,new_callid.len,HDR_CALLID_T)==NULL) {
		LM_ERR("Failed to insert new callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	return 0;
}

static int dlg_th_encode_callid(struct sip_msg *msg)
{
	struct lump *del;
	str new_callid;
	int i,word64_enc_len;

	if (msg->callid == NULL) {
		LM_ERR("Message with no callid\n");
		return -1;
	}

	word64_enc_len = calc_word64_encode_len(msg->callid->body.len);
	new_callid.len = word64_enc_len + topo_hiding_prefix.len;
	new_callid.s = pkg_malloc(new_callid.len);
	if (new_callid.s==NULL) {
		LM_ERR("Failed to allocate new callid\n");
		return -1;
	}

	memcpy(new_callid.s,topo_hiding_prefix.s,topo_hiding_prefix.len);
	for (i=0;i<msg->callid->body.len;i++)
		msg->callid->body.s[i] ^= topo_hiding_seed.s[i%topo_hiding_seed.len];

	word64encode((unsigned char *)(new_callid.s+topo_hiding_prefix.len),
		     (unsigned char *)(msg->callid->body.s),msg->callid->body.len);

	/* reset the callid back to original value - some might still need it ( eg. post script )
	FIXME : use bigger buffer here ? mem vs cpu */
	for (i=0;i<msg->callid->body.len;i++)
		msg->callid->body.s[i] ^= topo_hiding_seed.s[i%topo_hiding_seed.len];

	del=del_lump(msg, msg->callid->body.s-msg->buf, msg->callid->body.len, HDR_CALLID_T);
	if (del==NULL) {
		LM_ERR("Failed to delete old callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	if (insert_new_lump_after(del,new_callid.s,new_callid.len,HDR_CALLID_T)==NULL) {
		LM_ERR("Failed to insert new callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	return 0;
}

static int dlg_th_needs_decoding(struct sip_msg *msg)
{
	if (msg->callid == NULL) {
		LM_ERR("Message with no callid\n");
		return 0;
	}

	if (msg->callid->body.len > topo_hiding_prefix.len &&
        memcmp(msg->callid->body.s,topo_hiding_prefix.s,
	topo_hiding_prefix.len) == 0)
		return 1;

	return 0;
}

static inline char *dlg_th_rebuild_req(struct sip_msg *msg,int *len)
{
	return build_req_buf_from_sip_req(msg,(unsigned int*)len,
			NULL,PROTO_NONE,NULL,MSG_TRANS_NOVIA_FLAG);
}

static inline char *dlg_th_rebuild_rpl(struct sip_msg *msg,int *len)
{
	return build_res_buf_from_sip_res(msg,(unsigned int*)len,
			NULL,MSG_TRANS_NOVIA_FLAG);
}

#define MSG_SKIP_BITMASK	(METHOD_REGISTER|METHOD_PUBLISH|METHOD_SUBSCRIBE)
static int dlg_th_callid_pre_parse(struct sip_msg *msg,int want_from)
{
	/* do not throw errors from the upcoming parsing operations */
	set_proc_log_level(L_ALERT);

	if (parse_msg(msg->buf,msg->len,msg)!=0) {
		LM_ERR("Invalid SIP msg\n");
		goto error;
	}

	if (parse_headers(msg,HDR_EOH_F,0)<0) {
		LM_ERR("Failed to parse SIP headers\n");
		goto error;
	}

	if (msg->cseq==NULL || get_cseq(msg)==NULL) {
		LM_ERR("Failed to parse CSEQ header\n");
		goto error;
	}

	if((get_cseq(msg)->method_id)&MSG_SKIP_BITMASK) {
		LM_DBG("Skipping %d for DLG callid topo hiding\n",get_cseq(msg)->method_id);
		goto error;
	}

	if (parse_to_header(msg)<0 || msg->to==NULL || get_to(msg)==NULL) {
		LM_ERR("cannot parse TO header\n");
		goto error;
	}

	if (parse_from_header(msg)<0 || msg->from==NULL || get_from(msg)==NULL) {
		LM_ERR("cannot parse FROM header\n");
		goto error;
	}

	reset_proc_log_level();
	return 0;

error:
	reset_proc_log_level();
	return -1;
}