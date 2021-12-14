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

#include "topo_hiding_logic.h"

extern int force_dialog;
extern struct tm_binds tm_api;
extern struct rr_binds rr_api;
extern struct dlg_binds dlg_api;
extern str topo_hiding_prefix;
extern str topo_hiding_seed;
extern str topo_hiding_ct_encode_pw;
extern str th_contact_encode_param;
extern int th_ct_enc_scheme;

struct th_ct_params {
	str param_name;
	struct th_ct_params *next;
};
static struct th_ct_params *th_param_list=NULL;
static struct th_ct_params *th_hdr_param_list=NULL;

static int topo_hiding_with_dlg(struct sip_msg *req,struct cell* t,struct dlg_cell* dlg,int extra_flags);
static int topo_hiding_no_dlg(struct sip_msg *req,struct cell* t,int extra_flags);
static int topo_dlg_replace_contact(struct sip_msg* msg, struct dlg_cell* dlg);
static int topo_delete_vias(struct sip_msg* req);
static int topo_delete_record_routes(struct sip_msg *req); 
static struct lump* delete_existing_contact(struct sip_msg *msg);
static int topo_parse_passed_params(str *params,struct th_ct_params **lst);
static void topo_dlg_onroute (struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params);
static void topo_dlg_initial_reply (struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params);
static void th_down_onreply(struct cell* t, int type,struct tmcb_params *param);
static void th_up_onreply(struct cell* t, int type, struct tmcb_params *param);
static void th_no_dlg_onreply(struct cell* t, int type, struct tmcb_params *param);
static void th_no_dlg_user_onreply(struct cell* t, int type, struct tmcb_params *param);
static int topo_no_dlg_encode_contact(struct sip_msg *req,int flags);
static int topo_no_dlg_seq_handling(struct sip_msg *msg,str *info);
static int dlg_th_onreply(struct dlg_cell *dlg, struct sip_msg *rpl, struct sip_msg *req,
		int init_req, int dir);

/* exposed logic below */

int topology_hiding(struct sip_msg *req,int extra_flags)
{
	struct dlg_cell *dlg;
	struct cell* t;
	str tag;

	/* we should only initialize topology hiding for initial requests */
        if (!req->to && parse_headers(req, HDR_TO_F,0)==-1) {
                LM_ERR("To parsing failed\n");
                return -1;
        }
        if (!req->to) {
                LM_ERR("no To\n");
                return -1;
        }
        tag=get_to(req)->tag_value;
        if (tag.len>0) {
		LM_WARN("SCRIPT ERROR - trying to initialize topology hiding for sequential request \n");
		return -1;
        }

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

		if (!dlg)
			return topo_hiding_no_dlg(req,t,extra_flags);
		else
			return topo_hiding_with_dlg(req,t,dlg,extra_flags);
	}

	return topo_hiding_no_dlg(req,t,extra_flags);
}

int topo_parse_passed_ct_params(str *params)
{
	return topo_parse_passed_params(params,&th_param_list);
}

int topo_parse_passed_hdr_ct_params(str *params)
{
	return topo_parse_passed_params(params,&th_hdr_param_list);
}

int topology_hiding_match(struct sip_msg *msg)
{
	struct sip_uri *r_uri;
	int i;

	if (parse_sip_msg_uri(msg)<0) {
		LM_ERR("Failed to parse request URI\n");
		return -1;
	}

	if (parse_headers(msg, HDR_ROUTE_F, 0) == -1) {
		LM_ERR("failed to parse route headers\n");
	}

	r_uri = &msg->parsed_uri;

	if (check_self(&r_uri->host,r_uri->port_no ? r_uri->port_no : SIP_PORT, 0) == 1 && msg->route == NULL) {
		/* Seems we are in the topo hiding case :
		 * we are in the R-URI and there are no other route headers */
		for (i=0;i<r_uri->u_params_no;i++)
			if (r_uri->u_name[i].len == th_contact_encode_param.len &&
				memcmp(th_contact_encode_param.s,r_uri->u_name[i].s,th_contact_encode_param.len)==0) {
				LM_DBG("We found param in R-URI with value of %.*s\n",
					r_uri->u_val[i].len,r_uri->u_val[i].s);
				/* pass the param value to the matching funcs */
				return topo_no_dlg_seq_handling(msg,&r_uri->u_val[i]);
		}
	}

	return -1;
}

/* internal functionality */

#define init_new_ct_node(start,len,list) \
	do { \
		el = pkg_malloc(sizeof(struct th_ct_params));\
		if (!el) { \
			LM_ERR("No more pkg mem\n"); \
			return -1; \
		} \
		el->param_name.len = len; \
		el->param_name.s = start; \
		el->next = *list; \
		*list = el; \
	} while (0)

static int topo_parse_passed_params(str *params,struct th_ct_params **lst)
{
	char *p,*s,*end;
	struct th_ct_params* el;
	int len;

	p = params->s;
	end = p+params->len;
	while (1) {
		s = memchr(p,';',end-p);
		if (!s) {
			len = end-p;
			if (len > 0)
				init_new_ct_node(p,len,lst);
			break;
		}

		len = s-p;
		if (len > 0)
			init_new_ct_node(p,len,lst);
		p=s+1;
	}

	return 0;
}

static int topo_delete_record_routes(struct sip_msg *req) 
{
	struct lump* lump, *crt, *prev_crt =0, *a, *foo;
	struct hdr_field *it;
	char* buf;

	/* FIXME - we will be losing uac_replace_from/to in case of no dialog */

	/* delete also the added record route and the did param */
	for(crt=req->add_rm; crt;) {
		if ((crt->type==HDR_RECORDROUTE_T) && (crt->op==LUMP_NOP) ) {
			/* lump found */
			lump = crt;
			crt = crt->next;
			a=lump->before;
			while(a) {
				foo=a; a=a->before;
				if (!(foo->flags&LUMPFLAG_SHMEM))
					free_lump(foo);
				if (!(foo->flags&LUMPFLAG_SHMEM))
					pkg_free(foo);
			}

			a=lump->after;
			while(a) {
				foo=a; a=a->after;
				if (!(foo->flags&LUMPFLAG_SHMEM))
					free_lump(foo);
				if (!(foo->flags&LUMPFLAG_SHMEM))
					pkg_free(foo);
			}
			if (lump == req->add_rm) {
				if (lump->flags&LUMPFLAG_SHMEM) {
					/*
					 * if the chunk is in shm, we cannot remove it, because
					 * it be in the middle of the big shm chunk
					 * therefore we simply mark it as false and move on
					 */
					if (lump->after)
						insert_cond_lump_after(lump, COND_FALSE, 0);
					if (lump->before)
						insert_cond_lump_before(lump, COND_FALSE, 0);
				} else {
					req->add_rm = lump->next;
				}
				prev_crt = lump;
			} else
				prev_crt->next = lump->next;
			if (!(lump->flags&LUMPFLAG_SHMEM))
				free_lump(lump);
			if (!(lump->flags&LUMPFLAG_SHMEM))
				pkg_free(lump);
			continue;
		}
		prev_crt = crt;
		crt= crt->next;
	}

	buf = req->buf;

	/* delete record-route headers */
	for (it=req->record_route;it;it=it->sibling) {
		if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
			LM_ERR("del_lump failed - while deleting record-route\n");
			return -1;
		}
	}

	return 0;
}

static int topo_delete_vias(struct sip_msg* req)
{
	struct hdr_field *it;
	char *buf;

	/* parse all headers to be sure that all VIAs are found */
	if (parse_headers(req, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}

	buf = req->buf;
	it = req->h_via1;
	if(it) {
		/* delete first via1 to set the type (the build_req_buf_from_sip_req will know not to add lump in via1)*/
		if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
			LM_ERR("del_lump failed\n");
			return -1;
		}
		LM_DBG("Delete via [%.*s]\n", it->len, it->name.s);
		for (it=it->sibling; it; it=it->sibling) {
			if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
				LM_ERR("del_lump failed\n");
				return -1;
			}
			LM_DBG("Delete via [%.*s]\n", it->len, it->name.s);
		}
	}

	return 0;
}

static struct lump* delete_existing_contact(struct sip_msg *msg)
{
	int offset;
	int len;
	struct lump* lump, *crt;

	offset = msg->contact->body.s - msg->buf;
	len = msg->contact->body.len;

	for (crt = msg->add_rm; crt; crt = crt->next) {
		if (crt->type == HDR_CONTACT_T && crt->op == LUMP_DEL &&
				crt->u.offset >= offset && crt->u.offset <= offset + len) {
			/*
			 * we do not delete the lump because there might be pointers (such
			 * as contact->uri from the fix_nated_contact() function pointing
			 * to the lump's buffer; instead we simply replace the lump with a
			 * conditional false one
			 */
			/* mark DEL lump as NOP and add COND_FALSE for before and after */
			crt->op = LUMP_NOP;

			if (crt->after)
				insert_cond_lump_after(crt, COND_FALSE, 0);
			if (crt->before)
				insert_cond_lump_before(crt, COND_FALSE, 0);
		}
	}

	if ((lump = del_lump(msg, msg->contact->body.s - msg->buf, msg->contact->body.len,HDR_CONTACT_T)) == 0) {
		LM_ERR("del_lump failed\n");
		return NULL;
	}

	return lump;
}

static int topo_dlg_replace_contact(struct sip_msg* msg, struct dlg_cell* dlg)
{
	char *prefix=NULL,*suffix=NULL,*p,*p_init,*ct_username=NULL;
	int prefix_len,suffix_len,ct_username_len=0,n,i;
	struct sip_uri ctu;
	str contact;
	struct th_ct_params* el;
	param_t *it;
	str *rr_param;
	struct lump* lump;

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

	prefix_len = 5; /* <sip: */

	memset(&ctu, 0, sizeof(ctu));
	if (dlg_api.is_mod_flag_set(dlg,TOPOH_KEEP_USER)) {
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
						if (el->param_name.len == ctu.u_name[i].len &&
						(memcmp(el->param_name.s,ctu.u_name[i].s,
						       el->param_name.len) == 0)) {
							if (ctu.u_val[i].len)
								suffix_len += 1 /* ; */ + ctu.u_name[i].len +
								ctu.u_val[i].len + 1; /* = and value */
							else
								suffix_len += 1 /* ; */ + ctu.u_name[i].len;
						}

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
					if (it->name.len == el->param_name.len &&
					(memcmp(it->name.s,el->param_name.s,it->name.len) == 0)) {
						if (it->body.len)
							suffix_len += 1 /* ; */ + it->name.len +
							it->body.len + 1; /* = and value */
						else
							suffix_len += 1 /* ; */ + it->name.len;
					}
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
				if (el->param_name.len == ctu.u_name[i].len &&
				memcmp(el->param_name.s,ctu.u_name[i].s,
				       el->param_name.len) == 0) {
					*p++ = ';';
					memcpy(p,ctu.u_name[i].s,ctu.u_name[i].len);
					p+=ctu.u_name[i].len;
					if (ctu.u_val[i].len) {
						*p++ = '=';
						memcpy(p,ctu.u_val[i].s,ctu.u_val[i].len);
						p+=ctu.u_val[i].len;
					}
				}
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
					if (it->name.len == el->param_name.len &&
					(memcmp(it->name.s,el->param_name.s,it->name.len) == 0)) {
						*p++ = ';';
						memcpy(p,it->name.s,it->name.len);
						p += it->name.len;
						if (it->body.len) {
							*p++ = '=';
							memcpy(p,it->body.s,it->body.len);
							p += it->body.len;
						}
					}
				}
			}
		}
	}
	suffix_len = p - p_init;

	if (!(lump = delete_existing_contact(msg))){
		LM_ERR("Failed removing existing contact \n");
		goto error;
	}

	if ((lump = insert_new_lump_after(lump,prefix,prefix_len,HDR_CONTACT_T)) == 0) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}
	/* make sure we do not free this string in case of a further error */
	prefix = NULL;

	if ((lump = insert_subst_lump_after(lump, SUBST_SND_ALL, HDR_CONTACT_T)) == 0) {
		LM_ERR("failed inserting SUBST_SND buf\n");
		goto error;
	}

	if ((lump = insert_new_lump_after(lump,suffix,suffix_len,HDR_CONTACT_T)) == 0) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}

	return 0;
error:
	if (prefix) pkg_free(prefix);
	if (suffix) pkg_free(suffix);
	return -1;
}

struct lump* restore_vias_from_req(struct sip_msg *req,struct sip_msg *rpl)
{
	struct lump* lmp;
	struct hdr_field *it;
	str via_str;
	char *p,*buf = rpl->buf;
	char *received_buf=0,*rport_buf=0;
	unsigned int rport_len=0,received_len=0;
	int size;

	lmp = anchor_lump(rpl,rpl->headers->name.s - buf,0);
	if (lmp == 0)
	{
		LM_ERR("failed anchoring new lump\n");
		return NULL;
	}

	if ((req->msg_flags&FL_FORCE_RPORT)||(req->via1->rport)) {
		if ((received_buf=received_builder(req,&received_len))==0){
			LM_ERR("received_builder failed\n");
			return NULL;
		}

		if ((rport_buf=rport_builder(req, &rport_len))==0){
			LM_ERR("rport_builder failed\n");
			return NULL;
		}
		
		/* take care of via1 + rest of VIA headers in h_via1 */
		via_str.len = rport_len + received_len + req->h_via1->len;
		LM_DBG("via len = %d\n",via_str.len);
		if (req->via1->received) {
			via_str.len -= req->via1->received->size+1;
			LM_DBG(" have received will remove %d \n",req->via1->received->size+1);
		}
		if (req->via1->rport) {
			via_str.len -= req->via1->rport->size+1;
			LM_DBG(" have rport will remove %d \n",req->via1->rport->size+1);
		}

		/* copy rest of VIA headers */
		it = req->h_via1->sibling;
		while (it) {
			via_str.len += it->len;
			it = it->sibling;
		}

		via_str.s = pkg_malloc(via_str.len);
		if (!via_str.s) {
			LM_ERR("No more pkg mem\n");
			goto err_free_rport;
		}

		/* take care of via1 + rest of VIA headers in h_via1 */
		if (req->via1->params.s){
			size= req->via1->params.s-req->via1->hdr.s-1; /*compensate for ';' */
		}else{
			size= req->via1->host.s-req->via1->hdr.s+req->via1->host.len;
			if (req->via1->port!=0){
				size += req->via1->port_str.len + 1; /* +1 for ':'*/
			}
		}

		p = via_str.s;
		memcpy(p,req->via1->hdr.s,size);
		p += size;
		memcpy(p,received_buf,received_len);
		p += received_len;
		memcpy(p,rport_buf,rport_len);
		p += rport_len;

		int bytes_before = 0;
		int bytes_after = 0;
		int bytes_between = 0;
		char *between = NULL;
		char *after = NULL;

		if (req->via1->received) {
			if (!req->via1->rport) {
				bytes_before = req->via1->received->start-req->via1->hdr.s-size-1;
				memcpy(p,
				req->via1->hdr.s+size,
				bytes_before);
				p += bytes_before;
				
				bytes_after = req->h_via1->len - size - req->via1->received->size -
						bytes_before - 1; 
				memcpy(p,
				req->via1->received->start+req->via1->received->size,
				bytes_after);
				p += bytes_after;
			} else {
				/* we have both :( */
				if (req->via1->rport->start > req->via1->received->start) {
					bytes_before = req->via1->received->start-req->via1->hdr.s-size-1;
					bytes_between = req->via1->rport->start - req->via1->received->start - req->via1->received->size - 1;
					between = req->via1->received->start + req->via1->received->size;
					after = req->via1->rport->start+req->via1->rport->size;

					bytes_after = req->h_via1->len - size - req->via1->rport->size -
							bytes_before - 1 - bytes_between - req->via1->received->size  - 1; 
					LM_DBG("1 both , before = %d, between = %d, after = %d\n",bytes_before,bytes_between,bytes_after);
				} else {
					bytes_before = req->via1->rport->start-req->via1->hdr.s-size-1;
					bytes_between = req->via1->received->start - req->via1->rport->start - req->via1->rport->size - 1;
					between = req->via1->rport->start + req->via1->rport->size;

					after = req->via1->received->start+req->via1->received->size;

					bytes_after = req->h_via1->len - size - req->via1->rport->size -
							bytes_before - 1 - bytes_between - req->via1->received->size -1 ; 
					LM_DBG("2 both , before = %d, between = %d, after = %d\n",bytes_before,bytes_between,bytes_after);
				}

				memcpy(p,
				req->via1->hdr.s+size,
				bytes_before);
				p += bytes_before;	

				memcpy(p,
				between,
				bytes_between);
				p += bytes_between;	

				memcpy(p,
				after,
				bytes_after);
				p += bytes_after;	
			}
		} else if (req->via1->rport) {
			if (!req->via1->received) {
				bytes_before = req->via1->rport->start-req->via1->hdr.s-size-1;
				memcpy(p,
				req->via1->hdr.s+size,
				bytes_before);
				p += bytes_before;
				
				bytes_after = req->h_via1->len - size - req->via1->rport->size -
						bytes_before - 1; 
				memcpy(p,
				req->via1->rport->start+req->via1->rport->size,
				bytes_after);
				p += bytes_after;
			}
		} else {
			/* no rport or received already present */
			memcpy(p,req->via1->hdr.s+size,req->h_via1->len-size);
			p+= req->h_via1->len-size;
		}

		/* copy rest of VIA headers */
		it = req->h_via1->sibling;
		while (it) {
			memcpy(p,it->name.s,it->len);
			p+=it->len;
			it = it->sibling;
		}

		LM_DBG("built [%.*s], %d %d\n",(int)(p-via_str.s),via_str.s,(int)(p-via_str.s),via_str.len);

		if ((lmp = insert_new_lump_after(lmp, via_str.s, via_str.len, 0)) == 0) {
			LM_ERR("failed inserting new old vias\n");
			pkg_free(via_str.s);
			goto err_free_rport;
		}
			
		pkg_free(rport_buf);
		pkg_free(received_buf);
	} else {
		/* no need to add received/rport , just copy the headers altogether */
		it = req->h_via1;
		via_str.len = 0;

		while (it) {
			via_str.len += it->len;
			it = it->sibling;
		}

		LM_DBG("via len = %d\n",via_str.len);

		if (via_str.len == 0)
			return lmp;

		via_str.s = pkg_malloc(via_str.len);
		if (!via_str.s) {
			LM_ERR("no more pkg mem\n");
			return NULL;
		}

		LM_DBG("allocated via_str %p\n",via_str.s);

		it = req->h_via1;
		p = via_str.s;
		while (it) {
			memcpy(p,it->name.s,it->len);
			p+=it->len;
			it = it->sibling;
		}

		LM_DBG("inserting via headers - [%.*s]\n",via_str.len,via_str.s);

		if ((lmp = insert_new_lump_after(lmp, via_str.s, via_str.len, 0)) == 0) {
			LM_ERR("failed inserting new old vias\n");
			pkg_free(via_str.s);
			return NULL;
		}
	}

	return lmp;

err_free_rport:
	pkg_free(rport_buf);
	pkg_free(received_buf);
	return NULL;
}

#define RECORD_ROUTE "Record-Route: "
#define RECORD_ROUTE_LEN (sizeof(RECORD_ROUTE)-1)
static void _th_no_dlg_onreply(struct cell* t, int type, struct tmcb_params *param,int flags)
{
	struct lump* lmp;
	str rr_set;
	struct sip_msg *req = param->req;
	struct sip_msg *rpl = param->rpl;
	char *route;
	int size;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(rpl, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return;
	}

	if (topo_delete_record_routes(rpl) < 0) {
		LM_ERR("Failed to remove Record Route header \n");
		return;
	}

	if(topo_delete_vias(rpl) < 0) {
		LM_ERR("Failed to remove via headers\n");
		return;
	}

	if ( !(rpl->REPLY_STATUS>=300 && rpl->REPLY_STATUS<400) ) {
		if (topo_no_dlg_encode_contact(rpl,flags) < 0) {
			LM_ERR("Failed to encode contact header \n");
			return;
		}
	}

	if (!(lmp = restore_vias_from_req(req,rpl))) {
		LM_ERR("Failed to restore VIA headers from request \n");
		return ;
	}

	/* pass record route headers */
	if(req->record_route){
		if(print_rr_body(req->record_route, &rr_set, 0, 1, NULL) != 0 ){
			LM_ERR("failed to print route records \n");
			return;
		}

		size = rr_set.len + RECORD_ROUTE_LEN + CRLF_LEN;
		route = pkg_malloc(size);
		if (route == NULL) {
			LM_ERR("no more pkg memory\n");
			pkg_free(rr_set.s);
			return; 
		}

		memcpy(route, RECORD_ROUTE, RECORD_ROUTE_LEN);
		memcpy(route+RECORD_ROUTE_LEN, rr_set.s, rr_set.len);
		memcpy(route+RECORD_ROUTE_LEN+rr_set.len, CRLF, CRLF_LEN);
		/* put after Via */
		if ((lmp = insert_new_lump_after(lmp, route, size, HDR_RECORDROUTE_T)) == 0) {
			LM_ERR("failed inserting new route set\n");
			pkg_free(route);
			pkg_free(rr_set.s);
			return;
		}

		LM_DBG("Added record route [%.*s]\n", size, route);
		pkg_free(rr_set.s);
	}
	return;
}

static void th_no_dlg_onreply(struct cell* t, int type, struct tmcb_params *param)
{
	_th_no_dlg_onreply(t,type,param,0);
}

static void th_no_dlg_user_onreply(struct cell* t, int type, struct tmcb_params *param)
{
	_th_no_dlg_onreply(t,type,param,TOPOH_KEEP_USER);
}


static int topo_hiding_no_dlg(struct sip_msg *req,struct cell* t,int extra_flags)
{
	transaction_cb* used_cb;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(req, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}

	if (topo_delete_record_routes(req) < 0) {
		LM_ERR("Failed to remove Record Route header \n");
		return -1;
	}

	if(topo_delete_vias(req) < 0) {
		LM_ERR("Failed to remove via headers\n");
		return -1;
	}

	if (topo_no_dlg_encode_contact(req,extra_flags) < 0) {
		LM_ERR("Failed to encode contact header \n");
		return -1;
	}

	if (extra_flags & TOPOH_KEEP_USER)
		used_cb = th_no_dlg_user_onreply;
	else
		used_cb = th_no_dlg_onreply;

	if (extra_flags & TOPOH_HIDE_CALLID)
		LM_WARN("Cannot hide callid when dialog support is not engaged!\n");
	if (extra_flags & TOPOH_DID_IN_USER)
		LM_WARN("Cannot store DID in user when dialog support is not engaged!\n");

	if (tm_api.register_tmcb( req, 0, TMCB_RESPONSE_FWDED,
	used_cb,NULL, NULL)<0 ) {
		LM_ERR("failed to register TMCB\n");
		return -1;
	}

	return 1;
}

static int topo_hiding_with_dlg(struct sip_msg *req,struct cell* t,struct dlg_cell* dlg,int extra_flags)
{
	int already_engaged = dlg_api.is_mod_flag_set(dlg,TOPOH_ONGOING);

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

	if (topo_delete_record_routes(req) < 0) {
		LM_ERR("Failed to remove Record Route header \n");
		return -1;
	}

	if(topo_delete_vias(req) < 0) {
		LM_ERR("Failed to remove via headers\n");
		return -1;
	}

	if(topo_dlg_replace_contact(req, dlg) < 0) {
		LM_ERR("Failed to replace contact\n");
		return -1;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, topo_dlg_initial_reply, NULL, NULL)) {
		LM_ERR("cannot register callback for fwded replies in dialog\n");
		return -1;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_REQ_WITHIN,
	topo_dlg_onroute, NULL , NULL)) {
		LM_ERR("cannot register callback for sequential requests\n");
		return -1;
	}

	return 1;
}

/* restore callbacks */
void th_loaded_callback(struct dlg_cell *dlg, int type,
			struct dlg_cb_params *_params)
{
	if (!dlg) {
		LM_ERR("null dialog - cannot fetch message flags\n");
		return;
	}

	if (!dlg_api.is_mod_flag_set(dlg,TOPOH_ONGOING)) {
		LM_DBG("no topo hiding for dlg %p\n", dlg);
		return;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, topo_dlg_initial_reply, NULL, NULL)) {
		LM_ERR("cannot register callback for fwded replies in dialog\n");
		return ;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_REQ_WITHIN,
	topo_dlg_onroute, NULL , NULL)) {
		LM_ERR("cannot register callback for sequential requests\n");
		return ;
	}
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

	if(dlg_th_onreply(dlg, params->msg, t->uas.request, 1, DLG_DIR_UPSTREAM) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}


static void topo_dlg_onroute (struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params)
{
	int dir = params->direction;
	struct sip_msg *req = params->msg;

	if (!req) {
		LM_ERR("Called with NULL SIP message \n");
		return;
	}

	/* we also may end up here via TERMINATE event triggered by internal
	 * dlg termination -> the requests we have here are dummy, so nothing
	 * to be done */
	if (is_dummy_sip_msg(req)==0) {
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

	/* replace contact*/
	if(topo_dlg_replace_contact(req, dlg) < 0) {
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

	if (dir == DLG_DIR_UPSTREAM) {
		/* destination leg is the caller - force the send socket
		 * as the one the caller was inited from */
		req->force_send_socket = dlg->legs[DLG_CALLER_LEG].bind_addr;
		LM_DBG("forcing send socket for req going to caller\n");
	} else {
		/* destination leg is the callee - force the send socket
		 * as the one the callee was inited from */
		req->force_send_socket = dlg->legs[callee_idx(dlg)].bind_addr;
		LM_DBG("forcing send socket for req going to callee\n");
	}
}

static int dlg_th_onreply(struct dlg_cell *dlg, struct sip_msg *rpl,
								struct sip_msg *req, int init_req, int dir)
{
	int peer_leg;
	struct lump* lmp;
	int size;
	char* route;
	struct dlg_leg* leg;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(rpl, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}

	/* replace contact, but not if a redirect reply for initial INVITE */
	if ( !(init_req && dir == DLG_DIR_UPSTREAM &&
	rpl->REPLY_STATUS>=300 && rpl->REPLY_STATUS<400) ) {
		if(topo_dlg_replace_contact(rpl, dlg) < 0) {
			LM_ERR("Failed to replace contact\n");
			return -1;
		}
	}

	if(dir == DLG_DIR_UPSTREAM)
		peer_leg = DLG_CALLER_LEG;
	else
		peer_leg = callee_idx(dlg);
	leg = &dlg->legs[peer_leg];

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

	if(dlg_th_onreply(dlg, param->rpl, param->req,0, DLG_DIR_DOWNSTREAM) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}

static void th_up_onreply(struct cell* t, int type, struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (dlg==0)
		return;

	if(dlg_th_onreply(dlg, param->rpl, param->req, 0, DLG_DIR_UPSTREAM) < 0)
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

/* We encode the RR headers, the actual Contact and the socket str for this leg */
/* Via headers will be restored using the TM module, no need to save anything for them */
static char* build_encoded_contact_suffix(struct sip_msg* msg,int *suffix_len)
{
	short rr_len,ct_len,addr_len,enc_len;
	char *suffix_plain,*suffix_enc,*p,*s;
	str rr_set = {NULL, 0};
	str contact;
	int i,total_len;
	struct sip_uri ctu;
	struct th_ct_params* el;
	param_t *it;
	int is_req = (msg->first_line.type==SIP_REQUEST)?1:0;
	int local_len = sizeof(short) /* RR length */ +
			sizeof(short) /* Contact length */ +
			sizeof(short) /* bind addr */;

	/* parse all headers as we can have multiple
	   RR headers in the same message */
	if( parse_headers(msg,HDR_EOH_F,0)<0 ){
		LM_ERR("failed to parse all headers\n");
		return NULL;
	}

	if(msg->record_route){
		if(print_rr_body(msg->record_route, &rr_set, !is_req, 0, NULL) != 0){
			LM_ERR("failed to print route records \n");
			return NULL;
		}
		rr_len = (short)rr_set.len;
	} else {
		rr_len = 0;
	}

	if ( parse_contact(msg->contact)<0 ||
	((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
	((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
		LM_ERR("bad Contact HDR\n");
		goto error;
	} else {
		contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
		ct_len = (short)contact.len;
	}

	addr_len = (short)msg->rcv.bind_address->sock_str.len;
	local_len += rr_len + ct_len + addr_len; 
	enc_len = th_ct_enc_scheme == ENC_BASE64 ?
		calc_word64_encode_len(local_len) : calc_word32_encode_len(local_len);
	total_len = enc_len +  
		1 /* ; */ + 
		th_contact_encode_param.len + 
		1 /* = */  + 
		1 /* > */;	 

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
						if (el->param_name.len == ctu.u_name[i].len &&
						(memcmp(el->param_name.s,ctu.u_name[i].s,
						       el->param_name.len) == 0)) {
							if (ctu.u_val[i].len)
								total_len += 1 /* ; */ + ctu.u_name[i].len +
								ctu.u_val[i].len + 1; /* = and value */
							else
								total_len += 1 /* ; */ + ctu.u_name[i].len;
						}

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
					if (it->name.len == el->param_name.len &&
					(memcmp(it->name.s,el->param_name.s,it->name.len) == 0)) {
						if (it->body.len)
							total_len += 1 /* ; */ + it->name.len +
							it->body.len + 1; /* = and value */
						else
							total_len += 1 /* ; */ + it->name.len;
					}
				}
			}
		}
	}

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
	memcpy(p,&addr_len,sizeof(short));
	p+= sizeof(short);
	memcpy(p,msg->rcv.bind_address->sock_str.s,msg->rcv.bind_address->sock_str.len);
	p+= msg->rcv.bind_address->sock_str.len;
	for (i=0;i<(int)(p-suffix_plain);i++)
		suffix_plain[i] ^= topo_hiding_ct_encode_pw.s[i%topo_hiding_ct_encode_pw.len];

	s = suffix_enc;
	*s++ = ';';
	memcpy(s,th_contact_encode_param.s,th_contact_encode_param.len);
	s+= th_contact_encode_param.len;
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
				if (el->param_name.len == ctu.u_name[i].len &&
				memcmp(el->param_name.s,ctu.u_name[i].s,
				       el->param_name.len) == 0) {
					*s++ = ';';
					memcpy(s,ctu.u_name[i].s,ctu.u_name[i].len);
					s+=ctu.u_name[i].len;
					if (ctu.u_val[i].len) {
						*s++ = '=';
						memcpy(s,ctu.u_val[i].s,ctu.u_val[i].len);
						s+=ctu.u_val[i].len;
					}
				}
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
					if (it->name.len == el->param_name.len &&
					(memcmp(it->name.s,el->param_name.s,it->name.len) == 0)) {
						*s++ = ';';
						memcpy(s,it->name.s,it->name.len);
						s += it->name.len;
						if (it->body.len) {
							*s++ = '=';
							memcpy(s,it->body.s,it->body.len);
							s += it->body.len;
						}
					}
				}
			}
		}
	}

	if (rr_set.s)
		pkg_free(rr_set.s);
	pkg_free(suffix_plain);
	*suffix_len = total_len;
	return suffix_enc;
error:
	if (rr_set.s)
		pkg_free(rr_set.s);
	return NULL;
}

static int topo_no_dlg_encode_contact(struct sip_msg *msg,int flags) 
{
	struct lump* lump;
	char *prefix=NULL,*suffix=NULL,*ct_username=NULL;
	int prefix_len,suffix_len,ct_username_len=0;
	struct sip_uri ctu;
	str contact;

	if(!msg->contact) {
		if(parse_headers(msg, HDR_CONTACT_F, 0)< 0) {
			LM_ERR("Failed to parse headers\n");
			return -1;
		}
		if(!msg->contact)
			return 0;
	}

	if (!(lump = delete_existing_contact(msg))) {
		LM_ERR("Failed to delete existing contact \n");
		goto error;
	}

	prefix_len = 5; /* <sip: */
	if (flags & TOPOH_KEEP_USER) {
		if ( parse_contact(msg->contact)<0 ||
			((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
			((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
				LM_ERR("bad Contact HDR\n");
		} else {
			contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
			if(parse_uri(contact.s, contact.len, &ctu) < 0) {
				LM_ERR("Bad Contact URI\n");
			} else {
				ct_username = ctu.user.s;
				ct_username_len = ctu.user.len;
				LM_DBG("Trying to propagate username [%.*s]\n",ct_username_len,
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
	memcpy(prefix,"<sip:",5);
	if (flags & TOPOH_KEEP_USER && ct_username_len > 0) {
		memcpy(prefix+5,ct_username,ct_username_len);
		prefix[prefix_len-1] = '@';
	}

	if (!(lump = insert_new_lump_after(lump,prefix,prefix_len,HDR_CONTACT_T))) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}
	/* make sure we do not free this string in case of a further error */
	prefix = NULL;

	if (!(suffix = build_encoded_contact_suffix(msg,&suffix_len))) {
		LM_ERR("Failed to build suffix \n");
		goto error;
	}

	if (!(lump = insert_subst_lump_after(lump, SUBST_SND_ALL, HDR_CONTACT_T))) {
		LM_ERR("failed inserting SUBST_SND buf\n");
		goto error;
	}

	if (!(lump = insert_new_lump_after(lump,suffix,suffix_len,HDR_CONTACT_T))) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}

	return 0;
error:
	if (prefix) pkg_free(prefix);
	if (suffix) pkg_free(suffix);
	return -1;
}

#define ROUTE_STR "Route: "
#define ROUTE_LEN (sizeof(ROUTE_STR) - 1)
#define ROUTE_PREF "Route: <"
#define ROUTE_PREF_LEN (sizeof(ROUTE_PREF) -1)
#define ROUTE_SUFF ">\r\n"
#define ROUTE_SUFF_LEN (sizeof(ROUTE_SUFF) -1)

static int topo_no_dlg_seq_handling(struct sip_msg *msg,str *info)
{
	int max_size,dec_len,i,size;
	char *dec_buf,*p,*route=NULL,*hdrs,*remote_contact;
	struct hdr_field *it;
	str rr_buf,ct_buf,bind_buf;
	rr_t *head = NULL, *rrp;
	int next_strict=0;
	struct sip_uri fru;
	char* buf = msg->buf;
	struct lump* lmp = NULL;
	str host;
	int port,proto;
	struct socket_info *sock;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(msg, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}

	/* delete vias */
	if(topo_delete_vias(msg) < 0) {
		LM_ERR("Failed to remove via headers\n");
		return -1;
	}

	/* delete record route */
	for (it=msg->record_route;it;it=it->sibling) {
		if (del_lump(msg, it->name.s - buf, it->len, 0) == 0) {
			LM_ERR("del_lump failed\n");
			return -1;
		}
	}

	max_size = th_ct_enc_scheme == ENC_BASE64 ?
		calc_max_word64_decode_len(info->len) :
		calc_max_word32_decode_len(info->len);
	dec_buf = pkg_malloc(max_size);
	if (dec_buf==NULL) {
		LM_ERR("No more pkg\n");
		return -1;
	}

	if (th_ct_enc_scheme == ENC_BASE64)
		dec_len = word64decode((unsigned char *)dec_buf,
			(unsigned char *)info->s,info->len);
	else
		dec_len = word32decode((unsigned char *)dec_buf,
			(unsigned char *)info->s,info->len);
	for (i=0;i<dec_len;i++)
		dec_buf[i] ^= topo_hiding_ct_encode_pw.s[i%topo_hiding_ct_encode_pw.len]; 

	#define __extract_len_and_buf(_p, _len, _s) \
		do { \
			(_s).len = *(short *)p;\
			if ((_s).len<0 || (_s).len>_len) {\
				LM_ERR("bad length %hd in encoded contact\n", (short)(_s).len);\
				goto err_free_buf;\
			}\
			(_s).s = _p + sizeof(short);\
			_p += sizeof(short) + (_s).len;\
			_len -= sizeof(short) + (_s).len;\
		} while(0)

	p = dec_buf;
	size = dec_len;
	__extract_len_and_buf(p, size, rr_buf);
	__extract_len_and_buf(p, size, ct_buf);
	__extract_len_and_buf(p, size, bind_buf);

	LM_DBG("extracted routes [%.*s] , ct [%.*s] and bind [%.*s]\n",
		rr_buf.len,rr_buf.s,ct_buf.len,ct_buf.s,bind_buf.len,bind_buf.s);

	if (rr_buf.len) {
		if (parse_rr_body(rr_buf.s,rr_buf.len,&head) != 0) {
			LM_ERR("failed parsing route set\n");
			goto err_free_buf;
		}

		if(parse_uri(head->nameaddr.uri.s, head->nameaddr.uri.len, &fru) < 0) {
			LM_ERR("Failed to parse SIP uri\n");
			goto err_free_head;
		}
		if(is_strict(&fru.params))
			next_strict = 1;
	}

	if (msg->dst_uri.s && msg->dst_uri.len) {
		/* reset dst_uri if previously set
		 * either by loose route or manually */
		pkg_free(msg->dst_uri.s);
		msg->dst_uri.s = NULL;
		msg->dst_uri.len = 0;
	}

	if (!next_strict) {
		LM_DBG("Fixing message. Next hop is Loose router\n");
		if (ct_buf.len && ct_buf.s) {
			LM_DBG("Setting new URI to  <%.*s> \n",ct_buf.len,
					ct_buf.s);

			if (set_ruri(msg,&ct_buf) != 0) {
				LM_ERR("failed setting ruri\n");
				goto err_free_head;
			}
		}
		if( parse_headers( msg, HDR_EOH_F, 0)<0 ) {
			LM_ERR("failed to parse headers when looking after ROUTEs\n");
			goto err_free_head;
		}

		if (msg->route) {
			for (it=msg->route;it;it=it->sibling) {
				if (it->parsed && ((rr_t*)it->parsed)->deleted)
					continue;
				if ((lmp = del_lump(msg,it->name.s - buf,it->len,HDR_ROUTE_T)) == 0) {
					LM_ERR("del_lump failed \n");
					goto err_free_head;
				}
			}
		}

		if ( rr_buf.len !=0 && rr_buf.s) {

			lmp = anchor_lump(msg,msg->headers->name.s - buf,0);
			if (lmp == 0) {
				LM_ERR("failed anchoring new lump\n");
				goto err_free_head;
			}

			size = rr_buf.len + ROUTE_LEN + CRLF_LEN;
			route = pkg_malloc(size+1);
			if (route == 0) {
				LM_ERR("no more pkg memory\n");
				goto err_free_head;
			}

			memcpy(route,ROUTE_STR,ROUTE_LEN);
			memcpy(route+ROUTE_LEN,rr_buf.s,rr_buf.len);
			memcpy(route+ROUTE_LEN+rr_buf.len,CRLF,CRLF_LEN);

			route[size] = 0;

			if ((lmp = insert_new_lump_after(lmp,route,size,HDR_ROUTE_T)) == 0) {
				LM_ERR("failed inserting new route set\n");
				goto err_free_route;
			}

			LM_DBG("Setting route  header to <%s> \n",route);
			LM_DBG("setting dst_uri to <%.*s> \n",head->nameaddr.uri.len,
					head->nameaddr.uri.s);

			if (set_dst_uri(msg,&head->nameaddr.uri) !=0 ) {
				goto err_free_head;
			}
		}
	} else {
		LM_DBG("Fixing message. Next hop is Strict router\n");
		if (msg->route) {
			for (it=msg->route;it;it=it->sibling) {
				if (it->parsed && ((rr_t*)it->parsed)->deleted)
					continue;
				if ((lmp = del_lump(msg,it->name.s - buf,it->len,HDR_ROUTE_T)) == 0) {
					LM_ERR("del_lump failed \n");
					goto err_free_head;
				}
			}
		}

		if ( rr_buf.len !=0 && rr_buf.s) {
			if (set_ruri(msg,&head->nameaddr.uri) !=0 ) {
				LM_ERR("failed setting new dst uri\n");
				goto err_free_head;
			}
			i=0;
			rrp = head;
			while (rrp) {
				i++;
				rrp=rrp->next;
			}	

			/* If there are more routes other than the first, add them */
			if (i > 1) {
				lmp = anchor_lump(msg,msg->headers->name.s - buf,0);
				if (lmp == 0) {
					LM_ERR("failed anchoring new lump\n");
					goto err_free_head;
				}

				hdrs = rr_buf.s + head->len + 1;

				size = rr_buf.len - head->len - 1 + ROUTE_LEN + CRLF_LEN;
				route = pkg_malloc(size);
				if (route == 0) {
					LM_ERR("no more pkg memory\n");
					goto err_free_head;
				}

				memcpy(route,ROUTE_STR,ROUTE_LEN);
				memcpy(route+ROUTE_LEN,hdrs,rr_buf.len - head->len-1);
				memcpy(route+ROUTE_LEN+rr_buf.len - head->len-1,CRLF,CRLF_LEN);

				LM_DBG("Adding Route header : [%.*s] \n",size,route);

				if ((lmp = insert_new_lump_after(lmp,route,size,HDR_ROUTE_T)) == 0) {
					LM_ERR("failed inserting new route set\n");
					goto err_free_route;
				}
			}

			if (lmp == NULL) {
				lmp = anchor_lump(msg,msg->headers->name.s - buf,0);
				if (lmp == 0)
				{
					LM_ERR("failed anchoring new lump\n");
					return -1;
				}
			}

			if (ct_buf.len && ct_buf.s) {
				size = ct_buf.len + ROUTE_PREF_LEN + ROUTE_SUFF_LEN;
				remote_contact = pkg_malloc(size);
				if (remote_contact == NULL) {
					LM_ERR("no more pkg \n");
					goto err_free_head;
				}

				memcpy(remote_contact,ROUTE_PREF,ROUTE_PREF_LEN);
				memcpy(remote_contact+ROUTE_PREF_LEN,ct_buf.s,ct_buf.len);
				memcpy(remote_contact+ROUTE_PREF_LEN+ct_buf.len,
						ROUTE_SUFF,ROUTE_SUFF_LEN);

				LM_DBG("Adding remote contact route header : [%.*s]\n",
						size,remote_contact);

				if (insert_new_lump_after(lmp,remote_contact,size,HDR_ROUTE_T) == 0) {
					LM_ERR("failed inserting remote contact route\n");
					pkg_free(remote_contact);
					goto err_free_head;
				}
			}
		}
	}

	/* register tm callback for response in  */
	if (tm_api.register_tmcb( msg, 0, TMCB_RESPONSE_FWDED,
	th_no_dlg_onreply,NULL,NULL )<0 ) {
		LM_ERR("failed to register TMCB\n");
	}

	if (bind_buf.len && bind_buf.s) {
		LM_DBG("forcing send socket for req to [%.*s]\n",bind_buf.len,bind_buf.s);
		if (parse_phostport( bind_buf.s, bind_buf.len, &host.s, &host.len,
		&port, &proto)!=0) {
			LM_ERR("bad socket <%.*s>\n", bind_buf.len, bind_buf.s);
		} else {
			sock = grep_sock_info( &host, (unsigned short)port, proto);
			if (!sock) {
				LM_WARN("non-local socket <%.*s>...ignoring\n", bind_buf.len, bind_buf.s);
			}
			msg->force_send_socket = sock;
		}
	}

	if (rr_buf.len)
		free_rr(&head);
	pkg_free(dec_buf);

	if (topo_no_dlg_encode_contact(msg,0) < 0) {
		LM_ERR("Failed to encode contact header \n");
		return -1;
	}

	return 1;

err_free_route:
	if (route)
		pkg_free(route);
err_free_head:
	if (rr_buf.len)
		free_rr(&head);
err_free_buf:
	pkg_free(dec_buf);
	return -1;
}
