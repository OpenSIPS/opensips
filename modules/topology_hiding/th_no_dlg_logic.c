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
#include "../dialog/dlg_hash.h"
#include "../tm/tm_load.h"
#include "../rr/loose.h"

struct th_no_dlg_param {
	str routes;
	str username;
};

extern struct tm_binds tm_api;
extern struct th_ct_params *th_param_list;
extern struct th_ct_params *th_hdr_param_list;
extern str topo_hiding_ct_encode_pw;
extern str th_contact_encode_param;
extern int th_ct_enc_scheme;

/* We encode the RR headers, the actual Contact and the socket str for this leg */
/* Via headers will be restored using the TM module, no need to save anything for them */
static char* build_encoded_contact_suffix(struct sip_msg* msg, str *routes, int *suffix_len, int flags)
{
	short rr_len,ct_len,addr_len,flags_len,enc_len;
	char *suffix_plain,*suffix_enc,*p,*s;
	str rr_set = {NULL, 0};
	str contact;
	str flags_str;
	int i,total_len;
	struct sip_uri ctu;
	struct th_ct_params* el;
	param_t *it;
	int is_req = (msg->first_line.type==SIP_REQUEST)?1:0;
	int local_len = sizeof(short) /* RR length */ +
			sizeof(short) /* Contact length */ +
			sizeof(short) /* Flags length */ +
			sizeof(short) /* bind addr */;

	/* parse all headers as we can have multiple
	   RR headers in the same message */
	if( parse_headers(msg,HDR_EOH_F,0)<0 ){
		LM_ERR("failed to parse all headers\n");
		return NULL;
	}

	if (routes && routes->len) {
		rr_set = *routes;
		rr_len = (short)routes->len;
	} else if(msg->record_route){
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

	flags_str.s = int2str(flags, &flags_str.len);
	flags_len = (short)flags_str.len;
	
	addr_len = (short)msg->rcv.bind_address->sock_str.len;
	local_len += rr_len + ct_len + flags_len + addr_len; 
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
						if (str_match(&el->param_name, &ctu.u_name[i]))
							total_len += topo_ct_param_len(&ctu.u_name[i], &ctu.u_val[i], 0);
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
						total_len += topo_ct_param_len(&it->name, &it->body, 1);
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
	memcpy(p,&flags_len,sizeof(short));
	p+= sizeof(short);
	memcpy(p,flags_str.s, flags_str.len);
	p+= flags_str.len;
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

	if (rr_set.s && !routes)
		pkg_free(rr_set.s);
	pkg_free(suffix_plain);
	*suffix_len = total_len;
	return suffix_enc;
error:
	if (rr_set.s)
		pkg_free(rr_set.s);
	return NULL;
}


static void _th_no_dlg_onreply(struct cell* t, int type, struct tmcb_params *param,int flags, int do_rr)
{
	struct lump* lmp;
	str rr_set;
	struct th_no_dlg_param *p = *(param->param);
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
		if (topo_no_dlg_encode_contact(rpl,flags,
				(p?&p->routes:NULL),(p?&p->username:NULL)) < 0) {
			LM_ERR("Failed to encode contact header \n");
			return;
		}
	}

	if (!(lmp = restore_vias_from_req(req,rpl))) {
		LM_ERR("Failed to restore VIA headers from request \n");
		return ;
	}

	/* pass record route headers */
	if(do_rr && req->record_route){
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
	_th_no_dlg_onreply(t,type,param,0,1);
}

static void th_no_dlg_user_onreply(struct cell* t, int type, struct tmcb_params *param)
{
	_th_no_dlg_onreply(t,type,param,TOPOH_KEEP_USER,1);
}

static void th_no_dlg_onreply_within(struct cell* t, int type, struct tmcb_params *param)
{
	_th_no_dlg_onreply(t,type,param,0,0);
}

static void th_no_dlg_user_onreply_within(struct cell* t, int type, struct tmcb_params *param)
{
	_th_no_dlg_onreply(t,type,param,TOPOH_KEEP_USER,0);
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

int topo_hiding_no_dlg(struct sip_msg *req,
		struct cell* t,int extra_flags,struct th_params *params) {
	transaction_cb* used_cb;
	struct th_no_dlg_param *p = NULL;

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

	if (topo_no_dlg_encode_contact(req,extra_flags,NULL, &params->ct_caller_user) < 0) {
		LM_ERR("Failed to encode contact header \n");
		return -1;
	}

	if (extra_flags & TOPOH_KEEP_USER) {
		used_cb = th_no_dlg_user_onreply;
	} else {
		used_cb = th_no_dlg_onreply;
		if (params && params->ct_callee_user.len) {
			p = shm_malloc(sizeof *p + params->ct_callee_user.len);
			if (p) {
				memset(p, 0, sizeof *p);
				p->username.s = (char *)(p + 1);
				p->username.len =  params->ct_callee_user.len;
				memcpy(p->username.s,  params->ct_callee_user.s,
						params->ct_callee_user.len);
			}
		}
	}

	if (extra_flags & TOPOH_HIDE_CALLID)
		LM_WARN("Cannot hide callid when dialog support is not engaged!\n");
	if (extra_flags & TOPOH_DID_IN_USER)
		LM_WARN("Cannot store DID in user when dialog support is not engaged!\n");

	if (tm_api.register_tmcb( req, 0, TMCB_RESPONSE_FWDED,
	used_cb,p, (p?shm_free_wrap:NULL))<0 ) {
		LM_ERR("failed to register TMCB\n");
		return -1;
	}

	return 1;
}

#define ROUTE_STR "Route: "
#define ROUTE_LEN (sizeof(ROUTE_STR) - 1)
#define ROUTE_PREF "Route: <"
#define ROUTE_PREF_LEN (sizeof(ROUTE_PREF) -1)
#define ROUTE_SUFF ">\r\n"
#define ROUTE_SUFF_LEN (sizeof(ROUTE_SUFF) -1)

int topo_no_dlg_seq_handling(struct sip_msg *msg,str *info)
{
	int max_size,dec_len,i,size,flags;
	char *dec_buf,*p,*route=NULL,*hdrs,*remote_contact;
	struct hdr_field *it;
	str rr_buf,ct_buf,flags_buf,bind_buf;
	rr_t *head = NULL, *rrp;
	int next_strict=0;
	struct sip_uri fru;
	char* buf = msg->buf;
	struct lump* lmp = NULL;
	str host;
	int port,proto;
	const struct socket_info *sock;
	str route_buf = {0, 0};
	struct th_no_dlg_param *param = NULL;
	transaction_cb* used_cb;

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
				LM_ERR("bad length %d in encoded contact\n", (_s).len);\
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
	__extract_len_and_buf(p, size, flags_buf);
	__extract_len_and_buf(p, size, bind_buf);

	LM_DBG("extracted routes [%.*s] , ct [%.*s] , flags [%.*s] and bind [%.*s]\n",
		rr_buf.len,rr_buf.s,ct_buf.len,ct_buf.s,flags_buf.len,flags_buf.s,bind_buf.len,bind_buf.s);

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
			msg->msg_flags |= FL_HAS_ROUTE_LUMP;
			route_buf = rr_buf;

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
				msg->msg_flags |= FL_HAS_ROUTE_LUMP;
				route_buf.s = route;
				route_buf.len = rr_buf.len - head->len - 1;
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
				msg->msg_flags |= FL_HAS_ROUTE_LUMP;
			}
		}
	}
	if (route_buf.s && route_buf.len) {
		param = shm_malloc(sizeof *param + route_buf.len);
		if (param) {
			memset(param, 0, sizeof *param);
			param->routes.s = (char *)(param + 1);
			param->routes.len = route_buf.len;
			memcpy(param->routes.s, route_buf.s, route_buf.len);
		}
	}

	if (flags_buf.len && flags_buf.s) {
		if (str2int(&flags_buf, (unsigned int*) &flags) < 0) {
			LM_WARN("Failed to convert string to integer, default to no flags\n");
			flags = 0;
		}
	} else {
		flags = 0;
	}

	if (flags & TOPOH_KEEP_USER)
		used_cb = th_no_dlg_user_onreply_within;
	else
		used_cb = th_no_dlg_onreply_within;

	/* register tm callback for response in  */
	if (tm_api.register_tmcb( msg, 0, TMCB_RESPONSE_FWDED,
	used_cb,param,(param?shm_free_wrap:NULL))<0 ) {
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

	if (topo_no_dlg_encode_contact(msg,flags,NULL,NULL) < 0) {
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
