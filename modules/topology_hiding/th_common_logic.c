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

#include "th_common_logic.h"
#include "../../mem/mem.h"
#include "../../parser/hf.h"
#include "../../parser/parse_rr.h"
#include "../../msg_translator.h"

struct th_ct_params *th_param_list = NULL;
struct th_ct_params *th_hdr_param_list = NULL;

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

static int topo_parse_passed_params(str *params, struct th_ct_params **lst) {
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

int topo_parse_passed_ct_params(str *params)
{
	return topo_parse_passed_params(params, &th_param_list);
}

int topo_parse_passed_hdr_ct_params(str *params)
{
	return topo_parse_passed_params(params, &th_hdr_param_list);
}

static inline int topo_delete_record_route_or_route_uris(struct sip_msg *msg, hdr_types_t hdr_type, int uris_to_delete) {
	struct hdr_field *it = NULL;
	rr_t *curr_rr = NULL, *next_rr = NULL;
	unsigned int offset;
	int total_delete_count = 0;
    int delete_count = uris_to_delete > 0 ? uris_to_delete : 64;

	if (hdr_type != HDR_RECORDROUTE_T && hdr_type != HDR_ROUTE_T) {
		LM_ERR("Header type has to be one of Route or Record-Route\n");
		return -1;
	}

	LM_DBG("Attempting to delete %d '%s' headers\n", delete_count, hdr_type == HDR_RECORDROUTE_T ? "Record-Route" : "Route");

	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("Failed to parse '%s' headers\n", hdr_type == HDR_RECORDROUTE_T ? "Record-Route" : "Route");
		return -1;
	}
 
	it = hdr_type == HDR_RECORDROUTE_T ? msg->record_route : msg->route;
	while (it != NULL) {
		if (parse_rr(it) < 0) {
			LM_ERR("Failed to parse '%.*s' headers\n", it->name.len, it->name.s);
			return -1;
		}

		curr_rr = (rr_t*) it->parsed;
        next_rr = NULL;
		offset = 0;
		while (curr_rr) {
            next_rr = curr_rr->next;

            if (next_rr != NULL) {
                offset += next_rr->nameaddr.name.s - curr_rr->nameaddr.name.s;
            }

            curr_rr = next_rr;

			if (++total_delete_count == delete_count) {
				break;
			}
		}

		if (curr_rr == NULL) {
			if (del_lump(msg, it->name.s - msg->buf, it->len, hdr_type) == NULL) {
				LM_ERR("del_lump failed \n");
				return -1;
			}
		} else {
			if (del_lump(msg, it->body.s - msg->buf, offset, 0) == NULL) {
				LM_ERR("Failed to remove '%.*s' header\n",  it->name.len, it->name.s);
				return -1;
			}
		}

		if (total_delete_count == delete_count) {
			break;
		}

		it = it->sibling;
	}

    LM_DBG("Deleted %d '%s' headers\n", total_delete_count, hdr_type == HDR_RECORDROUTE_T ? "Record-Route" : "Route");

	return 1;
}

int topo_delete_route_uris(struct sip_msg *msg, int delete_count) {
	return topo_delete_record_route_or_route_uris(msg, HDR_ROUTE_T, delete_count);
}

int topo_delete_record_route_uris(struct sip_msg *msg, int delete_count) {
	return topo_delete_record_route_or_route_uris(msg, HDR_RECORDROUTE_T, delete_count);
}

int topo_delete_record_routes(struct sip_msg *req) {
	struct lump* lump, *crt, *prev_crt =0, *a, *foo;
	struct hdr_field *it;
	char* buf;

	/* FIXME - we will be losing uac_replace_from/to in case of no dialog */

	/* delete also the added record route and the did param */
	for(crt = req->add_rm; crt;) {
		if ((crt->type == HDR_RECORDROUTE_T) && (crt->op == LUMP_NOP) ) {
			/* lump found */
			lump = crt;
			crt = crt->next;
			a = lump->before;
			while(a) {
				foo = a; a = a->before;
				if (!(foo->flags & LUMPFLAG_SHMEM))
					free_lump(foo);
				if (!(foo->flags & LUMPFLAG_SHMEM))
					pkg_free(foo);
			}

			a = lump->after;
			while(a) {
				foo = a; a = a->after;
				if (!(foo->flags & LUMPFLAG_SHMEM))
					free_lump(foo);
				if (!(foo->flags & LUMPFLAG_SHMEM))
					pkg_free(foo);
			}
			if (lump == req->add_rm) {
				if (lump->flags & LUMPFLAG_SHMEM) {
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
			if (!(lump->flags & LUMPFLAG_SHMEM))
				free_lump(lump);
			if (!(lump->flags & LUMPFLAG_SHMEM))
				pkg_free(lump);
			continue;
		}
		prev_crt = crt;
		crt = crt->next;
	}

	buf = req->buf;

	/* delete record-route headers */
	for (it = req->record_route; it; it = it->sibling) {
		if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
			LM_ERR("del_lump failed - while deleting record-route\n");
			return -1;
		}
	}

	return 0;
}

int topo_delete_vias(struct sip_msg *req) {
	struct hdr_field *it;
	char *buf;

	/* parse all headers to be sure that all VIAs are found */
	if (parse_headers(req, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}

	buf = req->buf;
	it = req->h_via1;
	if (it) {
		/* delete first via1 to set the type (the build_req_buf_from_sip_req will know not to add lump in via1)*/
		if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
			LM_ERR("del_lump failed\n");
			return -1;
		}
		LM_DBG("Delete via [%.*s]\n", it->len, it->name.s);
		for (it = it->sibling; it; it = it->sibling) {
			if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
				LM_ERR("del_lump failed\n");
				return -1;
			}
			LM_DBG("Delete via [%.*s]\n", it->len, it->name.s);
		}
	}

	return 0;
}

struct lump* delete_existing_contact(struct sip_msg *msg, int del_hdr) {
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

	if (del_hdr) {
		/* we were asked to delete the entire header */
		offset = msg->contact->name.s - msg->buf;
		len = msg->contact->len;
	} else {
		/* delete only the contact */
		offset = msg->contact->body.s - msg->buf;
		len = msg->contact->body.len;
	}

	if ((lump = del_lump(msg, offset, len, HDR_CONTACT_T)) == 0) {
		LM_ERR("del_lump failed\n");
		return NULL;
	}

	return lump;
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

		LM_DBG("built [%.*s], %d %d\n",(int)(p-via_str.s), via_str.s, (int)(p-via_str.s), via_str.len);

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