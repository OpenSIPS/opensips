/*
 * presence module - presence server implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-08-15  initial version (Anca Vamanu)
 *  2010-10-19  support for extra headers (osas)
 */

#include <time.h>

#include "../../ut.h"
#include "../../str.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_event.h"
#include "../../parser/parse_content.h"
#include "../../lock_ops.h"
#include "../../hash_func.h"
#include "../../db/db.h"
#include "../../evi/evi_modules.h"
#include "presence.h"
#include "notify.h"
#include "utils_func.h"
#include "publish.h"
#include "presentity.h"
#include "clustering.h"

static str pu_400_rpl = str_init("Bad request");
static str pu_500_rpl  = str_init("Server Internal Error");
static str pu_489_rpl  = str_init("Bad Event");

struct p_modif
{
	presentity_t* p;
	str uri;
};

#define MAX_NO_OF_EXTRA_HDRS 4


void presence_raise_event(event_id_t event, presentity_t* presentity)
{
        evi_params_p list;
        static str parameter_user_str = { "user", 4 };
        static str parameter_domain_str = { "domain", 6 };
        static str parameter_eventname_str = { "event", 5 };
        static str parameter_expires_str = { "expires", 7 };
        static str parameter_etag_str = { "etag", 4 };
        static str parameter_body_str = { "body", 4 };
        if (event == EVI_ERROR) {
                LM_ERR("event not registered %d\n", presence_event_id);
                return;
        }

        if (evi_probe_event(event)) {
                if (!(list = evi_get_params()))
                        return;
                //if (evi_param_add_str(list, &parameter_user_str, &user)) {
                if (evi_param_add_str(list, &parameter_user_str, &presentity->user)) {
                         LM_ERR("unable to add user parameter\n");
                         evi_free_params(list);
                         return;
                }
                if (evi_param_add_str(list, &parameter_domain_str, &presentity->domain)) {
                         LM_ERR("unable to add domain parameter\n");
                         evi_free_params(list);
                         return;
                }
                if (evi_param_add_str(list, &parameter_eventname_str, &presentity->event->name)) {
                         LM_ERR("unable to add event parameter\n");
                         evi_free_params(list);
                         return;
                }
                if (evi_param_add_int(list, &parameter_expires_str, &presentity->expires)) {
                         LM_ERR("unable to add expires parameter\n");
                         evi_free_params(list);
                         return;
                }
                if (evi_param_add_str(list, &parameter_etag_str, &presentity->new_etag)) {
                         LM_ERR("unable to add etag parameter\n");
                         evi_free_params(list);
                         return;
                }
                if (evi_param_add_str(list, &parameter_body_str, &presentity->body)) {
                         LM_ERR("unable to add body parameter\n");
                         evi_free_params(list);
                         return;
                }
                if (evi_raise_event(event, list)) {
                        LM_ERR("unable to send event %d\n", presence_event_id);
                }
        } else {
                LM_DBG("no event sent\n");
        }
}


static inline void build_extra_hdrs(struct sip_msg* msg, const str* map, str* extra_hdrs)
{
	struct hdr_field *hf;
	str xtra_hdr_list[MAX_NO_OF_EXTRA_HDRS];
	char *p;
	int is_present, len=0, i=0;

	memset(xtra_hdr_list, 0, MAX_NO_OF_EXTRA_HDRS* sizeof(str));
	for (; map->s; map++) {
		if (i>=MAX_NO_OF_EXTRA_HDRS) {
			LM_WARN("maximum no of extra headers reached: "
				"increase MAX_NO_OF_EXTRA_HDRS and recompile\n");
			break;
		}
		is_present = 0;
		for (hf=msg->headers; hf; hf=hf->next) {
			if (hf->name.len!=map->len)
				continue;
			if (strncasecmp(hf->name.s,map->s,map->len)!=0)
				continue;
			is_present = 1;
			break;
		}
		if (is_present) {
			/* insert the header into the list */
			LM_DBG("found '%.*s'\n", hf->len, hf->name.s);
			xtra_hdr_list[i].s = hf->name.s;
			xtra_hdr_list[i].len = hf->len;
			len+= hf->len;
			i++;
		}
	}

	/* Concatenate found feaders */
	if (len) {
		p= (char*)pkg_malloc(len);
		if (p==NULL) {
			LM_ERR("oom: dropping extra hdrs\n");
			return;
		}
		extra_hdrs->s = p;
		extra_hdrs->len = len;
		for (i=0;i<MAX_NO_OF_EXTRA_HDRS;i++) {
			if (xtra_hdr_list[i].len) {
				memcpy(p, xtra_hdr_list[i].s, xtra_hdr_list[i].len);
				p+= xtra_hdr_list[i].len;
			} else {
				break;
			}
		}
	}
}

void msg_presentity_clean(unsigned int ticks,void *interval)
{
	static db_ps_t my_ps_delete = NULL;
	//static db_ps_t my_ps_select = NULL;
	static unsigned int last_expire_check = 0;
	db_key_t db_keys[2];
	db_val_t db_vals[2];
	db_op_t  db_ops[2] ;
	db_key_t result_cols[6];
	db_res_t *result = NULL;
	db_row_t *row ;
	db_val_t *row_vals ;
	int i =0, size= 0;
	struct p_modif* p= NULL;
	presentity_t* pres= NULL;
	int n= 0;
	int event_col, etag_col, user_col, domain_col;
	event_t ev;
	str user, domain, etag, event;
	int n_result_cols= 0;
	str* rules_doc= NULL;
	static str query_str = str_init("username");
	str **sh_tags;

	if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
	{
		LM_ERR("in use_table\n");
		return ;
	}

	sh_tags = is_presence_cluster_enabled() ?
		c_api.shtag_get_all_active(pres_cluster_id) : NULL;

	LM_DBG("cleaning expired presentity information\n");

	db_keys[0] = &str_expires_col;
	db_ops[0] = OP_GT;
	db_vals[0].type = DB_INT;
	db_vals[0].nul = 0;
	db_vals[0].val.int_val = last_expire_check;

	db_keys[1] = &str_expires_col;
	db_ops[1] = OP_LT;
	db_vals[1].type = DB_INT;
	db_vals[1].nul = 0;
	db_vals[1].val.int_val = (int)time(NULL) -10;

	last_expire_check = db_vals[1].val.int_val - 1;

	result_cols[user_col= n_result_cols++] = &str_username_col;
	result_cols[domain_col=n_result_cols++] = &str_domain_col;
	result_cols[etag_col=n_result_cols++] = &str_etag_col;
	result_cols[event_col=n_result_cols++] = &str_event_col;

	//CON_PS_REFERENCE(pa_db) = &my_ps_select;
	if(pa_dbf.query(pa_db, db_keys, db_ops, db_vals, result_cols,
						2, n_result_cols, &query_str, &result )< 0)
	{
		LM_ERR("querying database for expired messages\n");
		if(result)
			pa_dbf.free_result(pa_db, result);
		return;
	}
	if(result== NULL)
		return;

	if(result && result->n<= 0)
	{
		pa_dbf.free_result(pa_db, result);
		return;
	}
	LM_DBG("found n= %d expires messages\n",result->n);

	n= result->n;

	p= (struct p_modif*)pkg_malloc(n* sizeof(struct p_modif));
	if(p== NULL)
	{
		LM_ERR("failed to PKG allocate presentity array of %d\n",n);
		pa_dbf.free_result(pa_db, result);
		return;
	}
	memset(p, 0, n* sizeof(struct p_modif));

	for(i = 0; i< n; i++)
	{
		row = &result->rows[i];
		row_vals = ROW_VALUES(row);

		user.s= (char*)row_vals[user_col].val.string_val;
		user.len= strlen(user.s);

		domain.s= (char*)row_vals[domain_col].val.string_val;
		domain.len= strlen(domain.s);

		etag.s= (char*)row_vals[etag_col].val.string_val;
		etag.len= strlen(etag.s);

		event.s= (char*)row_vals[event_col].val.string_val;
		event.len= strlen(event.s);

		size= sizeof(presentity_t) + user.len+ domain.len+ etag.len;
		pres= (presentity_t*)pkg_malloc(size);
		if(pres== NULL)
		{
			LM_ERR("failde to PKG allocate new presentity\n");
			p[i].p = 0;
			continue;
		}
		memset(pres, 0, size);
		size= sizeof(presentity_t);

		pres->user.s= (char*)pres+ size;
		memcpy(pres->user.s, user.s, user.len);
		pres->user.len= user.len;
		size+= user.len;

		pres->domain.s= (char*)pres+ size;
		memcpy(pres->domain.s, domain.s, domain.len);
		pres->domain.len= domain.len;
		size+= domain.len;

		pres->new_etag.s= (char*)pres+ size;
		memcpy(pres->new_etag.s, etag.s, etag.len);
		pres->new_etag.len= etag.len;
		//size+= etag.len;

		pres->event= contains_event(&event, &ev);
		if(pres->event== NULL)
		{
			LM_DBG("event not found\n");
			p[i].p = 0;
			continue;
		}
		if(uandd_to_uri(user, domain, &p[i].uri)< 0)
		{
			LM_ERR("constructing uri\n");
			free_event_params(ev.params, PKG_MEM_TYPE);
			p[i].p = 0;
			continue;
		}
		free_event_params(ev.params, PKG_MEM_TYPE);
		p[i].p= pres;
	}
	pa_dbf.free_result(pa_db, result);
	result= NULL;

	for(i= 0; i<n ; i++)
	{
		if(p[i].p == 0)
			continue;

		LM_DBG("found expired publish for [user]=%.*s  [domanin]=%.*s\n",
			p[i].p->user.len,p[i].p->user.s,
			p[i].p->domain.len, p[i].p->domain.s);

		rules_doc= NULL;

		if(p[i].p->event->get_rules_doc &&
		p[i].p->event->get_rules_doc(&p[i].p->user, &p[i].p->domain, &rules_doc)< 0)
		{
			LM_ERR("getting rules doc\n");
			continue;
		}
		if(publ_notify( p[i].p, p[i].uri, NULL, &p[i].p->new_etag, rules_doc,
		NULL, 0, sh_tags)< 0)
		{
			LM_ERR("sending Notify request\n");
			continue;
		}
		if(rules_doc)
		{
			if(rules_doc->s)
				pkg_free(rules_doc->s);
			pkg_free(rules_doc);
		}
		rules_doc= NULL;
		/* delete from hash table */
		if(delete_phtable_query(&p[i].uri, ev.parsed, &p[i].p->new_etag)< 0)
		{
			LM_ERR("deleting from pres hash table\n");
		}
	}

	if(result)
		pa_dbf.free_result(pa_db, result);

	/* now remove the expired records from DB ; just to be sure
	 * that the presentity was handled (as expired) on all presence 
	 * servers (if DB is shared), remove from only presentities older
	 * than 3 times the timer cycle */
	db_vals[1].val.int_val -= 3 * ((int)(long)interval);

	if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
	{
		LM_ERR("in use_table\n");
	} else {
		CON_PS_REFERENCE(pa_db) = &my_ps_delete;
		if (pa_dbf.delete(pa_db, db_keys+1, db_ops+1, db_vals+1, 1) < 0)
			LM_ERR("cleaning expired messages\n");
	}

	if(p)
	{
		for(i= 0; i< n; i++)
		{

			if(p[i].p)
				pkg_free(p[i].p);
			if(p[i].uri.s)
				pkg_free(p[i].uri.s);
			else
				break;
		}
		pkg_free(p);
	}
	if(rules_doc)
	{
		if(rules_doc->s)
			pkg_free(rules_doc->s);
		pkg_free(rules_doc);
	}
}

/**
 * PUBLISH request handling
 *		returns:
 *				0: success
 *				-1: error
 *		- sends a reply in all cases (success or error).
 **/

int handle_publish(struct sip_msg* msg, str* sender_uri)
{
	struct sip_uri puri;
	str body;
	int lexpire;
	presentity_t presentity;
	struct hdr_field* hdr;
	int etag_new = 0;
	str etag={NULL, 0};
	str extra_hdrs={NULL, 0};
	str* sender= NULL;
	pres_ev_t* event= NULL;
	str pres_user;
	str pres_domain;
	int reply_code;
	str reply_str;
	int sent_reply= 0;
	char* sphere= NULL;

	reply_code= 400;
	reply_str= pu_400_rpl;

	counter++;
	if ( parse_headers(msg,HDR_EOH_F, 0)==-1 )
	{
		LM_ERR("parsing headers\n");
		goto error;
	}
	memset(&body, 0, sizeof(str));

	/* inspecting the Event header field */

	if(msg->event && msg->event->body.len > 0)
	{
		if (!msg->event->parsed && (parse_event(msg->event) < 0))
		{
			LM_ERR("cannot parse Event header\n");
			goto error;
		}
		if(((event_t*)msg->event->parsed)->parsed == EVENT_OTHER)
		{
			LM_ERR("unrecognized value [%.*s] in Event header\n",
				msg->event->body.len, msg->event->body.s);
			goto unsupported_event;
		}
	} else {
		LM_ERR("Missing Event header\n");
		goto unsupported_event;
	}

	/* search event in the list */
	event= search_event((event_t*)msg->event->parsed);
	if(event== NULL)
	{
		LM_ERR("un-registered support for known event [%.*s]\n",
			msg->event->body.len, msg->event->body.s);
		goto unsupported_event;
	}


	/* examine the expire header field */
	if(msg->expires && msg->expires->body.len > 0)
	{
		if (!msg->expires->parsed && (parse_expires(msg->expires) < 0))
		{
			LM_ERR("cannot parse Expires header\n");
			goto error;
		}
		lexpire = ((exp_body_t*)msg->expires->parsed)->val;
		LM_DBG("Expires header found, value= %d\n", lexpire);

	}
	else
	{
		LM_DBG("'expires' not found; default=%d\n",	event->default_expires);
		lexpire = event->default_expires;
	}
	if(lexpire > max_expires_publish)
		lexpire = max_expires_publish;

	/* get pres_uri from Request-URI*/
	if( parse_sip_msg_uri(msg)< 0)
	{
		LM_ERR("parsing Request URI\n");
		goto error;
	}
	pres_user= msg->parsed_uri.user;
	pres_domain= msg->parsed_uri.host;

	/* examine the SIP-If-Match header field */
	hdr = get_header_by_static_name( msg, "SIP-If-Match");
	if( hdr==NULL )
	{
		LM_DBG("SIP-If-Match header not found\n");
		if(generate_ETag(0, &etag) < 0)
		{
			LM_ERR("when generating etag\n");
			reply_code = 500;
			reply_str= pu_500_rpl;
			goto error;
		}
		etag_new=1;
		LM_DBG("new etag= %.*s\n", etag.len, etag.s);
	}
	else
	{
		LM_DBG("SIP-If-Match header found\n");
		etag = hdr->body;
		LM_DBG("existing etag= %.*s\n", etag.len, etag.s);
	}

	if (!msg->content_length)
	{
		LM_ERR("no Content-Length header found!\n");
		goto error;
	}

	/* process the body */
	if ( get_content_length(msg) == 0 )
	{
		body.s = NULL;
		if (etag_new)
		{
			if (event->mandatory_body)
			{
				LM_ERR("No E-Tag and no body found\n");
				goto error;
			}
		}
	}
	else
	{
		if ( event->content_type.len )
		{
			if (get_body(msg,&body)!=0 || body.len==0)
			{
				LM_ERR("cannot extract body\n");
				goto error;
			}

			if(sphere_enable && event->evp->parsed == EVENT_PRESENCE &&
				get_content_type(msg)== SUBTYPE_PIDFXML)
			{
				sphere= extract_sphere(body);
			}
		}
	}

	memset(&puri, 0, sizeof(struct sip_uri));
	if(sender_uri)
	{
		sender=(str*)pkg_malloc(sizeof(str));
		if(sender== NULL)
		{
			ERR_MEM(PKG_MEM_STR);
		}
		if(parse_uri(sender_uri->s, sender_uri->len, &puri)!=0)
		{
			LM_ERR("bad sender SIP address!\n");
			goto error;
		}
		else
		{
			LM_DBG("using user id [%.*s]\n",sender_uri->len,sender_uri->s);
		}
		*sender = *sender_uri;
	}
	/* call event specific handling function*/
	if(event->evs_publ_handl)
	{
		if(event->evs_publ_handl(msg, &sent_reply)< 0)
		{
			LM_ERR("in event specific publish handling\n");
			reply_code = 500;
			reply_str = pu_500_rpl;
			goto error;
		}
	}

	/* build extra headers list */
	if (event->extra_hdrs)
		build_extra_hdrs(msg, event->extra_hdrs, &extra_hdrs);

	/* now we have all the necessary values */
	/* fill in the filds of the structure */
	memset(&presentity, 0, sizeof(presentity_t));
	presentity.domain = pres_domain;
	presentity.user   = pres_user;
	if (etag_new)
		presentity.new_etag = etag;
	else
		presentity.old_etag = etag;
	if(sender)
		presentity.sender= sender;
	presentity.event= event;
	presentity.expires = lexpire;
	presentity.received_time= (int)time(NULL);
	if(extra_hdrs.s)
		presentity.extra_hdrs = &extra_hdrs;
	presentity.etag_new = etag_new;
	presentity.sphere = sphere;
	presentity.body = body;

	/* send event E_PRESENCE_PUBLISH */
	presence_raise_event(presence_event_id, &presentity);

	/* querry the database and update or insert */
	if(update_presentity(msg, &presentity, &sent_reply) <0)
	{
		LM_ERR("when updating presentity\n");
		reply_code = 500;
		reply_str = pu_500_rpl;
		goto error;
	}

	/* see if this PUBLISH needs to be replicated via cluster */
	if (is_cluster_federation_enabled() &&
	is_event_clustered(event->evp->parsed))
		replicate_publish_on_cluster(&presentity);

	if(sender)
		pkg_free(sender);
	if(sphere)
		pkg_free(sphere);
	if(extra_hdrs.s)
		pkg_free(extra_hdrs.s);

	return 1;

unsupported_event:

	LM_ERR("Missing or unsupported event header field value\n");

	if(msg->event && msg->event->body.s && msg->event->body.len>0)
		LM_ERR("\tevent=[%.*s]\n", msg->event->body.len, msg->event->body.s);

	reply_code= BAD_EVENT_CODE;
	reply_str=	pu_489_rpl;

error:
	if(sent_reply== 0)
	{
		if(send_error_reply(msg, reply_code, reply_str)< 0)
		{
			LM_ERR("failed to send error reply\n");
		}
	}
	if(sender)
		pkg_free(sender);
	if(sphere)
		pkg_free(sphere);
	if(extra_hdrs.s)
		pkg_free(extra_hdrs.s);

	return -1;
}


