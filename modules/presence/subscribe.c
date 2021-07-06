/*
 * presence module - presence server implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 *
 * This file is part of opensips, a free SIP serves.
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

#include "../../ut.h"
#include "../../usr_avp.h"
#include "../../mod_fix.h"
#include "../../data_lump_rpl.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_event.h"
#include "../../parser/contact/parse_contact.h"
#include "../pua/hash.h"
#include "presence.h"
#include "subscribe.h"
#include "utils_func.h"
#include "notify.h"
#include "clustering.h"


int get_stored_info(struct sip_msg* msg, subs_t* subs, int* error_ret,
		str* reply_str);
int get_database_info(struct sip_msg* msg, subs_t* subs, int* error_ret,
		str* reply_str);
int get_db_subs_auth(subs_t* subs, int* found);
int insert_db_subs_auth(subs_t* subs);
int insert_subs_db(subs_t* s);

static str su_200_rpl  = str_init("OK");
static str pu_481_rpl  = str_init("Subscription does not exist");
static str pu_400_rpl  = str_init("Bad request");
static str pu_500_rpl  = str_init("Server Internal Error");
static str pu_489_rpl  = str_init("Bad Event");


int send_2XX_reply(struct sip_msg * msg, int reply_code, int lexpire,
		str *rtag, str* local_contact)
{
	char * hdr_append=NULL;
	int lexpire_len;
	char *lexpire_s;
	int len;
	char *p;

	if(lexpire < 0 )
		lexpire = 0;

	lexpire_s = int2str((unsigned long)lexpire, &lexpire_len);

	len = 9 /*"Expires: "*/ + lexpire_len + CRLF_LEN
		+ 10 /*"Contact: <"*/ + local_contact->len + 1 /*">"*/ + CRLF_LEN;

	hdr_append = (char *)pkg_malloc( len );
	if(hdr_append == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}

	p = hdr_append;
	/* expires header */
	memcpy(p, "Expires: ", 9);
	p += 9;
	memcpy(p,lexpire_s,lexpire_len);
	p += lexpire_len;
	/* contact header */
	memcpy(p, CRLF "Contact: <", CRLF_LEN+10);
	p += CRLF_LEN + 10;
	memcpy(p,local_contact->s,local_contact->len);
	p += local_contact->len;
	memcpy(p, ">" CRLF, 1+CRLF_LEN);
	p += 1+CRLF_LEN;

	if (add_lump_rpl( msg, hdr_append, p-hdr_append, LUMP_RPL_HDR)==0 )
	{
		LM_ERR("unable to add lump_rl\n");
		goto error;
	}

	if( sigb.reply( msg, reply_code, &su_200_rpl, rtag)== -1)
	{
		LM_ERR("sending reply\n");
		goto error;
	}

	pkg_free(hdr_append);
	return 0;

error:
	if (hdr_append)
		pkg_free(hdr_append);
	return -1;
}


int delete_db_subs(str pres_uri, str ev_stored_name, str to_tag)
{
	static db_ps_t my_ps = NULL;
	db_key_t query_cols[5];
	db_val_t query_vals[5];
	int n_query_cols= 0;

	query_cols[n_query_cols] = &str_presentity_uri_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = pres_uri;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = ev_stored_name;
	n_query_cols++;

	query_cols[n_query_cols] = &str_to_tag_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = to_tag;
	n_query_cols++;

	if (pa_dbf.use_table(pa_db, &active_watchers_table) < 0)
	{
		LM_ERR("in use table sql operation\n");
		return -1;
	}

	CON_PS_REFERENCE(pa_db) = &my_ps;
	LM_DBG("delete subs \n");
	if(pa_dbf.delete(pa_db, query_cols, 0, query_vals,
				n_query_cols)< 0 )
	{
		LM_ERR("sql delete failed\n");
		return -1;
	}

	return 0;
}

int update_subs_db(subs_t* subs, int type)
{
	static db_ps_t my_ps_remote = NULL, my_ps_local = NULL;
	db_key_t query_cols[22], update_keys[8];
	db_val_t query_vals[22], update_vals[8];
	int n_update_cols= 0;
	int n_query_cols = 0;

	if (pa_dbf.use_table(pa_db, &active_watchers_table) < 0)
	{
		LM_ERR("in use table sql operation\n");
		return -1;
	}

	query_cols[n_query_cols] = &str_presentity_uri_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->pres_uri;
	n_query_cols++;

	query_cols[n_query_cols] = &str_watcher_username_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->from_user;
	n_query_cols++;

	query_cols[n_query_cols] = &str_watcher_domain_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->from_domain;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->event->name;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_id_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;

	if(subs->event_id.s)
	{
		query_vals[n_query_cols].val.str_val = subs->event_id;
	}
	else
	{
		query_vals[n_query_cols].val.str_val.s = "";
		query_vals[n_query_cols].val.str_val.len = 0;
	}
	n_query_cols++;

	query_cols[n_query_cols] = &str_callid_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->callid;
	n_query_cols++;

	query_cols[n_query_cols] = &str_to_tag_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->to_tag;
	n_query_cols++;

	query_cols[n_query_cols] = &str_from_tag_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->from_tag;
	n_query_cols++;

	if(type & REMOTE_TYPE)
	{
		update_keys[n_update_cols] = &str_expires_col;
		update_vals[n_update_cols].type = DB_INT;
		update_vals[n_update_cols].nul = 0;
		update_vals[n_update_cols].val.int_val = subs->expires + (int)time(NULL);
		n_update_cols++;

		update_keys[n_update_cols] = &str_remote_cseq_col;
		update_vals[n_update_cols].type = DB_INT;
		update_vals[n_update_cols].nul = 0;
		update_vals[n_update_cols].val.int_val = subs->remote_cseq;
		n_update_cols++;

		update_keys[n_update_cols] = &str_contact_col;
		update_vals[n_update_cols].type = DB_STR;
		update_vals[n_update_cols].nul = 0;
		update_vals[n_update_cols].val.str_val = subs->contact;
		n_update_cols++;

		CON_PS_REFERENCE(pa_db) = &my_ps_remote;
	}
	else
	{
		update_keys[n_update_cols] = &str_local_cseq_col;
		update_vals[n_update_cols].type = DB_INT;
		update_vals[n_update_cols].nul = 0;
		update_vals[n_update_cols].val.int_val = subs->local_cseq+ 1;
		n_update_cols++;

		update_keys[n_update_cols] = &str_version_col;
		update_vals[n_update_cols].type = DB_INT;
		update_vals[n_update_cols].nul = 0;
		update_vals[n_update_cols].val.int_val = subs->version+ 1;
		n_update_cols++;

		CON_PS_REFERENCE(pa_db) = &my_ps_local;
	}

	update_keys[n_update_cols] = &str_status_col;
	update_vals[n_update_cols].type = DB_INT;
	update_vals[n_update_cols].nul = 0;
	update_vals[n_update_cols].val.int_val = subs->status;
	n_update_cols++;

	update_keys[n_update_cols] = &str_reason_col;
	update_vals[n_update_cols].type = DB_STR;
	update_vals[n_update_cols].nul = 0;
	update_vals[n_update_cols].val.str_val = subs->reason;
	n_update_cols++;

	if(pa_dbf.update( pa_db,query_cols, 0, query_vals,
				update_keys, update_vals, n_query_cols,n_update_cols)<0)
	{
		LM_ERR("updating presence information\n");
		return -1;
	}
	return 0;
}

int subs_process_insert_status(subs_t* subs)
{
	struct sip_uri uri;

	/*default 'pending' status */
	subs->status= PENDING_STATUS;
	subs->reason.s= NULL;
	subs->reason.len= 0;

	if(parse_uri(subs->pres_uri.s, subs->pres_uri.len, &uri)< 0)
	{
		LM_ERR("parsing uri\n");
		goto error;

	}
	if(subs->event->get_rules_doc(&uri.user, &uri.host, &subs->auth_rules_doc)< 0)
	{
		LM_ERR("getting rules doc\n");
		goto error;
	}

	if(subs->event->get_auth_status(subs)< 0)
	{
		LM_ERR("in event specific function is_watcher_allowed\n");
		goto error;
	}
	if(get_status_str(subs->status)== NULL)
	{
		LM_ERR("wrong status= %d\n", subs->status);
		goto error;
	}

	if(insert_db_subs_auth(subs)< 0)
	{
		LM_ERR("while inserting record in watchers table\n");
		goto error;
	}

	return 0;

error:
	return -1;
}

/* Internally updates the subscription data and generates the
 * necessary NOTIFY's. It also takes care of sending back a reply
 * to the SUBSCRIBE request
 */
int update_subscription(struct sip_msg* msg, subs_t* subs, int init_req)
{
	unsigned int hash_code;
	int reply_code = 200;
	str reply_str;

	if(subs->event->type & PUBL_TYPE)
		reply_code=(subs->status==PENDING_STATUS)?202:200;

	hash_code= core_hash(&subs->pres_uri, &subs->event->name, shtable_size);

	if(init_req ==0) /*if a SUBSCRIBE within a dialog */
	{
		if(subs->expires == 0)
		{
			LM_DBG("expires=0, deleting subscription from "
				"[%.*s@%.*s] to [%.*s]\n",
				subs->from_user.len, subs->from_user.s, subs->from_domain.len,
				subs->from_domain.s, subs->pres_uri.len, subs->pres_uri.s);

			if(delete_db_subs(subs->pres_uri,subs->event->name,subs->to_tag)<0)
			{
				LM_ERR("deleting subscription record from database\n");
				goto error_500_reply;
			}
			/* delete record from hash table also */
			subs->local_cseq= delete_shtable(subs_htable,hash_code,
					subs->to_tag);

			if( msg && send_2XX_reply(msg, reply_code, subs->expires, 0,
						&subs->local_contact) <0)
			{
				LM_ERR("sending %d OK\n", reply_code);
				goto error_500_reply;
			}
			goto send_notify;
		}
		subs->expires+= expires_offset;
		if(update_shtable(subs_htable, hash_code, subs, REMOTE_TYPE)< 0)
		{
			LM_DBG("updating subscription record in hash table failed\n");
			if(!fallback2db)
				goto error_500_reply;
		}
		if(fallback2db)
		{
			if(update_subs_db(subs, REMOTE_TYPE)< 0)
			{
				LM_ERR("updating subscription in database table\n");
				goto error_500_reply;
			}
		}

		if(msg && send_2XX_reply(msg, reply_code, subs->expires, 0,
			&subs->local_contact)<0)
		{
			LM_ERR("sending 2XX reply\n");
			goto error_500_reply;
		}
	}
	else
	{
		/* first, generate the To-tag, so we can double check the 
		 * to-be-created subscription */
		if(msg)
			sigb.gen_totag( msg, &subs->to_tag);

		if(subs->expires!= 0)
		{
			/* be sure the SIP subscription does not exist in hash */
			if(update_shtable(subs_htable, hash_code, subs, JUST_CHECK)==0) {
				/* another subscription with same SIP coordinates already
				 * exists => decline */
				LM_ERR("subscription overlapping detected, rejecting\n");
				goto error_500_reply;
			}

			subs->expires += expires_offset;
			if(insert_shtable(subs_htable,hash_code,subs)< 0)
			{
				LM_ERR("inserting new record in subs_htable\n");
				goto error_500_reply;
			}

			if(fallback2db)
			{
				if(insert_subs_db(subs) < 0)
				{
					LM_ERR("failed to insert subscription in database\n");
					goto error_500_reply;
				}
			}
		}
		/*otherwise there is a subscription outside a dialog with expires= 0
		 * no update in database, but should try to send Notify */

		if(msg && send_2XX_reply(msg, reply_code, subs->expires, NULL,
			&subs->local_contact)<0)
		{
			LM_ERR("sending 2XX reply\n");
			goto error_500_reply;
		}

	}

	/* the SUBSCRIBE request is replied at this point */

	/* send Notifies */
send_notify:
	if((subs->event->type & PUBL_TYPE) && subs->event->wipeer)
	{
		LM_DBG("send Notify with winfo\n");
		if(query_db_notify(&subs->pres_uri, subs->event->wipeer, (subs->expires==0)?NULL:subs)< 0)
		{
			LM_ERR("Could not send notify winfo\n");
			goto error;
		}
	}

	LM_DBG("send NOTIFY's out\n");
	if(notify(subs, NULL, NULL, 0 , NULL, 0)< 0)
	{
		LM_ERR("Failed to send notify request\n");
		goto error;
	}

	return 0;

error_500_reply:
	reply_code = 500;
	reply_str.s = "Server Internal Error";
	reply_str.len = sizeof("Server Internal Error")-1;

	if (send_error_reply(msg, reply_code, reply_str)<0)
		LM_ERR("failed to send reply on error case\n");

error:
	return -1;
}

void msg_watchers_clean(unsigned int ticks,void *param)
{
	db_key_t db_keys[2];
	db_val_t db_vals[2];
	db_op_t  db_ops[2] ;

	LM_DBG("cleaning pending subscriptions\n");

	db_keys[0] = &str_inserted_time_col;
	db_ops[0] = OP_LT;
	db_vals[0].type = DB_INT;
	db_vals[0].nul = 0;
	db_vals[0].val.int_val = (int)time(NULL)- waiting_subs_time;

	db_keys[1] = &str_status_col;
	db_ops [1] = OP_EQ;
	db_vals[1].type = DB_INT;
	db_vals[1].nul = 0;
	db_vals[1].val.int_val = PENDING_STATUS;

	if (pa_dbf.use_table(pa_db, &watchers_table) < 0)
	{
		LM_ERR("unsuccessful use_table sql operation\n");
		return;
	}

	if (pa_dbf.delete(pa_db, db_keys, db_ops, db_vals, 2) < 0)
		LM_ERR("cleaning pending subscriptions\n");

}

/*
 *	Function called from the script to process a SUBSCRIBE request
 *		returns:
 *				1 : success
 *				-1: error
 *		- sends a reply in all cases (success or error).
 *	TODO replace -1 return code in error case with 0 ( exit from the script)
 * */
int handle_subscribe(struct sip_msg* msg, int* force_active_param, str* tag)
{
	int  init_req = 0;
	subs_t subs;
	pres_ev_t* event= NULL;
	event_t* parsed_event= NULL;
	param_t* ev_param= NULL;
	int found = 0;
	str reason= {0, 0};
	int reply_code;
	str reply_str;
	int ret;

	/* ??? rename to avoid collisions with other symbols */
	counter++;

	memset(&subs, 0, sizeof(subs_t));

	reply_code= 400;
	reply_str= pu_400_rpl;

	if( parse_headers(msg,HDR_EOH_F, 0)==-1 )
	{
		LM_ERR("parsing headers\n");
		goto error;
	}

	/* inspecting the Event header field */
	if(msg->event && msg->event->body.len > 0)
	{
		if (!msg->event->parsed && (parse_event(msg->event) < 0))
		{
			LM_ERR("bad Event header\n");
			goto error;
		}
		if(((event_t*)msg->event->parsed)->parsed == EVENT_OTHER)
		{
			LM_ERR("unrecognized value [%.*s] in Event header\n",
				msg->event->body.len, msg->event->body.s);
			goto bad_event;
		}
	} else {
		LM_ERR("Missing Event header\n");
		goto bad_event;
	}

	/* search event in the list */
	parsed_event= (event_t*)msg->event->parsed;
	event= search_event(parsed_event);
	if(event== NULL)
	{
		LM_ERR("un-registered support for known event [%.*s]\n",
			parsed_event->text.len, parsed_event->text.s);
		goto bad_event;
	}
	subs.event= event;

	/* extract the id if any*/
	ev_param= parsed_event->params;
	while(ev_param)
	{
		if(ev_param->name.len==2 && strncasecmp(ev_param->name.s, "id", 2)==0)
		{
			subs.event_id= ev_param->body;
			break;
		}
		ev_param= ev_param->next;
	}

	ret = extract_sdialog_info(&subs, msg, max_expires_subscribe, &init_req, contact_user);
	if(ret< 0)
	{
		LM_ERR("failed to extract dialog information\n");
		if(ret== -2)
		{
			reply_code= 500;
			reply_str= pu_500_rpl;
		}
		goto error;
	}

	/* from now one most of the possible error are due to fail
	 * in internal processing */
	reply_code= 500;
	reply_str= pu_500_rpl;

	if (tag) {
		subs.sh_tag = *tag;
		if (c_api.shtag_get( &subs.sh_tag, pres_cluster_id)<0) {
			LM_ERR("failed to lookup the <%.*s> sharing tag\n",
				subs.sh_tag.len, subs.sh_tag.s);
			goto error;
		}
	}

	/* getting presentity uri from Request-URI if initial subscribe;
	 * or else from database*/
	if(init_req)
	{
		if(parsed_event->parsed!= EVENT_DIALOG_SLA)
		{
			if( parse_sip_msg_uri(msg)< 0)
			{
				LM_ERR("failed to parse R-URI\n");
				reply_code= 400;
				reply_str= pu_400_rpl;
				goto error;
			}
			if(uandd_to_uri(msg->parsed_uri.user, msg->parsed_uri.host,
					&subs.pres_uri)< 0)
			{
				LM_ERR("failed to construct uri from user and domain\n");
				goto error;
			}
		}
	}
	else
	{
		if(get_stored_info(msg, &subs, &reply_code, &reply_str )< 0)
		{
			LM_ERR("getting stored info\n");
			goto error;
		}
		reason= subs.reason;
	}

	/* call event specific subscription handling */
	if(event->evs_subs_handl)
	{
		if(event->evs_subs_handl(msg, &subs, &reply_code, &reply_str)< 0)
		{
			LM_ERR("in event specific subscription handling\n");
			goto error;
		}
	}

	/* if dialog initiation Subscribe - get subscription state */
	if(init_req)
	{
		if(!event->req_auth ||(force_active_param && *force_active_param == 1))
			subs.status = ACTIVE_STATUS;
		else
		{
			/* query in watchers_table - if negative reply - server error */

			if(get_db_subs_auth(&subs, &found) < 0)
			{
				LM_ERR("getting subscription status from watchers table\n");
				goto error;
			}
			if(found== 0)
			{
				if( subs_process_insert_status(&subs) < 0)
				{
					LM_ERR("Failed to extract and insert authorization status\n");
					goto error;
				}
			}
			else
			{
				reason= subs.reason;
			}
		}
	}

	/* check if correct status */
	if(get_status_str(subs.status)== NULL)
	{
		LM_ERR("wrong status\n");
		goto error;
	}
	LM_DBG("subscription status= %s - %s\n", get_status_str(subs.status),
		found==0?"inserted":"found in watcher table");

	if(update_subscription(msg, &subs, init_req) <0)
	{
		LM_ERR("in update_subscription\n");
		goto error_free;
	}
	if(subs.auth_rules_doc)
	{
		pkg_free(subs.auth_rules_doc->s);
		pkg_free(subs.auth_rules_doc);
	}
	if(reason.s)
		pkg_free(reason.s);

	if(subs.pres_uri.s)
		pkg_free(subs.pres_uri.s);
	if(subs.record_route.s)
		pkg_free(subs.record_route.s);

	return 1;

bad_event:

	LM_INFO("Missing or unsupported event header field value\n");

	if(parsed_event && parsed_event->text.s)
		LM_INFO("\tevent= %.*s\n",parsed_event->text.len,parsed_event->text.s);

	reply_code= BAD_EVENT_CODE;
	reply_str= pu_489_rpl;

error:
	if(send_error_reply(msg, reply_code, reply_str)< 0)
	{
		LM_ERR("failed to send reply on error case\n");
	}

error_free:
	if(subs.pres_uri.s)
		pkg_free(subs.pres_uri.s);
	if(subs.auth_rules_doc)
	{
		if(subs.auth_rules_doc->s)
			pkg_free(subs.auth_rules_doc->s);
		pkg_free(subs.auth_rules_doc);
	}
	if(reason.s)
		pkg_free(reason.s);
	if(subs.record_route.s)
		pkg_free(subs.record_route.s);

	return -1;
}


// Return value: 0 = Success, -1 = Bad message, -2 = Internal error
//
int extract_sdialog_info(subs_t* subs, struct sip_msg* msg, int mexp, int* init_req, str contact_user)
{
	str rec_route = {0, 0};
	int rt = 0;
	contact_body_t *b;
	struct to_body *pto, *pfrom = NULL;
	int lexpire;
	struct sip_uri uri;

	/* examine the expire header field */
	if (msg->expires && msg->expires->body.len > 0)
	{
		if (!msg->expires->parsed && (parse_expires(msg->expires) < 0))
		{
			LM_ERR("cannot parse Expires header\n");
			return -1;
		}
		lexpire = ((exp_body_t*)msg->expires->parsed)->val;
		LM_DBG("'Expires' header found, value= %d\n", lexpire);

	}
	else
	{
		LM_DBG("'expires' not found; default=%d\n",subs->event->default_expires);
		lexpire = subs->event->default_expires;
	}
	if (lexpire > mexp)
		lexpire = mexp;

	subs->expires = lexpire;

	if ((!msg->to && parse_headers(msg, HDR_TO_F, 0)<0) || !msg->to) {
		LM_ERR("bad request or missing TO hdr\n");
		return -1;
	}

	pto = get_to(msg);
	if (pto == NULL || pto->error != PARSE_OK) {
		LM_ERR("failed to parse TO header\n");
		return -1;
	}

	if (pto->parsed_uri.user.s && pto->parsed_uri.host.s &&
		pto->parsed_uri.user.len && pto->parsed_uri.host.len)
	{
		subs->to_user = pto->parsed_uri.user;
		subs->to_domain = pto->parsed_uri.host;
	}
	else
	{
		if (parse_uri(pto->uri.s, pto->uri.len, &uri) < 0)
		{
			LM_ERR("while parsing uri\n");
			return -1;
		}
		subs->to_user = uri.user;
		subs->to_domain = uri.host;
	}

	/* examine the from header */
	if (!msg->from || !msg->from->body.s)
	{
		LM_ERR("cannot find 'from' header!\n");
		return -1;
	}
	if (msg->from->parsed == NULL)
	{
		LM_DBG("'From' header not parsed\n");
		/* parsing from header */
		if (parse_from_header( msg ) < 0)
		{
			LM_ERR("cannot parse From header\n");
			return -1;
		}
	}
	pfrom = (struct to_body*)msg->from->parsed;

	if (pfrom->parsed_uri.user.s && pfrom->parsed_uri.host.s &&
		pfrom->parsed_uri.user.len && pfrom->parsed_uri.host.len)
	{
		subs->from_user = pfrom->parsed_uri.user;
		subs->from_domain = pfrom->parsed_uri.host;
	}
	else
	{
		if (parse_uri(pfrom->uri.s, pfrom->uri.len, &uri) < 0)
		{
			LM_ERR("while parsing uri\n");
			return -1;
		}
		subs->from_user = uri.user;
		subs->from_domain = uri.host;
	}

	/*check if the message is an initial request */
	if (pto->tag_value.s == NULL || pto->tag_value.len == 0)
	{
		LM_DBG("initial request\n");
		*init_req = 1;
	}
	else
	{
		subs->to_tag = pto->tag_value;
		*init_req = 0;
	}
	if (msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot parse callid header\n");
		return -1;
	}
	subs->callid = msg->callid->body;

	if (msg->cseq==NULL || msg->cseq->body.s==NULL)
	{
		LM_ERR("cannot parse cseq header\n");
		return -1;
	}
	if (str2int(&(get_cseq(msg)->number), &subs->remote_cseq) != 0)
	{
		LM_ERR("cannot parse cseq number\n");
		return -1;
	}
	if (msg->contact==NULL || msg->contact->body.s==NULL)
	{
		LM_ERR("cannot parse contact header\n");
		return -1;
	}
	if (parse_contact(msg->contact) < 0)
	{
		LM_ERR(" cannot parse contact"
				" header\n");
		return -1;
	}

	b = (contact_body_t*)msg->contact->parsed;
	if (b == NULL)
	{
		LM_ERR("cannot parse contact header\n");
		return -1;
	}
	subs->contact = b->contacts->uri;

	LM_DBG("subs->contact= %.*s - len = %d\n", subs->contact.len, subs->contact.s, subs->contact.len);

	if (subs->event->evp->parsed == EVENT_DIALOG_SLA)
	{
		pv_value_t tok;
		/* if pseudovaraible set use that value */
		if (bla_presentity_spec_param.s) /* if parameter defined */
		{
			memset(&tok, 0, sizeof(pv_value_t));
			if (pv_get_spec_value(msg, &bla_presentity_spec, &tok) < 0)  /* if value set */
			{
				LM_ERR("Failed to get bla_presentity value\n");
				return -1;
			}
			if (!(tok.flags&PV_VAL_STR))
			{
				LM_ERR("Wrong value in bla_presentity pvar\n");
				return -1;
			}
			if (parse_uri(tok.rs.s, tok.rs.len, &uri) < 0)
			{
				LM_ERR("Not a valid value, must be a uri [%.*s]\n", tok.rs.len, tok.rs.s);
				return -1;
			}
			if (uandd_to_uri(uri.user, uri.host, &subs->pres_uri) < 0)
			{
				LM_ERR("failed to construct uri\n");
				return -1;
			}
		}
		else
		{
			/* user_contact@from_domain */
			if (parse_uri(subs->contact.s, subs->contact.len, &uri) < 0)
			{
				LM_ERR("failed to parse contact uri\n");
				return -1;
			}
			if (uandd_to_uri(uri.user, subs->from_domain, &subs->pres_uri) < 0)
			{
				LM_ERR("failed to construct uri\n");
				return -1;
			}
		}
	}

	/* process record route and add it to a string */
	if (*init_req && msg->record_route != NULL)
	{
		rt = print_rr_body(msg->record_route, &rec_route, 0, 0, NULL);
		if (rt != 0)
		{
			LM_ERR("processing the record route [%d]\n", rt);
			rec_route = (str) {NULL, 0};
			// return -1;
		}
	}
	subs->record_route = rec_route;

	subs->sockinfo = msg->rcv.bind_address;

	if (pfrom->tag_value.s == NULL || pfrom->tag_value.len == 0)
	{
		LM_ERR("no from tag value present\n");
		return -1;
	}
	subs->from_tag = pfrom->tag_value;

	subs->version = 0;

	if (get_local_contact(msg->rcv.bind_address, &contact_user, &subs->local_contact) < 0)
	{
		LM_ERR("Failed to get local contact\n");
		return -2;
	}

	return get_body(msg, &subs->subs_body);
}


/*
 * function that queries 'active_watchers' table for stored subscription dialog
 *	- sets reply_code and reply_str in error case if different than server error
 * */
int get_stored_info(struct sip_msg* msg, subs_t* subs, int* reply_code,
		str* reply_str)
{
	str pres_uri= {0, 0}, reason={0, 0};
	subs_t* s;
	int i;
	unsigned int hash_code;

	/* first try to_user== pres_user and to_domain== pres_domain */

	if(subs->pres_uri.s == NULL)
	{
		uandd_to_uri(subs->to_user, subs->to_domain, &pres_uri);
		if(pres_uri.s== NULL)
		{
			LM_ERR("creating uri from user and domain\n");
			return -1;
		}
	}
	else
		pres_uri = subs->pres_uri;

	hash_code= core_hash(&pres_uri, &subs->event->name, shtable_size);
	lock_get(&subs_htable[hash_code].lock);
	i= hash_code;
	s= search_shtable(subs_htable, subs->callid, subs->to_tag,
			subs->from_tag, hash_code);
	if(s)
	{
		goto found_rec;
	}
	lock_release(&subs_htable[hash_code].lock);

	if(subs->pres_uri.s)
		goto not_found;

	pkg_free(pres_uri.s);
	pres_uri.s= NULL;

	LM_DBG("record not found using R-URI search iteratively\n");
	/* take one row at a time */
	for(i= 0; i< shtable_size; i++)
	{
		lock_get(&subs_htable[i].lock);
		s= search_shtable(subs_htable, subs->callid,subs->to_tag,subs->from_tag, i);
		if(s)
		{
			if(s->event->evp->parsed != EVENT_DIALOG_SLA)
			{
				pres_uri.s= (char*)pkg_malloc(s->pres_uri.len);
				if(pres_uri.s== NULL)
				{
					lock_release(&subs_htable[i].lock);
					ERR_MEM(PKG_MEM_STR);
				}
				memcpy(pres_uri.s, s->pres_uri.s, s->pres_uri.len);
				pres_uri.len= s->pres_uri.len;
			}
			goto found_rec;
		}
		lock_release(&subs_htable[i].lock);
	}

	if(fallback2db)
	{
		return get_database_info(msg, subs, reply_code, reply_str);
	}

not_found:

	LM_ERR("record not found in hash_table\n");
	*reply_code= 481;
	*reply_str= pu_481_rpl;

	return -1;

found_rec:

	LM_DBG("Record found in hash_table\n");

	if(s->event->evp->parsed!= EVENT_DIALOG_SLA)
		subs->pres_uri= pres_uri;

	subs->version = s->version;
	subs->status= s->status;
	if(s->reason.s && s->reason.len)
	{
		reason.s= (char*)pkg_malloc(s->reason.len);
		if(reason.s== NULL)
		{
			lock_release(&subs_htable[i].lock);
			ERR_MEM(PKG_MEM_STR);
		}
		memcpy(reason.s, s->reason.s, s->reason.len);
		reason.len= s->reason.len;
		subs->reason= reason;
	}
	if(s->record_route.s && s->record_route.len)
	{
		subs->record_route.s= (char*)pkg_malloc
			(s->record_route.len);
		if(subs->record_route.s== NULL)
		{
			ERR_MEM(PKG_MEM_STR);
		}
		memcpy(subs->record_route.s, s->record_route.s, s->record_route.len);
		subs->record_route.len= s->record_route.len;
	}

	subs->local_cseq= s->local_cseq;

	if(subs->remote_cseq<= s->remote_cseq)
	{
		LM_ERR("wrong sequence number;received: %d - stored: %d\n",
				subs->remote_cseq, s->remote_cseq);

		*reply_code= 400;
		*reply_str= pu_400_rpl;

		lock_release(&subs_htable[i].lock);
		goto error;
	}
	lock_release(&subs_htable[i].lock);

	return 0;

error:
	if(subs->reason.s)
		pkg_free(subs->reason.s);
	subs->reason.s= NULL;
	if(subs->record_route.s)
		pkg_free(subs->record_route.s);
	subs->record_route.s= NULL;
	return -1;
}

int get_database_info(struct sip_msg* msg, subs_t* subs, int* reply_code, str* reply_str)
{
	static db_ps_t my_ps = NULL;
	db_key_t query_cols[10];
	db_val_t query_vals[10];
	db_key_t result_cols[9];
	db_res_t *result= NULL;
	db_row_t *row ;
	db_val_t *row_vals ;
	int n_query_cols = 0;
	int n_result_cols = 0;
	int remote_cseq_col= 0, local_cseq_col= 0, status_col, reason_col;
	int record_route_col, version_col;
	int pres_uri_col;
	unsigned int remote_cseq;
	str pres_uri, record_route;
	str reason;

	query_cols[n_query_cols] = &str_to_user_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->to_user;
	n_query_cols++;

	query_cols[n_query_cols] = &str_to_domain_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->to_domain;
	n_query_cols++;

	query_cols[n_query_cols] = &str_watcher_username_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->from_user;
	n_query_cols++;

	query_cols[n_query_cols] = &str_watcher_domain_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->from_domain;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->event->name;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_id_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	if( subs->event_id.s != NULL)
	{
		query_vals[n_query_cols].val.str_val.s = subs->event_id.s;
		query_vals[n_query_cols].val.str_val.len = subs->event_id.len;
	} else {
		query_vals[n_query_cols].val.str_val.s = "";
		query_vals[n_query_cols].val.str_val.len = 0;
	}
	n_query_cols++;

	query_cols[n_query_cols] = &str_callid_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->callid;
	n_query_cols++;

	query_cols[n_query_cols] = &str_to_tag_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->to_tag;
	n_query_cols++;

	query_cols[n_query_cols] = &str_from_tag_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->from_tag;
	n_query_cols++;

	result_cols[pres_uri_col=n_result_cols++] = &str_presentity_uri_col;
	result_cols[remote_cseq_col=n_result_cols++] = &str_remote_cseq_col;
	result_cols[local_cseq_col=n_result_cols++] = &str_local_cseq_col;
	result_cols[status_col=n_result_cols++] = &str_status_col;
	result_cols[reason_col=n_result_cols++] = &str_reason_col;
	result_cols[record_route_col=n_result_cols++] = &str_record_route_col;
	result_cols[version_col=n_result_cols++] = &str_version_col;

	if (pa_dbf.use_table(pa_db, &active_watchers_table) < 0)
	{
		LM_ERR("unsuccessful use_table sql operation\n");
		return -1;
	}

	CON_PS_REFERENCE(pa_db) = &my_ps;

	if (pa_dbf.query (pa_db, query_cols, 0, query_vals,
		 result_cols, n_query_cols, n_result_cols, 0,  &result) < 0)
	{
		LM_ERR("querying subscription dialog\n");
		if(result)
			pa_dbf.free_result(pa_db, result);
		return -1;
	}
	if(result== NULL)
		return -1;

	if(result && result->n <=0)
	{
		LM_ERR("No matching subscription dialog found in database\n");

		pa_dbf.free_result(pa_db, result);
		*reply_code= 481;
		*reply_str= pu_481_rpl;

		return -1;
	}

	row = &result->rows[0];
	row_vals = ROW_VALUES(row);
	remote_cseq= row_vals[remote_cseq_col].val.int_val;

	if(subs->remote_cseq<= remote_cseq)
	{
		LM_ERR("wrong sequence number received: %d - stored: %d\n",
				subs->remote_cseq, remote_cseq);
		*reply_code= 400;
		*reply_str= pu_400_rpl;
		pa_dbf.free_result(pa_db, result);
		return -1;
	}

	subs->status= row_vals[status_col].val.int_val;
	reason.s= (char*)row_vals[reason_col].val.string_val;
	if(reason.s)
	{
		reason.len= strlen(reason.s);
		subs->reason.s= (char*)pkg_malloc(reason.len);
		if(subs->reason.s== NULL)
		{
			ERR_MEM(PKG_MEM_STR);
		}
		memcpy(subs->reason.s, reason.s, reason.len);
		subs->reason.len= reason.len;
	}

	subs->local_cseq= row_vals[local_cseq_col].val.int_val;
	subs->version= row_vals[version_col].val.int_val;

	if(subs->event->evp->parsed!= EVENT_DIALOG_SLA)
	{
		pres_uri.s= (char*)row_vals[pres_uri_col].val.string_val;
		pres_uri.len= strlen(pres_uri.s);
		subs->pres_uri.s= (char*)pkg_malloc(pres_uri.len);
		if(subs->pres_uri.s== NULL)
		{
			if(subs->reason.s)
				pkg_free(subs->reason.s);
			ERR_MEM(PKG_MEM_STR);
		}
		memcpy(subs->pres_uri.s, pres_uri.s, pres_uri.len);
		subs->pres_uri.len= pres_uri.len;
	}

	record_route.s= (char*)row_vals[record_route_col].val.string_val;
	if(record_route.s)
	{
		record_route.len= strlen(record_route.s);
		subs->record_route.s= (char*)pkg_malloc(record_route.len);
		if(subs->record_route.s== NULL)
		{
			ERR_MEM(PKG_MEM_STR);
		}
		memcpy(subs->record_route.s, record_route.s, record_route.len);
		subs->record_route.len= record_route.len;
	}

	pa_dbf.free_result(pa_db, result);
	result= NULL;

	return 0;
error:
	if(result)
		pa_dbf.free_result(pa_db, result);

	return -1;
}


int handle_expired_subs(subs_t* s)
{
	if (s->event->mandatory_timeout_notification)
	{
		/* send Notify with state=terminated;reason=timeout */
		s->status= TERMINATED_STATUS;
		s->reason.s= "timeout";
		s->reason.len= 7;
		s->expires= 0;

		LM_DBG("send timeout NOTIFY's out\n");
		if(send_notify_request(s, NULL, NULL, 1, NULL, 0)< 0)
		{
			LM_ERR("send Notify not successful\n");
			return -1;
		}
	}

	return 0;

}

void timer_db_update(unsigned int ticks,void *param)
{
	int no_lock=0;

	if(ticks== 0 && param == NULL)
		no_lock= 1;

	if(pa_dbf.use_table(pa_db, &active_watchers_table)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

	update_db_subs(pa_db, &pa_dbf, subs_htable,
			shtable_size, no_lock, handle_expired_subs);
}


static inline int is_shtag_active( str *my_tag, str **active_tags)
{
	int i=0;

	while (active_tags[i]) {

		if (my_tag->len==active_tags[i]->len &&
		strncmp( my_tag->s, active_tags[i]->s, active_tags[i]->len)==0)
			/* found -> tag is active */
			return 1;

		i++;
	}

	/* not found -> tag is not active */
	return 0;
}


void update_db_subs(db_con_t *db,db_func_t *dbf, shtable_t hash_table,
	int htable_size, int no_lock, handle_expired_func_t handle_expired_func)
{
	static db_ps_t my_ps_delete = NULL;
	static db_ps_t my_ps_update = NULL, my_ps_insert = NULL;
	db_key_t query_cols[22], update_cols[8];
	db_val_t query_vals[22], update_vals[8];
	db_op_t update_ops[2];
	subs_t* del_s;
	int pres_uri_col, to_user_col, to_domain_col, from_user_col, from_domain_col,
		callid_col, totag_col, fromtag_col, event_col,status_col, event_id_col,
		local_cseq_col, remote_cseq_col, expires_col, record_route_col,
		contact_col, local_contact_col, version_col,socket_info_col,reason_col;
	int u_expires_col, u_local_cseq_col, u_remote_cseq_col, u_version_col,
		u_reason_col, u_status_col, u_contact_col;
	int i;
	subs_t* s= NULL, *prev_s= NULL;
	int n_query_cols= 0, n_update_cols= 0;
	int n_query_update;
	str **sh_tags=NULL;


	if (fallback2db==0) {
		/* if `fallback2db` is enabled, all the INSERT/UPDATED/DELETES ops
		 * triggered by received SUBSCRIBE requests are done in realtime, not
		 * on timer. */
		query_cols[pres_uri_col= n_query_cols] =&str_presentity_uri_col;
		query_vals[pres_uri_col].type = DB_STR;
		query_vals[pres_uri_col].nul = 0;
		n_query_cols++;

		query_cols[callid_col= n_query_cols] =&str_callid_col;
		query_vals[callid_col].type = DB_STR;
		query_vals[callid_col].nul = 0;
		n_query_cols++;

		query_cols[totag_col= n_query_cols] =&str_to_tag_col;
		query_vals[totag_col].type = DB_STR;
		query_vals[totag_col].nul = 0;
		n_query_cols++;

		query_cols[fromtag_col= n_query_cols] =&str_from_tag_col;
		query_vals[fromtag_col].type = DB_STR;
		query_vals[fromtag_col].nul = 0;
		n_query_cols++;

		n_query_update= n_query_cols;

		query_cols[to_user_col= n_query_cols] =&str_to_user_col;
		query_vals[to_user_col].type = DB_STR;
		query_vals[to_user_col].nul = 0;
		n_query_cols++;

		query_cols[to_domain_col= n_query_cols] =&str_to_domain_col;
		query_vals[to_domain_col].type = DB_STR;
		query_vals[to_domain_col].nul = 0;
		n_query_cols++;

		query_cols[from_user_col= n_query_cols] =&str_watcher_username_col;
		query_vals[from_user_col].type = DB_STR;
		query_vals[from_user_col].nul = 0;
		n_query_cols++;

		query_cols[from_domain_col= n_query_cols] =&str_watcher_domain_col;
		query_vals[from_domain_col].type = DB_STR;
		query_vals[from_domain_col].nul = 0;
		n_query_cols++;

		query_cols[event_col= n_query_cols] =&str_event_col;
		query_vals[event_col].type = DB_STR;
		query_vals[event_col].nul = 0;
		n_query_cols++;

		query_cols[event_id_col= n_query_cols] =&str_event_id_col;
		query_vals[event_id_col].type = DB_STR;
		query_vals[event_id_col].nul = 0;
		n_query_cols++;

		query_cols[local_cseq_col= n_query_cols]=&str_local_cseq_col;
		query_vals[local_cseq_col].type = DB_INT;
		query_vals[local_cseq_col].nul = 0;
		n_query_cols++;

		query_cols[remote_cseq_col= n_query_cols]=&str_remote_cseq_col;
		query_vals[remote_cseq_col].type = DB_INT;
		query_vals[remote_cseq_col].nul = 0;
		n_query_cols++;

		query_cols[expires_col= n_query_cols] =&str_expires_col;
		query_vals[expires_col].type = DB_INT;
		query_vals[expires_col].nul = 0;
		n_query_cols++;

		query_cols[status_col= n_query_cols] =&str_status_col;
		query_vals[status_col].type = DB_INT;
		query_vals[status_col].nul = 0;
		n_query_cols++;

		query_cols[reason_col= n_query_cols] =&str_reason_col;
		query_vals[reason_col].type = DB_STR;
		query_vals[reason_col].nul = 0;
		n_query_cols++;

		query_cols[record_route_col= n_query_cols] =&str_record_route_col;
		query_vals[record_route_col].type = DB_STR;
		query_vals[record_route_col].nul = 0;
		n_query_cols++;

		query_cols[contact_col= n_query_cols] =&str_contact_col;
		query_vals[contact_col].type = DB_STR;
		query_vals[contact_col].nul = 0;
		n_query_cols++;

		query_cols[local_contact_col= n_query_cols] =&str_local_contact_col;
		query_vals[local_contact_col].type = DB_STR;
		query_vals[local_contact_col].nul = 0;
		n_query_cols++;

		query_cols[socket_info_col= n_query_cols] =&str_socket_info_col;
		query_vals[socket_info_col].type = DB_STR;
		query_vals[socket_info_col].nul = 0;
		n_query_cols++;

		query_cols[version_col= n_query_cols]=&str_version_col;
		query_vals[version_col].type = DB_INT;
		query_vals[version_col].nul = 0;
		n_query_cols++;

		/* cols and values used for update */
		update_cols[u_expires_col= n_update_cols]= &str_expires_col;
		update_vals[u_expires_col].type = DB_INT;
		update_vals[u_expires_col].nul = 0;
		n_update_cols++;

		update_cols[u_status_col= n_update_cols]= &str_status_col;
		update_vals[u_status_col].type = DB_INT;
		update_vals[u_status_col].nul = 0;
		n_update_cols++;

		update_cols[u_reason_col= n_update_cols]= &str_reason_col;
		update_vals[u_reason_col].type = DB_STR;
		update_vals[u_reason_col].nul = 0;
		n_update_cols++;

		update_cols[u_remote_cseq_col= n_update_cols]= &str_remote_cseq_col;
		update_vals[u_remote_cseq_col].type = DB_INT;
		update_vals[u_remote_cseq_col].nul = 0;
		n_update_cols++;

		update_cols[u_local_cseq_col= n_update_cols]= &str_local_cseq_col;
		update_vals[u_local_cseq_col].type = DB_INT;
		update_vals[u_local_cseq_col].nul = 0;
		n_update_cols++;

		update_cols[u_contact_col= n_update_cols]= &str_contact_col;
		update_vals[u_contact_col].type = DB_STR;
		update_vals[u_contact_col].nul = 0;
		n_update_cols++;

		update_cols[u_version_col= n_update_cols]= &str_version_col;
		update_vals[u_version_col].type = DB_INT;
		update_vals[u_version_col].nul = 0;
		n_update_cols++;
	}

	if (db==NULL){
		LM_ERR("null database connection\n");
		return;
	}

	sh_tags = is_presence_cluster_enabled() ?
		c_api.shtag_get_all_active(pres_cluster_id) : NULL;

	for(i=0; i<htable_size; i++)
	{
		if(!no_lock)
			lock_get(&hash_table[i].lock);

		prev_s= hash_table[i].entries;
		s= prev_s->next;

		while(s)
		{
			printf_subs(s);

			/* delete from memory (only) whatever is expired, disregarding the
			 * any clustering policy */
			if(s->expires < (int)time(NULL))
			{
				LM_DBG("Found expired record\n");
				del_s= s;
				s= s->next;
				prev_s->next= s;

				if(!no_lock)
					lock_release(&hash_table[i].lock);

				/* if sharing tags (from clustering) are present, run the
				 * del callback only if the subscription's tag is active */
				if (sh_tags==NULL || del_s->sh_tag.len==0 ||
				is_shtag_active( &del_s->sh_tag, sh_tags)) {
					if (handle_expired_func(del_s)< 0)
						LM_ERR("in function handle_expired_record\n");
				}

				free_subs(del_s);

				if(!no_lock)
					lock_get(&hash_table[i].lock);

				continue;
			}

			/* perform pending UPDATE/INSERT if not in DB realtime */
			if (fallback2db==0) {

				switch(s->db_flag)
				{
					case NO_UPDATEDB_FLAG:
					{
						LM_DBG("NO_UPDATEDB_FLAG\n");
						break;
					}
					case UPDATEDB_FLAG:
					{
						LM_DBG("UPDATEDB_FLAG\n");

						query_vals[pres_uri_col].val.str_val= s->pres_uri;
						query_vals[callid_col].val.str_val= s->callid;
						query_vals[totag_col].val.str_val= s->to_tag;
						query_vals[fromtag_col].val.str_val= s->from_tag;

						update_vals[u_expires_col].val.int_val= s->expires;
						update_vals[u_local_cseq_col].val.int_val=
							s->local_cseq;
						update_vals[u_remote_cseq_col].val.int_val=
							s->remote_cseq;
						update_vals[u_version_col].val.int_val= s->version;
						update_vals[u_status_col].val.int_val= s->status;
						update_vals[u_reason_col].val.str_val= s->reason;
						update_vals[u_contact_col].val.str_val= s->contact;

						CON_PS_REFERENCE(db) = &my_ps_update;
						if(dbf->update(db, query_cols, 0, query_vals,
						update_cols, update_vals, n_query_update,
						n_update_cols)< 0)
						{
							LM_ERR("updating in database\n");
						}
						break;
					}
					case  INSERTDB_FLAG:
					{
						LM_DBG("INSERTDB_FLAG\n");

						query_vals[pres_uri_col].val.str_val= s->pres_uri;
						query_vals[callid_col].val.str_val= s->callid;
						query_vals[totag_col].val.str_val= s->to_tag;
						query_vals[fromtag_col].val.str_val= s->from_tag;
						query_vals[to_user_col].val.str_val = s->to_user;
						query_vals[to_domain_col].val.str_val = s->to_domain;
						query_vals[from_user_col].val.str_val = s->from_user;
						query_vals[from_domain_col].val.str_val =
							s->from_domain;
						query_vals[event_col].val.str_val = s->event->name;
						if (s->event_id.s) {
							query_vals[event_id_col].val.str_val = s->event_id;
						} else {
							query_vals[event_id_col].val.str_val.s = "";
							query_vals[event_id_col].val.str_val.len = 0;
						}
						query_vals[local_cseq_col].val.int_val= s->local_cseq;
						query_vals[remote_cseq_col].val.int_val=s->remote_cseq;
						query_vals[expires_col].val.int_val = s->expires;
						query_vals[record_route_col].val.str_val =
							s->record_route;
						query_vals[contact_col].val.str_val = s->contact;
						query_vals[local_contact_col].val.str_val =
							s->local_contact;
						query_vals[version_col].val.int_val= s->version;
						query_vals[status_col].val.int_val= s->status;
						query_vals[reason_col].val.str_val= s->reason;
						if(s->sockinfo)
							query_vals[socket_info_col].val.str_val=
								s->sockinfo->sock_str;
						else
						{
							query_vals[socket_info_col].val.str_val.s = 0;
							query_vals[socket_info_col].val.str_val.len = 0;
						}

						CON_PS_REFERENCE(db) = &my_ps_insert;
						if (dbf->insert( db, query_cols, query_vals,
						n_query_cols) < 0)
						{
							LM_ERR("unsuccessful sql insert\n");
						}
						break;
					}

				}
				s->db_flag= NO_UPDATEDB_FLAG;
			}

			prev_s= s;
			s= s->next;
		}
		if(!no_lock)
			lock_release(&hash_table[i].lock);
	}

	/* now that all records were updated, delete whatever 
	   was still left as expired */
	update_cols[0]= &str_expires_col;
	update_vals[0].type = DB_INT;
	update_vals[0].nul = 0;
	update_vals[0].val.int_val = (int)time(NULL);
	update_ops[0] = OP_LT;

	if (dbf->use_table(db, &active_watchers_table) < 0) {
		LM_ERR("deleting expired information from database\n");
		return;
	}

	if (sh_tags==NULL) {

		/* no clustering, simply delete all expired subs */
		LM_DBG("delete all expired subscriptions\n");

		if (dbf->delete(db, update_cols, update_ops, update_vals, 1) < 0)
			LM_ERR("deleting expired information from database\n");

	} else {

		/* clustering, delete only expired subs with active sh tags */
		update_cols[1]= &str_sharing_tag_col;
		update_vals[1].type = DB_STR;
		update_vals[1].nul = 0;
		update_ops[1] = OP_EQ;

		i = 0;
		while(sh_tags[i]) {
			LM_DBG("delete expired subscriptions for tag <%.*s>\n",
				sh_tags[i]->len, sh_tags[i]->s);

			update_vals[1].val.str_val = *sh_tags[i];
			CON_PS_REFERENCE(db) = &my_ps_delete;
			if (dbf->delete(db, update_cols, update_ops, update_vals, 2) < 0)
				LM_ERR("deleting expired information from database\n");
			i++;
		}

	}

	return;
}


int insert_subs_db(subs_t* s)
{
	static db_ps_t my_ps = NULL;
	db_key_t query_cols[23];
	db_val_t query_vals[23];
	int n_query_cols= 0;

	query_cols[n_query_cols] =&str_presentity_uri_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val= s->pres_uri;
	n_query_cols++;

	query_cols[n_query_cols] =&str_callid_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val= s->callid;
	n_query_cols++;

	query_cols[n_query_cols] =&str_to_tag_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val= s->to_tag;
	n_query_cols++;

	query_cols[n_query_cols] =&str_from_tag_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val= s->from_tag;
	n_query_cols++;

	query_cols[n_query_cols] =&str_to_user_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = s->to_user;
	n_query_cols++;

	query_cols[n_query_cols] =&str_to_domain_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = s->to_domain;
	n_query_cols++;

	query_cols[n_query_cols] =&str_watcher_username_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = s->from_user;
	n_query_cols++;

	query_cols[n_query_cols] =&str_watcher_domain_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = s->from_domain;
	n_query_cols++;

	query_cols[n_query_cols] =&str_event_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = s->event->name;
	n_query_cols++;

	query_cols[n_query_cols] =&str_event_id_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	if (s->event_id.s) {
		query_vals[n_query_cols].val.str_val = s->event_id;
	} else {
		query_vals[n_query_cols].val.str_val.s = "";
		query_vals[n_query_cols].val.str_val.len = 0;
	}
	n_query_cols++;

	query_cols[n_query_cols]=&str_local_cseq_col;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val= s->local_cseq;
	n_query_cols++;

	query_cols[n_query_cols]=&str_remote_cseq_col;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val= s->remote_cseq;
	n_query_cols++;

	query_cols[n_query_cols] =&str_expires_col;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val = s->expires + (int)time(NULL);
	n_query_cols++;

	query_cols[n_query_cols] =&str_status_col;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val= s->status;
	n_query_cols++;

	query_cols[n_query_cols] =&str_reason_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val= s->reason;
	n_query_cols++;

	query_cols[n_query_cols] =&str_record_route_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = s->record_route;
	n_query_cols++;

	query_cols[n_query_cols] =&str_contact_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = s->contact;
	n_query_cols++;

	query_cols[n_query_cols] =&str_local_contact_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = s->local_contact;
	n_query_cols++;

	query_cols[n_query_cols]=&str_version_col;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val= s->version;
	n_query_cols++;

	query_cols[n_query_cols] =&str_socket_info_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	if(s->sockinfo)
		query_vals[n_query_cols].val.str_val= s->sockinfo->sock_str;
	else
	{
		query_vals[n_query_cols].val.str_val.s = 0;
		query_vals[n_query_cols].val.str_val.len = 0;
	}
	n_query_cols++;

	query_cols[n_query_cols] =&str_sharing_tag_col;
	query_vals[n_query_cols].type = DB_STR;
	if (s->sh_tag.len==0) {
		query_vals[n_query_cols].nul = 1;
	} else {
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.str_val = s->sh_tag;
	}
	n_query_cols++;

	if(pa_dbf.use_table(pa_db, &active_watchers_table)< 0)
	{
		LM_ERR("in use table\n");
		return -1;
	}

	CON_PS_REFERENCE(pa_db) = &my_ps;
	if(pa_dbf.insert(pa_db,query_cols,query_vals,n_query_cols )<0)
	{
		LM_ERR("unsuccessful sql insert\n");
		return -1;
	}

	return 0;
}


int restore_db_subs(void)
{
	db_key_t result_cols[23];
	db_res_t *result= NULL;
	db_row_t *rows = NULL;
	db_val_t *row_vals= NULL;
	int i;
	int n_result_cols= 0;
	int pres_uri_col, expires_col, from_user_col, from_domain_col,to_user_col;
	int callid_col,totag_col,fromtag_col,to_domain_col,sockinfo_col,reason_col;
	int event_col,contact_col,record_route_col, event_id_col, status_col;
	int remote_cseq_col, local_cseq_col, local_contact_col, version_col;
	int sharing_tag_col;
	subs_t s;
	str ev_sname, sockinfo_str;
	pres_ev_t* event= NULL;
	event_t parsed_event;
	unsigned int expires;
	unsigned int hash_code;
	int port, proto;
	str host;
	int nr_rows;
	int no_rows = 10;

	result_cols[pres_uri_col=n_result_cols++]	=&str_presentity_uri_col;
	result_cols[expires_col=n_result_cols++]=&str_expires_col;
	result_cols[event_col=n_result_cols++]	=&str_event_col;
	result_cols[event_id_col=n_result_cols++]=&str_event_id_col;
	result_cols[to_user_col=n_result_cols++]	=&str_to_user_col;
	result_cols[to_domain_col=n_result_cols++]	=&str_to_domain_col;
	result_cols[from_user_col=n_result_cols++]	=&str_watcher_username_col;
	result_cols[from_domain_col=n_result_cols++]=&str_watcher_domain_col;
	result_cols[callid_col=n_result_cols++] =&str_callid_col;
	result_cols[totag_col=n_result_cols++]	=&str_to_tag_col;
	result_cols[fromtag_col=n_result_cols++]=&str_from_tag_col;
	result_cols[local_cseq_col= n_result_cols++]	=&str_local_cseq_col;
	result_cols[remote_cseq_col= n_result_cols++]	=&str_remote_cseq_col;
	result_cols[record_route_col= n_result_cols++]	=&str_record_route_col;
	result_cols[sockinfo_col= n_result_cols++]	=&str_socket_info_col;
	result_cols[contact_col= n_result_cols++]	=&str_contact_col;
	result_cols[local_contact_col= n_result_cols++]	=&str_local_contact_col;
	result_cols[version_col= n_result_cols++]	=&str_version_col;
	result_cols[status_col= n_result_cols++]	=&str_status_col;
	result_cols[reason_col= n_result_cols++]	=&str_reason_col;
	result_cols[sharing_tag_col= n_result_cols++]	=&str_sharing_tag_col;

	if(!pa_db)
	{
		LM_ERR("null database connection\n");
		return -1;
	}

	if(pa_dbf.use_table(pa_db, &active_watchers_table)< 0)
	{
		LM_ERR("in use table\n");
		return -1;
	}
	/* select the whole tabel and all the columns */
	if (DB_CAPABILITY(pa_dbf, DB_CAP_FETCH))
	{
		if(pa_dbf.query(pa_db,0,0,0,result_cols, 0,
		n_result_cols, 0, 0) < 0)
		{
			LM_ERR("Error while querying (fetch) database\n");
			return -1;
		}
		no_rows = estimate_available_rows( 64+4+32+4+64+64+64+64+128
			+32+32+8+8+256+32+64+64+8+8+8, n_result_cols);
		if (no_rows==0) no_rows = 10;
		if(pa_dbf.fetch_result(pa_db,&result, no_rows)<0)
		{
			LM_ERR("fetching rows failed\n");
			goto error;
		}
	} else
	{
		if (pa_dbf.query (pa_db, 0, 0, 0,result_cols,0, n_result_cols,
					0, &result) < 0)
		{
			LM_ERR("querying presentity\n");
			goto error;
		}
	}

	nr_rows = RES_ROW_N(result);

	do {
		LM_DBG("loading information from database %i records\n", nr_rows);

		rows = RES_ROWS(result);

		/* for every row */
		for(i=0; i<nr_rows; i++)
		{
			row_vals = ROW_VALUES(rows +i);
			memset(&s, 0, sizeof(subs_t));

			expires= row_vals[expires_col].val.int_val;

			if(expires< (int)time(NULL))
				continue;

			s.pres_uri.s= (char*)row_vals[pres_uri_col].val.string_val;
			s.pres_uri.len= strlen(s.pres_uri.s);

			s.to_user.s=(char*)row_vals[to_user_col].val.string_val;
			s.to_user.len= strlen(s.to_user.s);

			s.to_domain.s=(char*)row_vals[to_domain_col].val.string_val;
			s.to_domain.len= strlen(s.to_domain.s);

			s.from_user.s=(char*)row_vals[from_user_col].val.string_val;
			s.from_user.len= strlen(s.from_user.s);

			s.from_domain.s=(char*)row_vals[from_domain_col].val.string_val;
			s.from_domain.len= strlen(s.from_domain.s);

			s.to_tag.s=(char*)row_vals[totag_col].val.string_val;
			s.to_tag.len= strlen(s.to_tag.s);

			s.from_tag.s=(char*)row_vals[fromtag_col].val.string_val;
			s.from_tag.len= strlen(s.from_tag.s);

			s.callid.s=(char*)row_vals[callid_col].val.string_val;
			s.callid.len= strlen(s.callid.s);

			ev_sname.s= (char*)row_vals[event_col].val.string_val;
			ev_sname.len= strlen(ev_sname.s);

			event= contains_event(&ev_sname, &parsed_event);
			if(event== NULL)
			{
				LM_DBG("insert a new event structure in the list waiting"
						" to be filled in\n");

				/*insert a new event structure in the list waiting to be filled in*/
				event= (pres_ev_t*)shm_malloc(sizeof(pres_ev_t));
				if(event== NULL)
				{
					free_event_params(parsed_event.params, PKG_MEM_TYPE);
					ERR_MEM("shm");
				}
				memset(event, 0, sizeof(pres_ev_t));
				event->name.s= (char*)shm_malloc(ev_sname.len);
				if(event->name.s== NULL)
				{
					free_event_params(parsed_event.params, PKG_MEM_TYPE);
					ERR_MEM("shm");
				}
				memcpy(event->name.s,ev_sname.s, ev_sname.len);
				event->name.len= ev_sname.len;

				event->evp= shm_copy_event(&parsed_event);
				if(event->evp== NULL)
				{
					LM_ERR("ERROR copying event_t structure\n");
					free_event_params(parsed_event.params, PKG_MEM_TYPE);
					goto error;
				}
				event->next= EvList->events;
				EvList->events= event;
			}

			free_event_params(parsed_event.params, PKG_MEM_TYPE);

			s.event= event;

			s.event_id.s=(char*)row_vals[event_id_col].val.string_val;
			if(s.event_id.s)
				s.event_id.len= strlen(s.event_id.s);

			s.remote_cseq= row_vals[remote_cseq_col].val.int_val;
			s.local_cseq= row_vals[local_cseq_col].val.int_val;
			s.version= row_vals[version_col].val.int_val;

			s.expires= expires- (int)time(NULL);
			s.status = row_vals[status_col].val.int_val;

			if(!event->req_auth)
				s.status = ACTIVE_STATUS;
			else
			{
				if(subs_process_insert_status(&s)< 0)
				{
					LM_ERR("Failed to extract and insert status, skipping record\n");
					continue;
				}
			}

			s.reason.s= (char*)row_vals[reason_col].val.string_val;
			if(s.reason.s)
				s.reason.len= strlen(s.reason.s);

			s.contact.s=(char*)row_vals[contact_col].val.string_val;
			s.contact.len= strlen(s.contact.s);

			s.local_contact.s=(char*)row_vals[local_contact_col].val.string_val;
			s.local_contact.len= strlen(s.local_contact.s);

			s.record_route.s=(char*)row_vals[record_route_col].val.string_val;
			if(s.record_route.s)
				s.record_route.len= strlen(s.record_route.s);

			sockinfo_str.s = (char*)row_vals[sockinfo_col].val.string_val;
			if (sockinfo_str.s && (sockinfo_str.len=strlen(sockinfo_str.s))!=0)
			{
				if (parse_phostport (sockinfo_str.s, sockinfo_str.len, &host.s,
						&host.len, &port, &proto )< 0)
				{
					LM_ERR("bad format <%.*s> for stored sockinfo string,"
						" ignoring record\n", sockinfo_str.len,sockinfo_str.s);
					/* let it be NULL */
				} else {
					s.sockinfo = grep_sock_info(&host, (unsigned short) port,
						(unsigned short) proto);
					/* if not found, it will be NULL */
				}
			}

			if (row_vals[sharing_tag_col].nul==0) {
				s.sh_tag.s=(char*)row_vals[sharing_tag_col].val.string_val;
				s.sh_tag.len=strlen(s.sh_tag.s);
			}

			hash_code= core_hash(&s.pres_uri, &s.event->name, shtable_size);
			if(insert_shtable(subs_htable, hash_code, &s)< 0)
			{
				LM_ERR("adding new record in hash table, skipping record\n");
				continue;
			}
		}

		/* any more data to be fetched ?*/
		if (DB_CAPABILITY(pa_dbf, DB_CAP_FETCH)) {
			if (pa_dbf.fetch_result( pa_db, &result, no_rows ) < 0) {
				LM_ERR("fetching more rows failed\n");
				goto error;
			}
			nr_rows = RES_ROW_N(result);
		} else {
			nr_rows = 0;
		}

	}while (nr_rows>0);

	pa_dbf.free_result(pa_db, result);

	if(!fallback2db)
	{
		/* delete all records */
		if(pa_dbf.delete(pa_db, 0,0,0,0)< 0)
		{
			LM_ERR("deleting all records from database table\n");
			return -1;
		}
	}

	return 0;

error:
	if(result)
		pa_dbf.free_result(pa_db, result);
	return -1;
}

int refresh_watcher(str* pres_uri, str* watcher_uri, str* event,
		int status, str* reason)
{
	unsigned int hash_code;
	subs_t* s, *s_copy;
	pres_ev_t* ev;
	struct sip_uri uri;
	str user, domain;
	/* refresh status in subs_htable and send notify */

	ev=	contains_event(event, NULL);
	if(ev== NULL)
	{
		LM_ERR("while searching event in list\n");
		return -1;
	}

	if(parse_uri(watcher_uri->s, watcher_uri->len, &uri)< 0)
	{
		LM_ERR("parsing uri\n");
		return -1;
	}
	user= uri.user;
	domain= uri.host;

	hash_code= core_hash(pres_uri, event, shtable_size);

	lock_get(&subs_htable[hash_code].lock);

	s= subs_htable[hash_code].entries->next;

	while(s)
	{
		if(s->event== ev && s->pres_uri.len== pres_uri->len &&
			strncmp(s->pres_uri.s, pres_uri->s, pres_uri->len)== 0 &&
			s->from_user.len==user.len && strncmp(s->from_user.s,user.s, user.len)==0 &&
			s->from_domain.len== domain.len &&
			strncmp(s->from_domain.s, domain.s, domain.len)== 0)
		{
			s->status= status;
			if(reason)
				s->reason= *reason;

			s_copy= mem_copy_subs(s, PKG_MEM_TYPE);
			if(s_copy== NULL)
			{
				LM_ERR("copying subs_t\n");
				lock_release(&subs_htable[hash_code].lock);
				return -1;
			}
			lock_release(&subs_htable[hash_code].lock);
			if(notify(s_copy, NULL, NULL, 0, NULL, 0)< 0)
			{
				LM_ERR("in notify function\n");
				pkg_free(s_copy);
				return -1;
			}
			pkg_free(s_copy);
			lock_get(&subs_htable[hash_code].lock);
		}
		s= s->next;
	}
	return 0;
}

/*
* function that queries 'watchers' table from subscription status
* */
int get_db_subs_auth(subs_t* subs, int* found)
{
	static db_ps_t my_ps = NULL;
	db_key_t db_keys[5];
	db_val_t db_vals[5];
	int n_query_cols= 0;
	db_key_t result_cols[3];
	db_res_t *result = NULL;
	db_row_t *row ;
	db_val_t *row_vals ;

	db_keys[n_query_cols] =&str_presentity_uri_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.str_val= subs->pres_uri;
	n_query_cols++;

	db_keys[n_query_cols] =&str_watcher_username_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.str_val = subs->from_user;
	n_query_cols++;

	db_keys[n_query_cols] =&str_watcher_domain_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.str_val = subs->from_domain;
	n_query_cols++;

	db_keys[n_query_cols] =&str_event_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.str_val = subs->event->name;
	n_query_cols++;

	result_cols[0] = &str_status_col;
	result_cols[1] = &str_reason_col;

	if(pa_dbf.use_table(pa_db, &watchers_table)< 0)
	{
		LM_ERR("in use table\n");
		return -1;
	}

	CON_PS_REFERENCE(pa_db) = &my_ps;
	if(pa_dbf.query(pa_db, db_keys, 0, db_vals, result_cols,
					n_query_cols, 2, 0, &result )< 0)
	{
		LM_ERR("while querying watchers table\n");
		if(result)
			pa_dbf.free_result(pa_db, result);
		return -1;
	}
	if(result== NULL)
		return -1;

	if(result->n<= 0)
	{
		*found= 0;
		pa_dbf.free_result(pa_db, result);
		return 0;
	}

	*found= 1;
	row = &result->rows[0];
	row_vals = ROW_VALUES(row);
	subs->status= row_vals[0].val.int_val;

	if(row_vals[1].val.string_val)
	{

		subs->reason.len= strlen(row_vals[1].val.string_val);
		if(subs->reason.len== 0)
			subs->reason.s= NULL;
		else
		{
			subs->reason.s= (char*)pkg_malloc(subs->reason.len);
			if(subs->reason.s== NULL)
			{
				pa_dbf.free_result(pa_db, result);
				ERR_MEM(PKG_MEM_STR);
			}
			memcpy(subs->reason.s, row_vals[1].val.string_val, subs->reason.len);
		}
	}

	pa_dbf.free_result(pa_db, result);
	return 0;
error:
	if (result)
		pa_dbf.free_result(pa_db, result);
	return -1;
}

int insert_db_subs_auth(subs_t* subs)
{
	static db_ps_t my_ps = NULL;
	db_key_t db_keys[10];
	db_val_t db_vals[10];
	int n_query_cols= 0;

	db_keys[n_query_cols] =&str_presentity_uri_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.str_val= subs->pres_uri;
	n_query_cols++;

	db_keys[n_query_cols] =&str_watcher_username_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.str_val = subs->from_user;
	n_query_cols++;

	db_keys[n_query_cols] =&str_watcher_domain_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.str_val = subs->from_domain;
	n_query_cols++;

	db_keys[n_query_cols] =&str_event_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.str_val = subs->event->name;
	n_query_cols++;

	db_keys[n_query_cols] =&str_status_col;
	db_vals[n_query_cols].type = DB_INT;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.int_val = subs->status;
	n_query_cols++;

	db_keys[n_query_cols] = &str_inserted_time_col;
	db_vals[n_query_cols].type = DB_INT;
	db_vals[n_query_cols].nul = 0;
	db_vals[n_query_cols].val.int_val= (int)time(NULL);
	n_query_cols++;

	db_keys[n_query_cols] =&str_reason_col;
	db_vals[n_query_cols].type = DB_STR;
	db_vals[n_query_cols].nul = 0;

	if(subs->reason.s && subs->reason.len)
	{
		db_vals[n_query_cols].val.str_val = subs->reason;
	}
	else
	{
		db_vals[n_query_cols].val.str_val.s = "";
		db_vals[n_query_cols].val.str_val.len = 0;
	}
	n_query_cols++;

	if (pa_dbf.use_table(pa_db, &watchers_table) < 0)
	{
		LM_ERR("in use_table\n");
		return -1;
	}

	CON_PS_REFERENCE(pa_db) = &my_ps;
	if(pa_dbf.insert(pa_db, db_keys, db_vals, n_query_cols )< 0)
	{
		LM_ERR("in sql insert\n");
		return -1;
	}

	return 0;
}
