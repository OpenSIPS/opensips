/*
 * Copyright (C) 2017 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#include <fnmatch.h>

#include "../../ut.h"
#include "../../usr_avp.h"
#include "../../ipc.h"
#include "../../action.h"
#include "../../route.h"
#include "../../evi/evi_modules.h"
#include "../tm/tm_load.h"

#include "ebr_data.h"
#include "api.h"

/* structure holding all the needed data to be passed via IPC to 
 * the process that has to run the notification route */
typedef struct _ebr_ipc_job {
	/* pointer to the event definition
	 * shm, shared, static */
	ebr_event *ev;
	/* list of AVPs holding the EVI attributes
	 * shm, not-shared, dynamic */
	struct usr_avp *avps;
	/* some generic data related to event resume */
	void *data;
	/* subscription flags */
	int flags;
	/* TM specific data (transaction ID) */
	struct tm_id tm;
} ebr_ipc_job;

/* IPC type registered with the IPC layer */
extern int ebr_ipc_type;

/* TM API */
extern struct tm_binds ebr_tmb;

/* list of used EBR events */
static ebr_event *ebr_events = NULL;



ebr_event* search_ebr_event( const str *name )
{
	ebr_event *ev;

	for ( ev=ebr_events ; ev ; ev=ev->next ) {
		if (ev->event_name.len==name->len &&
		strncasecmp(ev->event_name.s, name->s, name->len)==0 )
			return ev;
	}
	return NULL;
}

ebr_event* add_ebr_event( const str *name )
{
	ebr_event *ev;

	LM_DBG("Adding new event <%.*s>\n", name->len, name->s);
	ev = (ebr_event*)shm_malloc(sizeof(ebr_event)+name->len);
	if (ev==NULL) {
		LM_ERR("failed to allocate a new EBR event in SHM\n");
		return NULL;
	}

	lock_init( &(ev->lock) );

	ev->event_name.s = (char*)(ev+1);
	memcpy(ev->event_name.s, name->s, name->len);
	ev->event_name.len = name->len;

	/* the event ID will be looked up and set of first function call */
	ev->event_id = -1;

	ev->subs = NULL;

	/* link it to the list */
	ev->next = ebr_events;
	ebr_events = ev;

	return ev;
}


int init_ebr_event( ebr_event *ev )
{
	int event_id;
	str sock;

	lock_get( &(ev->lock) );

	/* already initialized by other process? */
	if (ev->event_id>=0) {
		lock_release( &(ev->lock) );
		return 0;
	}

	/* do the actual init under lock */

	/* get the event id */
	if ( (event_id=evi_get_id(&ev->event_name))==EVI_ERROR) {
		LM_ERR("Event <%.*s> not available\n",
			ev->event_name.len, ev->event_name.s);
		goto error;
	}
	ev->event_id = event_id;

	/* register this EBR event as subscriber to EVI */
	sock.len = (sizeof(EVI_ROUTING_NAME)-1) + 1 +
		ev->event_name.len;
	sock.s = (char*)pkg_malloc( sock.len );
	if (sock.s == NULL) {
		LM_ERR("failed to allocate EBR socket\n");
		goto error;
	}
	memcpy( sock.s, EVI_ROUTING_NAME, sizeof(EVI_ROUTING_NAME)-1);
	sock.s[sizeof(EVI_ROUTING_NAME)-1] = TRANSPORT_SEP;
	memcpy( sock.s+sizeof(EVI_ROUTING_NAME), ev->event_name.s,
		ev->event_name.len);
	LM_DBG("registering socket <%.*s> for event <%.*s>/%d\n",
		sock.len, sock.s,
		ev->event_name.len, ev->event_name.s, ev->event_id);

	if (evi_event_subscribe( ev->event_name, sock, 0, 0) < 0) {
		LM_ERR("cannot subscribe to event %.*s\n",
			ev->event_name.len, ev->event_name.s);
		return -1;
	}

	lock_release( &(ev->lock) );
	return 0;

error:
	lock_release( &(ev->lock) );
	ev->event_id = -1;
	return -1;
}


int pack_ebr_filters(struct sip_msg *msg, int filter_avp_id,
                     ebr_filter **filters)
{
	struct usr_avp *avp;
	int_str val;
	ebr_filter *f_first, *f_last, *f_curr;
	str k_name, k_val;
	char *p;

	avp = NULL;
	f_first = f_last = NULL;

	/* search all the filter AVPs */
	while ((avp=search_first_avp(AVP_VAL_STR,filter_avp_id,&val,avp))!=NULL) {

		/* split and evaluate the value part */
		if ( (p=q_memchr( val.s.s, '=', val.s.len))==NULL) {
			LM_ERR("filter <%.*s> has no key separtor '=', discarding\n",
				val.s.len, val.s.s);
			continue;
		}
		k_name.s = val.s.s;
		k_name.len = p-val.s.s;
		p++;
		if (p==val.s.s+val.s.len) {
			LM_ERR("filter <%.*s> has no value, discarding\n",
				val.s.len, val.s.s);
			continue;
		}
		k_val.s = p;
		k_val.len = val.s.s+val.s.len-p;

		f_curr = (ebr_filter*)shm_malloc( sizeof(ebr_filter)+k_name.len+1+
			k_val.len+1 );
		if (f_curr==NULL) {
			LM_ERR("failed to shm malloc a new EBR filter\n");
			goto error;
		}
		memset(&f_curr->uri_param_key, 0, sizeof f_curr->uri_param_key);

		/* the key string comes just right after the structure */
		f_curr->key.s = (char*)(f_curr+1);
		f_curr->key.len = k_name.len;
		memcpy(f_curr->key.s, k_name.s, k_name.len);
		f_curr->key.s[f_curr->key.len] = 0;

		/* and the val string comes after the key string */
		f_curr->val.s = f_curr->key.s + f_curr->key.len + 1;
		f_curr->val.len = k_val.len;
		memcpy(f_curr->val.s, k_val.s, k_val.len);
		f_curr->val.s[f_curr->val.len] = 0;

		LM_DBG("converted key <%.*s>(%p) + val <%.*s>(%p) at %p \n",
			f_curr->key.len, f_curr->key.s, f_curr->key.s,
			f_curr->val.len, f_curr->val.s, f_curr->val.s,
			f_curr);

		if (f_first==NULL) {
			f_first = f_last = f_curr;
		} else {
			f_last->next = f_curr;
			f_last = f_curr;
		}
		f_curr->next = NULL;

	}

	*filters = f_first;
	return 0;

error:
	shm_free_all(f_first);
	*filters = NULL;
	return -1;
}


int dup_ebr_filters(const ebr_filter *src, ebr_filter **dst)
{
	ebr_filter *filter, *first = NULL, *last;

	for (; src; src = src->next) {
		filter = shm_malloc(sizeof *filter + src->key.len + 1 +
		                    src->uri_param_key.len + 1 + src->val.len + 1);
		if (!filter)
			goto oom;

		filter->key.s = (char *)(filter + 1);
		str_cpy(&filter->key, &src->key);
		filter->key.s[filter->key.len] = '\0';

		filter->uri_param_key.s = filter->key.s + filter->key.len + 1;
		str_cpy(&filter->uri_param_key, &src->uri_param_key);
		filter->uri_param_key.s[filter->uri_param_key.len] = '\0';

		filter->val.s = filter->uri_param_key.s +
		                         filter->uri_param_key.len + 1;
		str_cpy(&filter->val, &src->val);
		filter->val.s[filter->val.len] = '\0';

		filter->next = NULL;

		if (!first) {
			first = last = filter;
		} else {
			last->next = filter;
			last = filter;
		}
	}

	*dst = first;
	return 0;

oom:
	shm_free_all(first);
	LM_ERR("oom\n");
	*dst = NULL;
	return -1;
}


void free_ebr_subscription( ebr_subscription *sub)
{
	ebr_filter *h, *n;

	h = sub->filters;
	while(h) {
		n = h->next;
		shm_free(h);
		h = n;
	}
	shm_free(sub);
}


int add_ebr_subscription( struct sip_msg *msg, ebr_event *ev,
               ebr_filter *filters, int expire, ebr_pack_params_cb pack_params,
               void *data, int flags)
{
	ebr_subscription *sub;

	sub = (ebr_subscription*)shm_malloc(sizeof(ebr_subscription));
	if (sub==NULL) {
		LM_ERR("failed to SHM malloc a new EBR subscription\n");
		return -1;
	}

	sub->data = data;
	sub->filters = filters;
	sub->pack_params = pack_params;
	sub->flags = flags;
	sub->proc_no = process_no;
	sub->event = ev;
	sub->expire = get_ticks() + expire;
	/* for notification-type subscription, add transaction coordinates if
	 * available */
	if ( !(flags&EBR_SUBS_TYPE_NOTY && ebr_tmb.t_get_trans_ident
	&& ebr_tmb.t_get_trans_ident(msg, &sub->tm.hash, &sub->tm.label)>0) ){
		sub->tm.hash = 0;
		sub->tm.label = 0;
	}
	LM_DBG("transaction reference is %X:%X\n",sub->tm.hash,sub->tm.label);

	/* link subscription to the event */
	lock_get( &(ev->lock) );
	sub->next = ev->subs;
	ev->subs = sub;
	lock_release( &(ev->lock) );

	LM_DBG("new subscription [%s] on event %.*s/%d successfully added from "
		"process %d\n", (flags&EBR_SUBS_TYPE_WAIT)?"WAIT":"NOTIFY",
		ev->event_name.len, ev->event_name.s, ev->event_id, process_no);

	return 0;
}


static struct usr_avp *pack_evi_params_as_avp_list(evi_params_t *params)
{
	struct usr_avp *avp, *head=NULL;
	evi_param_t *e_param;
	int_str val;
	int avp_id;

	/* take all the EVI parameters and convert them into AVPs */
	for( e_param=params->first ; e_param ; e_param=e_param->next ) {

		/* get an AVP name matching the param name */
		if (parse_avp_spec( &e_param->name, &avp_id)<0) {
			LM_ERR("cannot get AVP ID for name <%.*s>, skipping..\n",
				e_param->name.len, e_param->name.s);
			continue;
		}

		/* create a new AVP */
		if (e_param->flags&EVI_STR_VAL) {
			val.s = e_param->val.s;
			avp = new_avp( AVP_VAL_STR, avp_id, val);
		} else if (e_param->flags&EVI_INT_VAL) {
			val.n = e_param->val.n;
			avp = new_avp( 0, avp_id, val);
		} else {
			LM_BUG("EVI param no STR, nor INT, ignoring...\n");
			continue;
		}

		if (avp==NULL) {
			LM_ERR("cannot get create new AVP name <%.*s>, skipping..\n",
				e_param->name.len, e_param->name.s);
			continue;
		}

		/* link the AVP */
		avp->next = head;
		head = avp;
	}

	return head;
}


/* Return: 1 on successful match, 0 otherwise */
static inline int ebr_filter_match_evp(const ebr_filter *filter,
                                       const evi_param_t *e_param)
{
	char *s;
	str match_str;
	struct sip_uri puri;
	int rc;

	/* a "no value" matches anything */
	if (filter->val.len == 0)
		return 1;

	/* do we have to perform an URI param value matching? */
	if (filter->uri_param_key.s) {
		if (!(e_param->flags & EVI_STR_VAL))
			return 0;

		if (parse_uri(e_param->val.s.s, e_param->val.s.len, &puri) != 0) {
			LM_ERR("failed to parse URI: '%.*s'\n",
			       e_param->val.s.len, e_param->val.s.s);
			return 0;
		}

		if (get_uri_param_val(&puri, &filter->uri_param_key, &match_str) != 0)
			return 0;

	} else if (e_param->flags & EVI_STR_VAL) {
		match_str = e_param->val.s;
	}

	if (e_param->flags&EVI_INT_VAL) {
		s=int2str((unsigned long)e_param->val.n, NULL);
		if (s==NULL) {
			LM_ERR("failed to covert int EVI param to "
				"string, EBR filter failed\n");
			return 0;
		} else {
			/* the output of int2str is NULL terminated */
			if (fnmatch( filter->val.s, s, 0)!=0)
				return 0;
		}

	} else if (e_param->flags&EVI_STR_VAL) {
#ifdef EXTRA_DEBUG
		LM_DBG("match %s against '%.*s'\n", filter->val.s,
		       match_str.len, match_str.s);
#endif

		s=(char*)pkg_malloc(match_str.len + 1);
		if (s==NULL) {
			LM_ERR("failed to allocate PKG fnmatch "
				"buffer, EBR filter failed\n");
			return 0;
		} else {
			memcpy(s, match_str.s, match_str.len);
			s[match_str.len] = 0;
			rc = fnmatch( filter->val.s, s, 0);
			pkg_free(s);
			if (rc != 0)
				return 0;
		}
	} else {
		LM_ERR("non-string EVI params are not supported yet\n");
		return 0;
	}

	return 1;
}


int notify_ebr_subscriptions( ebr_event *ev, evi_params_t *params)
{
	ebr_subscription *sub, *sub_next, *sub_prev;
	ebr_filter *filter;
	ebr_ipc_job *job;
	evi_param_t *e_param;
	int matches;
	struct usr_avp *avps=(void*)-1;
	unsigned int my_time;

	LM_DBG("notification received for event %.*s, checking subscriptions\n",
		ev->event_name.len, ev->event_name.s);

	my_time = get_ticks();

	lock_get( &(ev->lock) );

	/* check the EBR subscription on this event and apply the filters */
	sub_prev = NULL;
	for ( sub=ev->subs ; sub ; sub_prev=sub,
								sub=sub_next?sub_next:(sub?sub->next:NULL) ) {

		/* discard expired subscriptions */
		if (sub->expire<my_time) {
			LM_DBG("subscription type [%s] from process %d(pid %d) on "
				"event <%.*s> expired at %d\n",
				(sub->flags&EBR_SUBS_TYPE_WAIT)?"WAIT":"NOTIFY",
				sub->proc_no, pt[sub->proc_no].pid,
				sub->event->event_name.len, sub->event->event_name.s,
				sub->expire );
			/* remove the subscription */
			sub_next = sub->next;
			/* unlink it */
			if (sub_prev) sub_prev->next = sub_next;
			else ev->subs = sub_next;
			/* free it */
			free_ebr_subscription(sub);
			/* do not count us as prev, as we are removed */
			sub = sub_prev;
			continue;
		}

		/* run the filters */
		matches = 1;
		sub_next = NULL;
		for ( filter=sub->filters ; matches && filter ; filter=filter->next ) {

			/* look for the evi param with the same name */
			for ( e_param=params->first ; e_param ; e_param=e_param->next ) {
				if (str_casematch(&e_param->name, &filter->key)) {
					LM_DBG("key <%.*s> found, checking value\n",
					       filter->key.len, filter->key.s);

					if (!ebr_filter_match_evp(filter, e_param))
						matches = 0;

					break;
				}
			}

			/* a filter not matching any EVI params is simply ignored */
		}

		/* did the EVI event match the EBR filters for this subscription ? */
		if (matches) {

			LM_DBG("subscription type [%s]from process %d(pid %d) matched "
				"event, generating notification via IPC\n",
				(sub->flags&EBR_SUBS_TYPE_WAIT)?"WAIT":"NOTIFY",
				sub->proc_no, pt[sub->proc_no].pid);

			/* convert the EVI params into AVP (only once) */
			if (avps == (void *)-1 && !sub->pack_params)
				avps = pack_evi_params_as_avp_list(params);

			/* pack the EVI params to be attached to the IPC job */
			job =(ebr_ipc_job*)shm_malloc( sizeof(ebr_ipc_job) );
			if (job==NULL) {
				LM_ERR("failed to allocated new IPC job, skipping..\n");
				continue; /* with the next subscription */
			}

			if (sub->pack_params)
				job->avps = sub->pack_params(params);
			else
				job->avps = clone_avp_list( avps );

			job->ev = ev;
			job->data = sub->data;
			job->flags = sub->flags;
			job->tm = sub->tm;

			if (sub->flags&EBR_SUBS_TYPE_NOTY) {
				/* dispatch the event notification via IPC to the right 
				 * process. Key question - which one is the "right" process ?
				 *   - the current processs
				 *   - the process which performed the subscription
				 * Let's give it to ourselves for the moment */
				if (ipc_send_job( process_no, ebr_ipc_type , (void*)job)<0) {
					LM_ERR("failed to send job via IPC, skipping...\n");
					shm_free(job);
				}
			} else {
				/* sent the event notification via IPC to resume on the
				 * subscribing process */
				if (ipc_send_job( sub->proc_no, ebr_ipc_type , (void*)job)<0) {
					LM_ERR("failed to send job via IPC, skipping...\n");
					shm_free(job);
				}
				/* remove the subscription, as it can be triggered only 
				 * one time */
				sub_next = sub->next;
				/* unlink it */
				if (sub_prev) sub_prev->next = sub_next;
				else ev->subs = sub_next;
				/* free it */
				free_ebr_subscription(sub);
				/* do not count us as prev, as we are removed */
				sub = sub_prev;
			}

		}

	} /* end EBR subscription iterator */

	lock_release( &(ev->lock) );

	if (avps!=(void*)-1)
		destroy_avp_list( &avps );

	return 0;
}


void handle_ebr_ipc(int sender, void *payload)
{
	ebr_ipc_job *job = (ebr_ipc_job*)payload;
	struct usr_avp **old_avps;
	struct sip_msg *req;

	LM_DBG("EBR notification received via IPC for event %.*s\n",
		job->ev->event_name.len, job->ev->event_name.s);

	if (job->flags&EBR_SUBS_TYPE_NOTY) {

		/* this is a job for notifiying on an event */

		/* prepare a fake/dummy request */
		req = get_dummy_sip_msg();
		if(req == NULL) {
			LM_ERR("cannot create new dummy sip request\n");
			goto cleanup;
		}

		/* push our list of AVPs */
		old_avps = set_avp_list( &job->avps );

		LM_DBG("using transaction reference %X:%X\n",
			job->tm.hash, job->tm.label);
		if (ebr_tmb.t_set_remote_t && job->tm.hash!=0 && job->tm.label!=0 )
			ebr_tmb.t_set_remote_t( &job->tm );

		if (job->flags & EBR_DATA_TYPE_FUNC) {
			((ebr_notify_cb)job->data)();
		} else {
			/* run the notification route */
			set_route_type( REQUEST_ROUTE );
			run_top_route( sroutes->request[(int)(long)job->data].a, req);
		}

		if (ebr_tmb.t_set_remote_t)
			ebr_tmb.t_set_remote_t( NULL );

		/* cleanup over route execution */
		set_avp_list( old_avps );
		release_dummy_sip_msg(req);

		cleanup:
		/* destroy everything */
		destroy_avp_list( &job->avps );
		shm_free(job);

	} else {

		/* this is a job for resuming on WAIT */

		/* pass the list of AVPs to be pushed into the msg */
		((async_ctx*)job->data)->resume_param = job->avps;

		/* invoke the global resume ASYNC function */
		async_script_resume_f(ASYNC_FD_NONE, job->data /*the async ctx*/, 0 );

		shm_free(job);

	}

	return;
}


int ebr_resume_from_wait(int *fd, struct sip_msg *msg, void *param)
{
	struct usr_avp *avps=(struct usr_avp *)param;
	struct usr_avp *last_avp;
	struct usr_avp **avp_head;

	if (param==NULL)
		return 1;

	/* the only thing to do here is to inject the AVPs */
	for( last_avp=avps ; last_avp->next ; last_avp=last_avp->next );

	avp_head = get_avp_list();
	last_avp->next = *avp_head;
	*avp_head = avps;

	return 1;
}

