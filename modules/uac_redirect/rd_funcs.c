/*
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 *
 * History:
 * ---------
 *  2005-06-22  first version (bogdan)
 *  2006-05-23  push also q value into branches (bogdan)
 */


#include "../../usr_avp.h"
#include "../../dset.h"
#include "../../dprint.h"
#include "../../qvalue.h"
#include "../../parser/contact/parse_contact.h"
#include "../../qvalue.h"
#include "rd_filter.h"
#include "rd_funcs.h"


#define MAX_CONTACTS_PER_REPLY   16
#define DEFAULT_Q_VALUE          10

static int shmcontact2dset(struct sip_msg *req, struct sip_msg *shrpl, long max);

int get_redirect( struct sip_msg *msg , int maxt, int maxb)
{
	struct cell *t;
	int max;
	int cts_added;
	int n;
	int i;

	/* get transaction */
	t = rd_tmb.t_gett();
	if (t==T_UNDEFINED || t==T_NULL_CELL)
	{
		LM_CRIT("no current transaction found\n");
		goto error;
	}

	LM_DBG("resume branch=%d\n", t->first_branch);

	cts_added = 0; /* no contact added */

	/* look if there are any 3xx branches starting from resume_branch */
	for( i=t->first_branch ; i<t->nr_of_outgoings ; i++) {
		LM_DBG("checking branch=%d (added=%d)\n", i, cts_added);
		/* is a redirected branch? */
		if (t->uac[i].last_received<300 || t->uac[i].last_received>399)
			continue;
		LM_DBG("branch=%d is a redirect (added=%d)\n", i, cts_added);
		/* ok - we have a new redirected branch -> how many contacts can
		 * we get from it*/
		if (maxb==0) {
			max = maxt?(maxt-cts_added):(-1);
		} else {
			max = maxt?((maxt-cts_added>=maxb)?maxb:(maxt-cts_added)):maxb;
		}
		if (max==0)
			continue;
		/* get the contact from it */
		n = shmcontact2dset( msg, t->uac[i].reply, max);
		if ( n<0 ) {
			LM_ERR("get contact from shm_reply branch %d failed\n",i);
			/* do not go to error, try next branches */
		} else {
			/* count the added contacts */
			cts_added += n;
		}
	}

	/* return false if no contact was appended */
	return (cts_added>0)?1:-1;
error:
	return -1;
}



/* returns the number of contacts put in the sorted array */
static void sort_contacts(contact_t *ct_list, str *ct_array,
													qvalue_t *q_array, int *n)
{
	param_t *q_para;
	qvalue_t q;
	int i, j, rc;
	char backup;

	for( ; ct_list ; ct_list = ct_list->next ) {
		/* check the filters first */
		backup = ct_list->uri.s[ct_list->uri.len];
		ct_list->uri.s[ct_list->uri.len] = 0;
		if ( run_filters( ct_list->uri.s )==-1 ){
			ct_list->uri.s[ct_list->uri.len] = backup;
			continue;
		}
		ct_list->uri.s[ct_list->uri.len] = backup;
		/* does the contact has a q val? */
		q_para = ct_list->q;
		if (q_para==0 || q_para->body.len==0) {
			q = DEFAULT_Q_VALUE;
		} else {
			rc = str2q( &q, q_para->body.s, q_para->body.len);
			if (rc != 0) {
				LM_ERR("invalid qvalue (%.*s): %s\n",
						q_para->body.len, q_para->body.s, qverr2str(rc));
				/* skip this contact */
				continue;
			}
		}
		LM_DBG("sort_contacts: <%.*s> q=%d\n",
				ct_list->uri.len,ct_list->uri.s,q);
		/*insert the contact into the sorted array */
		for(i=0;i<*n;i++) {
			/* keep in mind that the contact list is reversts */
			if (q_array[i]<=q)
				continue;
			break;
		}
		if (i!=MAX_CONTACTS_PER_REPLY) {
			/* insert the contact at this position */
			for( j=(*n)-1-1*((*n)==MAX_CONTACTS_PER_REPLY) ; j>=i ; j-- ) {
				ct_array[j+1] = ct_array[j];
				q_array[j+1] = q_array[j];
			}
			ct_array[j+1] = ct_list->uri;
			q_array[j+1] = q;
			if ((*n)!=MAX_CONTACTS_PER_REPLY)
				(*n)++;
		}
	}
}



/* returns : -1 - error
 *            0 - ok, but no contact added
 *            n - ok and n contacts added
 */
static int shmcontact2dset(struct sip_msg *req, struct sip_msg *sh_rpl, long max)
{
	static struct sip_msg  dup_rpl;
	static str scontacts[MAX_CONTACTS_PER_REPLY];
	static qvalue_t  sqvalues[MAX_CONTACTS_PER_REPLY];
	struct hdr_field *hdr;
	struct hdr_field *contact_hdr;
	contact_t        *contacts;
	int n,i;
	int added;
	int dup;
	int ret;

	dup = 0; /* sh_rpl not duplicated */
	ret = 0; /* success and no contact added */
	contact_hdr = NULL;
	hdr = NULL;

	if (sh_rpl==0 || sh_rpl==FAKED_REPLY)
		return 0;

	if ( sh_rpl->msg_flags&FL_SHM_CLONE ) {
		/* duplicate the reply into private memory to be able
		 * to parse it and after words to free the parsed mems */
		memcpy( &dup_rpl, sh_rpl, sizeof(struct sip_msg) );
		LM_DBG("duplicating shm reply\n");
		dup = 1;
		/* ok -> force the parsing of contact header */
		if ( parse_headers( &dup_rpl, HDR_EOH_F, 0)<0 ) {
			LM_ERR("dup_rpl parse failed\n");
			ret = -1;
			goto restore;
		}
		if (dup_rpl.contact==0) {
			LM_DBG("contact hdr not found in dup_rpl\n");
			goto restore;
		}
		contact_hdr = dup_rpl.contact;
	} else {
		/* parse directly the current copy */
		/* force the parsing of contact header */
		if ( parse_headers( sh_rpl, HDR_EOH_F, 0)<0 ) {
			LM_ERR("sh_rpl parse failed\n");
			ret = -1;
			goto restore;
		}
		if (sh_rpl->contact==0) {
			LM_DBG("contact hdr not found in sh_rpl\n");
			goto restore;
		}
		contact_hdr = sh_rpl->contact;
	}

	/* iterate through all contact headers and extract the URIs */
	for( n=0,hdr=contact_hdr ; hdr ; hdr=hdr->sibling ) {

		/* parse the body of contact header */
		if (hdr->parsed==0) {
			if ( parse_contact(hdr)<0 ) {
				LM_ERR("contact hdr parse failed\n");
				ret = -1;
				goto restore;
			}
		}

		/* we have the contact header and its body parsed -> sort the contacts
		 * based on the q value */
		contacts = ((contact_body_t*)hdr->parsed)->contacts;
		if (contacts==0) {
			LM_DBG("contact hdr has no contacts\n");
		} else {
			sort_contacts( contacts, scontacts, sqvalues, &n);
		}

		/* clean currently added contact */
		if (dup)
			free_contact( (contact_body_t**)(void*)(&hdr->parsed) );
	}

	if (n==0) {
		LM_DBG("no contacts left after filtering\n");
		goto restore;
	}

	/* to many branches ? */
	if (max!=-1 && n>max)
		n = max;

	LM_DBG("%d contacts remaining after filtering and sorting\n",n);

	added = 0;

	/* add the sorted contacts as branches in dset and log this! */
	for ( i=0 ; i<n ; i++ ) {
		LM_DBG("adding contact <%.*s>\n",
			scontacts[i].len, scontacts[i].s);
		if (i==0) {
			/* set RURI*/
			if ( set_ruri( req, &scontacts[i])==-1 ) {
				LM_ERR("failed to set new RURI\n");
				goto restore;
			}
			set_ruri_q(req, sqvalues[i]);
		} else {
			if (append_branch(0,&scontacts[i],0,0,sqvalues[i],0,0)<0) {
				LM_ERR("failed to add contact to dset\n");
				continue;
			}
		}
		added++;
	}

	ret = (added==0)?-1:added;
restore:
	if (dup==1) {
		/* free current parsed contact header */
		if (hdr && hdr->parsed)
			free_contact( (contact_body_t**)(void*)(&hdr->parsed) );
		/* are any new headers found? */
		if (dup_rpl.last_header!=sh_rpl->last_header) {
			/* identify in the new headere list (from dup_rpl)
			 * the sh_rpl->last_header and start remove everything after */
			hdr = sh_rpl->last_header;
			free_hdr_field_lst(hdr->next);
			hdr->next=0;
		}
	}
	return ret;
}

