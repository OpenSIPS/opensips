/*
 * pua_reginfo module - Presence-User-Agent Handling of reg events
 *
 * Copyright (C) 2011, 2023 Carsten Bock, carsten@ng-voice.com
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
 */
#include "usrloc_cb.h"
#include "pua_reginfo.h"
#include <libxml/parser.h>
#include "../pua/pua.h"
#include "../presence/bind_presence.h"
#include "../../qvalue.h"
#include "../../lib/csv.h"
#include "../../trim.h"

/*
Contact: <sip:carsten@10.157.87.36:44733;transport=udp>;expires=600000;+g.oma.sip-im;language="en,fr";+g.3gpp.smsip;+g.oma.sip-im.large-message;audio;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-vs";+g.3gpp.cs-voice.
Call-ID: 9ad9f89f-164d-bb86-1072-52e7e9eb5025.
*/

/*<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="0" state="full">
.<registration aor="sip:carsten@ng-voice.com" id="0xb33fa860" state="active">
..<contact id="0xb33fa994" state="active" event="registered" expires="3600">
...<uri>sip:carsten@10.157.87.36:43582;transport=udp</uri>
...<unknown-param name="+g.3gpp.cs-voice"></unknown-param>
...<unknown-param name="+g.3gpp.icsi-ref">urn0X0.0041FB74E7B54P-1022urn-70X0P+03gpp-application.ims.iari.gsma-vs</unknown-param>
...<unknown-param name="audio"></unknown-param>
...<unknown-param name="+g.oma.sip-im.large-message"></unknown-param>
...<unknown-param name="+g.3gpp.smsip"></unknown-param>
...<unknown-param name="language">en,fr</unknown-param>
...<unknown-param name="+g.oma.sip-im"></unknown-param>
...<unknown-param name="expires">600000</unknown-param>
..</contact>
.</registration>
</reginfo> */

static int _pua_reginfo_self_op = 0;

static pres_ev_t *reginfo_event = NULL;

void pua_reginfo_update_self_op(int v)
{
	_pua_reginfo_self_op = v;
}

str r_active = str_init("active");
str r_terminated = str_init("terminated");
str r_registered = str_init("registered");
str r_refreshed = str_init("refreshed");
str r_expired = str_init("expired");
str r_unregistered = str_init("unregistered");
#define VERSION_HOLDER "00000000000"

str reginfo_key_etag = str_init("reginfo_etag");

str *build_reginfo_full(urecord_t *record, ucontact_t *contact, str aor[], unsigned int aor_count, int type, int * count)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root_node = NULL;
	xmlNodePtr registration_node = NULL;
	xmlNodePtr contact_node = NULL;
	xmlNodePtr uri_node = NULL;
	str *body = NULL;
	str state = STR_NULL;
	str event = STR_NULL;
	ucontact_t *ptr;
	char buf[512];
	int reg_active = 0;
	time_t cur_time = time(0);
	int expires = 0;
	int i = 0;

	/* create the XML-Body */
	doc = xmlNewDoc(BAD_CAST "1.0");
	if(doc == 0) {
		LM_ERR("Unable to create XML-Doc\n");
		return NULL;
	}

	root_node = xmlNewNode(NULL, BAD_CAST "reginfo");
	if(root_node == 0) {
		LM_ERR("Unable to create reginfo-XML-Element\n");
		xmlFreeDoc(doc);
		return NULL;
	}
	/* This is our Root-Element: */
	xmlDocSetRootElement(doc, root_node);

	xmlNewProp(root_node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:reginfo");

	/* we set the version to 0 but it should be set to the correct value in the pua module */
	xmlNewProp(root_node, BAD_CAST "version", BAD_CAST VERSION_HOLDER);
	xmlNewProp(root_node, BAD_CAST "state", BAD_CAST "full");

	for (i = 0; i < aor_count; i++) {
		/* Registration Node */
		registration_node =
				xmlNewChild(root_node, NULL, BAD_CAST "registration", NULL);
		if(registration_node == NULL) {
			LM_ERR("while adding child\n");
			goto error;
		}
		reg_active = 0;

		/* Add the properties to this Node for AOR and ID: */
		xmlNewProp(registration_node, BAD_CAST "aor", BAD_CAST aor[i].s);
		snprintf(buf, sizeof(buf), "%p.%i", record, i);
		xmlNewProp(registration_node, BAD_CAST "id", BAD_CAST buf);

		ptr = record->contacts;
		LM_DBG("Records %p\n", ptr);
		*count = 0;
		while(ptr) {
			expires = (int)(ptr->expires - cur_time);
			LM_DBG("Contact %.*s (Expires %i, now %i, in %i)\n", ptr->c.len, ptr->c.s, (int)ptr->expires, (int)cur_time, expires);
			if(ptr == contact) {
				switch(type) {
						//richard we only use registered and refreshed and expired and unregistered
					case UL_CONTACT_INSERT:
						state = r_active;
						event = r_registered;
						reg_active = 1;
						break;
					case UL_CONTACT_UPDATE:
						state = r_active;
						event = r_refreshed;
						reg_active = 1;
						break;
					case UL_CONTACT_EXPIRE:
						state = r_terminated;
						event = r_expired;
						expires = 0;
						break;
					case UL_CONTACT_DELETE:
						state = r_terminated;
						event = r_unregistered;
						expires = 0;
						break;
					default:
						state = r_active;
						event = r_registered;
						reg_active = 1;
				}
			} else {
				if (VALID_CONTACT(ptr, cur_time)) {
					state = r_active;
					event = r_registered;
					reg_active = 1;
				} else {
					state = r_terminated;
					event = r_expired;
					expires = 0;
				}
			}
			*count = *count + 1;
			LM_DBG("Contact %.*s\n", ptr->c.len, ptr->c.s);
			/* Contact-Node */
			contact_node = xmlNewChild(
					registration_node, NULL, BAD_CAST "contact", NULL);
			if(contact_node == NULL) {
				LM_ERR("while adding child\n");
				goto error;
			}
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%p", ptr);
			xmlNewProp(contact_node, BAD_CAST "id", BAD_CAST buf);
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%.*s", state.len, state.s);
			xmlNewProp(contact_node, BAD_CAST "state", BAD_CAST buf);
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%.*s", event.len, event.s);
			xmlNewProp(
					contact_node, BAD_CAST "event", BAD_CAST buf);
			memset(buf, 0, sizeof(buf));
			snprintf(
					buf, sizeof(buf), "%i", (int)expires);
			xmlNewProp(contact_node, BAD_CAST "expires", BAD_CAST buf);
			if(ptr->q != Q_UNSPECIFIED) {
				float q = (float)ptr->q / 1000;
				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf), "%.3f", q);
				xmlNewProp(contact_node, BAD_CAST "q", BAD_CAST buf);
			}
			/* CallID Attribute */
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%.*s", ptr->callid.len, ptr->callid.s);
			xmlNewProp(contact_node, BAD_CAST "callid", BAD_CAST buf);

			/* CSeq Attribute */
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%d", ptr->cseq);
			xmlNewProp(contact_node, BAD_CAST "cseq", BAD_CAST buf);

			if (ptr->received.len) {
				/* received Attribute */
				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf), "%.*s", ptr->received.len,
						ptr->received.s);
				xmlNewProp(contact_node, BAD_CAST "received", BAD_CAST buf);
			}

			if (ptr->path.len) {
				/* path Attribute */
				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf), "%.*s", ptr->path.len, ptr->path.s);
				xmlNewProp(contact_node, BAD_CAST "path", BAD_CAST buf);
			}

			if (ptr->user_agent.len) {
				/* user_agent Attribute */
				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf), "%.*s", ptr->user_agent.len,
						ptr->user_agent.s);
				xmlNewProp(contact_node, BAD_CAST "user_agent", BAD_CAST buf);
			}

			/* URI-Node */
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%.*s", ptr->c.len, ptr->c.s);
			uri_node = xmlNewChild(
					contact_node, NULL, BAD_CAST "uri", BAD_CAST buf);
			if(uri_node == NULL) {
				LM_ERR("while adding child\n");
				goto error;
			}
			ptr = ptr->next;
		}

		/* add registration state (at least one active contact): */
		if(reg_active == 0)
			xmlNewProp(registration_node, BAD_CAST "state", BAD_CAST "terminated");
		else
			xmlNewProp(registration_node, BAD_CAST "state", BAD_CAST "active");
	}

	/* create the body */
	body = (str *)pkg_malloc(sizeof(str));
	if(body == NULL) {
		LM_ERR("while allocating memory\n");
		return NULL;
	}
	memset(body, 0, sizeof(str));

	/* Write the XML into the body */
	xmlDocDumpFormatMemory(
			doc, (unsigned char **)(void *)&body->s, &body->len, 1);

	/*free the document */
	xmlFreeDoc(doc);
	xmlCleanupParser();

	return body;
error:
	if(body) {
		if(body->s)
			xmlFree(body->s);
		pkg_free(body);
	}
	if(doc)
		xmlFreeDoc(doc);
	return NULL;
}

void reginfo_usrloc_cb(void *binding, ul_cb_type type, ul_cb_extra *_) {
	ucontact_t *contact = (ucontact_t*)binding;
	urecord_t *record = NULL;
	event_t ev;
	str *body = NULL;
	publ_info_t publ;
	presentity_t presentity;
	str content_type;
	str uri = {NULL, 0};
	struct sip_uri pres_uri;
	char etag_buf[MD5_LEN];
	str etag = {NULL, 0};
	int_str_t * key_value;
	int_str_t new_value;

	char *at = NULL;
	char id_buf[512];
	int id_buf_len;
	int count = 0, i = 0;
	str aorlist[20];
	unsigned int aor_count = 0;
	csv_record *pai_list = NULL;
	str s, str_dup;

	/* Get the URecord for the contact */
	LM_DBG("Searching urecord for contact-AOR %.*s (Contact %.*s)\n",
		contact->aor->len, contact->aor->s,
		contact->c.len, contact->c.s);
	ul.get_urecord(ul_domain, contact->aor, &record);
	if (record == NULL) {
		LM_DBG("Unable to get urecord for contact-AOR %.*s (Contact %.*s)\n",
			contact->aor->len, contact->aor->s,
			contact->c.len, contact->c.s);
		return;
	}

	if(_pua_reginfo_self_op == 1) {
		LM_DBG("operation triggered by own action for aor: %.*s (%d)\n",
				record->aor.len, record->aor.s, type);
		return;
	}

	/* Debug Output: */
	LM_DBG("AOR: %.*s (%.*s)\n", record->aor.len, record->aor.s, record->domain->len,
			record->domain->s);
	
	if (ul_identities_key.len > 0) {
		key_value = ul.get_urecord_key(record, &ul_identities_key);
		if (key_value && key_value->is_str) {
			LM_DBG("Got associated identities: %.*s\n", key_value->s.len, key_value->s.s);
			pai_list = parse_csv_record(&key_value->s);
			while(pai_list) {
				str_dup = pai_list->s;
				trim(&str_dup);
				if (str_dup.s[0] == '<') {
					// Strip tags <>:
					str_dup.s += 1;
					str_dup.len -= 2;
				}
				if (pkg_nt_str_dup(&s, &str_dup) < 0) {
					LM_ERR("Out of memory\n");
					goto error;
				}				
				LM_DBG("  Identity %.*s\n", s.len, s.s);
				aorlist[aor_count] = s;
				aor_count += 1;
				pai_list = pai_list->next;
				if (aor_count >= 20) break;
			}
		} else {
			LM_INFO("Looking for identities, but no info found in usrloc - not updating presence\n");
			return;
		}
	}

	/* Create AOR to be published */
	/* Search for @ in the AOR. In case no domain was provided, we will add the "default_domain" */
	at = memchr(record->aor.s, '@', record->aor.len);
	if(!at) {
		uri.len = record->aor.len + reginfo_default_domain.len + 6;
		uri.s = (char *)pkg_malloc(sizeof(char) * uri.len);
		if(uri.s == NULL) {
			LM_ERR("Error allocating memory for URI!\n");
			goto error;
		}
		memset(uri.s, 0, uri.len);
		if(record->aor.len > 0)
			uri.len = snprintf(uri.s, uri.len, "sip:%.*s@%.*s", record->aor.len,
					record->aor.s, reginfo_default_domain.len, reginfo_default_domain.s);
		else
			uri.len = snprintf(uri.s, uri.len, "sip:%.*s", reginfo_default_domain.len,
					reginfo_default_domain.s);
	} else {
		uri.len = record->aor.len + 6;
		uri.s = (char *)pkg_malloc(sizeof(char) * uri.len);
		if(uri.s == NULL) {
			LM_ERR("Error allocating memory for URI!\n");
			goto error;
		}
		uri.len = snprintf(
				uri.s, uri.len, "sip:%.*s", record->aor.len, record->aor.s);
	}

	if (parse_uri(uri.s, uri.len, &pres_uri)<0){
		LM_ERR("bad uri <%.*s>\n", uri.len, uri.s);
		goto error;
	}
	
	if (aor_count == 0) {
		aorlist[0] = uri;
		aor_count = 1;
	}
	
	/* Build the XML-Body: */
	body = build_reginfo_full(record, contact, aorlist, aor_count, type, &count);

	if(body == NULL || body->s == NULL) {
		LM_ERR("Error on creating XML-Body for publish\n");
		goto error;
	}
	LM_DBG("XML-Body (%i entries):\n%.*s\n", count, body->len, body->s);

	if (pres.update_presentity != NULL) {
		if (reginfo_event == NULL) {
			/* now search it back as we need the internal event structure */
			memset(&ev, 0, sizeof(event_t));
			ev.parsed = EVENT_REG;
			ev.text.s = "reg";
			ev.text.len = 3;
			reginfo_event = pres.search_event( &ev );
			if (reginfo_event==NULL) {
				LM_CRIT("BUG: failed to get back the registered REG-INFO event!\n");
				goto error;
			}		
		}

		/* now we have all the necessary values */
		/* fill in the fields of the structure */
		memset(&presentity, 0, sizeof(presentity_t));
		presentity.domain = pres_uri.host;
		presentity.user   = pres_uri.user;
		presentity.event = reginfo_event;
		if ((type & (UL_CONTACT_DELETE|UL_CONTACT_EXPIRE)) && (count == 0))	{
			presentity.expires = 0;
		} else {
			presentity.expires = 3600;
		}
		presentity.received_time = (int)time(NULL);
		key_value = ul.get_urecord_key(record, &reginfo_key_etag);
		if (key_value && key_value->is_str) {
			presentity.old_etag = key_value->s;
		} else {
			id_buf_len = snprintf(id_buf, sizeof(id_buf), "%.*s;%i",
					record->aor.len, record->aor.s, count);
			etag.s = id_buf;
			etag.len = id_buf_len;
			MD5StringArray(etag_buf, &etag, 1);

			presentity.etag_new = 1;
			presentity.new_etag.s = etag_buf;
			presentity.new_etag.len = MD5_LEN;
		}
		LM_DBG("etag_new = %i, new_etag %.*s, old_etag %.*s\n", presentity.etag_new,
		  presentity.new_etag.len, presentity.new_etag.s,
		  presentity.old_etag.len, presentity.old_etag.s);
		
		presentity.body = *body;

		/* query the database and update or insert */
		if(pres.update_presentity(&presentity) <0)
		{
			LM_ERR("when updating presentity\n");
			goto error;
		}

		LM_DBG("etag_new = %i, new_etag %.*s, old_etag %.*s\n", presentity.etag_new,
		  presentity.new_etag.len, presentity.new_etag.s,
		  presentity.old_etag.len, presentity.old_etag.s);

		memset(&new_value, 0, sizeof(int_str_t));
		new_value.is_str = 1;
		new_value.s = presentity.new_etag;
		ul.put_urecord_key(record, &reginfo_key_etag, &new_value);
	}

	if (publish_reginfo && pua.send_publish != NULL) {
		content_type.s = "application/reginfo+xml";
		content_type.len = 23;


		memset(&publ, 0, sizeof(publ_info_t));

		publ.pres_uri = &uri;
		publ.body = body;
		id_buf_len = snprintf(id_buf, sizeof(id_buf), "REGINFO_PUBLISH.%.*s@%.*s",
				record->aor.len, record->aor.s, record->domain->len, record->domain->s);
		publ.id.s = id_buf;
		publ.id.len = id_buf_len;
		publ.content_type = content_type;
		publ.expires = 3600;

		/* make UPDATE_TYPE, as if this "publish dialog" is not found
		by pua it will fallback to INSERT_TYPE anyway */
		publ.flag |= UPDATE_TYPE;
		publ.source_flag |= REGINFO_PUBLISH;
		publ.event |= REGINFO_EVENT;
		publ.extra_headers = NULL;

		if(outbound_proxy.s && outbound_proxy.len)
			publ.outbound_proxy = outbound_proxy;

		if(pua.send_publish(&publ) < 0) {
			LM_ERR("Error while sending publish\n");
		}
	}
error:
	for (i = 0; i < aor_count; i++)
		pkg_free(aorlist[i].s);
	if(body) {
		if(body->s)
			xmlFree(body->s);
		pkg_free(body);
	}

	return;
}

int w_reginfo_update(struct sip_msg *msg, str * aor) {
	urecord_t *record = NULL;

	/* Let's lock that domain for this AOR: */
	ul.lock_udomain(ul_domain, aor);
	/* Get the URecord for the contact */
	LM_DBG("Searching urecord for contact-AOR %.*s\n",
		aor->len, aor->s);
	ul.get_urecord(ul_domain, aor, &record);
	if (record == NULL) {
		LM_DBG("Unable to get urecord for contact-AOR %.*s\n",
			aor->len, aor->s);
		/* Let's lock that domain for this AOR: */
		ul.unlock_udomain(ul_domain, aor);
		return -1;
	}
	if (record->contacts) {
		if (record->contacts->next)
			reginfo_usrloc_cb((void*)record->contacts, UL_CONTACT_UPDATE, NULL);
		else
			reginfo_usrloc_cb((void*)record->contacts, UL_CONTACT_INSERT, NULL);
	} else {
		LM_DBG("Registered, but no contacts. Not updating Reg-Info-State");
	}

	/* Let's lock that domain for this AOR: */
	ul.unlock_udomain(ul_domain, aor);
	return 1;
}