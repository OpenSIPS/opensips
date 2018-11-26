/*
 * presence_dialoginfo module -
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 * Copyright (C) 2008 Klaus Darilion, IPCom
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
 *  2008-08-25  initial version (kd)
 */

#define MAX_INT_LEN 11 /* 2^32: 10 chars + 1 char sign */

#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>

#include "../../mem/mem.h"
#include "../presence/utils_func.h"
#include "../presence/hash.h"
#include "../presence/event_list.h"
#include "../presence/presence.h"
#include "../presence/presentity.h"
#include "presence_dialoginfo.h"
#include "notify_body.h"
#include "pidf.h"

str* agregate_xmls(str* pres_user, str* pres_domain, str** body_array, int n, int partial);
str* build_dialoginfo(str* pres_user, str* pres_domain);
extern int force_single_dialog;

static str* _build_empty_dialoginfo(const char* pres_uri_char, str* extra_hdrs);

#define VERSION_HOLDER "00000000000"

void free_xml_body(char* body)
{
	if(body)
		xmlFree(body);
}

/* Joins user and domain into "sip:USER@DOMAIN".
 * dst must fit at least MAX_URI_SIZE+1 characters! */
static inline int sipuri_cat(char* dst, const str* user, const str* domain) {
	if ((4 + user->len + 1 + domain->len) > MAX_URI_SIZE) {
	        LM_ERR("entity URI too long, maximum=%d\n", MAX_URI_SIZE);
		return -1;
	}
	memcpy(dst, "sip:", 4);
	memcpy(dst + 4, user->s, user->len);
	dst[user->len + 4] = '@';
	memcpy(dst + user->len + 5, domain->s, domain->len);
	dst[user->len + 5 + domain->len] = '\0';
	return 0;
}

str* dlginfo_agg_nbody(str* pres_user, str* pres_domain, str** body_array, int n, int off_index)
{
	str* n_body= NULL;
	char pres_uri_char[MAX_URI_SIZE+1];

	if (sipuri_cat(pres_uri_char, pres_user, pres_domain) != 0)
		return NULL;
	LM_DBG("[pres_uri] %s (%d), [n]=%d\n", pres_uri_char,
		pres_user->len + 5 + pres_domain->len, n);

	if(body_array == NULL)
		return _build_empty_dialoginfo(pres_uri_char, NULL);

	if (n == -2)
		n_body= agregate_xmls(pres_user, pres_domain, body_array, 1, 1);
	else
		n_body= agregate_xmls(pres_user, pres_domain, body_array, n, 0);

	LM_DBG("[n_body]=%p\n", n_body);
	if(n_body) {
		LM_DBG("[*n_body]=%.*s\n",
			n_body->len, n_body->s);
	}
	if(n_body== NULL && n!= 0)
	{
		LM_ERR("while aggregating body\n");
	}

	xmlCleanupParser();
	xmlMemoryDump();

	if (n_body== NULL)
		n_body = _build_empty_dialoginfo(pres_uri_char, NULL);
	return n_body;
}

str* agregate_xmls(str* pres_user, str* pres_domain, str** body_array, int n, int partial)
{
	int i, j= 0;

	xmlDocPtr  doc = NULL;
	xmlNodePtr root_node = NULL;
	xmlNsPtr   namespace = NULL;

	xmlNodePtr p_root= NULL;
	xmlDocPtr* xml_array ;
	xmlNodePtr node = NULL;
	char *state;
	int winner_priority = -1, priority ;
	xmlNodePtr winner_dialog_node = NULL ;
	str *body= NULL;
	char buf[MAX_URI_SIZE+1];

	LM_DBG("[pres_user]=%.*s [pres_domain]= %.*s, [n]=%d\n",
			pres_user->len, pres_user->s, pres_domain->len, pres_domain->s, n);

	xml_array = (xmlDocPtr*)pkg_malloc( n*sizeof(xmlDocPtr));
	if(xml_array== NULL)
	{
		LM_ERR("while allocating memory\n");
		return NULL;
	}
	memset(xml_array, 0, n*sizeof(xmlDocPtr)) ;

	/* parse all the XML documents */
	for(i=0; i<n; i++)
	{
		if(body_array[i] == NULL )
			continue;

		xml_array[j] = NULL;
		xml_array[j] = xmlParseMemory( body_array[i]->s, body_array[i]->len );

		/* LM_DBG("parsing XML body: [n]=%d, [i]=%d, [j]=%d xml_array[j]=%p\n", n, i, j, xml_array[j] ); */

		if( xml_array[j]== NULL)
		{
			LM_ERR("while parsing xml body message\n");
			goto error;
		}
		j++;

	}

	if(j== 0)  /* no body */
	{
		if(xml_array)
			pkg_free(xml_array);
		return NULL;
	}

	/* n: number of bodies in total */
	/* j: number of useful bodies; created XML structures */
	/* i: loop counter */
	/* LM_DBG("number of bodies in total [n]=%d, number of useful bodies [j]=%d\n", n, j ); */

	/* create the new NOTIFY body  */
	if (sipuri_cat(buf, pres_user, pres_domain) != 0)
		goto error;

    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc==0)
        return NULL;

    root_node = xmlNewNode(NULL, BAD_CAST "dialog-info");
    if(root_node==0)
        goto error;

    xmlDocSetRootElement(doc, root_node);
	namespace = xmlNewNs(root_node, BAD_CAST "urn:ietf:params:xml:ns:dialog-info", NULL);
	if (!namespace) {
		LM_ERR("creating namespace failed\n");
	}
	xmlSetNs(root_node, namespace);
	/* The version must be increased for each new document and is a 32bit int.
       As the version is different for each watcher, we can not set here the
       correct value. Thus, we just put here a placeholder which will be
	   replaced by the correct value in the aux_body_processing callback.
	   Thus we have CPU intensive XML aggregation only once and can use
	   quick search&replace in the per-watcher aux_body_processing callback.
	   We use 11 chracters as an signed int (although RFC says unsigned int we
	   use signed int as presence module stores "version" in DB as
	   signed int) has max. 10 characters + 1 character for the sign
	*/
    xmlNewProp(root_node, BAD_CAST "version", BAD_CAST VERSION_HOLDER);
    xmlNewProp(root_node, BAD_CAST "entity",  BAD_CAST buf);
	if (!partial)
		xmlNewProp(root_node, BAD_CAST "state",  BAD_CAST "full" );
	else
		xmlNewProp(root_node, BAD_CAST "state",  BAD_CAST "partial" );

	/* loop over all bodies and create the aggregated body */
	for(i=0; i<j; i++)
	{
		/* LM_DBG("[n]=%d, [i]=%d, [j]=%d xml_array[i]=%p\n", n, i, j, xml_array[j] ); */
		p_root= xmlDocGetRootElement(xml_array[i]);
			if(p_root ==NULL) {
				LM_ERR("while getting the xml_tree root element\n");
				goto error;
			}
			if (p_root->children) {
			for (node = p_root->children; node; node = node->next) {
				if (node->type == XML_ELEMENT_NODE) {
					LM_DBG("node type: Element, name: %s\n", node->name);
					/* we do not copy the node, but unlink it and then add it ot the new node
					 * this destroys the original document but we do not need it anyway.
					 * using "copy" instead of "unlink" would also copy the namespace which
					 * would then be declared redundant (libxml unfortunately can not remove
					 * namespaces)
					 */
					if (!force_single_dialog || (j==1)) {
						xmlUnlinkNode(node);
						if(xmlAddChild(root_node, node)== NULL) {
							LM_ERR("while adding child\n");
							goto error;
						}
					} else {
						/* try to put only the most important into the XML document
						 * order of importance: terminated->trying->proceeding->confirmed->early
						 */
						state = xmlNodeGetNodeContentByName(node, "state", NULL);
						if (state) {
							LM_DBG("state element content = %s\n", state);
							priority = get_dialog_state_priority(state);
							if (priority > winner_priority) {
								winner_priority = priority;
								LM_DBG("new winner priority = %s (%d)\n", state, winner_priority);
								winner_dialog_node = node;
							}
							xmlFree(state);
						}
					}
				}
			}
		}
	}

	if (force_single_dialog && (j!=1)) {
		xmlUnlinkNode(winner_dialog_node);
		if(xmlAddChild(root_node, winner_dialog_node)== NULL) {
			LM_ERR("while adding winner-child\n");
			goto error;
		}
	}

	body = (str*)pkg_malloc(sizeof(str));
	if(body == NULL) {
		ERR_MEM(PKG_MEM_STR);
	}

	xmlDocDumpMemory(doc,(xmlChar**)(void*)&body->s,
			&body->len);

  	for(i=0; i<j; i++)
	{
		if(xml_array[i]!=NULL)
			xmlFreeDoc( xml_array[i]);
	}
	if (doc)
		xmlFreeDoc(doc);
	if(xml_array!=NULL)
		pkg_free(xml_array);

	xmlCleanupParser();
    xmlMemoryDump();

	return body;

error:
	if(xml_array!=NULL)
	{
		for(i=0; i<=j; i++)
		{
			if(xml_array[i]!=NULL)
				xmlFreeDoc( xml_array[i]);
		}
		pkg_free(xml_array);
	}
	if(body)
		pkg_free(body);

	return NULL;
}


int get_dialog_state_priority(char *state) {
	if (strcasecmp(state,"terminated") == 0)
		return 0;
	if (strcasecmp(state,"trying") == 0)
		return 1;
	if (strcasecmp(state,"proceeding") == 0)
		return 2;
	if (strcasecmp(state,"confirmed") == 0)
		return 3;
	if (strcasecmp(state,"early") == 0)
		return 4;

	return 0;
}


str *dlginfo_body_setversion(subs_t *subs, str *body) {
	char *version_start=0;
	char version[MAX_INT_LEN + 2]; /* +2 becasue of trailing " and \0 */
	int version_len;

	if (!body) {
		return NULL;
	}

	LM_DBG("set version\n");
	/* xmlDocDumpFormatMemory creates \0 terminated string */
	/* version parameters starts at minimum at character 34 */
	if (body->len < 41) {
		LM_ERR("body string too short!\n");
		return NULL;
	}
	version_start = strstr(body->s + 34, "version=");
	if (!version_start) {
	    LM_ERR("version string not found!\n");
		return NULL;
	}
	version_start += 9;

	version_len = snprintf(version, MAX_INT_LEN + 2,"%d\"", subs->version);
	if (version_len >= MAX_INT_LEN + 2) {
		LM_ERR("failed to convert 'version' to string\n");
		return NULL;
	}
	/* Replace the placeholder 00000000000 with the version.
	 * Put the padding behind the ""
	 */
	LM_DBG("replace version with \"%s\n",version);
	memcpy(version_start, version, version_len);
	memset(version_start + version_len, ' ', MAX_INT_LEN + 2 - version_len);

	return NULL;
}

str* build_dialoginfo(str* pres_user, str* pres_domain)
{
	xmlDocPtr  doc = NULL;
	xmlNodePtr root_node = NULL;
	xmlNodePtr dialog_node = NULL;
	xmlNodePtr state_node = NULL;

	str *body= NULL;
	str pres_uri;
	char buf[MAX_URI_SIZE+1];

	if (sipuri_cat(buf, pres_user, pres_domain) != 0)
		return NULL;
	pres_uri.s = buf;
	pres_uri.len = 4 + pres_user->len + 1 + pres_domain->len;
	LM_DBG("[pres_uri] %.*s\n", pres_uri.len, pres_uri.s);

	if (pres_contains_presence(&pres_uri) < 0) {
		LM_DBG("No record exists in hash_table\n");
		goto error;
	}

	/* create the Publish body */
	doc = xmlNewDoc(BAD_CAST "1.0");
	if(doc==0)
		goto error;

	root_node = xmlNewNode(NULL, BAD_CAST "dialog-info");
	if(root_node==0)
		goto error;

	xmlDocSetRootElement(doc, root_node);

	xmlNewProp(root_node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:dialog-info");
	/* we set the version to 0 but it should be set to the correct value
       in the pua module */
	xmlNewProp(root_node, BAD_CAST "version", BAD_CAST  VERSION_HOLDER);
	xmlNewProp(root_node, BAD_CAST "state",   BAD_CAST "partial" );
	xmlNewProp(root_node, BAD_CAST "entity",  BAD_CAST buf);
	/* dialog tag */
	dialog_node =xmlNewChild(root_node, NULL, BAD_CAST "dialog", NULL) ;
	if( dialog_node ==NULL)
	{
		LM_ERR("while adding child [dialog]\n");
		goto error;
	}

	/* reuse buf for user-part only */
	memcpy(buf, pres_user->s, pres_user->len);
	buf[pres_user->len] = '\0';

	xmlNewProp(dialog_node, BAD_CAST "id", BAD_CAST buf);

	/* state tag */
	state_node = xmlNewChild(dialog_node, NULL, BAD_CAST "state", BAD_CAST "terminated");
	if( state_node ==NULL)
	{
		LM_ERR("while adding child [state]\n");
		goto error;
	}
	/* create the body */
	body = (str*)pkg_malloc(sizeof(str));
	if(body == NULL)
	{
		LM_ERR("while allocating memory\n");
		goto error;
	}
	memset(body, 0, sizeof(str));

	xmlDocDumpMemory(doc,(unsigned char**)(void*)&body->s,&body->len);

	LM_DBG("new_body:\n%.*s\n",body->len, body->s);
	/*free the document */
	xmlFreeDoc(doc);
	xmlCleanupParser();
	return body;
error:
	if(doc)
		xmlFreeDoc(doc);
	return NULL;
}

static str* _build_empty_dialoginfo(const char* pres_uri_char, str* extra_hdrs)
{
	str* nbody= 0;
	xmlDocPtr doc = NULL;
	xmlNodePtr node;

	nbody= (str*) pkg_malloc(sizeof(str));
	if(nbody== NULL)
	{
		LM_ERR("No more memory\n");
		return 0;
	}

	doc = xmlNewDoc(BAD_CAST "1.0");
	if(doc == NULL)
	{
		LM_ERR("Failed to create new xml document\n");
		goto error;
	}

	node = xmlNewNode(0, BAD_CAST "dialog-info");
	if(node == NULL)
	{
		LM_ERR("Failed to create new xml node\n");
		goto error;
	}
	xmlDocSetRootElement(doc, node);
	xmlNewProp(node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:dialog-info");
	xmlNewProp(node, BAD_CAST "version", BAD_CAST VERSION_HOLDER);
	xmlNewProp(node, BAD_CAST "state",   BAD_CAST "full");

	xmlNewProp(node, BAD_CAST "entity", BAD_CAST pres_uri_char);

	xmlDocDumpMemory(doc,(xmlChar**)(void*)&nbody->s,
		&nbody->len);

	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();

	return nbody;
error:
	if(doc)
		xmlFreeDoc(doc);
	if(nbody)
		pkg_free(nbody);
	return 0;
}

str* build_empty_dialoginfo(str* pres_uri, str* extra_hdrs)
{
	char* pres_uri_char;
	str* ret;

	pres_uri_char = (char*)pkg_malloc(pres_uri->len + 1);
	if(pres_uri_char == NULL)
	{
		LM_ERR("No more memory\n");
		return NULL;
	}
	memcpy(pres_uri_char, pres_uri->s, pres_uri->len);
	pres_uri_char[pres_uri->len] = '\0';

	/* do the call with a null-terminated pres_uri */
	ret = _build_empty_dialoginfo(pres_uri_char, extra_hdrs);
	
	pkg_free(pres_uri_char);

	return ret;
}
