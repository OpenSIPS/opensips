/*
 * presence_xml module -
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
 *  2007-04-11  initial version (anca)
 */

#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>

#include "../../mem/mem.h"
#include "../presence/utils_func.h"
#include "../presence/hash.h"
#include "xcap_auth.h"
#include "pidf.h"
#include "notify_body.h"
#include "presence_xml.h"

str* get_final_notify_body( subs_t *subs, str* notify_body, xmlNodePtr rule_node);

enum {
	OFFB_STATUS_OK = 0,
	OFFB_STATUS_NO_DIALOG,
	OFFB_STATUS_ERROR,
};

#define GET_LAST_XML_ERROR(e, msg) \
	(e) = xmlGetLastError(); (msg) = (e) ? (e)->message : "unknown error"


struct xml_node_s {
    xmlNodePtr node;
    struct xml_node_s *next;
};
typedef struct xml_node_s xml_node_t;

static inline int check_duplicated_id(const char *id, xml_node_t *list)
{
    int found = 0;
    char *curr_id;
    xml_node_t *curr;

    curr = list;
    while (curr) {
        curr_id = xmlNodeGetAttrContentByName(curr->node, "id");
        if(curr_id == NULL)
            continue;
        if(xmlStrcasecmp(BAD_CAST id, BAD_CAST curr_id )== 0)
        {
                found = 1;
                xmlFree(curr_id);
                break;
        }
        xmlFree(curr_id);
        curr = curr->next;
    }
    return found;
}


int dialog_offline_body(str* body, str** offline_body)
{
	xmlDocPtr doc= NULL;
	xmlNodePtr node;
	xmlErrorPtr xml_error;
	str* new_body = NULL;
	char *err_msg;
	int rc = OFFB_STATUS_ERROR;

	if (!offline_body)
	{
		LM_ERR("invalid parameter\n");
		return OFFB_STATUS_ERROR;
	}
	*offline_body = NULL;

	doc= xmlParseMemory(body->s, body->len);
	if(doc==  NULL)
	{
		GET_LAST_XML_ERROR(xml_error, err_msg);
		LM_ERR("xml memory parsing failed: %s\n", err_msg);
		goto done;
	}
	node= xmlDocGetNodeByName(doc, "dialog", NULL);
	if(node== NULL)
	{
		LM_DBG("no dialog nodes found\n");
		rc = OFFB_STATUS_NO_DIALOG;
		goto done;
	}
	node= xmlNodeGetChildByName(node,  "state");
	if(node== NULL)
	{
		LM_ERR("while extracting state node\n");
		goto done;
	}
	xmlNodeSetContent(node, (const unsigned char*)"terminated");

	new_body = (str*)pkg_malloc(sizeof(str));
	if(new_body == NULL)
	{
		LM_ERR("No more pkg memory\n");
		goto done;
	}
	memset(new_body, 0, sizeof(str));

	xmlDocDumpMemory(doc,(xmlChar**)(void*)&new_body->s,
		&new_body->len);

	*offline_body = new_body;
	rc = OFFB_STATUS_OK;

done:
	if (doc)
	    xmlFreeDoc(doc);

	return rc;
}

int presence_offline_body(str* body, str** offline_body)
{
	xmlDocPtr doc= NULL;
	xmlDocPtr new_doc= NULL;
	xmlNodePtr node, tuple_node= NULL, status_node;
	xmlNodePtr root_node, add_node, pres_node;
	xmlErrorPtr	xml_error;
	str* new_body;
	char *err_msg;
	int rc = OFFB_STATUS_ERROR;

	doc= xmlParseMemory(body->s, body->len);
	if(doc==  NULL)
	{
		GET_LAST_XML_ERROR(xml_error, err_msg);
		LM_ERR("xml memory parsing failed: %s\n", err_msg);
		goto done;
	}
	node= xmlDocGetNodeByName(doc, "basic", NULL);
	if(node== NULL)
	{
		LM_ERR("while extracting basic node\n");
		goto done;
	}
	xmlNodeSetContent(node, (const unsigned char*)"closed");

	tuple_node= xmlDocGetNodeByName(doc, "tuple", NULL);
	if(tuple_node== NULL)
	{
		LM_ERR("while extracting tuple node\n");
		goto done;
	}
	status_node= xmlDocGetNodeByName(doc, "status", NULL);
	if(status_node== NULL)
	{
		LM_ERR("while extracting tuple node\n");
		goto done;
	}

	pres_node= xmlDocGetNodeByName(doc, "presence", NULL);
	if(pres_node== NULL)
	{
		LM_ERR("while extracting presence node\n");
		goto done;
	}

	new_doc = xmlNewDoc(BAD_CAST "1.0");
	if(new_doc==0)
	{
		GET_LAST_XML_ERROR(xml_error, err_msg);
		LM_ERR("failed to create new XML document: %s\n", err_msg);
		goto done;
	}

	root_node= xmlCopyNode(pres_node, 2);
	if(root_node== NULL)
	{
		GET_LAST_XML_ERROR(xml_error, err_msg);
		LM_ERR("failed to copy root node: %s\n", err_msg);
		goto done;
	}
	xmlDocSetRootElement(new_doc, root_node);

	tuple_node= xmlCopyNode(tuple_node, 2);
	if(tuple_node== NULL)
	{
		GET_LAST_XML_ERROR(xml_error, err_msg);
		LM_ERR("failed to copy tuple node: %s\n", err_msg);
		goto done;
	}

	xmlAddChild(root_node, tuple_node);

	add_node= xmlCopyNode(status_node, 1);
	if(add_node== NULL)
	{
		GET_LAST_XML_ERROR(xml_error, err_msg);
		LM_ERR("failed to copy status node: %s\n", err_msg);
		goto done;
	}

	xmlAddChild(tuple_node, add_node);

	new_body = (str*)pkg_malloc(sizeof(str));
	if(new_body == NULL)
	{
		LM_ERR("No more pkg memory\n");
		goto done;
	}
	memset(new_body, 0, sizeof(str));

	xmlDocDumpMemory(new_doc,(xmlChar**)(void*)&new_body->s,
		&new_body->len);

	*offline_body = new_body;
	rc = OFFB_STATUS_OK;

done:
	if(doc)
		xmlFreeDoc(doc);
	if(new_doc)
		xmlFreeDoc(new_doc);

	return rc;
}

void free_xml_body(char* body)
{
	if(body== NULL)
		return;

	xmlFree(body);
	body= NULL;
}

str* agregate_dialog_xmls(str* pres_user, str* pres_domain, str** body_array, int n)
{
	char* root_name = "dialog-info";
	char* elem_name = "dialog";
	int i, j= 0, append ;
	xmlNodePtr p_root= NULL, new_p_root= NULL ;
	xmlDocPtr* xml_array ;
	xmlNodePtr node = NULL;
	xmlNodePtr add_node = NULL ;
	str *body= NULL;
	char* id= NULL, *elem_id = NULL;

	xml_array = (xmlDocPtr*)pkg_malloc( (n+2)*sizeof(xmlDocPtr));
	if(xml_array== NULL)
	{

		LM_ERR("while allocating memory\n");
		return NULL;
	}
	memset(xml_array, 0, (n+2)*sizeof(xmlDocPtr)) ;

	for(i=0; i<n; i++)
	{
		if(body_array[i] == NULL )
			continue;

		xml_array[j] = NULL;
		xml_array[j] = xmlParseMemory( body_array[i]->s, body_array[i]->len );
		LM_DBG("i = [%d] - body: %.*s\n", i,  body_array[i]->len, body_array[i]->s);

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

	j--;
	p_root = xmlDocGetNodeByName( xml_array[j], root_name, NULL);
	if(p_root ==NULL)
	{
		LM_ERR("while getting the xml_tree root\n");
		goto error;
	}

	for(i= j-1; i>=0; i--)
	{
		LM_DBG("i = %d\n", i);

		new_p_root= xmlDocGetNodeByName( xml_array[i], root_name, NULL);
		if(new_p_root ==NULL)
		{
			LM_ERR("while getting the xml_tree root\n");
			goto error;
		}

		node= xmlNodeGetChildByName(new_p_root, elem_name);
		if(node== NULL)
		{
			LM_DBG("no %s node found\n", elem_name);
			append = 1;
			goto append_label;
		}
		elem_id= xmlNodeGetAttrContentByName(node, "id");
		if(elem_id== NULL)
		{
			LM_ERR("while extracting %s id\n", elem_name);
			goto error;
		}
		append= 1;
		for (node = p_root->children; node!=NULL; node = node->next)
		{
			if( xmlStrcasecmp(node->name,(unsigned char*)"text")==0)
				continue;

			if( xmlStrcasecmp(node->name,(unsigned char*)elem_name)==0)
			{
				id = xmlNodeGetAttrContentByName(node, "id");
				if(id== NULL)
				{
					LM_ERR("while extracting %s id\n", elem_name);
					goto error;
				}

				if(xmlStrcasecmp((unsigned char*)elem_id,
							(unsigned char*)id )== 0)
				{
					append = 0;
					xmlFree(id);
					break;
				}
				xmlFree(id);
			}
		}
		xmlFree(elem_id);
		elem_id= NULL;

append_label:
		if(append)
		{
			LM_DBG("in if\n");
			for(node= new_p_root->children; node; node= node->next)
			{
				LM_DBG("adding node [%s]\n", node->name);
				add_node= xmlCopyNode(node, 1);
				if(add_node== NULL)
				{
					LM_ERR("while copying node [%s]\n", node->name);
					goto error;
				}

				if(xmlAddChild(p_root, add_node)== NULL)
				{
					LM_ERR("while adding child\n");
					goto error;
				}
			}
		}
	}

	body = (str*)pkg_malloc(sizeof(str));
	if(body == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}

	xmlDocDumpMemory(xml_array[j],(xmlChar**)(void*)&body->s,
			&body->len);

	LM_DBG("body = %.*s\n", body->len, body->s);

	for(i=0; i<=j; i++)
	{
		if(xml_array[i]!=NULL)
			xmlFreeDoc( xml_array[i]);
	}
	if(xml_array!=NULL)
		pkg_free(xml_array);

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
	if(elem_id)
		xmlFree(elem_id);
	if(body)
		pkg_free(body);
	return NULL;
}

#define ADD_NODE(node, list_head, list_tail)                            \
    do {                                                                \
        LM_DBG("adding node [%s]\n", node->name);                       \
        add_node = xmlCopyNode(node, 1);                                \
        if(add_node == NULL)                                            \
        {                                                               \
            LM_ERR("while copying node [%s]\n", node->name);            \
            goto error;                                                 \
        }                                                               \
        tmp_node = (xml_node_t *)pkg_malloc(sizeof(xml_node_t));        \
        if(tmp_node == NULL)                                            \
        {                                                               \
            ERR_MEM(PKG_MEM_STR);                                       \
        }                                                               \
        tmp_node->node = add_node;                                      \
        tmp_node->next = NULL;                                          \
        if (!list_head)                                                 \
        {                                                               \
            list_head = tmp_node;                                       \
            list_tail = tmp_node;                                       \
        }                                                               \
        else                                                            \
        {                                                               \
            list_tail->next = tmp_node;                                 \
            list_tail = tmp_node;                                       \
        }                                                               \
    } while(0)                                                          \

str* agregate_presence_xmls(str* pres_user, str* pres_domain, str** body_array, int n)
{
    static char* root_name   = "presence";
    static char* tuple_name  = "tuple";
    static char* note_name   = "note";
    static char* person_name = "person";
    static char* device_name = "device";

    int i, j = 0, len;
    char* id = NULL;
    char buf[MAX_URI_SIZE+1];
    str *body= NULL;
    str* pidf_doc= NULL;
    str pres_uri = {0,0};

    xmlDocPtr* xml_array;
    xmlDocPtr new_doc = NULL;
    xmlDocPtr pidf_manip_doc = NULL;
    xmlNodePtr new_doc_root = NULL;
    xmlNodePtr current_doc_root = NULL;
    xmlNodePtr node = NULL;
    xmlNodePtr add_node = NULL;

    xml_node_t *tmp_node = NULL;
    xml_node_t *tmp_node2 = NULL;
    xml_node_t *tuples_head = NULL;
    xml_node_t *tuples_tail = NULL;
    xml_node_t *notes_head = NULL;
    xml_node_t *notes_tail = NULL;
    xml_node_t *persons_head = NULL;
    xml_node_t *persons_tail = NULL;
    xml_node_t *devices_head = NULL;
    xml_node_t *devices_tail = NULL;
    xml_node_t *others_head = NULL;
    xml_node_t *others_tail = NULL;

    xml_array = (xmlDocPtr*)pkg_malloc( (n+2)*sizeof(xmlDocPtr));
    if(xml_array == NULL)
    {
        LM_ERR("while allocating memory\n");
        return NULL;
    }
    memset(xml_array, 0, (n+2)*sizeof(xmlDocPtr)) ;

    if ((4 + pres_user->len + 1 + pres_domain->len + 1) > MAX_URI_SIZE)
    {
        LM_ERR("entity URI too long, maximum=%d\n", MAX_URI_SIZE);
        return NULL;
    }
    memcpy(buf, "sip:", 4);
    len = 4;
    memcpy(buf+len, pres_user->s, pres_user->len);
    len += pres_user->len;
    buf[len] = '@';
    len += 1;
    memcpy(buf+len, pres_domain->s, pres_domain->len);
    len += pres_domain->len;
    buf[len]= '\0';

    pres_uri.s = buf;
    pres_uri.len = len;

    LM_DBG("[pres_uri] %.*s\n", pres_uri.len, pres_uri.s);

    /* if pidf_manipulation usage is configured and there are no other bodies */
    if(pidf_manipulation && body_array == NULL)
    {
        if(p_get_xcap_doc(pres_user, pres_domain, PIDF_MANIPULATION, &pidf_doc) < 0)
        {
            LM_ERR("while getting xcap tree for doc_type PIDF_MANIPULATION\n");
            goto error;
        }
        if(pidf_doc == NULL)
        {
            LM_DBG("No PIDF_MANIPULATION doc for [user]= %.*s [domain]= %.*s\n",
                    pres_user->len, pres_user->s, pres_domain->len, pres_domain->s);
        }
        else
        {
            pidf_manip_doc = xmlParseMemory(pidf_doc->s, pidf_doc->len);
            pkg_free(pidf_doc->s);
            pkg_free(pidf_doc);

            if(pidf_manip_doc == NULL)
            {
                LM_ERR("parsing xml memory\n");
                goto error;
            }
            else
            {
                xml_array[0]= pidf_manip_doc;
                j++;
            }
        }
    }

    for(i = 0; i < n; i++)
    {
        if(body_array[i] == NULL )
            continue;

        xml_array[j] = NULL;
        xml_array[j] = xmlParseMemory( body_array[i]->s, body_array[i]->len );
        LM_DBG("i = [%d] - body: %.*s\n", i,  body_array[i]->len, body_array[i]->s);

        if(xml_array[j] == NULL)
        {
            LM_ERR("while parsing xml body message\n");
            goto error;
        }
        j++;
    }

    if(j == 0)  /* no body */
    {
        if(xml_array)
            pkg_free(xml_array);
        return NULL;
    }
    j--;

    for(i = j; i >= 0; i--)
    {
        LM_DBG("i = %d\n", i);

        current_doc_root = xmlDocGetRootElement(xml_array[i]);
        if(current_doc_root == NULL)
        {
            LM_ERR("while getting the xml_tree root\n");
            continue;
        }

        if(!(xmlStrcasecmp(current_doc_root->name, (unsigned char*)root_name)==0 && xmlStrcasecmp(current_doc_root->ns->href, BAD_CAST "urn:ietf:params:xml:ns:pidf")==0))
        {
            LM_ERR("invalid root element\n");
            continue;
        }

        for (node = current_doc_root->children; node; node = node->next)
        {
	    if (node->type != XML_ELEMENT_NODE)
	        continue;

            /* Handle tuple elements */
            if(xmlStrcasecmp(node->name, (unsigned char*)tuple_name)==0 && xmlStrcasecmp(node->ns->href, BAD_CAST "urn:ietf:params:xml:ns:pidf")==0)
            {
                id = xmlNodeGetAttrContentByName(node, "id");
                if(id == NULL)
                {
                    LM_ERR("while extracting %s id\n", node->name);
                    goto error;
                }

                /* xs:ID needs to be unique in the whole document */
                if (check_duplicated_id(id, tuples_head) || check_duplicated_id(id, persons_head) || check_duplicated_id(id, devices_head))
                {
                    xmlFree(id);
                    continue;
                }
                xmlFree(id);

                ADD_NODE(node, tuples_head, tuples_tail);
                continue;
            }

            /* Handle note elements */
            if(xmlStrcasecmp(node->name, (unsigned char*)note_name)==0 && xmlStrcasecmp(node->ns->href, BAD_CAST "urn:ietf:params:xml:ns:pidf")==0)
            {
                ADD_NODE(node, notes_head, notes_tail);
                continue;
            }

            /* Handle person elements */
            if(xmlStrcasecmp(node->name, (unsigned char*)person_name)==0 && xmlStrcasecmp(node->ns->href, BAD_CAST "urn:ietf:params:xml:ns:pidf:data-model")==0)
            {
                id = xmlNodeGetAttrContentByName(node, "id");
                if(id == NULL)
                {
                    LM_ERR("while extracting %s id\n", node->name);
                    goto error;
                }

                /* xs:ID needs to be unique in the whole document */
                if (check_duplicated_id(id, persons_head) || check_duplicated_id(id, tuples_head) || check_duplicated_id(id, devices_head))
                {
                    xmlFree(id);
                    continue;
                }
                xmlFree(id);

                ADD_NODE(node, persons_head, persons_tail);
                continue;
            }

            /* Handle device elements */
            if(xmlStrcasecmp(node->name, (unsigned char*)device_name)==0 && xmlStrcasecmp(node->ns->href, BAD_CAST "urn:ietf:params:xml:ns:pidf:data-model")==0)
            {
                id = xmlNodeGetAttrContentByName(node, "id");
                if(id == NULL)
                {
                    LM_ERR("while extracting %s id\n", node->name);
                    goto error;
                }

                /* xs:ID needs to be unique in the whole document */
                if (check_duplicated_id(id, devices_head) || check_duplicated_id(id, tuples_head) || check_duplicated_id(id, persons_head))
                {
                    xmlFree(id);
                    continue;
                }
                xmlFree(id);

                ADD_NODE(node, devices_head, devices_tail);
                continue;
            }

            /* Handle other elements */
            ADD_NODE(node, others_head, others_tail);

        }

    }

    /* We built all lists, we can now build the new document */
    new_doc = xmlNewDoc(BAD_CAST "1.0");
    if(new_doc == NULL)
    {
        LM_ERR("allocating new xml doc\n");
        goto error;
    }

    new_doc_root = xmlNewNode(NULL, BAD_CAST "presence");
    if(new_doc_root == NULL)
    {
        LM_ERR("Failed to create xml node\n");
        goto error;
    }
    xmlNewProp(new_doc_root, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:pidf");
    xmlDocSetRootElement(new_doc, new_doc_root);
    xmlNewProp(new_doc_root, BAD_CAST "entity", BAD_CAST pres_uri.s);

    /* Add tuple elements */
    tmp_node = tuples_head;
    while(tmp_node) {
        xmlAddChild(new_doc_root, tmp_node->node);
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }

    /* Add note elements */
    tmp_node = notes_head;
    while(tmp_node) {
        xmlAddChild(new_doc_root, tmp_node->node);
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }

    /* Add person elements */
    tmp_node = persons_head;
    while(tmp_node) {
        xmlAddChild(new_doc_root, tmp_node->node);
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }

    /* Add devices elements */
    tmp_node = devices_head;
    while(tmp_node) {
        xmlAddChild(new_doc_root, tmp_node->node);
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }

    /* Add other elements */
    tmp_node = others_head;
    while(tmp_node) {
        xmlAddChild(new_doc_root, tmp_node->node);
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }

    tmp_node = tmp_node2 = tuples_head = tuples_tail = notes_head = notes_tail = persons_head = persons_tail = devices_head = devices_tail = others_head = others_tail = NULL;

    body = (str *)pkg_malloc(sizeof(str));
    if(body == NULL)
    {
        ERR_MEM(PKG_MEM_STR);
    }

    xmlDocDumpMemory(new_doc, (xmlChar**)(void*)&body->s, &body->len);

    LM_DBG("body = %.*s\n", body->len, body->s);

    for(i = 0; i <= j; i++)
    {
        if(xml_array[i] != NULL)
            xmlFreeDoc(xml_array[i]);
    }
    if(xml_array != NULL)
        pkg_free(xml_array);

    xmlFreeDoc(new_doc);

    return body;

error:
    if (new_doc)
        xmlFreeDoc(new_doc);
    tmp_node = tuples_head;
    while(tmp_node) {
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }
    tmp_node = notes_head;
    while(tmp_node) {
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }
    tmp_node = persons_head;
    while(tmp_node) {
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }
    tmp_node = devices_head;
    while(tmp_node) {
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }
    tmp_node = others_head;
    while(tmp_node) {
        tmp_node2 = tmp_node;
        tmp_node = tmp_node->next;
        pkg_free(tmp_node2);
    }
    if(xml_array != NULL)
    {
        for(i = 0; i <= j; i++)
        {
            if(xml_array[i] != NULL)
                xmlFreeDoc(xml_array[i]);
        }
        pkg_free(xml_array);
    }
    if(body)
        pkg_free(body);
    return NULL;
}

#undef ADD_NODE

str* dialog_agg_nbody(str* pres_user, str* pres_domain, str** body_array, int n, int off_index)
{
        str* n_body = NULL;
        str* body = NULL;
        int status = OFFB_STATUS_OK;

        if(body_array == NULL)
            return NULL;

        if(off_index >= 0 && generate_offline_body)
        {
            body = body_array[off_index];
            status = dialog_offline_body(body, &n_body);
            if (status != OFFB_STATUS_OK && status != OFFB_STATUS_NO_DIALOG)
            {
                LM_ERR("constructing offline body failed\n");
                return NULL;
            }
            body_array[off_index] = n_body;
        }

        LM_DBG("[user]=%.*s  [domain]= %.*s\n", pres_user->len, pres_user->s, pres_domain->len, pres_domain->s);
        n_body = agregate_dialog_xmls(pres_user, pres_domain, body_array, n);
        if(n_body == NULL && n != 0 && generate_offline_body != 0)
        {
            LM_ERR("while aggregating body\n");
        }

        if(off_index >= 0 && generate_offline_body && status == OFFB_STATUS_OK)
        {
            xmlFree(body_array[off_index]->s);
            pkg_free(body_array[off_index]);
            body_array[off_index] = body;
        }

        return n_body;
}

str* presence_agg_nbody(str* pres_user, str* pres_domain, str** body_array, int n, int off_index)
{
	str* n_body = NULL;
	str* body = NULL;
	int status = OFFB_STATUS_OK;

        if(body_array == NULL && !pidf_manipulation)
            return NULL;

        if(off_index >= 0 && generate_offline_body)
        {
            body = body_array[off_index];
            status = presence_offline_body(body, &n_body);
            if (status != OFFB_STATUS_OK)
            {
                LM_ERR("constructing offline body failed\n");
                return NULL;
            }
            body_array[off_index] = n_body;
        }

        LM_DBG("[user]=%.*s  [domain]= %.*s\n", pres_user->len, pres_user->s, pres_domain->len, pres_domain->s);
        n_body = agregate_presence_xmls(pres_user, pres_domain, body_array, n);

        if(n_body == NULL && n != 0 && generate_offline_body != 0)
        {
            LM_ERR("while aggregating body\n");
        }

        if(off_index >= 0 && generate_offline_body && status == OFFB_STATUS_OK)
        {
            xmlFree(body_array[off_index]->s);
            pkg_free(body_array[off_index]);
            body_array[off_index] = body;
        }

        return n_body;
}

int pres_apply_auth(str* notify_body, subs_t* subs, str** final_nbody)
{
	xmlDocPtr doc= NULL;
	xmlNodePtr node= NULL;
	str* n_body= NULL;

	*final_nbody= NULL;
	if(force_active)
		return 0;

	if(subs->auth_rules_doc== NULL)
	{
		LM_ERR("NULL rules doc\n");
		return -1;
	}
	doc= xmlParseMemory(subs->auth_rules_doc->s, subs->auth_rules_doc->len);
	if(doc== NULL)
	{
		LM_ERR("parsing xml doc\n");
		return -1;
	}

	node= get_rule_node(subs, doc);
	if(node== NULL)
	{
		LM_DBG("The subscriber didn't match the conditions\n");
		xmlFreeDoc(doc);
		return 0;
	}

	n_body= get_final_notify_body(subs, notify_body, node);
	if(n_body== NULL)
	{
		LM_ERR("in function get_final_notify_body\n");
		xmlFreeDoc(doc);
		return -1;
	}

	xmlFreeDoc(doc);

	*final_nbody= n_body;
	return 1;

}

str* get_final_notify_body( subs_t *subs, str* notify_body, xmlNodePtr rule_node)
{
	xmlNodePtr transf_node = NULL, node = NULL, dont_provide = NULL;
	xmlNodePtr doc_root = NULL, doc_node = NULL, provide_node = NULL;
	xmlNodePtr all_node = NULL;
	xmlDocPtr doc= NULL;
	char name[15];
	char service_uri_scheme[10];
	int i= 0, found = 0;
	str* new_body = NULL;
    char* class_cont = NULL, *occurence_ID= NULL, *service_uri= NULL;
	char* deviceID = NULL;
	char* content = NULL;
	char all_name[20];

	strcpy(all_name, "all-");

	new_body = (str*)pkg_malloc(sizeof(str));
	if(new_body == NULL)
	{
		LM_ERR("while allocating memory\n");
		return NULL;
	}

	memset(new_body, 0, sizeof(str));

	doc = xmlParseMemory(notify_body->s, notify_body->len);
	if(doc== NULL)
	{
		LM_ERR("while parsing the xml body message\n[%.*s]\n",
				notify_body->len, notify_body->s);
		goto error;
	}
	doc_root = xmlDocGetNodeByName(doc,"presence", NULL);
	if(doc_root == NULL)
	{
		LM_ERR("while extracting the presence node\n");
		goto error;
	}

	transf_node = xmlNodeGetChildByName(rule_node, "transformations");
	if(transf_node == NULL)
	{
		LM_DBG("No transformations node found\n");
		goto done;
	}

	for(node = transf_node->children; node; node = node->next )
	{
		if(xmlStrcasecmp(node->name, (unsigned char*)"text")== 0)
			continue;

		LM_DBG("transf_node->name:%s\n",node->name);

		strcpy((char*)name ,(char*)(node->name + 8));
		strcpy(all_name+4, name);

		if(xmlStrcasecmp((unsigned char*)name,(unsigned char*)"services") == 0)
			strcpy(name, "tuple");
		if(strncmp((char*)name,"person", 6) == 0)
			name[6] = '\0';

		doc_node = xmlNodeGetNodeByName(doc_root, name, NULL);
		if(doc_node == NULL)
			continue;
		LM_DBG("searched doc_node->name:%s\n",name);

		content = (char*)xmlNodeGetContent(node);
		if(content)
		{
			LM_DBG("content = %s\n", content);

			if(xmlStrcasecmp((unsigned char*)content,
					(unsigned char*) "FALSE") == 0)
			{
				LM_DBG("found content false\n");
				while( doc_node )
				{
					xmlUnlinkNode(doc_node);
					xmlFreeNode(doc_node);
					doc_node = xmlNodeGetChildByName(doc_root, name);
				}
				xmlFree(content);
				continue;
			}

			if(xmlStrcasecmp((unsigned char*)content,
					(unsigned char*) "TRUE") == 0)
			{
				LM_DBG("found content true\n");
				xmlFree(content);
				continue;
			}
			xmlFree(content);
		}

		while (doc_node )
		{
			if (xmlStrcasecmp(doc_node->name,(unsigned char*)"text")==0)
			{
				doc_node = doc_node->next;
				continue;
			}

			if (xmlStrcasecmp(doc_node->name,(unsigned char*)name)!=0)
			{
				break;
			}
			all_node = xmlNodeGetChildByName(node, all_name) ;

			if( all_node )
			{
				LM_DBG("must provide all\n");
				doc_node = doc_node->next;
				continue;
			}

			found = 0;
			class_cont = xmlNodeGetNodeContentByName(doc_node, "class",
					NULL);
			if(class_cont == NULL)
				LM_DBG("no class tag found\n");
			else
				LM_DBG("found class = %s\n", class_cont);

			occurence_ID = xmlNodeGetAttrContentByName(doc_node, "id");
			if(occurence_ID == NULL)
				LM_DBG("no id found\n");
			else
				LM_DBG("found id = %s\n", occurence_ID);


			deviceID = xmlNodeGetNodeContentByName(doc_node, "deviceID",
					NULL);
			if(deviceID== NULL)
				LM_DBG("no deviceID found\n");
			else
				LM_DBG("found deviceID = %s\n",	deviceID);


			service_uri = xmlNodeGetNodeContentByName(doc_node, "contact",
					NULL);
			if(service_uri == NULL)
				LM_DBG("no service_uri found\n");
			else
				LM_DBG("found service_uri = %s\n", service_uri);
			i = 0;
			if(service_uri!= NULL)
			{
				while(service_uri[i]!= ':')
				{
					service_uri_scheme[i] = service_uri[i];
					i++;
				}
				service_uri_scheme[i] = '\0';
				LM_DBG("service_uri_scheme: %s\n", service_uri_scheme);
			}

			provide_node = node->children;

			while ( provide_node!= NULL )
			{
				if(xmlStrcasecmp(provide_node->name,(unsigned char*) "text")==0)
				{
					provide_node = 	provide_node->next;
					continue;
				}

				if(xmlStrcasecmp(provide_node->name,(unsigned char*)"class")== 0
						&& class_cont )
				{
					content = (char*)xmlNodeGetContent(provide_node);

					if(content&& xmlStrcasecmp((unsigned char*)content,
								(unsigned char*)class_cont) == 0)
					{
						found = 1;
						LM_DBG("found class= %s", class_cont);
						xmlFree(content);
						break;
					}
					if(content)
						xmlFree(content);
				}
				if(xmlStrcasecmp(provide_node->name,
							(unsigned char*) "deviceID")==0&&deviceID )
				{
					content = (char*)xmlNodeGetContent(provide_node);

					if(content && xmlStrcasecmp ((unsigned char*)content,
								(unsigned char*)deviceID) == 0)
					{
						found = 1;
						LM_DBG("found deviceID= %s", deviceID);
						xmlFree(content);
						break;
					}
					if(content)
						xmlFree(content);

				}
				if(xmlStrcasecmp(provide_node->name,
							(unsigned char*)"occurence-id")== 0&& occurence_ID)
				{
					content = (char*)xmlNodeGetContent(provide_node);
					if(content && xmlStrcasecmp ((unsigned char*)content,
								(unsigned char*)occurence_ID) == 0)
					{
						found = 1;
						LM_DBG("found occurenceID= %s\n", occurence_ID);
						xmlFree(content);
						break;
					}
					if(content)
						xmlFree(content);

				}
				if(xmlStrcasecmp(provide_node->name,
							(unsigned char*)"service-uri")== 0 && service_uri)
				{
					content = (char*)xmlNodeGetContent(provide_node);
					if(content&& xmlStrcasecmp ((unsigned char*)content,
								(unsigned char*)service_uri) == 0)
					{
						found = 1;
						LM_DBG("found service_uri= %s", service_uri);
						xmlFree(content);
						break;
					}
					if(content)
						xmlFree(content);

				}

				if(xmlStrcasecmp(provide_node->name,
						(unsigned char*)"service-uri-scheme")==0&& i)
				{
					content = (char*)xmlNodeGetContent(provide_node);
					LM_DBG("service_uri_scheme=%s\n",content);
					if(content && xmlStrcasecmp((unsigned char*)content,
								(unsigned char*)service_uri_scheme) == 0)
					{
						found = 1;
						LM_DBG("found service_uri_scheme= %s", service_uri_scheme);
						xmlFree(content);
						break;
					}
					if(content)
						xmlFree(content);

				}

				provide_node = provide_node->next;
			}

			if(found == 0)
			{
				LM_DBG("delete node: %s\n", doc_node->name);
				dont_provide = doc_node;
				doc_node = doc_node->next;
				xmlUnlinkNode(dont_provide);
				xmlFreeNode(dont_provide);
			}
			else
				doc_node = doc_node->next;

		}
	}
done:
	xmlDocDumpMemory(doc,(xmlChar**)(void*)&new_body->s,
			&new_body->len);
	LM_DBG("body = \n%.*s\n", new_body->len,
			new_body->s);

    xmlFreeDoc(doc);

	xmlFree(class_cont);
	xmlFree(occurence_ID);
	xmlFree(deviceID);
	xmlFree(service_uri);

    return new_body;
error:
    if(doc)
		xmlFreeDoc(doc);
	if(new_body)
	{
		if(new_body->s)
			xmlFree(new_body->s);
		pkg_free(new_body);
	}
	/* none of these are used before error!
	 * Detected by Coverity 40606-40609
	if(class_cont)
		xmlFree(class_cont);
	if(occurence_ID)
		xmlFree(occurence_ID);
	if(deviceID)
		xmlFree(deviceID);
	if(service_uri)
		xmlFree(service_uri);
	*/

	return NULL;
}
