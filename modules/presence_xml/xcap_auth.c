/*
 * presence_xml module -
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 *  2007-04-11  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "../../str.h"
#include "../../dprint.h"
#include "../../parser/parse_uri.h"
#include "../presence/utils_func.h"
#include "../presence/hash.h"
#include "presence_xml.h"
#include "xcap_auth.h"
#include "pidf.h"

str str_username_col = str_init("username");
str str_domain_col = str_init("domain");
str str_doc_type_col = str_init("doc_type");
str str_doc_col = str_init("doc");
str str_doc_uri_col = str_init("doc_uri");


static void ietf_get_rules(subs_t* subs, xmlDocPtr xcap_tree, xcap_rule_t **rules)
{
	str w_uri= {0, 0};
	char* id = NULL, *domain = NULL, *time_cont= NULL;
	int apply_rule = -1;
	xmlNodePtr ruleset_node = NULL, node1= NULL, node2= NULL;
	xmlNodePtr cond_node = NULL, except_node = NULL;
	xmlNodePtr identity_node = NULL, sphere_node = NULL;
	xmlNodePtr iden_child;
	xmlNodePtr validity_node, time_node;
	time_t t_init, t_fin, t;
	int valid= 0;
	xcap_rule_t *rule = NULL;

        *rules = NULL;

	uandd_to_uri(subs->from_user, subs->from_domain, &w_uri);
	if(w_uri.s == NULL)
	{
		LM_ERR("while creating uri\n");
		return;
	}
	ruleset_node = xmlDocGetNodeByName(xcap_tree, "ruleset", NULL);
	if(ruleset_node == NULL)
	{
		LM_DBG("ruleset_node NULL\n");
		goto error;

	}
	for(node1 = ruleset_node->children ; node1; node1 = node1->next)
	{
		if(xmlStrcasecmp(node1->name, (unsigned char*)"text")==0 )
				continue;

		/* process conditions */
		LM_DBG("node1->name= %s\n", node1->name);

		cond_node = xmlNodeGetChildByName(node1, "conditions");
		if(cond_node == NULL)
		{
			LM_DBG("cond node NULL\n");
			goto error;
		}
		LM_DBG("cond_node->name= %s\n", cond_node->name);

		validity_node = xmlNodeGetChildByName(cond_node, "validity");
		if(validity_node !=NULL)
		{
			LM_DBG("found validity tag\n");

			t= time(NULL);

			/* search all from-until pair */
			for(time_node= validity_node->children; time_node;
					time_node= time_node->next)
			{
				if(xmlStrcasecmp(time_node->name, (unsigned char*)"from")!= 0)
				{
					continue;
				}
				time_cont= (char*)xmlNodeGetContent(time_node);
				t_init= xml_parse_dateTime(time_cont);
				xmlFree(time_cont);
				if(t_init< 0)
				{
					LM_ERR("failed to parse xml dateTime\n");
					goto error;
				}

				if(t< t_init)
				{
					LM_DBG("the lower time limit is not respected\n");
					continue;
				}

				time_node= time_node->next;
				while(1)
				{
					if(time_node== NULL)
					{
						LM_ERR("bad formatted xml doc:until child not found in"
								" validity pair\n");
						goto error;
					}
					if( xmlStrcasecmp(time_node->name,
								(unsigned char*)"until")== 0)
						break;
					time_node= time_node->next;
				}

				time_cont= (char*)xmlNodeGetContent(time_node);
				t_fin= xml_parse_dateTime(time_cont);
				xmlFree(time_cont);

				if(t_fin< 0)
				{
					LM_ERR("failed to parse xml dateTime\n");
					goto error;
				}

				if(t <= t_fin)
				{
					LM_DBG("the rule is active at this time\n");
					valid= 1;
				}

			}

			if(!valid)
			{
				LM_DBG("the rule is not active at this time\n");
				continue;
			}

		}

		sphere_node = xmlNodeGetChildByName(cond_node, "sphere");
		if(sphere_node!= NULL)
		{
			/* check to see if matches presentity current sphere */
			/* ask presence for sphere information */

			char* sphere= pres_get_sphere(&subs->pres_uri);
			if(sphere)
			{
				char* attr= (char*)xmlNodeGetContent(sphere_node);
				if(xmlStrcasecmp((unsigned char*)attr, (unsigned char*)sphere)!= 0)
				{
					LM_DBG("sphere condition not respected\n");
					pkg_free(sphere);
					xmlFree(attr);
					continue;
				}
				pkg_free(sphere);
				xmlFree(attr);

			}
			else
			{
				LM_DBG("Noo sphere definition found\n");
				continue;
			}
			/* if the user has not define a sphere
			 *						consider the condition false*/
		}

		identity_node = xmlNodeGetChildByName(cond_node, "identity");
		if(identity_node == NULL)
		{
			LM_ERR("didn't find identity tag\n");
			goto error;
		}

		iden_child= xmlNodeGetChildByName(identity_node, "one");
		if(iden_child)
		{
			for(node2 = identity_node->children; node2; node2 = node2->next)
			{
				if(xmlStrcasecmp(node2->name, (unsigned char*)"one")!= 0)
					continue;

				id = xmlNodeGetAttrContentByName(node2, "id");
				if(id== NULL)
				{
					LM_ERR("while extracting attribute\n");
					goto error;
				}
				if((strlen(id)== w_uri.len &&
							(strncmp(id, w_uri.s, w_uri.len)==0)))
				{
					apply_rule = 1;
					xmlFree(id);
					break;
				}
				xmlFree(id);
			}
		}

		/* search for many node*/
		iden_child= xmlNodeGetChildByName(identity_node, "many");
		if(iden_child)
		{
			domain = NULL;
			for(node2 = identity_node->children; node2; node2 = node2->next)
			{
				if(xmlStrcasecmp(node2->name, (unsigned char*)"many")!= 0)
					continue;

				domain = xmlNodeGetAttrContentByName(node2, "domain");
				if(domain == NULL)
				{
					LM_DBG("No domain attribute to many\n");
				}
				else
				{
					LM_DBG("<many domain= %s>\n", domain);
					if((strlen(domain)!= subs->from_domain.len &&
								strncmp(domain, subs->from_domain.s,
									subs->from_domain.len) ))
					{
						xmlFree(domain);
						continue;
					}
				}
				xmlFree(domain);
				apply_rule = 1;
				if(node2->children == NULL)       /* there is no exception */
					break;

				for(except_node = node2->children; except_node;
						except_node= except_node->next)
				{
					if(xmlStrcasecmp(except_node->name, (unsigned char*)"except"))
						continue;

					id = xmlNodeGetAttrContentByName(except_node, "id");
					if(id!=NULL)
					{
						if((strlen(id)- 1== w_uri.len &&
								(strncmp(id, w_uri.s, w_uri.len)==0)))
						{
							xmlFree(id);
							apply_rule = 0;
							break;
						}
						xmlFree(id);
					}
					else
					{
						domain = NULL;
						domain = xmlNodeGetAttrContentByName(except_node, "domain");
						if(domain!=NULL)
						{
							LM_DBG("Found except domain= %s\n- strlen(domain)= %d\n",
									domain, (int)strlen(domain));
							if(strlen(domain)==subs->from_domain.len &&
								(strncmp(domain,subs->from_domain.s , subs->from_domain.len)==0))
							{
								LM_DBG("except domain match\n");
								xmlFree(domain);
								apply_rule = 0;
								break;
							}
							xmlFree(domain);
						}

					}
				}
				if(apply_rule== 1)  /* if a match was found no need to keep searching*/
					break;

			}
		}
		if(apply_rule ==1)
			break;
	}

	LM_DBG("apply_rule= %d\n", apply_rule);
	if(w_uri.s!=NULL)
		pkg_free(w_uri.s);

	if( !apply_rule || !node1)
		return;

	rule = (xcap_rule_t *)pkg_malloc(sizeof(*rule));
	if (rule == NULL)
	{
		LM_ERR("cannot allocate pkg_mem\n");
		return;
	}

	/* TODO: in IETF mode only the first matching rule is returned */
	rule->node = node1;
	rule->next = NULL;
	*rules = rule;

	return;
error:
	if(w_uri.s)
		pkg_free(w_uri.s);
}


/* OMA mode auth handling */

static inline int oma_match_identity_condition(xmlNodePtr condition, subs_t *subs, str *w_uri)
{
        int r = 0, many_match = 0;
        char *domain = NULL;
        str uri;
        str *normalized_uri;
        xmlNodePtr node = NULL, except_node = NULL;

        for(node = condition->children; node; node = node->next)
        {
                if(xmlStrcasecmp(node->name, (unsigned char*)"one") == 0)
                {
			uri.s = xmlNodeGetAttrContentByName(node, "id");
			if(uri.s == NULL)
			{
				LM_ERR("when extracting entry attribute\n");
				continue;
			}
                        uri.len = strlen(uri.s);

                        normalized_uri = normalizeSipUri(&uri);
                        if (normalized_uri->s == NULL || normalized_uri->len == 0)
                        {
                                LM_ERR("normalizing URI\n");
                                xmlFree(uri.s);
                                continue;
                        }
                        xmlFree(uri.s);

                        if (normalized_uri->len == w_uri->len && strncmp(normalized_uri->s, w_uri->s, w_uri->len) == 0)
                        {
                                r = 1;
                                break;
                        }
                }
                else if(xmlStrcasecmp(node->name, (unsigned char*)"many") == 0)
                {
                        domain = xmlNodeGetAttrContentByName(node, "domain");
                        if(domain == NULL)
                        {
                                LM_DBG("No domain attribute in identity many\n");
                        }
                        else
                        {
                                LM_DBG("<many domain= %s>\n", domain);
                                if(!(strlen(domain) == subs->from_domain.len &&
                                    strncmp(domain, subs->from_domain.s, subs->from_domain.len) == 0))
                                {
                                        xmlFree(domain);
                                        continue;
                                }
                                xmlFree(domain);
                        }

                        many_match = 1;
                        for(except_node = node->children; except_node; except_node= except_node->next)
                        {
                                if(xmlStrcasecmp(except_node->name, (unsigned char*)"except"))
                                        continue;

                                uri.s = xmlNodeGetAttrContentByName(except_node, "id");
                                if(uri.s != NULL)
                                {
                                    uri.len = strlen(uri.s);
                                    normalized_uri = normalizeSipUri(&uri);
                                    if (normalized_uri->s == NULL || normalized_uri->len == 0)
                                    {
                                            LM_ERR("normalizing URI\n");
                                            xmlFree(uri.s);
                                            continue;
                                    }
                                    xmlFree(uri.s);

                                    if (normalized_uri->len == w_uri->len && strncmp(normalized_uri->s, w_uri->s, w_uri->len) == 0)
                                    {
                                            many_match = 0;
                                            break;
                                    }
                                }
                                else
                                {
                                        domain = NULL;
                                        domain = xmlNodeGetAttrContentByName(except_node, "domain");
                                        if(domain != NULL)
                                        {
                                                LM_DBG("Found except domain= %s\n- strlen(domain)= %d\n", domain, (int)strlen(domain));
                                                if(strlen(domain)==subs->from_domain.len &&
                                                    (strncmp(domain,subs->from_domain.s , subs->from_domain.len)==0))
                                                {
                                                        LM_DBG("except domain match\n");
                                                        xmlFree(domain);
                                                        many_match = 0;
                                                        break;
                                                }
                                                xmlFree(domain);
                                        }

                                }
                        }

                        if(many_match)
                        {
                                r = 1;
                                break;
                        }
                }

        }

        return r;

}


#define MAX_PATH_LEN	127

static inline int get_resource_list(str *username, str *domain, str *filename, str *selector,
                                    xmlNodePtr *rl_node, xmlDocPtr *xmldoc)
{
        static char path_buf[MAX_PATH_LEN+1];

        int checked = 0;
        str path;
        str *doc = NULL;
        str *etag = NULL;
	xmlXPathContextPtr xpathCtx = NULL;
	xmlXPathObjectPtr xpathObj = NULL;

	if (filename==NULL || username==NULL || domain==NULL)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}

        if (xcapDbGetDoc(username, domain, RESOURCE_LISTS, filename, NULL, &doc, &etag) < 0 || doc == NULL)
        {
		LM_DBG("No rl document found\n");
                return -1;
        }
	LM_DBG("rl document:\n%.*s\n", doc->len, doc->s);

	path.s = path_buf;
	path.len = 0;
	if (selector->s) {
            while (checked < selector->len && path.len  + 7 + 1/* \0 */ <= MAX_PATH_LEN)
            {
                    if (selector->s[checked] == '/')
                    {
                            memcpy(path.s+path.len, "/xmlns:", 7);
                            path.len += 7;
                    }
                    else
                    {
                            path.s[path.len++] = selector->s[checked];
                    }
                    checked++;
            }
            path.s[path.len] = '\0';
            LM_DBG("path: %.*s", path.len, path.s);
        }

	*xmldoc = xmlParseMemory(doc->s, doc->len);
	if (*xmldoc == NULL)
	{
		LM_ERR("while parsing XML memory\n");
		goto error;
	}

	if(path.len == 0)
	{
		LM_ERR("no path specified\n");
		goto error;
	}

        /* TODO: move this to xcap module? */
        xpathCtx = xmlXPathNewContext(*xmldoc);
        if (xpathCtx == NULL)
        {
                LM_ERR("unable to create new XPath context\n");
                goto error;
        }

        if (xmlXPathRegisterNs(xpathCtx, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:resource-lists") != 0)
        {
                LM_ERR("unable to register xmlns\n");
                goto error;
        }

        xpathObj = xmlXPathEvalExpression(BAD_CAST path.s, xpathCtx);
        if (xpathObj == NULL)
        {
                LM_ERR("unable to evaluate path\n");
                goto error;
        }

        if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr <= 0)
        {
                LM_ERR("no nodes found\n");
                goto error;
        }
        if (xpathObj->nodesetval->nodeTab[0] != NULL && xpathObj->nodesetval->nodeTab[0]->type != XML_ELEMENT_NODE)
        {
                LM_ERR("no nodes of the correct type found\n");
                goto error;

        }

        *rl_node = xpathObj->nodesetval->nodeTab[0];

        xmlXPathFreeObject(xpathObj);
        xmlXPathFreeContext(xpathCtx);

        pkg_free(doc->s);
        pkg_free(doc);
        pkg_free(etag->s);
        pkg_free(etag);

        return 0;

error:
		pkg_free(doc->s);
		pkg_free(doc);
        if (etag != NULL)
        {
                if (etag->s != NULL)
                        pkg_free(etag->s);
                pkg_free(etag);
        }
	if (xpathObj)
		xmlXPathFreeObject(xpathObj);
	if (xpathCtx)
		xmlXPathFreeContext(xpathCtx);
	if (*xmldoc)
		xmlFreeDoc(*xmldoc);
	return -1;
}


static inline int oma_match_external_list_condition(xmlNodePtr condition, subs_t *subs, str *w_uri)
{
        int found = 0;
        str anchor, uri;
        str *normalized_uri;
	struct sip_uri sip_uri;
        xcap_uri_t anchor_uri;
        xmlNodePtr entry_node = NULL;
        xmlNodePtr rl_node = NULL, rl_entry = NULL;
        xmlDocPtr rl_doc = NULL;

        if(!integrated_xcap_server)
        {
	        LM_ERR("<external-list> is not supported in non integrated mode\n");
	        return 0;
        }

        if(parse_uri(subs->pres_uri.s, subs->pres_uri.len, &sip_uri) < 0)
        {
                LM_ERR("failed to parse uri\n");
                return 0;
        }

	for(entry_node = condition->children; entry_node; entry_node = entry_node->next)
	{
		if(xmlStrcasecmp(entry_node->name, (unsigned char*)"entry") != 0)
		        continue;

		rl_node = NULL;
		rl_doc = NULL;
		anchor.s = NULL;
		uri.s = NULL;

                anchor.s = xmlNodeGetAttrContentByName(entry_node, "anc");
                if(anchor.s == NULL)
                {
                        LM_ERR("cannot get external-list entry anchor\n");
                        continue;
                }
                anchor.len = strlen(anchor.s);
		if(xcapParseUri(&anchor, &anchor_uri) != 0)
                {
		        LM_ERR("unable to parse URI for external-list entry anchor\n");
			xmlFree(anchor.s);
			continue;
                }
		xmlFree(anchor.s);
                /* TODO: validate XUI? */
		if(get_resource_list(&sip_uri.user, &sip_uri.host, &anchor_uri.filename, &anchor_uri.selector, &rl_node, &rl_doc) < 0)
                {
		        LM_ERR("error getting resource-list list pointed by external list anchor\n");
			continue;
                }
                for(rl_entry = rl_node->children; rl_entry; rl_entry = rl_entry->next)
                {
                        if(xmlStrcasecmp(rl_entry->name, (unsigned char*)"entry") != 0)
                                continue;
			uri.s = xmlNodeGetAttrContentByName(rl_entry, "uri");
			if(uri.s == NULL)
			{
				LM_ERR("when extracting entry uri attribute\n");
				continue;
			}
                        uri.len = strlen(uri.s);

                        normalized_uri = normalizeSipUri(&uri);
                        if (normalized_uri->s == NULL || normalized_uri->len == 0)
                        {
                                LM_ERR("normalizing URI\n");
                                xmlFree(uri.s);
                                continue;
                        }
                        xmlFree(uri.s);

                        if (normalized_uri->len == w_uri->len && strncmp(normalized_uri->s, w_uri->s, w_uri->len) == 0)
                        {
                                found = 1;
                                break;
                        }
                }
		xmlFreeDoc(rl_doc);
                if (found)
                        break;
	}

	return found;

}

static inline int oma_match_anonymous_condition(xmlNodePtr condition, subs_t *subs, str *w_uri)
{
    if (strncmp(subs->from_user.s , "anonymous", subs->from_user.len)==0 &&
        strncmp(subs->from_domain.s , "anonymous.invalid", subs->from_domain.len)==0)
        return 1;
    return 0;
}


static inline void free_rules(xcap_rule_t *rules)
{
        xcap_rule_t *ptr = NULL, *current = NULL;
        ptr = rules;
        while (ptr)
        {
                current = ptr;
                ptr = ptr->next;
                pkg_free(current);
        }
}


static void oma_get_rules(subs_t* subs, xmlDocPtr xcap_tree, xcap_rule_t **rules)
{
	int apply_rule = 0, current_node_type = -1;
	str w_uri = {0, 0};
	xmlNodePtr ruleset_node = NULL, cond_node = NULL;
	xmlNodePtr node1 = NULL, node2 = NULL, current_node = NULL;
	xcap_rule_t *tmp_rule = NULL;
	xcap_rule_t *identity_rules = NULL, *external_rules = NULL, *anonymous_rules = NULL, *other_identity_rules = NULL;
	xcap_rule_t *identity_tail = NULL, *external_tail = NULL, *anonymous_tail = NULL, *other_identity_tail = NULL;

        *rules = NULL;

	uandd_to_uri(subs->from_user, subs->from_domain, &w_uri);
	if(w_uri.s == NULL)
	{
		LM_ERR("while creating uri\n");
		return;
	}

	ruleset_node = xmlDocGetNodeByName(xcap_tree, "ruleset", NULL);
	if(ruleset_node == NULL)
	{
		LM_ERR("ruleset_node not found\n");
		pkg_free(w_uri.s);
	        return;
	}

	for(node1 = ruleset_node->children; node1; node1 = node1->next)
	{
		if(xmlStrcasecmp(node1->name, (unsigned char*)"text")==0)
		        continue;

		cond_node = xmlNodeGetChildByName(node1, "conditions");
		if(cond_node == NULL)
		{
			LM_WARN("condition node not found\n");
			continue;
		}

                apply_rule = 0;
                current_node = node1;
                current_node_type = -1;

                for(node2 = cond_node->children; node2; node2 = node2->next)
                {
                        if(xmlStrcasecmp(node2->name, (unsigned char*)"identity") == 0)
                        {
                                current_node_type = IDENTITY_RULE;
                                apply_rule = oma_match_identity_condition(node2, subs, &w_uri);
                                break;
                        }
                        else if(xmlStrcasecmp(node2->name, (unsigned char*)"external-list") == 0)
                        {
                                current_node_type = EXTERNAL_LIST_RULE;
                                apply_rule = oma_match_external_list_condition(node2, subs, &w_uri);
                                break;
                        }
                        else if(xmlStrcasecmp(node2->name, (unsigned char*)"anonymous-request") == 0)
                        {
                                current_node_type = ANONYMOUS_REQUEST_RULE;
                                apply_rule = oma_match_anonymous_condition(node2, subs, &w_uri);
                                break;
                        }
                        else if(xmlStrcasecmp(node2->name, (unsigned char*)"other-identity") == 0)
                        {
                                current_node_type = OTHER_IDENTITY_RULE;
                                apply_rule = 1;
                                break;
                        }
                        else
                        {
                                /* unknown condition */
                                continue;
                        }

                }

                /* finished scanning all conditions for a given rule */
                if (apply_rule)
                {
                        tmp_rule = (xcap_rule_t *)pkg_malloc(sizeof(*tmp_rule));
                        if (tmp_rule == NULL)
                        {
                                LM_ERR("pkg mem\n");
                                goto error;
                        }
                        tmp_rule->node = current_node;
                        tmp_rule->next = NULL;
                        switch (current_node_type)
                        {
                                case IDENTITY_RULE:
                                        if(identity_rules == NULL)
                                                identity_rules = tmp_rule;
                                        else
                                                identity_tail->next = tmp_rule;
                                        identity_tail = tmp_rule;
                                        break;
                                case EXTERNAL_LIST_RULE:
                                        if(external_rules == NULL)
                                                external_rules = tmp_rule;
                                        else
                                                external_tail->next = tmp_rule;
                                        external_tail = tmp_rule;
                                        break;
                                case ANONYMOUS_REQUEST_RULE:
                                        if(anonymous_rules == NULL)
                                                anonymous_rules = tmp_rule;
                                        else
                                                anonymous_tail->next = tmp_rule;
                                        anonymous_tail = tmp_rule;
                                        break;
                                case OTHER_IDENTITY_RULE:
                                        if(other_identity_rules == NULL)
                                                other_identity_rules = tmp_rule;
                                        else
                                                other_identity_tail->next = tmp_rule;
                                        other_identity_tail = tmp_rule;
                                        break;
                                default:
                                        /* this will never happen */
                                        break;
                        }
                }
	}

        if (anonymous_rules)
        {
                *rules = anonymous_rules;
                free_rules(identity_rules);
                free_rules(external_rules);
                free_rules(other_identity_rules);
        }
        else if (identity_rules)
        {
                *rules = identity_rules;
                free_rules(external_rules);
                free_rules(anonymous_rules);
                free_rules(other_identity_rules);
        }
        else if (external_rules)
        {
                *rules = external_rules;
                free_rules(identity_rules);
                free_rules(anonymous_rules);
                free_rules(other_identity_rules);
        }
        else if (other_identity_rules)
        {
                *rules = other_identity_rules;
                free_rules(identity_rules);
                free_rules(external_rules);
                free_rules(anonymous_rules);
        }
        else
        {
                *rules = NULL;
                LM_DBG("no matching rules found\n");
        }

        pkg_free(w_uri.s);
        return;

error:
        if (w_uri.s)
                pkg_free(w_uri.s);
        free_rules(identity_rules);
        free_rules(external_rules);
        free_rules(anonymous_rules);
        free_rules(other_identity_rules);
}


static inline int get_action_value(char *action)
{
        if(strncmp(action, "block",5 )==0)
                return SH_ACTION_BLOCK;
        if(strncmp(action, "confirm",7 )==0)
                return SH_ACTION_CONFIRM;
        if(strncmp(action, "polite-block",12 )==0)
                return SH_ACTION_POLITE_BLOCK;
        if(strncmp(action, "allow",5 )==0)
                return SH_ACTION_ALLOW;
        return -1;
}


xmlNodePtr get_rule_node(subs_t* subs, xmlDocPtr xcap_tree)
{
	int action_value = -1, max_action_value = -1;
	char* sub_handling = NULL;
        xmlNodePtr node = NULL, actions_node = NULL, sub_handling_node = NULL;
        xcap_rule_t *rules = NULL, *rule_ptr = NULL;

        if (pres_rules_doc_id == OMA_PRES_RULES)
            oma_get_rules(subs, xcap_tree, &rules);
        else
            ietf_get_rules(subs, xcap_tree, &rules);
        if (rules == NULL)
                return NULL;

        for (rule_ptr = rules; rule_ptr; rule_ptr = rule_ptr->next)
        {
            actions_node = xmlNodeGetChildByName(rule_ptr->node, "actions");
            if(actions_node == NULL)
            {
                    LM_DBG("actions_node NULL\n");
                    continue;
            }

            sub_handling_node = xmlNodeGetChildByName(actions_node, "sub-handling");
            if(sub_handling_node == NULL)
            {
                    LM_DBG("sub_handling_node NULL\n");
		    xmlFree(sub_handling);
                    continue;
            }
            sub_handling = (char*)xmlNodeGetContent(sub_handling_node);
            if(sub_handling == NULL)
            {
                    LM_ERR("Couldn't get sub-handling content\n");
                    continue;
            }
            LM_DBG("sub_handling_node->content= %s\n", sub_handling);

            action_value = get_action_value((char*)sub_handling);
            if (action_value > max_action_value)
            {
                    max_action_value = action_value;
                    node = rule_ptr->node;
            }
	    xmlFree(sub_handling);
        }

        free_rules(rules);
        return node;
}


static char* subs_strstatus(subs_t* subs)
{
        static char buf[64];
        int len = 0;

        switch(subs->status)
        {
            case ACTIVE_STATUS:
                memcpy(buf, "active", 6);
                len += 6;
                break;
            case PENDING_STATUS:
                memcpy(buf, "pending", 7);
                len += 7;
                break;
            case TERMINATED_STATUS:
                memcpy(buf, "terminated", 10);
                len += 10;
                break;
            case WAITING_STATUS:
                memcpy(buf, "waiting", 7);
                len += 7;
                break;
            default:
                memcpy(buf, "unknown", 7);
                len += 7;
                break;
        }

        if (subs->reason.s != NULL)
        {
                sprintf(buf+len, " (%.*s)", subs->reason.len, subs->reason.s);
                len += subs->reason.len+3;
        }

        buf[len] = '\0';
        return buf;
}


int pres_watcher_allowed(subs_t* subs)
{
	xmlDocPtr xcap_tree = NULL;
        xmlNodePtr node = NULL, actions_node = NULL, sub_handling_node = NULL;
	char* sub_handling = NULL;
	int action_value = -1, ret = 0;
	str watcher = {0, 0};

	uandd_to_uri(subs->from_user, subs->from_domain, &watcher);
	if(watcher.s == NULL)
	{
		LM_ERR("while creating uri\n");
		return -1;
	}

	/* if force_active set status to active*/
	if(force_active)
	{
		subs->status = ACTIVE_STATUS;
		subs->reason.s = NULL;
		subs->reason.len = 0;
		ret = 0;
		goto done;
	}

	if(subs->auth_rules_doc == NULL)
	{
		subs->status = PENDING_STATUS;
		subs->reason.s = NULL;
		subs->reason.len = 0;
		ret = 0;
		goto done;
	}

	xcap_tree = xmlParseMemory(subs->auth_rules_doc->s, subs->auth_rules_doc->len);
	if(xcap_tree == NULL)
	{
		LM_ERR("parsing xml memory\n");
		ret = -1;
		goto done;
	}

	node = get_rule_node(subs, xcap_tree);
	if(node == NULL)
	{
		/* if no rule node was found and the previous state was active -> set the
		 * state to terminated with reason deactivated */
		if(subs->status != PENDING_STATUS)
		{
			subs->status = TERMINATED_STATUS;
			subs->reason.s = "deactivated";
			subs->reason.len = 11;
		}
		ret = 0;
		goto done;
	}

        /* If node is not NULL then there should be a actions element and a sub-handling element
         * for sure, get_rule_node makes sure of that */

        actions_node = xmlNodeGetChildByName(node, "actions");
        if (actions_node == NULL)
        {
                ret = -1;
                goto done;
        }
        sub_handling_node = xmlNodeGetChildByName(actions_node, "sub-handling");
        if (sub_handling_node == NULL)
        {
                ret = -1;
                goto done;
        }
        sub_handling = (char*)xmlNodeGetContent(sub_handling_node);
        if (sub_handling == NULL)
        {
                ret = -1;
                goto done;
        }

        action_value = get_action_value(sub_handling);
        switch (action_value)
        {
                case SH_ACTION_BLOCK:
                        subs->status = TERMINATED_STATUS;
                        subs->reason.s = "rejected";
                        subs->reason.len = 8;
                        break;
                case SH_ACTION_CONFIRM:
                        subs->status = PENDING_STATUS;
                        subs->reason.s = NULL;
                        subs->reason.len = 0;
                        break;
                case SH_ACTION_POLITE_BLOCK:
                        subs->status = ACTIVE_STATUS;
                        subs->reason.s = "polite-block";
                        subs->reason.len = 12;
                        break;
                case SH_ACTION_ALLOW:
                        subs->status = ACTIVE_STATUS;
                        subs->reason.s = NULL;
                        subs->reason.len = 0;
                        break;
                default:
                        LM_ERR("unknown subscription handling action\n");
                        subs->status = PENDING_STATUS;
                        subs->reason.s = NULL;
                        subs->reason.len = 0;
                        break;
        }

        LM_INFO("Subscription from %.*s to %.*s is %s\n", watcher.len, watcher.s,
                                                          subs->pres_uri.len, subs->pres_uri.s,
                                                          subs_strstatus(subs));

done:
        if (watcher.s)
                pkg_free(watcher.s);
	if (sub_handling)
		xmlFree(sub_handling);
	xmlFreeDoc(xcap_tree);
	return ret;
}

int pres_get_rules_doc(str* user, str* domain, str** rules_doc)
{
	if(force_active)
        {
                *rules_doc = NULL;
		return 0;
        }
	return p_get_xcap_doc(user, domain, pres_rules_doc_id, rules_doc);
}


static int http_get_xcap_doc(str* user, str* domain, int type, str** doc)
{
	str body = {0, 0};
	str *doc_tmp;
	xcap_doc_sel_t doc_sel;
	xcap_serv_t* xs;
	xcap_get_req_t req;

	*doc = NULL;

        if (type != PRES_RULES && type != OMA_PRES_RULES)
        {
                LM_ERR("only pres-rules documents can be fetched though HTTP for now\n");
                goto error;
        }

	memset(&req, 0, sizeof(xcap_get_req_t));
	if(uandd_to_uri(*user, *domain, &doc_sel.xid) < 0)
	{
		LM_ERR("constructing uri\n");
		goto error;
	}

	if(pres_rules_auid.s && pres_rules_auid.len)
	{
		doc_sel.auid = pres_rules_auid;
	}
	else
	{
		doc_sel.auid.s = "pres-rules";
		doc_sel.auid.len = strlen(doc_sel.auid.s);
	}
	doc_sel.doc_type = pres_rules_doc_id;
	doc_sel.type = USERS_TYPE;

	if(pres_rules_filename.s && pres_rules_filename.len)
        {
		doc_sel.filename = pres_rules_filename;
        }
	else
	{
		doc_sel.filename.s = "index";
		doc_sel.filename.len = strlen(doc_sel.filename.s);
	}

	/* need the whole document so the node selector is NULL */
	/* don't know which is the authoritative server for the user
	 * so send request to all in the list */
	req.doc_sel = doc_sel;

	xs = xs_list;
	while (xs)
	{
		req.xcap_root = xs->addr;
		req.port = xs->port;
		if(xcap_GetNewDoc(req, *user, *domain, &body) < 0)
		{
			LM_ERR("while fetching data from xcap server\n");
                        pkg_free(doc_sel.xid.s);
			goto error;
		}
		if(body.s)
                {
		        /* if document found, stop searching */
			break;
                }
		xs = xs->next;
	}

        pkg_free(doc_sel.xid.s);

        if (body.s == NULL)
                goto error;

	doc_tmp = pkg_malloc(sizeof(*doc_tmp));
	if(doc_tmp == NULL)
	{
		LM_ERR("No more pkg memory\n");
		goto error;
	}
	doc_tmp->s = pkg_malloc(body.len);
	if(doc_tmp->s == NULL)
	{
		pkg_free(doc_tmp);
		LM_ERR("No more pkg memory\n");
		goto error;
	}
	memcpy(doc_tmp->s, body.s, body.len);
	doc_tmp->len = body.len;
	pkg_free(body.s);

        *doc = doc_tmp;
	return 0;

error:
        if (body.s)
                pkg_free(body.s);
	return -1;
}


int p_get_xcap_doc(str* user, str* domain, int type, str** doc)
{
        str *etag = NULL;

        if (xcapDbGetDoc(user, domain, type, NULL, NULL, doc, &etag) < 0)
        {
                LM_ERR("whie fetching XCAP document from DB\n");
                return -1;
        }

        if (*doc == NULL)
        {
		if(integrated_xcap_server)
		        return 0;

                if (http_get_xcap_doc(user, domain, type, doc) < 0)
                        return 0;
        }

        pkg_free(etag->s);
        pkg_free(etag);

        return 0;
}

