/*
 * $Id$
 *
 * PERMISSIONS module
 *
 * Copyright (C) 2003 Mikl�s Tirp�k (mtirpak@sztaki.hu)
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
 
#include <stdio.h>
#include "permissions.h"
#include "rule.h"
#include "parse_config.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"

MODULE_VERSION

rule	*allow_rules = NULL, *deny_rules = NULL;

/* Module parameter variables */
char	*allow_file = ALLOW_FILE;
char	*deny_file = DENY_FILE;

/* Exported functions */
static cmd_export_t cmds[] = {
        {"allow_routing", allow_routing, 0, 0, REQUEST_ROUTE},
        {0, 0, 0, 0, 0}
};

/* Exported parameters */
static param_export_t params[] = {
        {"allow_file", 	STR_PARAM,	&allow_file},
        {"deny_file", 	STR_PARAM,	&deny_file},
        {0, 0, 0}
};

/* Module interface */
struct module_exports exports = {
        "permissions",
        cmds,      /* Exported functions */
        params,    /* Exported parameters */
        mod_init,  /* module initialization function */
        0,         /* response function */
        mod_exit,   /* destroy function */
        0,         /* oncancel function */
        0	/* child initialization function */
};

/* module initialization function */
int mod_init(void)
{
	
	fprintf(stderr, "print - initializing\n");

	allow_rules = parse_config_file(allow_file);
	if (allow_rules) LOG(L_INFO, "Allow file (%s) parsed\n", allow_file);
	else LOG(L_WARN, "Allow file (%s) not found\n", allow_file);

	deny_rules = parse_config_file(deny_file);
	if (deny_rules) LOG(L_INFO, "Deny file (%s) parsed\n", deny_file);
	else LOG(L_WARN, "Deny file (%s) not found\n", deny_file);
	
	return 0;
}

/* destroy function */
void mod_exit(void) {

	if (allow_rules) free_rule(allow_rules);
	if (deny_rules) free_rule(deny_rules);
}

/*
determinates the permission of the call
return values:
-1:	deny
1:	allow
*/
int allow_routing(struct sip_msg* msg, char* str1, char* str2) {
	struct hdr_field *from;
	int len;
	char from_str[EXPRESSION_LENGTH+1], req_uri_str[EXPRESSION_LENGTH+1];
	
	/* turn off control, allow any routing */
	if ((!allow_rules) && (!deny_rules)) {
	    LOG(L_INFO, "allow_routing(): (module permissions) No rules => allow any routing\n");
	    return 1;
	}
	
	/* looking for FROM HF */
        if ((!msg->from) && (parse_headers(msg, HDR_FROM, 0) == -1)) {
                LOG(L_ERR, "allow_routing(): (module permissions) Error while parsing message\n");
                return -1;
        }
	
	if (!msg->from) {
		LOG(L_ERR, "allow_ruting(): (module permissions) FROM header field not found\n");
		return -1;
	}
	
	/* we must call parse_from_header explicitly */
        if ((!(msg->from)->parsed) && (parse_from_header(msg) < 0)) {
                LOG(L_ERR, "allow_ruting(): (module permissions) Error while parsing From body\n");
                return -1;
        }
	
	from = msg->from;
	len = ((struct to_body*)from->parsed)->uri.len;
	if (len > EXPRESSION_LENGTH) {
                LOG(L_ERR, "allow_ruting(): (module permissions) From header field is too long: %d chars\n", len);
                return -1;
	}
	strncpy(from_str, ((struct to_body*)from->parsed)->uri.s, len);
	from_str[len] = '\0';
	
	/* looking for request URI */
	if (parse_sip_msg_uri(msg) < 0) {
	        LOG(L_ERR, "allow_routing(): uri parsing failed\n");
	        return -1;
	}
	
	len = msg->parsed_uri.user.len + msg->parsed_uri.host.len + 5;
	if (len > EXPRESSION_LENGTH) {
                LOG(L_ERR, "allow_ruting(): (module permissions) Request URI is too long: %d chars\n", len);
                return -1;
	}
	
	strcpy(req_uri_str, "sip:");
	memcpy(req_uri_str + 4, msg->parsed_uri.user.s, msg->parsed_uri.user.len);
	req_uri_str[msg->parsed_uri.user.len + 4] = '@';
	memcpy(req_uri_str + msg->parsed_uri.user.len + 5, msg->parsed_uri.host.s, msg->parsed_uri.host.len);
	req_uri_str[len] = '\0';
	
        LOG(L_INFO, "allow_ruting(): (module permissions) looking for FROM: %s Request URI: %s\n", from_str, req_uri_str);
	/* rule exists in allow file */
	if (search_rule(allow_rules, from_str, req_uri_str)) {
    		LOG(L_INFO, "allow_ruting(): (module permissions) allow roule found => routing is allowed\n");
		return 1;
	}
	
	/* rule exists in deny file */
	if (search_rule(deny_rules, from_str, req_uri_str)) {
		LOG(L_INFO, "allow_ruting(): (module permissions) deny roule found => routing is denied\n");
		return -1;
	}
	/* allow any other rule */
	LOG(L_INFO, "allow_ruting(): (module permissions) neither allow nor deny roule found => routing is allowed\n");
	return 1;
}


