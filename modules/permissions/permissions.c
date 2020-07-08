/*
 * PERMISSIONS module
 *
 * Copyright (C) 2003 Miklós Tirpák (mtirpak@sztaki.hu)
 * Copyright (C) 2003 iptel.org
 * Copyright (C) 2003-2007 Juha Heinanen
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
 */

#include <stdio.h>
#include "../../sr_module.h"
#include "permissions.h"
#include "parse_config.h"
#include "partitions.h"

#include "address.h"
#include "hash.h"
#include "mi.h"

#include "../../mem/mem.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_refer_to.h"
#include "../../parser/contact/parse_contact.h"
#include "../../str.h"
#include "../../dset.h"
#include "../../globals.h"
#include "../../mod_fix.h"
#include "../../ut.h"


static rule_file_t allow[MAX_RULE_FILES]; /* Parsed allow files */
static rule_file_t deny[MAX_RULE_FILES];  /* Parsed deny files */
static int rules_num;  /* Number of parsed allow/deny files */


/* Module parameter variables */
static char* default_allow_file = DEFAULT_ALLOW_FILE;
static char* default_deny_file = DEFAULT_DENY_FILE;
char* allow_suffix = ".allow";
static char* deny_suffix = ".deny";


/*
 * By default we check all branches
 */
static int check_all_branches = 1;

/*
 * Convert the name of the files into table index
 */
static int load_fixup(void** param, int param_no);

/*
 * Convert the name of the file into table index, this
 * function takes just one name, appends .allow and .deny
 * to and and the rest is same as in load_fixup
 */
static int fix_filename(void** param);

static int fix_str2s(void** param);
static int free_str2s(void** param);

static int fix_proto(void** param);
static int fix_part(void** param);

static int allow_routing(struct sip_msg* msg, int idx);
static int allow_register(struct sip_msg* msg, int idx);
static int allow_uri(struct sip_msg* msg, int idx, pv_spec_t *sp);

static int mod_init(void);
static void mod_exit(void);
static int child_init(int rank);
static int mi_address_child_init();

/* Exported functions */
static cmd_export_t cmds[] = {
	{"check_address", (cmd_function)check_addr,
		{ {CMD_PARAM_INT, NULL, NULL},
		  {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_INT, NULL, NULL},
		  {CMD_PARAM_STR, fix_proto, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, fix_str2s, free_str2s},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_part, NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE
	},
	{"check_source_address", (cmd_function)check_src_addr,
		{ {CMD_PARAM_INT, NULL, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, fix_str2s, free_str2s},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_part, NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE
	},
	{"get_source_group", (cmd_function)get_source_group,
		{ {CMD_PARAM_VAR, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_part, NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE
	},
	{"allow_routing",  (cmd_function)allow_routing,
		{ {CMD_PARAM_STR|CMD_PARAM_OPT, fix_filename, NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE
	},
	{"allow_register",  (cmd_function)allow_register,
		{ {CMD_PARAM_STR, fix_filename, NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE
	},
	{"allow_uri", (cmd_function)allow_uri,
		{ {CMD_PARAM_STR, fix_filename, NULL},
		  {CMD_PARAM_STR, NULL, NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE
	},
	{0,0,{{0,0,0}},0}
};


/* Exported parameters */
static param_export_t params[] = {
	{"default_allow_file", STR_PARAM, &default_allow_file},
	{"default_deny_file",  STR_PARAM, &default_deny_file },
	{"check_all_branches", INT_PARAM, &check_all_branches},
	{"allow_suffix",       STR_PARAM, &allow_suffix      },
	{"deny_suffix",        STR_PARAM, &deny_suffix       },
	{"partition",		   STR_PARAM|USE_FUNC_PARAM,
							(void *)parse_partition      },
	{"db_url",             STR_PARAM, &db_url            },
	{"address_table",      STR_PARAM, &address_table     },
	{"ip_col",             STR_PARAM, &ip_col.s          },
	{"proto_col",          STR_PARAM, &proto_col.s       },
	{"pattern_col",        STR_PARAM, &pattern_col.s     },
	{"info_col",           STR_PARAM, &info_col.s        },
	{"grp_col",            STR_PARAM, &grp_col.s         },
	{"mask_col",           STR_PARAM, &mask_col.s        },
	{"port_col",           STR_PARAM, &port_col.s        },
	{0, 0, 0}
};

/*
 * Exported MI functions
 */
static mi_export_t mi_cmds[] = {
	{ MI_ADDRESS_RELOAD, 0, 0, mi_address_child_init, {
		{mi_address_reload, {0}},
		{mi_address_reload_1, {"partition", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_ADDRESS_DUMP, 0, 0, 0, {
		{mi_address_dump, {0}},
		{mi_address_dump_1, {"partition", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_SUBNET_DUMP, 0, 0, 0, {
		{mi_subnet_dump, {0}},
		{mi_subnet_dump_1, {"partition", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ MI_ALLOW_URI, 0, 0, 0, {
		{mi_allow_uri, {"basename", "uri", "contact", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

/* Module interface */
struct module_exports exports = {
	"permissions",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,      /* Exported functions */
	0,         /* Exported async functions */
	params,    /* Exported parameters */
	0,         /* exported statistics */
	mi_cmds,   /* exported MI functions */
	0,         /* exported pseudo-variables */
	0,		   /* exported transformations */
	0,         /* extra processes */
	0,         /* module pre-initialization function */
	mod_init,  /* module initialization function */
	0,         /* response function */
	mod_exit,  /* destroy function */
	child_init,/* child initialization function */
	0          /* reload confirm function */
};



static int fix_str2s(void** param)
{
	str *in = (str*)*param;
	char *out;

	if (in==NULL) return 1;

	out = (char*)pkg_malloc(in->len+1);
	if (out==NULL) {
		LM_ERR("failed to allocate new string\n");
		return -1;
	}
	memcpy( out, in->s, in->len);
	out[in->len] = 0;

	*param = out;

	return 1;
}


static int free_str2s(void** param)
{
	if (*param)
		pkg_free(*param);

	return 1;
}


static int fix_proto(void** param)
{
	str *s_proto = (str*)*param;
	int proto;

	/* proto */
	if (s_proto->len <= 0 || !s_proto->s) {
		s_proto->s = "any";
		s_proto->len = strlen(s_proto->s);
	}
	if ((proto = proto_char2int(s_proto)) < 0) {
		LM_ERR("unknown protocol <%.*s>\n", s_proto->len, s_proto->s);
		return -1;
	}

	*param = (void*)(long)proto;

	return 1;
}


static int fix_part(void** param)
{
	str *s=(str*)*param;
	struct pm_part_struct *part;

	/* handle the special case when the fix is triggered for 
	   missing parameter */
	if (!s)
		s = &def_part;

	part = get_part_struct(s);
	if (!part) {
		LM_ERR("invoked partition <%.*s> not defined\n", s->len, s->s);
		return -1;
	}

	*param = part;
	return 1;
}



/*
 * Extract path (the beginning of the string
 * up to the last / character
 * Returns length of the path
 */
static int get_path(char* pathname)
{
	char* c;
	if (!pathname) return 0;

	c = strrchr(pathname, '/');
	if (!c) return 0;

	return c - pathname + 1;
}


/*
 * Prepend path if necessary
 */
static char* get_pathname(char* name)
{
	char* buffer;
	int path_len, name_len;

	if (!name) return 0;

	name_len = strlen(name);
	if (strchr(name, '/')) {
		buffer = (char*)pkg_malloc(name_len + 1);
		if (!buffer) goto err;
		strcpy(buffer, name);
		return buffer;
	} else {
		path_len = get_path(cfg_file);
		buffer = (char*)pkg_malloc(path_len + name_len + 1);
		if (!buffer) goto err;
		memcpy(buffer, cfg_file, path_len);
		memcpy(buffer + path_len, name, name_len);
		buffer[path_len + name_len] = '\0';
		return buffer;
	}

 err:
	LM_ERR("no pkg memory left\n");
	return 0;
}


/*
 * If the file pathname has been parsed already then the
 * function returns its index in the tables, otherwise it
 * returns -1 to indicate that the file needs to be read
 * and parsed yet
 */
static int find_index(rule_file_t* array, char* pathname)
{
	int i;

	for(i = 0; i < rules_num; i++) {
		if (!strcmp(pathname, array[i].filename)) return i;
	}

	return -1;
}


/*
 * Return URI without all the bells and whistles, that means only
 * sip:username@domain, resulting buffer is statically allocated and
 * zero terminated
 */
static char* get_plain_uri(const str* uri)
{
	static char buffer[EXPRESSION_LENGTH + 1];
	struct sip_uri puri;
	int len;

	if (!uri) return 0;

	if (parse_uri(uri->s, uri->len, &puri) < 0) {
		LM_ERR("failed to parse URI\n");
		return 0;
	}

	if (puri.user.len) {
		len = puri.user.len + puri.host.len + 5;
	} else {
		len = puri.host.len + 4;
	}

	if (len > EXPRESSION_LENGTH) {
		LM_ERR("Request-URI is too long: %d chars\n", len);
		return 0;
	}

	strcpy(buffer, "sip:");
	if (puri.user.len) {
		memcpy(buffer + 4, puri.user.s, puri.user.len);
	        buffer[puri.user.len + 4] = '@';
		memcpy(buffer + puri.user.len + 5, puri.host.s, puri.host.len);
	} else {
		memcpy(buffer + 4, puri.host.s, puri.host.len);
	}

	buffer[len] = '\0';
	return buffer;
}


/*
 * determines the permission of the call
 * return values:
 * -1:	deny
 * 1:	allow
 */
static int allow_routing(struct sip_msg* msg, int idx)
{
	struct hdr_field *from;
	int len, q;
	static char from_str[EXPRESSION_LENGTH+1];
	static char ruri_str[EXPRESSION_LENGTH+1];
	char* uri_str;
	str branch;
	int br_idx;

	/* turn off control, allow any routing */
	if ((!allow[idx].rules) && (!deny[idx].rules)) {
		LM_DBG("no rules => allow any routing\n");
		return 1;
	}

	/* looking for FROM HF */
        if ((!msg->from) && (parse_headers(msg, HDR_FROM_F, 0) == -1)) {
                LM_ERR("failed to parse message\n");
                return -1;
        }

	if (!msg->from) {
		LM_ERR("FROM header field not found\n");
		return -1;
	}

	/* we must call parse_from_header explicitly */
        if ((!(msg->from)->parsed) && (parse_from_header(msg) < 0)) {
                LM_ERR("failed to parse From body\n");
                return -1;
        }

	from = msg->from;
	len = ((struct to_body*)from->parsed)->uri.len;
	if (len > EXPRESSION_LENGTH) {
                LM_ERR("From header field is too long: %d chars\n", len);
                return -1;
	}
	strncpy(from_str, ((struct to_body*)from->parsed)->uri.s, len);
	from_str[len] = '\0';

	/* looking for request URI */
	if (parse_sip_msg_uri(msg) < 0) {
	        LM_ERR("uri parsing failed\n");
	        return -1;
	}

	len = msg->parsed_uri.user.len + msg->parsed_uri.host.len + 5;
	if (len > EXPRESSION_LENGTH) {
                LM_ERR("Request URI is too long: %d chars\n", len);
                return -1;
	}

	strcpy(ruri_str, "sip:");
	memcpy(ruri_str + 4, msg->parsed_uri.user.s, msg->parsed_uri.user.len);
	ruri_str[msg->parsed_uri.user.len + 4] = '@';
	memcpy(ruri_str + msg->parsed_uri.user.len + 5, msg->parsed_uri.host.s, msg->parsed_uri.host.len);
	ruri_str[len] = '\0';

        LM_DBG("looking for From: %s Request-URI: %s\n", from_str, ruri_str);
	     /* rule exists in allow file */
	if (search_rule(allow[idx].rules, from_str, ruri_str)) {
		if (check_all_branches) goto check_branches;
    		LM_DBG("allow rule found => routing is allowed\n");
		return 1;
	}

	/* rule exists in deny file */
	if (search_rule(deny[idx].rules, from_str, ruri_str)) {
		LM_DBG("deny rule found => routing is denied\n");
		return -1;
	}

	if (!check_all_branches) {
		LM_DBG("neither allow nor deny rule found => routing is allowed\n");
		return 1;
	}

 check_branches:
	for( br_idx=0 ; (branch.s=get_branch(br_idx,&branch.len,&q,0,0,0,0))!=0 ;
	br_idx++ ) {
		uri_str = get_plain_uri(&branch);
		if (!uri_str) {
			LM_ERR("failed to extract plain URI\n");
			return -1;
		}
		LM_DBG("looking for From: %s Branch: %s\n", from_str, uri_str);

		if (search_rule(allow[idx].rules, from_str, uri_str)) {
			continue;
		}

		if (search_rule(deny[idx].rules, from_str, uri_str)) {
			LM_DBG("deny rule found for one of branches => routing"
			       "is denied\n");
			return -1;
		}
	}

	LM_DBG("check of branches passed => routing is allowed\n");
	return 1;
}


/*
 * Convert the name of the files into table index
 */
static int load_fixup(void** param, int param_no)
{
	char* pathname;
	int idx;
	rule_file_t* table;

	if (param_no == 1) {
		table = allow;
	} else {
		table = deny;
	}

	pathname = get_pathname(*param);
	idx = find_index(table, pathname);

	if (idx == -1) {
		     /* Not opened yet, open the file and parse it */
		table[rules_num].filename = pathname;
		table[rules_num].rules = parse_config_file(pathname);
		if (table[rules_num].rules) {
			LM_DBG("file (%s) parsed\n", pathname);
		} else {
			LM_INFO("file (%s) not found => empty rule set\n", pathname);
		}
		*param = (void*)(long)rules_num;
		if (param_no == 2) rules_num++;
	} else {
		     /* File already parsed, re-use it */
		LM_DBG("file (%s) already loaded, re-using\n", pathname);
		pkg_free(pathname);
		*param = (void*)(long)idx;
	}

	return 0;
}


/*
 * Convert the name of the file into table index
 */
static int fix_filename(void** param)
{
	char* buffer;
	void* tmp;
	int ret, suffix_len;
	str *s = (str*)*param;

	if (strlen(allow_suffix) > strlen(deny_suffix)) {
		suffix_len = strlen(allow_suffix);
	} else {
		suffix_len = strlen(deny_suffix);
	}

	buffer = pkg_malloc(s->len + suffix_len + 1);
	if (!buffer) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memcpy( buffer, s->s, s->len );
	strcpy( buffer+s->len, allow_suffix);
	tmp = buffer;
	ret = load_fixup(&tmp, 1);

	strcpy( buffer+s->len, deny_suffix);
	tmp = buffer;
	ret |= load_fixup(&tmp, 2);

	*param = tmp;

	pkg_free(buffer);
	return ret;
}


/*
 * module initialization function
 */
static int mod_init(void)
{
	LM_DBG("initializing...\n");

	allow[0].filename = get_pathname(default_allow_file);
	allow[0].rules = parse_config_file(allow[0].filename);

	if (allow[0].rules) {
		LM_DBG("default allow file (%s) parsed\n", allow[0].filename);
	} else {
		LM_INFO("default allow file (%s) not found => empty rule set\n",
			allow[0].filename);
	}

	deny[0].filename = get_pathname(default_deny_file);
	deny[0].rules = parse_config_file(deny[0].filename);

	if (deny[0].rules) {
		LM_DBG("default deny file (%s) parsed\n", deny[0].filename);
	} else {
		LM_INFO("default deny file (%s) not found => empty rule set\n",
			deny[0].filename);
	}

	if (init_address() != 0) {
		LM_ERR("failed to init or load DB partitions\n");
		return -1;
	}

	rules_num = 1;
	return 0;
}


static int child_init(int rank)
{
	return 0;
}


static int mi_address_child_init(void)
{
    return mi_init_address();
}

/*
static int mi_addr_child_init(void)
{
    return mi_init_addresses();
}
*/

/*
 * destroy function
 */
static void mod_exit(void)
{
	int i;
	struct pm_part_struct *it;

	for(i = 0; i < rules_num; i++) {
		free_rule(allow[i].rules);
		pkg_free(allow[i].filename);

		free_rule(deny[i].rules);
		pkg_free(deny[i].filename);
	}

	for (it=get_part_structs(); it; it=it->next)
		clean_address(it);
//	clean_addresses();
}


/*
 * Test of REGISTER messages. Creates To-Contact pairs and compares them
 * against rules in allow and deny files passed as parameters. The function
 * iterates over all Contacts and creates a pair with To for each contact
 * found. That allows to restrict what IPs may be used in registrations, for
 * example
 */
static int allow_register(struct sip_msg* msg, int idx)
{
	int len;
	static char to_str[EXPRESSION_LENGTH + 1];
	char* contact_str;
	contact_t* c;

	     /* turn off control, allow any routing */
	if ((!allow[idx].rules) && (!deny[idx].rules)) {
		LM_DBG("no rules => allow any registration\n");
		return 1;
	}

	     /*
	      * Note: We do not parse the whole header field here although the message can
	      * contain multiple Contact header fields. We try contacts one by one and if one
	      * of them causes reject then we don't look at others, this could improve performance
	      * a little bit in some situations
	      */
	if (parse_headers(msg, HDR_TO_F | HDR_CONTACT_F, 0) == -1) {
		LM_ERR("failed to parse headers\n");
		return -1;
	}

	if (!msg->to) {
		LM_ERR("To or Contact not found\n");
		return -1;
	}

	if (!msg->contact) {
		     /* REGISTER messages that contain no Contact header field
		      * are allowed. Such messages do not modify the contents of
		      * the user location database anyway and thus are not harmful
		      */
		LM_DBG("no Contact found, allowing\n");
		return 1;
	}

	     /* Check if the REGISTER message contains start Contact and if
	      * so then allow it
	      */
	if (parse_contact(msg->contact) < 0) {
		LM_ERR("failed to parse Contact HF\n");
		return -1;
	}

	if (((contact_body_t*)msg->contact->parsed)->star) {
		LM_DBG("* Contact found, allowing\n");
		return 1;
	}

	len = ((struct to_body*)msg->to->parsed)->uri.len;
	if (len > EXPRESSION_LENGTH) {
                LM_ERR("To header field is too long: %d chars\n", len);
                return -1;
	}
	strncpy(to_str, ((struct to_body*)msg->to->parsed)->uri.s, len);
	to_str[len] = '\0';

	if (contact_iterator(&c, msg, 0) < 0) {
		return -1;
	}

	while(c) {
		contact_str = get_plain_uri(&c->uri);
		if (!contact_str) {
			LM_ERR("can't extract plain Contact URI\n");
			return -1;
		}

		LM_DBG("looking for To: %s Contact: %s\n", to_str, contact_str);

		     /* rule exists in allow file */
		if (search_rule(allow[idx].rules, to_str, contact_str)) {
			if (check_all_branches) goto skip_deny;
		}

		     /* rule exists in deny file */
		if (search_rule(deny[idx].rules, to_str, contact_str)) {
			LM_DBG("deny rule found => Register denied\n");
			return -1;
		}

	skip_deny:
		if (contact_iterator(&c, msg, c) < 0) {
			return -1;
		}
	}

	LM_DBG("no contact denied => Allowed\n");
	return 1;
}


/*
 * determines the permission to an uri
 * return values:
 * -1:	deny
 * 1:	allow
 */
static int allow_uri(struct sip_msg* msg, int idx, pv_spec_t *sp)
{
	struct hdr_field *from;
	int len;
	static char from_str[EXPRESSION_LENGTH+1];
	static char uri_str[EXPRESSION_LENGTH+1];
	pv_value_t pv_val;

	/* turn off control, allow any uri */
	if ((!allow[idx].rules) && (!deny[idx].rules)) {
		LM_DBG("no rules => allow any uri\n");
		return 1;
	}

	/* looking for FROM HF */
        if ((!msg->from) && (parse_headers(msg, HDR_FROM_F, 0) == -1)) {
                LM_ERR("failed to parse message\n");
                return -1;
        }

	if (!msg->from) {
		LM_ERR("FROM header field not found\n");
		return -1;
	}

	/* we must call parse_from_header explicitly */
        if ((!(msg->from)->parsed) && (parse_from_header(msg) < 0)) {
                LM_ERR("failed to parse From body\n");
                return -1;
        }

	from = msg->from;
	len = ((struct to_body*)from->parsed)->uri.len;
	if (len > EXPRESSION_LENGTH) {
               LM_ERR("From header field is too long: %d chars\n", len);
                return -1;
	}
	strncpy(from_str, ((struct to_body*)from->parsed)->uri.s, len);
	from_str[len] = '\0';

	if (sp && (pv_get_spec_value(msg, sp, &pv_val) == 0)) {
	    if (pv_val.flags & PV_VAL_STR) {
		if (pv_val.rs.len > EXPRESSION_LENGTH) {
		    LM_ERR("pseudo variable value is too "
					"long: %d chars\n", pv_val.rs.len);
		    return -1;
		}
		strncpy(uri_str, pv_val.rs.s, pv_val.rs.len);
		uri_str[pv_val.rs.len] = '\0';
	    } else {
		LM_ERR("pseudo variable value is not string\n");
		return -1;
	    }
	} else {
	    LM_ERR("cannot get pseudo variable value\n");
	    return -1;
	}

    LM_DBG("looking for From: %s URI: %s\n", from_str, uri_str);
	     /* rule exists in allow file */
	if (search_rule(allow[idx].rules, from_str, uri_str)) {
    		LM_DBG("allow rule found => URI is allowed\n");
		return 1;
	}

	/* rule exists in deny file */
	if (search_rule(deny[idx].rules, from_str, uri_str)) {
	    LM_DBG("deny rule found => URI is denied\n");
	    return -1;
	}

	LM_DBG("neither allow nor deny rule found => URI is allowed\n");

	return 1;
}


/*
 * Test URI against Contact.
 */
int allow_test(char *file, char *uri, char *contact)
{
    char *pathname;
    int idx;

    pathname = get_pathname(file);
    if (!pathname) {
	LM_ERR("Cannot get pathname of <%s>\n", file);
	return 0;
    }

    idx = find_index(allow, pathname);
    if (idx == -1) {
	LM_ERR("File <%s> has not been loaded\n", pathname);
	pkg_free(pathname);
	return 0;
    }

    pkg_free(pathname);

    /* turn off control, allow any routing */
    if ((!allow[idx].rules) && (!deny[idx].rules)) {
	LM_DBG("No rules => Allowed\n");
	return 1;
    }

    LM_DBG("Looking for URI: %s, Contact: %s\n", uri, contact);

    /* rule exists in allow file */
    if (search_rule(allow[idx].rules, uri, contact)) {
	LM_DBG("Allow rule found => Allowed\n");
	return 1;
    }

    /* rule exists in deny file */
    if (search_rule(deny[idx].rules, uri, contact)) {
	LM_DBG("Deny rule found => Denied\n");
	return 0;
    }

    LM_DBG("Neither allow or deny rule found => Allowed\n");
    return 1;
}


