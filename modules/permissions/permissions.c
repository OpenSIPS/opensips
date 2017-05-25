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


/* for allow_address and allow_address function */
str db_url = {NULL, 0};                    /* Don't connect to the database by default */

/* for allow_address function */
str address_table = str_init("address");	/* Name of address table */
str ip_col = str_init("ip");				/* Name of ip column */
str proto_col = str_init("proto");			/* Name of protocol column */
str pattern_col = str_init("pattern"); 		/* Name of pattern column */
str info_col = str_init("context_info");	/* Name of context info column */
str grp_col = str_init("grp");				/* Name of address group column */
str mask_col = str_init("mask");			/* Name of mask column */
str port_col = str_init("port");			/* Name of port column */
str id_col = str_init("id");				/* Name of id column */

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
static int single_fixup(void** param, int param_no);


/*
 * Parse pseudo variable parameter
 */
static int double_fixup(void** param, int param_no);

static int check_addr_fixup(void** param, int param_no);
static int check_src_addr_fixup(void** param, int param_no);
static int get_src_grp_fixup(void** param, int param_no);

static int allow_routing_0(struct sip_msg* msg, char* str1, char* str2);
static int allow_routing_1(struct sip_msg* msg, char* basename, char* str2);
static int allow_routing_2(struct sip_msg* msg, char* allow_file, char* deny_file);
static int allow_register_1(struct sip_msg* msg, char* basename, char* s);
static int allow_register_2(struct sip_msg* msg, char* allow_file, char* deny_file);
static int allow_uri(struct sip_msg* msg, char* basename, char* uri);

static int mod_init(void);
static void mod_exit(void);
static int child_init(int rank);
static int mi_address_child_init();

/* Exported functions */
static cmd_export_t cmds[] = {
	{"check_address" , (cmd_function) check_addr_4, 4,
		check_addr_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"check_address" , (cmd_function) check_addr_5, 5,
		check_addr_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"check_address" , (cmd_function) check_addr_6, 6,
		check_addr_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"check_source_address" ,(cmd_function)check_src_addr_1, 1,
		check_src_addr_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"check_source_address" , (cmd_function) check_src_addr_2, 2,
		check_src_addr_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"check_source_address" , (cmd_function) check_src_addr_3, 3,
		check_src_addr_fixup, 0,
		REQUEST_ROUTE| FAILURE_ROUTE|LOCAL_ROUTE},
	{"get_source_group", (cmd_function) get_source_group, 1,
		get_src_grp_fixup, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | LOCAL_ROUTE },
	{"allow_routing",  (cmd_function)allow_routing_0,  0,
		0, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | LOCAL_ROUTE},
	{"allow_routing",  (cmd_function)allow_routing_1,  1,
		single_fixup, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | LOCAL_ROUTE},
	{"allow_routing",  (cmd_function)allow_routing_2,  2,
		load_fixup, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | LOCAL_ROUTE},
	{"allow_register", (cmd_function)allow_register_1, 1,
		single_fixup, 0,
		REQUEST_ROUTE | FAILURE_ROUTE},
	{"allow_register", (cmd_function)allow_register_2, 2,
		load_fixup, 0,
		REQUEST_ROUTE | FAILURE_ROUTE},
	{"allow_uri",      (cmd_function)allow_uri, 2,
		double_fixup, 0,
		REQUEST_ROUTE | FAILURE_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
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
	{"db_url",			   STR_PARAM|USE_FUNC_PARAM,
						    (void *)set_default_db_url   },
	{"address_table",      STR_PARAM|USE_FUNC_PARAM,
							(void *)set_default_table    },
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
	{ MI_ADDRESS_RELOAD,  0, mi_address_reload,  0,  0, mi_address_child_init },
	{ MI_ADDRESS_DUMP,    0, mi_address_dump,    0,  0,  0 },
	{ MI_SUBNET_DUMP,     0, mi_subnet_dump,     0,  0,  0 },
	{ MI_ALLOW_URI,       0, mi_allow_uri,       0,  0,  0 },
	{ 0, 0, 0, 0, 0, 0}
};

/* Module interface */
struct module_exports exports = {
	"permissions",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,      /* Exported functions */
	0,         /* Exported async functions */
	params,    /* Exported parameters */
	0,         /* exported statistics */
	mi_cmds,   /* exported MI functions */
	0,         /* exported pseudo-variables */
	0,		   /* exported transformations */
	0,         /* extra processes */
	mod_init,  /* module initialization function */
	0,         /* response function */
	mod_exit,  /* destroy function */
	child_init /* child initialization function */
};


static int get_src_grp_fixup(void** param, int param_no)
{
	int ret;
	str s;
	struct part_var *pv;
	struct part_pvar *ppv;


	if (get_part_structs() == NULL) {
		LM_ERR("get_source_group() needs at least default partition!\n");
		return E_UNSPEC;
	}


	if(param_no==1) {
		pv = pkg_malloc(sizeof(struct part_var));
		if (pv == NULL) {
			LM_ERR("no more pkg mem\n");
			return -1;
		}

		s.s = *param;
		s.len = strlen(s.s);
		if (check_addr_param1(&s, pv))
			return -1;


		ppv = pkg_malloc(sizeof(struct part_pvar));
		if (ppv == NULL) {
			LM_ERR("no more pkg mem\n");
			return -1;
		}

		ppv->sp = (pv_spec_t *)pv->u.parsed_part.v.sval.s;
		ret=fixup_pvar((void **)&ppv->sp);
		if (ret)
			return E_UNSPEC;

		if (pv->u.parsed_part.partition.s) {
			pv->u.parsed_part.partition.s[pv->u.parsed_part.partition.len] = '\0';
			if (fixup_sgp((void **)&pv->u.parsed_part.partition.s))
				return E_UNSPEC;

			ppv->part = (gparam_p)pv->u.parsed_part.partition.s;

		} else {
			ppv->part = NULL;
		}

		*param = ppv;
		pkg_free(pv);

		return 0;
	}

	return E_UNSPEC;
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
static int check_routing(struct sip_msg* msg, int idx)
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
static int single_fixup(void** param, int param_no)
{
	char* buffer;
	void* tmp;
	int param_len, ret, suffix_len;

	if (param_no != 1) return 0;

	param_len = strlen((char*)*param);
	if (strlen(allow_suffix) > strlen(deny_suffix)) {
		suffix_len = strlen(allow_suffix);
	} else {
		suffix_len = strlen(deny_suffix);
	}

	buffer = pkg_malloc(param_len + suffix_len + 1);
	if (!buffer) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	strcpy(buffer, (char*)*param);
	strcat(buffer, allow_suffix);
	tmp = buffer;
	ret = load_fixup(&tmp, 1);

	strcpy(buffer + param_len, deny_suffix);
	tmp = buffer;
	ret |= load_fixup(&tmp, 2);

	*param = tmp;

	pkg_free(buffer);
	return ret;
}


/*
 * Convert the name of the file into table index and pvar into parsed pseudo
 * variable specification
 */
static int double_fixup(void** param, int param_no)
{
	char* buffer;
	void* tmp;
	int param_len, ret, suffix_len;
	pv_spec_t *sp;
	str s;

	if (param_no == 1) { /* basename */
	    param_len = strlen((char*)*param);
	    if (strlen(allow_suffix) > strlen(deny_suffix)) {
		suffix_len = strlen(allow_suffix);
	    } else {
		suffix_len = strlen(deny_suffix);
	    }

	    buffer = pkg_malloc(param_len + suffix_len + 1);
	    if (!buffer) {
		LM_ERR("no pkg memory left\n");
		return -1;
	    }

	    strcpy(buffer, (char*)*param);
	    strcat(buffer, allow_suffix);
	    tmp = buffer;
	    ret = load_fixup(&tmp, 1);

	    strcpy(buffer + param_len, deny_suffix);
	    tmp = buffer;
	    ret |= load_fixup(&tmp, 2);

	    *param = tmp;
	    pkg_free(buffer);

	    return 0;

	} else if (param_no == 2) { /* pseudo variable */

	    sp = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t));
	    if (sp == 0) {
		LM_ERR("no pkg memory left\n");
		return -1;
	    }
		s.s = (char*)*param; s.len = strlen(s.s);
	    if (pv_parse_spec(&s, sp) == 0) {
		LM_ERR("parsing of pseudo variable %s failed!\n", (char*)*param);
		pkg_free(sp);
		return -1;
	    }

	    if (sp->type == PVT_NULL) {
		LM_ERR("bad pseudo variable\n");
		pkg_free(sp);
		return -1;
	    }

	    *param = (void*)sp;

	    return 0;
	}

	*param = (void *)0;

	return 0;
}


/*
 * module initialization function
 */
static int mod_init(void)
{
	struct pm_partition *el, *prev_el=NULL;

	LM_DBG("initializing...\n");

	ip_col.len = strlen(ip_col.s);
	proto_col.len = strlen(proto_col.s);
	pattern_col.len = strlen(pattern_col.s);
	info_col.len = strlen(info_col.s);
	grp_col.len = strlen(grp_col.s);
	mask_col.len = strlen(mask_col.s);
	port_col.len = strlen(port_col.s);

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


	el = get_partitions();
	while (el) {
		/* initialize table name if not done from script */
		if (el->table.s == NULL) {
			el->table.s = "address";
			el->table.len = strlen(el->table.s);
		}

		if (init_address(el) != 0) {
			LM_ERR("failed to initialize the allow_address function\n");
			return -1;
		}
		prev_el = el;
		el = el->next;
		pkg_free(prev_el);
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
 * Uses default rule files from the module parameters
 */
int allow_routing_0(struct sip_msg* msg, char* str1, char* str2)
{
	return check_routing(msg, 0);
}


int allow_routing_1(struct sip_msg* msg, char* basename, char* s)
{
	return check_routing(msg, (int)(long)basename);
}


/*
 * Accepts allow and deny files as parameters
 */
int allow_routing_2(struct sip_msg* msg, char* allow_file, char* deny_file)
{
	     /* Index converted by load_lookup */
	return check_routing(msg, (int)(long)allow_file);
}


/*
 * Test of REGISTER messages. Creates To-Contact pairs and compares them
 * against rules in allow and deny files passed as parameters. The function
 * iterates over all Contacts and creates a pair with To for each contact
 * found. That allows to restrict what IPs may be used in registrations, for
 * example
 */
static int check_register(struct sip_msg* msg, int idx)
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


int allow_register_1(struct sip_msg* msg, char* basename, char* s)
{
	return check_register(msg, (int)(long)basename);
}


int allow_register_2(struct sip_msg* msg, char* allow_file, char* deny_file)
{
	return check_register(msg, (int)(long)allow_file);
}


/*
 * determines the permission to an uri
 * return values:
 * -1:	deny
 * 1:	allow
 */
static int allow_uri(struct sip_msg* msg, char* _idx, char* _sp)
{
	struct hdr_field *from;
	int idx, len;
	static char from_str[EXPRESSION_LENGTH+1];
	static char uri_str[EXPRESSION_LENGTH+1];
	pv_spec_t *sp;
	pv_value_t pv_val;

	idx = (int)(long)_idx;
	sp = (pv_spec_t *)_sp;

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


static int check_addr_fixup(void** param, int param_no) {
	int ret;
	gparam_p gp;
	struct part_var *pv;

	if (get_part_structs() == NULL) {
		LM_ERR("check_source_address needs db_url to be set!\n");
		return E_UNSPEC;
	}

	/* grp ip port proto info pattern*/
	switch (param_no) {
		case 1:
			ret = fixup_spve(param);

			if (0 == ret) {
				gp = *param;
				pv = pkg_malloc(sizeof(struct part_var));
				if (pv == NULL) {
					LM_ERR("no more pkg mem\n");
					return -1;
				}

				if (gp->type == GPARAM_TYPE_STR) {
					pv->type = TYPE_PARSED;
					ret = check_addr_param1(&gp->v.sval, pv);
				} else {
					pv->type = TYPE_PV;
					pv->u.gp = gp;
				}
				*param = pv;
			}

			return ret;
		case 2:
		case 3:
		case 4:
			return fixup_spve(param);
		case 5:
			if (*param && strlen((char*)*param))
				return fixup_pvar(param);
			*param = NULL;
			return 0;
		case 6:
			if (*param && strlen((char*)*param))
				return fixup_spve(param);
			*param = NULL;
			return 0;
	}
	return E_UNSPEC;
}


static int check_src_addr_fixup(void** param, int param_no) {
	int ret;
	gparam_p gp;
	struct part_var *pv;

	if (get_part_structs() == NULL) {
		LM_ERR("check_source_address needs db_url to be set!\n");
		return E_UNSPEC;
	}

	/* grp info pattern */
	switch (param_no) {
		case 1:
			ret = fixup_spve(param);

			if (0 == ret) {
				gp = *param;
				pv = pkg_malloc(sizeof(struct part_var));
				if (pv == NULL) {
					LM_ERR("no more pkg mem\n");
					return -1;
				}

				if (gp->type == GPARAM_TYPE_STR) {
					pv->type = TYPE_PARSED;
					ret = check_addr_param1(&gp->v.sval, pv);
				} else {
					pv->type = TYPE_PV;
					pv->u.gp = gp;
				}

				*param = pv;
			}

			return ret;
		case 2:
			if (*param && strlen((char*)*param))
				return fixup_pvar(param);
			*param = NULL;
			return 0;
		case 3:
			if (*param && strlen((char*)*param))
				return fixup_spve(param);
			*param = NULL;
			return 0;
	}
	return E_UNSPEC;
}
