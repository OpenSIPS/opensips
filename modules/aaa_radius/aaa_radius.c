/*
 * $Id$
 *
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * --------
 * 2009-07-20    First version (Irina Stanescu)
 * 2009-07-29	 Second version (Irina Stanescu) - new exported functions for
 *	 											custom RADIUS commands added
 */

/*
 * This is an implementation of the generic AAA Interface that also provides 
 * via script functions the possibility to run custom RADIUS requests and 
 * to get information from the RADIUS reply.
 */

#ifndef USE_FREERADIUS
	#include <radiusclient-ng.h>
#else
	#include <freeradius-client.h>
#endif

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../aaa/aaa.h"
#include "../../pvar.h"
#include "rad.h"
#include <ctype.h>


typedef struct _map_list {
	pv_spec_p pv;
	str name;
	int value;
	struct _map_list *next;
} map_list;

typedef struct _rad_set_elem {
	str set_name;
	map_list *parsed;
} rad_set_elem;


rad_set_elem **sets = NULL;
int set_size = 0;
char* config_file = NULL;
rc_handle *rh = NULL;
DICT_ATTR *attr;

int mod_init(void);
int init_radius_handle(void);

void destroy(void);
int aaa_radius_bind_api(aaa_prot *rad_prot);

int send_auth_func(struct sip_msg* msg, str* s1, str* s2);
int send_auth_fixup(void** param, int param_no);

int send_acct_func(struct sip_msg* msg, str* s);
int send_acct_fixup(void** param, int param_no);

int parse_sets_func(unsigned int type, void *val);

static cmd_export_t cmds[]= {
	{"aaa_bind_api",  (cmd_function) aaa_radius_bind_api,  0, 0, 0, 0},
	{"radius_send_auth", (cmd_function) send_auth_func, 2, send_auth_fixup, 0,
			REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE |
			ERROR_ROUTE | LOCAL_ROUTE | STARTUP_ROUTE | TIMER_ROUTE },
	{"radius_send_acct", (cmd_function) send_acct_func, 1, send_acct_fixup, 0,
			REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE |
			ERROR_ROUTE | LOCAL_ROUTE | STARTUP_ROUTE | TIMER_ROUTE },
	{ 0,      0,                 0,     0,         0,  0}
};



static param_export_t params[] = {
	{"sets", STR_PARAM | USE_FUNC_PARAM, parse_sets_func},
	{"radius_config", STR_PARAM, &config_file},
	{0, 0, 0}
};


struct module_exports exports= {
	"aaa_radius",				/* module name */
	MODULE_VERSION,				/* module version */
	DEFAULT_DLFLAGS,			/* dlopen flags */
	cmds,						/* exported functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* extra processes */
	(init_function) mod_init,	/* module initialization function */
	0, 							/* response handling function */
	(destroy_function) destroy,	/* destroy function */
	0                  			/* per-child init function */
};


#define CHECK_COND(cond) \
	if ((cond) == 0) { \
		LM_ERR("malformed modparam\n"); \
		return -1;							\
    }

#define CHECK_ALLOC(p) \
	if (!(p)) {	\
		LM_ERR("no memory left\n"); \
		return -1;	\
	}


int parse_set_content(str content, rad_set_elem *elem) {

	char *p;
	str *s;
	map_list *mp;

	//LM_DBG("%.*s\n", content.len, content.s);

	p = (char*) pkg_malloc (content.len + 1);
	CHECK_ALLOC(p);

	p[content.len] = '\0';
	memcpy(p, content.s, content.len);

	s = (str*) pkg_malloc(sizeof(str));
	CHECK_ALLOC(s);

	for (;*p != '\0';) {

		mp = (map_list*) pkg_malloc (sizeof(map_list));
		CHECK_ALLOC(mp);
		mp->next = elem->parsed;
		mp->pv = (pv_spec_p) pkg_malloc (sizeof(pv_spec_t));
		CHECK_ALLOC(mp->pv);

		for (; isspace(*p); p++);
		CHECK_COND(*p != '\0');

		mp->name.s = p;

		for(; isgraph(*p) && *p != '='; p++)
			CHECK_COND(*p != '\0');

		mp->name.len = p - mp->name.s;

		for (; isspace(*p); p++);
		CHECK_COND(*p != '\0' && *p == '=');
		p++;

		//LM_DBG("%.*s\n", mp->name.len, mp->name.s);

		for (; isspace(*p); p++);
		CHECK_COND(*p != '\0' && *p == '$');

		s->s = p;
		s->len = strlen(p);

		p = pv_parse_spec(s, mp->pv);

		for (; isspace(*p); p++);
		if (*p != '\0') {
			CHECK_COND(*p == ',');
			p++;
		}
		elem->parsed = mp;

	}

	return 0;
}


int parse_sets_func(unsigned int type, void *val) {

	rad_set_elem *elem;
	char *p = (char*) val, *pp = NULL;
	str content;
	int nr;

	elem = (rad_set_elem*) pkg_malloc (sizeof(rad_set_elem));
	CHECK_ALLOC(elem);

	for (; isspace(*p); p++);
	CHECK_COND(*p != '\0');

	elem->set_name.s = p;

	for(;isgraph(*p) && *p != '='; p++)
	CHECK_COND(*p != '\0');

	elem->set_name.len = p - elem->set_name.s;

	for (; isspace(*p); p++);
	CHECK_COND(*p != '\0' && *p == '=');
	p++;

	for (; isspace(*p); p++);
	CHECK_COND(*p != '\0' && *p == '(');
	p++;
	CHECK_COND(*p != '\0');

	elem->parsed = NULL;
	content.s = p;
	nr = 1;

	for (; *p != '\0'; p++) {
		if (*p == '(')
			nr++;
		if (*p == ')')
			pp = p, nr--;
	}

	CHECK_COND(pp && !nr);

	content.len = (pp - content.s) * sizeof(char);
	set_size++;

	sets = (rad_set_elem**) pkg_realloc (sets, set_size * sizeof(rad_set_elem*));
	CHECK_ALLOC(sets);

	sets[set_size - 1] = elem;

	if (parse_set_content(content, elem)) {
		LM_ERR("malformed modparam %.*s\n",sets[set_size - 1]->set_name.len,
				sets[set_size - 1]->set_name.s);
		return -1;
	}

	return 0;
}


int make_send_message(struct sip_msg* msg, int index, VALUE_PAIR **send) {

	pv_value_t pt;
	map_list *mp = sets[index]->parsed;

	for (; mp; mp = mp->next) {
		pv_get_spec_value(msg, mp->pv, &pt);

		if (pt.flags & PV_VAL_INT) {
			//LM_DBG("%.*s---->%d---->%d---->%d\n",mp->name.len, mp->name.s, 
			//		pt.ri, mp->value, pt.flags);

			if (!rc_avpair_add(rh, send, ATTRID(mp->value), &pt.ri, -1, VENDOR(mp->value)))
				return -1;
		}
		else
		if (pt.flags & PV_VAL_STR) {
			//LM_DBG("%.*s----->%.*s---->%d---->%d---->%d\n",mp->name.len, 
			//		mp->name.s, pt.rs.len, pt.rs.s, mp->value, pt.flags, pt.rs.len);
			if (rc_dict_getattr(rh,mp->value)->type == PW_TYPE_IPADDR) {
				uint32_t ipaddr=rc_get_ipaddr(pt.rs.s);
				if (!rc_avpair_add(rh, send, ATTRID(mp->value), &ipaddr, -1, VENDOR(mp->value)))
					return -1;
			} else {
				if (!rc_avpair_add(rh, send, ATTRID(mp->value), pt.rs.s, pt.rs.len, VENDOR(mp->value)))
					return -1;
			}
		}
	}
	return 0;
}


int send_auth_func(struct sip_msg* msg, str* s1, str* s2) {

	int i, res;
	int index1 = -1, index2 = -1;
	map_list *mp;
	pv_value_t pvt;
	char mess[1024];

	VALUE_PAIR *send = NULL, *recv = NULL, *vp = NULL;

	if (!rh) {
		if (init_radius_handle()) {
			LM_ERR("invalid radius handle\n");
			return -1;
		}
	}

	for (i = 0; i < set_size; i++) {
		if (sets[i]->set_name.len == s1->len &&
				!strncmp(sets[i]->set_name.s, s1->s, s1->len))
				index1 = i;
		if (sets[i]->set_name.len == s2->len &&
				!strncmp(sets[i]->set_name.s, s2->s, s2->len))
				index2 = i;
	}

	if (index1 == -1) {
		LM_ERR("the first set was not found\n");
		return -1;
	}

	if (index2 == -1) {
		LM_ERR("the second set was not found\n");
		return -1;
	}

	if (make_send_message(msg, index1, &send) < 0) {
		LM_ERR("make message failed\n");
		return -1;
	}

	res = rc_auth(rh, SIP_PORT, send, &recv, mess);
	if (res!=OK_RC && res!=BADRESP_RC) {
		LM_ERR("radius authentication message failed with %s\n",
			(res==TIMEOUT_RC)?"TIMEOUT":"ERROR");
		goto error;
	}

	LM_DBG("radius authentication message sent\n");

	for ( mp=sets[index2]->parsed; mp ; mp = mp->next) {
		if ((vp = rc_avpair_get(recv, ATTRID(mp->value), VENDOR(mp->value)))) {
			memset(&pvt, 0, sizeof(pv_value_t));
			if (vp->type == PW_TYPE_INTEGER) {
				pvt.flags = PV_VAL_INT|PV_TYPE_INT;
				pvt.ri = vp->lvalue;
			}
			else
			if (vp->type == PW_TYPE_STRING) {
				pvt.flags = PV_VAL_STR;
				pvt.rs.s = vp->strvalue;
				pvt.rs.len = vp->lvalue;
			}
			if (pv_set_value(msg, mp->pv, (int)EQ_T, &pvt) < 0) {
				LM_ERR("setting avp failed....skipping\n");
			}
		} else {
			LM_DBG("attribute was not found in received radius message\n");
		}
	}

	vp = recv;
	if (attr)
		for(; (vp = rc_avpair_get(vp, attr->value, 0)); vp = vp->next)
			extract_avp(vp);

	if (send) rc_avpair_free(send);
	if (recv) rc_avpair_free(recv);

	return (res==OK_RC)?1:-2;
error:
	if (send) rc_avpair_free(send);
	if (recv) rc_avpair_free(recv);
	return -1;
}


int send_auth_fixup(void** param, int param_no) {

	str *s;

	if (!rh) {
		if (init_radius_handle()) {
			LM_ERR("invalid radius handle\n");
    		return E_UNSPEC;
		}
    }

	s = (str*) pkg_malloc(sizeof(str));
	CHECK_ALLOC(s);

	if (param_no == 1 || param_no == 2) {
		s->s = *param;
		s->len = strlen(s->s);
		*param = s;
		return 0;
	}

    return E_UNSPEC;
}


int send_acct_func(struct sip_msg* msg, str *s) {

	int i, index = -1;
	VALUE_PAIR *send = NULL;

	if (!rh) {
		if (init_radius_handle()) {
			LM_ERR("invalid radius handle\n");
			return -1;
		}
	}

	for (i = 0; i < set_size; i++) {
		if (sets[i]->set_name.len == s->len &&
				!strncmp(sets[i]->set_name.s, s->s, s->len))
				index = i;
	}

	if (index == -1) {
		LM_ERR("set not found\n");
		return -1;
	}

	if (make_send_message(msg, index, &send) < 0) {
		LM_ERR("make message failed\n");
		return -1;
	}

	if (rc_acct(rh, SIP_PORT, send) != OK_RC){
		if (send) rc_avpair_free(send);
		LM_ERR("radius accounting message failed to send\n");
		return -1;
	}

	if (send) rc_avpair_free(send);
	return 1;
}


int send_acct_fixup(void** param, int param_no) {

	str *s = (str*) pkg_malloc(sizeof(str));
	CHECK_ALLOC(s);

	if (!rh) {
		if (init_radius_handle()) {
			LM_ERR("invalid radius handle\n");
    		return E_UNSPEC;
		}
    }

	if (param_no == 1) {
		s->s = *param;
		s->len = strlen(s->s);
		*param = s;
		return 0;
	}

	return E_UNSPEC;
}

int init_radius_handle(void) {

	int i;
	DICT_ATTR *da;
	char name[256];
	map_list *mp;


	if (!config_file) {
		LM_ERR("radius configuration file not set\n");
		return -1;
	}

	if (!(rh = rc_read_config(config_file))) {
		LM_ERR("failed to open radius config file: %s\n", config_file);
		return -1;
	}

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary"))) {
		LM_ERR("failed to read radius dictionary\n");
		return -1;
	}

	attr = rc_dict_findattr(rh, "SIP-AVP");

	/* initialize values for the attributes in sets */
	for (i = 0; i < set_size; i++) {
		mp = sets[i]->parsed;

		while (mp) {
			sprintf(name,"%.*s", mp->name.len, mp->name.s);
			da = rc_dict_findattr(rh, name);
			if (!da) {
				LM_ERR("attribute not found %s\n", name);
				return -1;
			} else
			mp->value = da->value;
			mp = mp->next;
		}
	}

	return 0;
}

int mod_init(void) {
	LM_DBG("aaa_radius module was initiated\n");

	return 0;
}


void destroy(void) {
	int i;
	map_list *cur, *next;

	for (i = 0; i < set_size; i++) {
		LM_DBG("%.*s\n",sets[i]->set_name.len, sets[i]->set_name.s);
		cur = sets[i]->parsed;
		while (cur) {
			next = cur->next;
			pkg_free(cur);
			cur = next;
		}
		pkg_free(sets[i]);
	}
}


int aaa_radius_bind_api(aaa_prot *rad_prot) {

	if (!rad_prot)
		return -1;

	memset(rad_prot, 0, sizeof(aaa_prot));

	rad_prot->create_aaa_message = rad_create_message;
	rad_prot->destroy_aaa_message = rad_destroy_message;
	rad_prot->send_aaa_request = rad_send_message;
	rad_prot->init_prot = rad_init_prot;
	rad_prot->dictionary_find = rad_find;
	rad_prot->avp_add = rad_avp_add;
	rad_prot->avp_get = rad_avp_get;

	return 0;
}


