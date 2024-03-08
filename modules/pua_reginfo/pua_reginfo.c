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

/* Bindings to PUA */
#include "../pua/pua_bind.h"
/* Bindings to usrloc */
#include "../usrloc/usrloc.h"
/* Bindings to Presence */
#include "../presence/bind_presence.h"

#include "pua_reginfo.h"
#include "subscribe.h"
#include "notify.h"
#include "usrloc_cb.h"

usrloc_api_t ul; 		/*!< Structure containing pointers to usrloc functions*/
pua_api_t pua;	 		/*!< Structure containing pointers to PUA functions*/
presence_api_t pres;	/*!< Structure containing pointers to Presence functions*/

/* Default domain to be added, if none provided. */
str reginfo_default_domain = {NULL, 0};
str outbound_proxy = {NULL, 0};
str server_address = {NULL, 0};
str uldomain_str = {NULL, 0};
str ul_identities_key = {NULL, 0};

int publish_reginfo = 0;

udomain_t* ul_domain = 0;

int reginfo_use_domain = 0;

/** Fixup functions */
static int domain_fixup(void **param);

/** module functions */
static int mod_init(void);

/* Commands */
static cmd_export_t cmds[] = {
		{"reginfo_subscribe", (cmd_function)reginfo_subscribe, {
				{CMD_PARAM_STR, 0, 0},
				{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0},
				{0,0,0},
			},
			REQUEST_ROUTE | ONREPLY_ROUTE},
		{"reginfo_handle_notify", (cmd_function)reginfo_handle_notify, {
				{CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0},
				{0,0,0},
			},
			REQUEST_ROUTE},
		{"reginfo_update", (cmd_function)w_reginfo_update, {
				{CMD_PARAM_STR, 0, 0},
				{0,0,0},
			},
			REQUEST_ROUTE | ONREPLY_ROUTE},
		{0,0,{{0,0,0}},0}
	};

static param_export_t params[] = {
		{"default_domain", STR_PARAM, &reginfo_default_domain.s},
		{"outbound_proxy", STR_PARAM, &outbound_proxy.s},
		{"server_address", STR_PARAM, &server_address.s},
		{"ul_domain", STR_PARAM, &uldomain_str.s},
		{"ul_identities_key", STR_PARAM, &ul_identities_key.s},
		{"publish_reginfo", INT_PARAM, &publish_reginfo}, {0, 0, 0}};

/* module exports */
static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "presence", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "pua", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "usrloc", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/* module exports */
struct module_exports exports= {
    "pua_reginfo",		/* module name */
    MOD_TYPE_DEFAULT,           /* class of this module */
    MODULE_VERSION,				/* module version */
    DEFAULT_DLFLAGS,			/* dlopen flags */
    0,							/* load function */
    &deps,                      /* OpenSIPS module dependencies */
    cmds,						/* exported functions */
    0,							/* exported async functions */
    params,						/* exported parameters */
    0,							/* exported statistics */
    0,							/* exported MI functions */
    0,							/* exported pseudo-variables */
    0,			 				/* exported transformations */
    0,							/* extra processes */
    0,							/* module pre-initialization function */
    mod_init,					/* module initialization function */
    0,							/* response handling function */
    0,							/* destroy function */
    0,							/* per-child init function */
    0							/* reload confirm function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	bind_pua_t bind_pua;
	bind_usrloc_t bind_usrloc;
	bind_presence_t bind_presence;

	if(publish_reginfo == 1) {
		/* Verify the default domain: */
		if(!reginfo_default_domain.s) {
			LM_ERR("default domain parameter not set\n");
			return -1;
		}
		reginfo_default_domain.len = strlen(reginfo_default_domain.s);
	}
	
	if(!server_address.s) {
		LM_ERR("server_address parameter not set\n");
		return -1;
	}
	server_address.len = strlen(server_address.s);

	if(!outbound_proxy.s)
		LM_DBG("No outbound proxy set\n");
	else {
		outbound_proxy.len = strlen(outbound_proxy.s);
		LM_DBG("Using %.*s as outbound proxy\n", outbound_proxy.len, outbound_proxy.s);
	}

	/* Bind to Presence: */
	memset(&pres, 0, sizeof(presence_api_t));
	bind_presence= (bind_presence_t)find_export("bind_presence", 0);
	if(!bind_presence) {
		LM_INFO("can't bind presence\n");
		return -1;
	} else {
		if(bind_presence(&pres) < 0) {
			LM_ERR("can't bind presence\n");
			return -1;
		}
	}

	/* Bind to PUA: */
	memset(&pua, 0, sizeof(pua_api_t));
	bind_pua = (bind_pua_t)find_export("bind_pua", 0);
	if(!bind_pua) {
		LM_INFO("Can't bind pua\n");
		if (pres.update_presentity == NULL) {
			LM_ERR("Either PUA or Presence required, none found.\n");
			return -1;
		}
		LM_INFO("Disabling sending of PUBLISH\n");
		publish_reginfo = 0;
	} else {
		if(bind_pua(&pua) < 0) {
			LM_ERR("Can't bind pua\n");
			return -1;
		}
		/* Check for Publish/Subscribe methods */
		if(pua.send_publish == NULL) {
			LM_ERR("Could not import send_publish\n");
			return -1;
		}
		if(pua.send_subscribe == NULL) {
			LM_ERR("Could not import send_subscribe\n");
			return -1;
		}
	}

	/* Bind to URSLOC: */
	bind_usrloc = (bind_usrloc_t)find_export("ul_bind_usrloc", 0);
	if(!bind_usrloc) {
		LM_ERR("Can't bind usrloc\n");
		return -1;
	}
	if(bind_usrloc(&ul) < 0) {
		LM_ERR("Can't bind usrloc\n");
		return -1;
	}
	if(!uldomain_str.s) {
		LM_ERR("uldomain parameter not set\n");
		return -1;
	}
	uldomain_str.len = strlen(uldomain_str.s);
	if (ul.register_udomain(uldomain_str.s, &ul_domain) < 0) {
		LM_ERR("failed to register domain\n");
		return E_UNSPEC;
	}
	if(ul.register_ulcb == NULL) {
		LM_ERR("Could not import ul_register_ulcb\n");
		return -1;
	}
	if(ul.register_ulcb(UL_CONTACT_INSERT|UL_CONTACT_UPDATE|UL_CONTACT_DELETE|UL_CONTACT_EXPIRE, reginfo_usrloc_cb) < 0) {
		LM_ERR("can not register callback for usrloc\n");
		return -1;
	}

	ul_identities_key.len = strlen(ul_identities_key.s);

	/*
	 * Import use_domain parameter from usrloc
	 */
	reginfo_use_domain = ul.use_domain;

	return 0;
}

/*! \brief
 * Convert char* parameter to udomain_t* pointer
 */
static int domain_fixup(void **param)
{
	udomain_t* d;
	str d_nt;

	if (pkg_nt_str_dup(&d_nt, (str*)*param) < 0)
		return E_OUT_OF_MEM;

	if (ul.register_udomain(d_nt.s, &d) < 0) {
		LM_ERR("failed to register domain\n");
		return E_UNSPEC;
	}

	pkg_free(d_nt.s);

	*param = (void*)d;
	return 0;
}
