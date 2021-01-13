/*
 * Copyright (C) 2018 OpenSIPS Solutions
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../usr_avp.h"
#include "../../mod_fix.h"
#include "../../ut.h"

#include "mmgeoip.h"

#ifdef GEOIP
#include "geoip_legacy.h"
#else
#include "geoip2.h"
#endif

#ifdef GEOIP
	#define geoip_open_db() 			legacy_open_db()
	#define geoip_close_db() 			legacy_close_db()
	#define geoip_lookup_ip(ip, status) legacy_lookup_ip((ip), (status))
	#define geoip_free_lookup_res(res)  legacy_free_lookup_res((res))
	#define geoip_get_field(ip_data, field, buf) \
										legacy_get_field((ip_data), (field), (buf))
#else
	#define geoip_open_db() 			geoip2_open_db()
	#define geoip_close_db() 			geoip2_close_db()
	#define geoip_lookup_ip(ip, status) geoip2_lookup_ip((ip), (status))
	#define geoip_free_lookup_res(res)  
	#define geoip_get_field(ip_data, field, buf) \
										geoip2_get_field((ip_data), (field), (buf))
#endif

#define MMG_OP_DELIMS ":|,/ "
str MMG_city_db_path = {NULL, 0};

int parse_mem_option( unsigned int type, void *val)
{
	#ifdef GEOIP
	return legacy_parse_cache_type((char *)val);
	#else
	LM_INFO("Parameter only supported for legacy GeoIP, ignoring...\n");
	return 0;
	#endif
}

static int mod_init(void)
{
	LM_INFO("MM GeoIP module - initializing\n");

	if (!MMG_city_db_path.s) {
		LM_ERR("mandatory parameter 'city_db_path' not set.\n");
		return -1;
	}

	if (geoip_open_db() < 0)
		return -1;

	LM_INFO("MM GeoIP module - city_db_path:'%s'\n", MMG_city_db_path.s);

	return 0;
}

static void mod_destroy(void)
{
	geoip_close_db();
}

static int fixup_check_avp(void **param)
{
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("return parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}

#include <string.h>
static int mmg_lookup_cmd(struct sip_msg *msg, str *_fields, str *ipaddr_str,
					pv_spec_t *dst_spec)
{
	char rslt_buf[256], ipaddr_buf[256], field_buf[256];
	char *token=0, *saveptr=0;
	int dst_name=-1;
	int_str rslt=(int_str)0;
	unsigned short dstType=0;
	lookup_res_t lookup_res;
	int rc;

	#ifdef GEOIP
	static str cc_s = str_init("cc");
	#else
	static str cc_s = str_init("country.iso_code");
	#endif

	if (!_fields)
		_fields = &cc_s;

	if(pv_get_avp_name(msg, &(dst_spec->pvp), &dst_name, &dstType)!=0) {
		LM_ERR("Internal error getting AVP name.\n");
		return -1;
	}

	memcpy(ipaddr_buf, ipaddr_str->s, ipaddr_str->len);
	ipaddr_buf[ipaddr_str->len] = 0;
	memcpy(field_buf, _fields->s, _fields->len);
	field_buf[_fields->len] = 0;

	lookup_res = geoip_lookup_ip(ipaddr_buf, &rc);
	if (rc != 0)
		return -1;

	LM_DBG("ipaddr: '%.*s'; fields: '%.*s'\n",
		   ipaddr_str->len, ipaddr_str->s, _fields->len, _fields->s);
	*rslt_buf=0;
	rslt.s.s=rslt_buf;
	token=strtok_r(field_buf,MMG_OP_DELIMS,&saveptr);
	while (token) {
		rslt.s.len = geoip_get_field(lookup_res, token, rslt_buf);

		if(rslt.s.len<0 || rslt.s.len>sizeof rslt_buf ||
		add_avp(dstType|AVP_VAL_STR,dst_name,rslt)==-1 ) {
			LM_ERR("Internal error processing field/IP '%s/%s'.\n",
				token,ipaddr_buf);
			geoip_free_lookup_res(lookup_res);
			return -1;
		}
		LM_DBG("field: %s[%s] = %.*s\n",ipaddr_buf,token,rslt.s.len,rslt.s.s);
		token=strtok_r(0,MMG_OP_DELIMS,&saveptr);
	}

	geoip_free_lookup_res(lookup_res);

	return 1;
}

/*
 * wire module pieces together.
 */
static param_export_t mod_params[]={
	{"mmgeoip_city_db_path",   STR_PARAM, &MMG_city_db_path.s},
	{"cache_type", STR_PARAM|USE_FUNC_PARAM, parse_mem_option},
	{ 0,0,0 }
};

static cmd_export_t cmds[] = {
	{"mmg_lookup",  (cmd_function)mmg_lookup_cmd, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR, fixup_check_avp, 0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports= {
	"mmgeoip",        /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,   /* module's name */
	DEFAULT_DLFLAGS,  /* dlopen flags */
	0,				  /* load function */
	NULL,             /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	0,                /* exported async functions */
	mod_params,       /* param exports */
	0,                /* exported statistics */
	0,                /* exported MI functions */
	0,                /* exported pseudo-variables */
	0,			 	  /* exported transformations */
	0,				  /* extra processes */
	0,                /* module pre-initialization function */
	mod_init,         /* module initialization function */
	0,                /* reply processing function */
	mod_destroy,      /* Destroy function */
	0,                /* per-child init function */
	0                 /* reload confirm function */
};
