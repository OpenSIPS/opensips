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
	LM_INFO("Parameter only supported for legacy GeoIP, ignoring...");
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

static int fixup_lookup3(void **param, int param_no)
{
	str s;

	s.s=(char *)(*param);
	s.len=strlen(s.s);
	if(!s.len) {
		LM_ERR("fixup_lookup3:Parameter %d is empty.\n", param_no);
		return E_CFG;
	}
	if(1==param_no || 2==param_no) {
		/* Expecting input pseudo vars --> pv_elem_t */
		pv_elem_t *model=0;
		if(pv_parse_format(&s,&model) || !model) {
			LM_ERR("Bad format for input PV: '%s'.", s.s);
			return E_CFG;
		}
		*param=(void*)model;
		return 0;
	} else if(3==param_no) {
		/* Expecting AVP spec --> pv_spec_t */
		pv_spec_t *spec;
		int ret=fixup_pvar(param);
		if(ret<0) return ret;
		spec=(pv_spec_t*)(*param);
		if(spec->type!=PVT_AVP) {
			LM_ERR("AVP required for return value!\n");
			return E_CFG;
		}
		return 0;
	} else {
		LM_ERR("Invalid parameter number: %d.\n", param_no);
		return E_CFG;
	}
	return 0;
}

static int fixup_lookup2(void **param, int param_no)
{
	if(1==param_no)
		return fixup_lookup3(param,2);
	if(2==param_no)
		return fixup_lookup3(param,3);
	LM_ERR("Invalid parameter number: %d.\n", param_no);
	return E_CFG;
}

#include <string.h>
static int mmg_lookup_cmd(struct sip_msg *msg, char *_fields_pv, char *_ipaddr_pv, char *_dst_spec)
{
	pv_elem_t *fields_pv=(pv_elem_t*)_fields_pv, *ipaddr_pv=(pv_elem_t*)_ipaddr_pv;
	pv_spec_t *dst_spec=(pv_spec_t*)_dst_spec;
	str field_str, ipaddr_str;
	char rslt_buf[256], ipaddr_buf[256], field_buf[256];
	char *token=0, *saveptr=0;
	int dst_name=-1;
	int_str rslt=(int_str)0;
	unsigned short dstType=0;

	lookup_res_t lookup_res;
	int rc;

	/* Sanity checks */
	if(!(ipaddr_pv && fields_pv && dst_spec)) {
		LM_ERR("Missing argument(s).\n");
		return -1;
	}
	if(dst_spec->type != PVT_AVP) {
		LM_ERR("Invalid destination spec -- expected AVP.\n");
		return -1;
	}
	if(pv_get_avp_name(msg, &(dst_spec->pvp), &dst_name, &dstType)!=0) {
		LM_ERR("Internal error getting AVP name.\n");
		return -1;
	}

	/* Expand input args: lookup field list and IP address.*/
	*ipaddr_buf=0;
	ipaddr_str.s=ipaddr_buf;
	ipaddr_str.len=sizeof ipaddr_buf;
	if(pv_printf(msg, ipaddr_pv, ipaddr_buf,  &ipaddr_str.len) || ipaddr_str.len==0) {
		LM_ERR("Internal error parsing IP address.\n");
		return -1;
	}

	*field_buf=0;
	field_str.s=field_buf;
	field_str.len=sizeof field_buf;
	if(pv_printf(msg, fields_pv, field_buf,  &field_str.len) || field_str.len==0) {
		LM_ERR("Internal error parsing lookup fields.\n");
		return -1;
	}

	lookup_res = geoip_lookup_ip(ipaddr_buf, &rc);
	if (rc != 0)
		return -1;

	LM_DBG("ipaddr: '%.*s'; fields: '%.*s'\n",
		   ipaddr_str.len, ipaddr_str.s, field_str.len, field_str.s);
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

static int w_lookup_cmd2(struct sip_msg *m, char *ipaddr, char *dst)
{
	#ifdef GEOIP
	return mmg_lookup_cmd(m,"cc",ipaddr,dst);
	#else
	return mmg_lookup_cmd(m,"country.iso_code",ipaddr,dst);
	#endif
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
	{"mmg_lookup",  (cmd_function)w_lookup_cmd2, 2, fixup_lookup2, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|ERROR_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"mmg_lookup",  (cmd_function)mmg_lookup_cmd, 3, fixup_lookup3, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|ERROR_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0, 0, 0, 0, 0, 0}
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
	0                 /* per-child init function */
};
