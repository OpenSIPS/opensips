/*
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * History:
 * --------
 * 080511 -- Initial revision, KE
 *
 * XXX -- todo: Add command variant to pull source/dest IP from 
 *              current SIP message.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../usr_avp.h"
#include "../../mod_fix.h"
#include "GeoIP.h"
#include "GeoIPCity.h"


#define MMG_OP_DELIMS ":|,/ "
static str MMG_city_db_path = {NULL, 0};
static GeoIP *MMG_gi = NULL;

static int
mod_init(void) 
{
	LM_INFO("MM GeoIP module - initializing\n");

	if (!MMG_city_db_path.s) {
		LM_ERR("mandatory parameter 'city_db_path' not set.\n");
		return -1;
	}

	MMG_city_db_path.len=strlen(MMG_city_db_path.s);
	if(0==(MMG_gi = GeoIP_open(MMG_city_db_path.s, GEOIP_MMAP_CACHE))){
		LM_ERR("Unable to open City DB at path '%.*s'.\n",
			MMG_city_db_path.len,MMG_city_db_path.s);
		return -1;
	}

	LM_INFO("MM GeoIP module - city_db_path:'%s'\n", MMG_city_db_path.s);
	return 0;
}

static void
mod_destroy(void)
{
	if(MMG_gi)GeoIP_delete(MMG_gi);
	return;
}

static int
fixup_lookup3(void **param, int param_no)
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

static int
fixup_lookup2(void **param, int param_no)
{
	if(1==param_no)
		return fixup_lookup3(param,2);
	if(2==param_no)
		return fixup_lookup3(param,3);
	LM_ERR("Invalid parameter number: %d.\n", param_no);
	return E_CFG;
}

#include <string.h>
static int
mmg_lookup_cmd(struct sip_msg *msg, char *_fields_pv, char *_ipaddr_pv, char *_dst_spec)
{
	pv_elem_t *fields_pv=(pv_elem_t*)_fields_pv, *ipaddr_pv=(pv_elem_t*)_ipaddr_pv;
	pv_spec_t *dst_spec=(pv_spec_t*)_dst_spec;
	GeoIPRecord *gir=0;
	str field_str, ipaddr_str;
	char rslt_buf[256], ipaddr_buf[256], field_buf[256];
	char *token=0, *saveptr=0;

	int dst_name=-1;
	int_str rslt=(int_str)0;
	unsigned short dstType=0;

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

	/* Attempt lookup */
	if(!(gir=GeoIP_record_by_name (MMG_gi,ipaddr_buf))){
		LM_DBG("'%s'--> 'Unknown'.\n", *ipaddr_buf?ipaddr_buf:"Undefined");
		return -1;
	}

	/* Construct return data. Know fields are: */
	/* 	   lat		- latitude */
	/* 	   lon		- longitude */
	/* 	   cont		- continent  */
	/* 	   cc		- country code */
	/* 	   reg		- region */
	/* 	   city		- city */
	/* 	   pc		- postal code */
	/* 	   dma		- dma code */
	/* 	   ac		- area code  */
	/* 	   tz		- timezone  */

#define MMG_FAIL_EXIT if(gir) GeoIPRecord_delete(gir); return -1

	LM_DBG("ipaddr:'%.*s'; fields:'%.*s'.\n",
		   ipaddr_str.len, ipaddr_str.s, field_str.len, field_str.s);
	*rslt_buf=0;
	rslt.s.s=rslt_buf;
	token=strtok_r(field_buf,MMG_OP_DELIMS,&saveptr);
	while (token) {
		if(!strcmp(token,"lat")) { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%f",gir->latitude); }
		else if(!strcmp(token,"lon"))  { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%f",gir->longitude); } 
		else if(!strcmp(token,"cont")) { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%s",gir->continent_code); } 
		else if(!strcmp(token,"cc"))   { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%s",gir->country_code); } 
		else if(!strcmp(token,"reg"))  { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%s",gir->region); } 
		else if(!strcmp(token,"city")) { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%s",gir->city); } 
		else if(!strcmp(token,"pc"))   { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%s",gir->postal_code); } 
		else if(!strcmp(token,"dma"))  { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%d",gir->dma_code); } 
		else if(!strcmp(token,"ac"))   { rslt.s.len=snprintf(rslt_buf,sizeof rslt_buf,"%d",gir->area_code); } 
		else if(!strcmp(token,"rbc"))  {
			rslt.s.len=snprintf(
				rslt_buf,sizeof rslt_buf,"%s",GeoIP_region_name_by_code(gir->country_code, gir->region));
		}
		else if(!strcmp(token,"tz"))   {
			rslt.s.len=snprintf(
				rslt_buf,sizeof rslt_buf,"%s",GeoIP_time_zone_by_country_and_region(gir->country_code, gir->region));
		} else {
			LM_ERR("unknown field:'%s'\n",token);
			MMG_FAIL_EXIT;
		}
		if(rslt.s.len<0 || rslt.s.len>sizeof rslt_buf ||
		add_avp(dstType|AVP_VAL_STR,dst_name,rslt)==-1 ) {
			LM_ERR("Internal error processing field/IP '%s/%s'.\n",
				token,ipaddr_buf);
			MMG_FAIL_EXIT;
		}
		LM_DBG("field %s[%s] %.*s\n",ipaddr_buf,token,rslt.s.len,rslt.s.s);
		token=strtok_r(0,MMG_OP_DELIMS,&saveptr);
	}
	GeoIPRecord_delete(gir);
	return 1;
}

static int
w_lookup_cmd2(struct sip_msg *m, char *ipaddr, char *dst)
{
	return mmg_lookup_cmd(m,"lon:lat",ipaddr,dst);
}

/*
 * wire module pieces together.
 */
static param_export_t mod_params[]={
	{"mmgeoip_city_db_path",   STR_PARAM, &MMG_city_db_path.s},
	{ 0,0,0 }
};

static cmd_export_t cmds[] = {
	{"mmg_lookup",  (cmd_function)w_lookup_cmd2, 2, fixup_lookup2, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|ERROR_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{"mmg_lookup",  (cmd_function)mmg_lookup_cmd, 3, fixup_lookup3, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|ERROR_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

struct module_exports exports= {
	"mmgeoip",        /* module's name */
	MODULE_VERSION,   /* module's name */
	DEFAULT_DLFLAGS,  /* dlopen flags */
	cmds,             /* exported functions */
	mod_params,       /* param exports */
	0,                /* exported statistics */
	0,                /* exported MI functions */
	0,                /* exported pseudo-variables */
	0,				  /* extra processes */
	mod_init,         /* module initialization function */
	0,                /* reply processing function */
	mod_destroy,      /* Destroy function */
	0                 /* per-child init function */
};
