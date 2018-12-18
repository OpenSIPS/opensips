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

#ifdef GEOIP

#include <string.h>
#include "../../dprint.h"

#include "mmgeoip.h"
#include "geoip_legacy.h"

int legacy_cache_option = GEOIP_MMAP_CACHE;
GeoIP *MMG_gi;

int legacy_parse_cache_type(char *val)
{
	str opt_s;
	static const str opt_STANDARD = str_init("STANDARD");
	static const str opt_MMAP = str_init("MMAP_CACHE");
	static const str opt_MEM_CHECK = str_init("MEM_CACHE_CHECK");

	opt_s.s = val;
	opt_s.len = strlen(opt_s.s);

	if (opt_s.len == opt_STANDARD.len &&
			!strncasecmp(opt_s.s, opt_STANDARD.s, opt_s.len)) {
		legacy_cache_option = GEOIP_STANDARD;
	} else if (opt_s.len == opt_MMAP.len &&
			!strncasecmp(opt_s.s, opt_MMAP.s, opt_s.len)) {
		legacy_cache_option = GEOIP_MMAP_CACHE;
	} else if (opt_s.len == opt_MEM_CHECK.len &&
			!strncasecmp(opt_s.s, opt_MEM_CHECK.s, opt_s.len)) {
		legacy_cache_option = GEOIP_MEMORY_CACHE|GEOIP_CHECK_CACHE;
	} else {
		LM_ERR("Invalid cache option!\n");
		return -1;
	}

	return 0;
}

int legacy_open_db(void)
{
	if(0==(MMG_gi = GeoIP_open(MMG_city_db_path.s,
					legacy_cache_option))){
		LM_ERR("Unable to open City DB at path '%.*s'.\n",
			MMG_city_db_path.len,MMG_city_db_path.s);
		return -1;
	}

	return 0;
}

void legacy_close_db(void)
{
	if (MMG_gi)
		GeoIP_delete(MMG_gi);
}

lookup_res_t legacy_lookup_ip(char *ip, int *status)
{
	GeoIPRecord *gir=0;

	if(!(gir=GeoIP_record_by_name (MMG_gi,ip))){
		LM_DBG("'%s'--> 'Unknown'.\n", *ip?ip:"Undefined");
		*status = -1;
		return NULL;
	}

	*status = 0;
	return gir;
}

void legacy_free_lookup_res(lookup_res_t res)
{
	GeoIPRecord_delete(res);
}

int legacy_get_field(lookup_res_t ip_data, char *field, char *buf)
{
	int res_len;

	if(!strcmp(field,SHORT_FIELD_LAT))
		res_len=snprintf(buf,RES_BUF_LEN,"%f",ip_data->latitude);
	else if(!strcmp(field,SHORT_FIELD_LON))
		res_len=snprintf(buf,RES_BUF_LEN,"%f",ip_data->longitude);
	else if(!strcmp(field,SHORT_FIELD_CONT))
		res_len=snprintf(buf,RES_BUF_LEN,"%s",ip_data->continent_code);
	else if(!strcmp(field,SHORT_FIELD_CC))
		res_len=snprintf(buf,RES_BUF_LEN,"%s",ip_data->country_code);
	else if(!strcmp(field,SHORT_FIELD_REG))
		res_len=snprintf(buf,RES_BUF_LEN,"%s",ip_data->region);
	else if(!strcmp(field,SHORT_FIELD_CITY))
		res_len=snprintf(buf,RES_BUF_LEN,"%s",ip_data->city);
	else if(!strcmp(field,SHORT_FIELD_PC))
		res_len=snprintf(buf,RES_BUF_LEN,"%s",ip_data->postal_code);
	else if(!strcmp(field,SHORT_FIELD_DMA))
		res_len=snprintf(buf,RES_BUF_LEN,"%d",ip_data->dma_code);
	else if(!strcmp(field,SHORT_FIELD_AC))
		res_len=snprintf(buf,RES_BUF_LEN,"%d",ip_data->area_code);
	else if(!strcmp(field,SHORT_FIELD_RN))
		res_len=snprintf( buf,RES_BUF_LEN,"%s",
			GeoIP_region_name_by_code(ip_data->country_code, ip_data->region));
	else if(!strcmp(field,SHORT_FIELD_TZ))
		res_len=snprintf(buf,RES_BUF_LEN,"%s",
			GeoIP_time_zone_by_country_and_region(ip_data->country_code,
													ip_data->region));
	else {
		LM_ERR("unknown field:'%s'\n",field);
		return -1;
	}

	return res_len;
}

#endif