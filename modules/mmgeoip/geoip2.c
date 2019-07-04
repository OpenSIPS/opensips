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

#ifndef GEOIP

#include <string.h>
#include <errno.h>
#include "../../lib/csv.h"
#include "../../dprint.h"

#include "mmgeoip.h"
#include "geoip2.h"

MMDB_s mmdb;

int geoip2_open_db(void)
{
	int rc;

	if ((rc = MMDB_open(MMG_city_db_path.s, MMDB_MODE_MMAP, &mmdb)) != MMDB_SUCCESS) {
		if (rc == MMDB_IO_ERROR)
			LM_ERR("IO error: %s\n", strerror(errno));
		LM_ERR("Unable to open City DB at path '%.*s'\n",
				(int)strlen(MMG_city_db_path.s),MMG_city_db_path.s);

		return -1;
	}

	return 0;
}

void geoip2_close_db(void)
{
	MMDB_close(&mmdb);
}

lookup_res_t geoip2_lookup_ip(char *ip, int *status)
{
	int gai_error, mmdb_error;

	MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip, &gai_error,
		&mmdb_error);

	if (gai_error) {
		LM_ERR("getaddrinfo() error\n");
		goto error;
	}
	if (mmdb_error != MMDB_SUCCESS) {
		LM_ERR("libmaxminddb error: %s\n", MMDB_strerror(mmdb_error));
		goto error;
	}

	if (!result.found_entry) {
		LM_DBG("IP: %s not found\n", ip);
		goto error;
	}

	*status = 0;
	return result;

error:
	*status = -1;
	return result;
}

char *check_short_fields(char *field)
{
	if(!strcmp(field,SHORT_FIELD_LAT))
		return "location.latitude";
	else if(!strcmp(field,SHORT_FIELD_LON))
		return "location.longitude";
	else if(!strcmp(field,SHORT_FIELD_CONT))
		return "continent.names.en";
	else if(!strcmp(field,SHORT_FIELD_CC))
		return "country.iso_code";
	else if(!strcmp(field,SHORT_FIELD_REG))
		return "subdivisions.0.iso_code";
	else if(!strcmp(field,SHORT_FIELD_CITY))
		return "city.names.en";
	else if(!strcmp(field,SHORT_FIELD_PC))
		return "postal.code";
	else if(!strcmp(field,SHORT_FIELD_DMA))
		return "location.metro_code";
	else if(!strcmp(field,SHORT_FIELD_RN))
		return "subdivisions.0.names.en";
	else if(!strcmp(field,SHORT_FIELD_TZ))
		return "location.time_zone";

	return NULL;
}

int geoip2_get_field(lookup_res_t ip_data, char *field, char *buf)
{
	char *path_arr[MAX_PATH_DEPTH+1];
	int i = 0;
	csv_record *path_list, *it;
	str field_str;
	MMDB_entry_data_s entry_data;
	int status;
	int len = 0;

	field_str.s = check_short_fields(field);
	if (!field_str.s)
		field_str.s = field;
	field_str.len = strlen(field_str.s);

	path_list = __parse_csv_record(&field_str, CSV_DUP_FIELDS, FIELD_PATH_SEP);
	if (!path_list) {
		LM_ERR("bad field:'%s'\n", field);
		return -1;
	}

	for (it = path_list; it; it = it->next) {
		if (i == MAX_PATH_DEPTH) {
			LM_ERR("unknown field:'%s'\n", field);
			goto error;
		}
		path_arr[i++] = it->s.s;
	}
	path_arr[i] = NULL;

	status = MMDB_aget_value(&ip_data.entry, &entry_data,
		(const char *const *const)path_arr);
	if (status != MMDB_SUCCESS) {
		LM_ERR("Failed to get IP data field: %s\n", field);
		goto error;
	}
	if (!entry_data.has_data) {
		LM_ERR("No data for field:'%s'\n", field);
		goto error;
	}

	switch (entry_data.type) {
	case MMDB_DATA_TYPE_UTF8_STRING:
		if (entry_data.data_size > RES_BUF_LEN) {
			LM_ERR("string field to big\n");
			goto error;
		}
		memcpy(buf, entry_data.utf8_string, entry_data.data_size);
		len = entry_data.data_size;
		break;
	case MMDB_DATA_TYPE_DOUBLE:
		len = sprintf(buf, "%f", entry_data.double_value);
		break;
	case MMDB_DATA_TYPE_BYTES:
		if (2*entry_data.data_size > RES_BUF_LEN) {
			LM_ERR("byte field to big\n");
			goto error;
		}
		for (i = 0; i < entry_data.data_size; i++)
			sprintf(buf+2*i, "%x", entry_data.bytes[i]);
		len = 2*entry_data.data_size;
		break;
	case MMDB_DATA_TYPE_UINT16:
		len = sprintf(buf, "%hu", entry_data.uint16);
		break;
	case MMDB_DATA_TYPE_UINT32:
		len = sprintf(buf, "%u", entry_data.uint32);
		break;
	case MMDB_DATA_TYPE_INT32:
		len = sprintf(buf, "%d", entry_data.int32);
		break;
	case MMDB_DATA_TYPE_UINT64:
		len = sprintf(buf, "%lu", entry_data.uint64);
		break;
	case MMDB_DATA_TYPE_BOOLEAN:
		if (entry_data.boolean)
			len = sprintf(buf, "true");
		else
			len = sprintf(buf, "false");
		break;
	case MMDB_DATA_TYPE_FLOAT:
		len = sprintf(buf, "%f", entry_data.float_value);
		break;
	default:
		LM_ERR("Unsupported data type for field: '%s'\n", field);
		goto error;
	}

	free_csv_record(path_list);
	return len;

error:
	free_csv_record(path_list);
	return -1;
}

#endif
