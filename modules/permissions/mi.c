/*
 * Permissions MI functions
 *
 * Copyright (C) 2006 Juha Heinanen
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
 * History:
 * --------
 *  2006-10-16  created (juhe)
 */


#include "../../dprint.h"
#include "address.h"
#include "hash.h"
#include "mi.h"
#include "permissions.h"


/*
 * MI function to reload address table
 */
mi_response_t *mi_address_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct pm_part_struct *it;
	char errbuf[100] = "failed to reload partition ";
	int errlen = strlen(errbuf);

	for (it=get_part_structs(); it; it = it->next) {
		if (it->hash_table == NULL)
			continue;

		sprintf(errbuf + errlen, " %.*s!", it->name.len, it->name.s);
		LM_DBG("trying to reload address table for %.*s\n",
									it->name.len, it->name.s);
		if (reload_address_table(it) != 1)
			return init_mi_error( 400, MI_SSTR(errbuf));
	}

	return init_mi_result_ok();
}

mi_response_t *mi_address_reload_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct pm_part_struct *ps;
	str partn;

	if (get_mi_string_param(params, "partition", &partn.s, &partn.len) < 0)
		return init_mi_param_error();

	ps = get_part_struct(&partn);
	if (ps == NULL)
		return init_mi_error( 400, MI_SSTR("Trusted table reload failed"));
	if (ps->hash_table == NULL)
		return init_mi_result_ok();

	LM_INFO("trying to reload address table for %.*s\n",
									ps->name.len, ps->name.s);
	if (reload_address_table(ps) == 1)
		return init_mi_result_ok();
	else
		return init_mi_error(500, MI_SSTR("Failed to reolad"));
}

/*
 * MI function to print address entries from current hash table
 */
mi_response_t *mi_address_dump(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct pm_part_struct *it;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *parts_arr, *part_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	parts_arr = add_mi_array(resp_obj, MI_SSTR("Partitions"));
	if (!parts_arr)
		goto error;

	for (it=get_part_structs(); it; it = it->next) {
		if (it->hash_table == NULL)
			continue;

		part_item = add_mi_object(parts_arr, NULL, 0);
		if (!part_item)
			goto error;

		if (add_mi_string(part_item, MI_SSTR("name"),
			it->name.s, it->name.len) < 0)
			goto error;

		if(hash_mi_print(*it->hash_table, part_item, it)< 0)
			goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_address_dump_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct pm_part_struct *ps;
	str partn;
	mi_response_t *resp;
	mi_item_t *resp_obj;

	if (get_mi_string_param(params, "partition", &partn.s, &partn.len) < 0)
		return init_mi_param_error();

	ps = get_part_struct(&partn);
	if (ps == NULL)
		return init_mi_error(404, MI_SSTR("No such partition"));

	if (ps->hash_table == NULL)
		return init_mi_result_ok();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string(resp_obj, MI_SSTR("part"),ps->name.s, ps->name.len) < 0)
		goto error;

	if(hash_mi_print(*ps->hash_table, resp_obj, ps)< 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

#define MAX_FILE_LEN 128

/*
 * MI function to make allow_uri query.
 */
mi_response_t *mi_allow_uri(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
    str basename_s, uri_s, contact_s;
    char basename[MAX_FILE_LEN + 1];
    char uri[MAX_URI_SIZE + 1], contact[MAX_URI_SIZE + 1];
    unsigned int allow_suffix_len;

    if (get_mi_string_param(params, "basename",
    	&basename_s.s, &basename_s.len) < 0)
		return init_mi_param_error();
    if (basename_s.s == NULL || basename_s.len == 0)
		return init_mi_error(404, MI_SSTR("Basename is empty"));

    allow_suffix_len = strlen(allow_suffix);
    if (basename_s.len + allow_suffix_len + 1 > MAX_FILE_LEN)
		return init_mi_error(404, MI_SSTR("Basename is too long"));
    memcpy(basename, basename_s.s, basename_s.len);
    memcpy(basename + basename_s.len, allow_suffix, allow_suffix_len);
    basename[basename_s.len + allow_suffix_len] = 0;

	if (get_mi_string_param(params, "uri",
    	&uri_s.s, &uri_s.len) < 0)
		return init_mi_param_error();
    if (uri_s.s == NULL || uri_s.len == 0)
		return init_mi_error(404, MI_SSTR("Basename is empty"));    
    
    if (uri_s.len > MAX_URI_SIZE)
		return init_mi_error(404, MI_SSTR("URI is too long"));
    memcpy(uri, uri_s.s, uri_s.len);
    uri[uri_s.len] = 0;

    if (get_mi_string_param(params, "contact",
    	&contact_s.s, &contact_s.len) < 0)
		return init_mi_param_error();
    if (contact_s.s == NULL || contact_s.len == 0)
		return init_mi_error(404, MI_SSTR("Basename is empty"));    

    if (contact_s.len > MAX_URI_SIZE)
		return init_mi_error(404, MI_SSTR("Contact is too long"));
    memcpy(contact, contact_s.s, contact_s.len);
    contact[contact_s.len] = 0;

    if (allow_test(basename, uri, contact) == 1) {
	return init_mi_result_ok();
    } else {
	return init_mi_error(403, MI_SSTR("Forbidden"));
    }
}

/*
 * MI function to print subnets from current subnet table
 */
mi_response_t *mi_subnet_dump(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct pm_part_struct *it;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *parts_arr, *part_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	parts_arr = add_mi_array(resp_obj, MI_SSTR("Partitions"));
	if (!parts_arr)
		goto error;

	for (it=get_part_structs(); it; it = it->next) {
		if (it->subnet_table == NULL)
			continue;

		part_item = add_mi_object(parts_arr, NULL, 0);
		if (!part_item)
			goto error;

		if (add_mi_string(part_item, MI_SSTR("name"),
			it->name.s, it->name.len) < 0)
			goto error;

		if (subnet_table_mi_print(*it->subnet_table, part_item, it) <  0)
			goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_subnet_dump_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str partn;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	struct pm_part_struct *ps;

	if (get_mi_string_param(params, "partition", &partn.s, &partn.len) < 0)
		return init_mi_param_error();

	ps = get_part_struct(&partn);
	if (ps == NULL)
		return init_mi_error(404, MI_SSTR("No such partition"));
	
	if (ps->subnet_table == NULL)
		return init_mi_result_ok();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string(resp_obj, MI_SSTR("part"),ps->name.s, ps->name.len) < 0)
		goto error;

	if (subnet_table_mi_print(*ps->subnet_table, resp_obj, ps) <  0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return 0;
}
