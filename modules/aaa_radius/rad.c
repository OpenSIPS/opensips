/*
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
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
 * History
 * --------
 * 2009-07-20    First version (Irina Stanescu)
 * 2009-08-13 	 Second version (Irina Stanescu) - extract_avp added
 */

/*
 * This is the Radius implementation for the generic AAA Interface.
 */

#ifdef FREERADIUS
	#include <freeradius-client.h>
#else
	#ifdef RADCLI
		#include <radcli/radcli.h>
	#else
		#ifdef RADIUSCLIENT
			#include <radiusclient-ng.h>
		#endif
	#endif
#endif

#ifndef REJECT_RC
	#define REJECT_RC 2
#endif

#include "../../aaa/aaa.h"
#include "../../config.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "rad.h"
#include "../../ut.h"
#include "../../usr_avp.h"
#include "../../resolve.h"

/**
 * this function is removed from current versions
 * of FREERADIUS-CLIENT and RADCLI because it only offers
 * support for IPv4
 * but since the whole code is built around IPv4 we will
 * implement it only for IPv4 usage
 */
#ifdef RADCLI
uint32_t rc_get_ipaddr (char *host)
{
	const struct hostent* he;
	struct in_addr** addr_list;

	he=resolvehost(host, 0/*do test if is ip*/);

	/* FIXME the function is not for IPV6 */
	addr_list = (struct in_addr **)he->h_addr_list;
	if (addr_list[0])
		return addr_list[0]->s_addr;

	return 0;

}
#endif



/*
	Radius implementation for the init_prot callback

	For Radius, initialization consists of:
	- the url is parsed and a configuration structure is obtained
	- the rest field from the configuration structure is, for the radius
	module, a string for the path of the radius configuration file
	- obtain the connection handle
	- initialize the dictionary

	For Radius, the aaa_conn is actually the rc_handle resulted by reading
	the Radius configuration file.
 */
aaa_conn* rad_init_prot(str* aaa_url) {

	rc_handle *rh;
	aaa_prot_config cfg;

	if (!aaa_url) {
		LM_ERR("null aaa url \n");
		return NULL;
	}

	if (aaa_parse_url(aaa_url, &cfg)) {
		LM_ERR("aaa parse url error\n");
		return NULL;
	}

	if (!(rh = rc_read_config((char*)(cfg.rest)))) {
		LM_ERR("failed to open radius config file: %s\n", (char*)(cfg.rest));
		return NULL;
	}

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary"))) {
		LM_ERR("failed to read radius dictionary\n");
		return NULL;
	}

	return rh;
}


/*
	Radius implementation for the create_aaa_message callback
 */
aaa_message* rad_create_message(aaa_conn* rh, int flag) {

	aaa_message* message;

	if (!rh) {
		LM_ERR("invalid aaa connection argument\n");
		return NULL;
	}

	if (flag != AAA_AUTH && flag != AAA_ACCT) {
		LM_ERR("invalid flag\n");
		return NULL;
	}

	message = (aaa_message*) pkg_malloc (sizeof(aaa_message));

	if (!message) {
		LM_ERR("no pkg memory left \n");
		return NULL;
	}

	message->type = flag;
	message->avpair = NULL;
	message->last_found = NULL;

	return message;
}


/*
	Radius implementation for the destroy_aaa_message callback
 */
int rad_destroy_message(aaa_conn* rh, aaa_message* message) {

	if (!rh || ! message) {
		LM_ERR("invalid arguments\n");
		return -1;
	}

 	rc_avpair_free((VALUE_PAIR*) message->avpair);
	pkg_free(message);
	return 0;
}


/*
	Exctracts and generates AVPs from the Radius reply
 */
int extract_avp(VALUE_PAIR* vp) {
	static str names, values;
	int name;
	unsigned int r;
	char *p;
	char *end;
	int_str value;
	unsigned short flags = 0;

	/* empty? */
	if (vp->lvalue == 0)
		return -1;

	p = vp->strvalue;
	end = vp->strvalue + vp->lvalue;

	/* get name */
	if (*p == '#') {
		/* name is always a string */
		++p;
	}
	names.s = p;

	names.len = 0;
	while (p < end && *p != ':' && *p != '#')
		p++;

	if (names.s == p || p == end) {
		LM_ERR("empty AVP name\n");
		return -1;
	}
	names.len = p - names.s;

	/* get value */
	if (*p != '#') {
		/* string value */
		flags |= AVP_VAL_STR;
	}

	values.s = ++p;
	values.len = end-values.s;
	if (values.len == 0) {
		LM_ERR("empty AVP value\n");
		return -1;
	}

	if (!(flags&AVP_VAL_STR)) {
		/* convert value to integer */
		if (str2int(&values,&r) != 0) {
			LM_ERR("invalid AVP numrical value '%.*s'\n", values.len,values.s);
			return -1;
		}
		value.n = (int)r;
	} else
		value.s = values;

	name = get_avp_id(&names);
	if (name < 0) {
		LM_ERR("cannot get AVP id (%.*s)\n", names.len, names.s);
		return -1;
	}
	if (add_avp( flags, name, value) < 0) {
		LM_ERR("unable to create a new AVP\n");
		return -1;
	} else {
		LM_DBG("AVP '%.*s'='%.*s'/%d has been added\n",
			names.len, names.s,
			(flags&AVP_VAL_STR)?value.s.len:4,
			(flags&AVP_VAL_STR)?value.s.s:"null",
			(flags&AVP_VAL_STR)?0:value.n );
	}


	return 0;
}


/*
	Radius implementation for the send_message callback
 */
int rad_send_message(aaa_conn* rh, aaa_message* request, aaa_message** reply) {
	char msg[4096];
	VALUE_PAIR *vp;
 	DICT_ATTR *attr;
	int result;

	if (!rh) {
		LM_ERR("invalid aaa connection argument\n");
		return -1;
	}

	if (!request) {
		LM_ERR("invalid argument\n");
		return -1;
	}

	if (request->type == AAA_AUTH) {

		*reply = (aaa_message*) pkg_malloc (sizeof(aaa_message));

		if (!(*reply)) {
			LM_ERR("no pkg memory left \n");
			return -1;
		}

		(*reply)->type = AAA_RECV;
		(*reply)->avpair = NULL;
		(*reply)->last_found = NULL;

		result = rc_auth(rh, SIP_PORT, (VALUE_PAIR*) request->avpair,
						(VALUE_PAIR**)(void*)&(*reply)->avpair, msg);

		if (result == OK_RC) {
			attr = rc_dict_findattr(rh, "SIP-AVP");
			if (attr) {
				vp = (*reply)->avpair;
				for(; (vp = rc_avpair_get(vp, attr->value, 0)); vp = vp->next)
					if (extract_avp(vp)) {
						LM_ERR("extract_avp failed\n");
						return -1;
					}
				return 0;
			} else {
				LM_ERR("SIP-AVP was not found in the radius dictionary\n");
				return -1;
			}
		} else if (result == REJECT_RC) {
			LM_DBG("rc_auth function succeeded with result REJECT_RC\n");
			return result;
		} else {
			LM_ERR("rc_auth function failed\n");
			return -1;
		}
	}

	if (request->type == AAA_ACCT) {
			return rc_acct(rh, SIP_PORT, (VALUE_PAIR*) request->avpair);
	}

	LM_ERR("send message failure\n");
	return -1;
}


/*
	Radius implementation for the dictionary_find callback

	The return value is:
	0, if the name is found
	1, if the name isn't found
	-1, if an error occurred
 */
int rad_find(aaa_conn* rh, aaa_map *map, int flag) {

	DICT_ATTR *attr_result;
	DICT_VALUE *val_result;
	DICT_VENDOR *vend_result;

	if (!rh) {
		LM_ERR("invalid aaa connection argument\n");
		return -1;
	}

	if (!map) {
		LM_ERR("invalid argument\n");
		return -1;
	}

	switch (flag) {
		case AAA_DICT_FIND_VAL:
			val_result = rc_dict_findval(rh, map->name);
			if (val_result) {
				map->value = val_result->value;
				return 0;
			}
			/* not found */
			return -1;
		case AAA_DICT_FIND_ATTR:
			attr_result = rc_dict_findattr(rh, map->name);
			if (attr_result) {
				map->value = attr_result->value;
				map->type = attr_result->type;
				return 0;
			}

			/* not found */
			return -1;
		case AAA_DICT_FIND_VEND:
			vend_result = rc_dict_findvend(rh, map->name);
			if (vend_result) {
				map->value = vend_result->vendorpec;
				return 0;
			}

			/* not found */
			return -1;
	}

	LM_ERR("failure\n");
	return -1;
}


/*
	Radius implementation for the avp_get callback

	The last parameter specifies the type of search in the AVPs list.
	If the flag is AAA_GET_FROM_CURRENT the search is made relative to the
	last_found field in the aaa_message structure.
  */
int rad_avp_get(aaa_conn* rh, aaa_message* message, aaa_map* attribute,
					void** value, int* val_length, int flag) {

	VALUE_PAIR* vp = NULL;

	if (!rh) {
		LM_ERR("invalid aaa connection argument\n");
		return -1;
	}

	if (!message || !attribute || !value){
		LM_ERR("invalid argument\n");
		return -1;
	}

	if (flag != AAA_GET_FROM_START && flag != AAA_GET_FROM_CURRENT) {
		LM_CRIT("bug - no flag set for rad_avp_get\n");
		return -1;
	}

	if (flag == AAA_GET_FROM_START) {
		vp = (VALUE_PAIR*) message->avpair;
		vp = rc_avpair_get(vp, attribute->value, 0);
	}

	if (flag == AAA_GET_FROM_CURRENT) {
		if (!message->last_found) {
			vp = (VALUE_PAIR*) message->avpair;
			vp = rc_avpair_get(vp, attribute->value, 0);
		} else {
			vp = (VALUE_PAIR*) message->last_found;
			vp = rc_avpair_get(vp->next, attribute->value, 0);
		}
	}

	if (vp) {
		switch (vp->type) {
			case PW_TYPE_STRING:
				*value = &vp->strvalue;
				*val_length = vp->lvalue;
				break;
			case PW_TYPE_INTEGER:
			case PW_TYPE_IPADDR:
			case PW_TYPE_DATE:
				*value = &vp->lvalue;
				*val_length = 4;
				break;
			default:
				LM_ERR("type unknown\n");
				return -1;
		}

		message->last_found = vp;
		return 0;
	} else {
		*value = NULL;
		*val_length = 0;
		message->last_found = message->avpair;
		return -1;
	}

	return 0;
}


/*
	Radius implementation for the avp_add callback
 */
int rad_avp_add(aaa_conn* rh, aaa_message* message, aaa_map* name, void* value,
					int val_length, int vendor)
{
	uint32_t int4_val;
	str s;

	if (!rh) {
		LM_ERR("invalid aaa connection argument\n");
		return -1;
	}

	if (!message) {
		LM_ERR("invalid message argument\n");
		return -1;
	}

	if (!name) {
		LM_ERR("invalid name argument\n");
		return -1;
	}

	if (!value) {
		LM_ERR("invalid value argument\n");
		return -1;
	}

	if (vendor)
		vendor = VENDOR(vendor);

	/* check if this might be a string, we might have to do some conversions */
	if (val_length > -1) {
		if (name->type == PW_TYPE_IPADDR) {
			char ipstr[val_length + 1];
			memcpy( ipstr, value, val_length);
			ipstr[val_length] = 0;
			int4_val = rc_get_ipaddr((char*)&ipstr);
			LM_DBG("detected TYPE_IPADDR attribute %s = %s (%u)\n",
				name->name, ipstr, (unsigned int)int4_val);
			value = (void *)&int4_val;
			val_length = -1;
		} else if (name->type == PW_TYPE_INTEGER) {
			LM_DBG("detected TYPE_INTEGER attribute %s = %s\n",
				name->name, (char*)value);
			s.s = (char*)value;
			s.len = val_length;
			if (str2int( &s, (unsigned int*)(void*)&int4_val) != 0 ) {
				LM_ERR("error converting string to integer\n");
				return -1;
			}
			value = (void*)&int4_val;
			val_length = -1;
		}
	}

	if (rc_avpair_add (rh, (VALUE_PAIR**)(void*)&message->avpair, name->value,
	value, val_length, vendor)) {
		return 0;
	}

	LM_ERR("failure\n");
	return -1;
}
