/**
 * Copyright (C) 2021 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <freeDiameter/extension.h>

#include "../../ut.h"
#include "../../lib/list.h"
#include "../../lib/hash.h"

#include "aaa_impl.h"
#include "peer.h"

struct _acc_dict acc_dict;

/* Workaround until we find a way of looking up a single enum val in fD */
static gen_hash_t *osips_enumvals;

struct local_rules_definition {
	char 			*avp_name;
	enum rule_position	position;
	int 			min;
	int			max;
};

#define RULE_ORDER( _position ) ((((_position) == RULE_FIXED_HEAD) || ((_position) == RULE_FIXED_TAIL)) ? 1 : 0 )
#define PARSE_loc_rules( _rulearray, _parent) {								\
	int __ar;											\
	for (__ar=0; __ar < sizeof(_rulearray) / sizeof((_rulearray)[0]); __ar++) {			\
		struct dict_rule_data __data = { NULL, 							\
			(_rulearray)[__ar].position,							\
			0, 										\
			(_rulearray)[__ar].min,								\
			(_rulearray)[__ar].max};							\
		__data.rule_order = RULE_ORDER(__data.rule_position);					\
		FD_CHECK(fd_dict_search( 								\
			fd_g_config->cnf_dict,								\
			DICT_AVP, 									\
			AVP_BY_NAME, 									\
			(_rulearray)[__ar].avp_name, 							\
			&__data.rule_avp, 0 ) );							\
		if ( !__data.rule_avp ) {								\
			LM_ERR("AVP not found: '%s'\n", (_rulearray)[__ar].avp_name );		\
			return -1;									\
		}											\
		FD_CHECK_dict_new(DICT_RULE, &__data, _parent, NULL);	\
	} \
}

static int os_cb(struct msg ** msg, struct avp * avp, struct session * sess, void * data, enum disp_action * act)
{
	struct msg_hdr *hdr = NULL;

	FD_CHECK(fd_msg_hdr(*msg, &hdr));

	if (hdr->msg_flags & CMD_FLAG_REQUEST) {
		/* we received an ACR message (??), just discard it */
		FD_CHECK(fd_msg_free(*msg));
		*msg = NULL;
		return 0;
	}

	if (hdr->msg_flags & CMD_FLAG_ERROR) {
		LM_ERR("XXXXXXXXXXX failed to send msg?!\n");
		FD_CHECK(fd_msg_free(*msg));
		*msg = NULL;
		return 0;
	}

	/* we received an ACA reply! */

	LM_ERR("XXXXXXXXXXX wooot?!\n");
	FD_CHECK(fd_msg_free(*msg));
	*msg = NULL;

	return 0;
}


/* entry point: register handler for Base Accounting messages in the daemon */
static int tac_entry(void)
{
	struct disp_when data;

	memset(&data, 0, sizeof data);

	/* Initialize the dictionary objects we use */
	fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION,
		APPLICATION_BY_NAME, "Diameter Base Accounting", &data.app, ENOENT);

	/* Register the dispatch callback */
	FD_CHECK(fd_disp_register(os_cb, DISP_HOW_APPID, &data, NULL, NULL));

	/* Advertise support for the Diameter Base Accounting app in the peer */
	FD_CHECK(fd_disp_app_support(data.app, NULL, 0, 1 ));

	return 0;
}


static int dm_store_enumval(const char *name, int value)
{
	unsigned int e;
	int *val_holder;
	const str *_name = _str(name);

	e = hash_entry(osips_enumvals, *_name);
	val_holder = (int *)hash_get(osips_enumvals, e, *_name);
	if (!val_holder) {
		LM_ERR("oom\n");
		return -1;
	}

	*val_holder = value;
	return 0;
}


static int dm_register_radius_avps(void)
{
	int i;

	/* Service-Type, RFC 2865 */
	{
		/*
			The Service-Type AVP (AVP Code 6) indicates the type of service the
			user has requested, or the type of service to be provided.  It MAY
			be used in both Access-Request and Access-Accept packets.  A NAS is
			not required to implement all of these service types, and MUST
			treat unknown or unsupported Service-Types as though an
			Access-Reject had been received instead.
		*/
		struct dict_object 	* 	type;
		struct dict_type_data 		tdata = {
			AVP_TYPE_INTEGER32, "Enumerated(Service-Type)",
			NULL, NULL, NULL, NULL, NULL };
		struct dict_enumval_data 	vals[] = {
			{ "Call-Check",				{ .i32 = 10 }},
			{ "Group-Check", 			{ .i32 = 12 }},
			{ "Sip-Session", 			{ .i32 = 15 }},
			{ "Sip-Verify-Destination",	{ .i32 = 21 }},
			{ "Sip-Verify-Source",		{ .i32 = 22 }},
			{ "Sip-Caller-AVPs", 		{ .i32 = 30 }},
			{ "Sip-Callee-AVPs", 		{ .i32 = 31 }},
			{ NULL, {.i32 = 0} },
		};

		struct dict_avp_data 		data = {
				6,				/* Code */
				0, 				/* Vendor */
				"Service-Type",	/* Name */
				AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		/* Fixed flag values */
				AVP_TYPE_INTEGER32 		/* base type of data */
				};

		/* Create the Enumerated type, and then the AVP */
		FD_CHECK_dict_new(DICT_TYPE, &tdata, NULL, &type);

		for (i = 0; vals[i].enum_name; i++) {
			FD_CHECK_dict_new(DICT_ENUMVAL, &vals[i], type, NULL);
			FD_CHECK(dm_store_enumval(vals[i].enum_name, vals[i].enum_value.i32));
		}

		FD_CHECK_dict_new(DICT_AVP, &data, type, NULL);
	}

	/* Acct-Status-Type, RFC 2866 */
	{
		/*
			The Acct-Status-Type AVP (AVP Code 40) indicates whether this
			Accounting-Request marks the beginning of the user service (Start)
			or the end (Stop).

			It MAY be used by the client to mark the start of accounting (for
			example, upon booting) by specifying Accounting-On and to mark the
			end of accounting (for example, just before a scheduled reboot) by
			specifying Accounting-Off.
		*/
		struct dict_object 	* 	type;
		struct dict_type_data 		tdata = {
			AVP_TYPE_INTEGER32, "Enumerated(Acct-Status-Type)",
			NULL, NULL, NULL, NULL, NULL };
		struct dict_enumval_data 	vals[] = {
			{ "Start",	{ .i32 = 1 }},
			{ "Stop", 	{ .i32 = 2 }},
			{ "Alive", 	{ .i32 = 3 }},
			{ "Failed",	{ .i32 = 15 }},
			{ NULL, {.i32 = 0} },
		};

		struct dict_avp_data 		data = {
				40,					/* Code */
				0, 					/* Vendor */
				"Acct-Status-Type",	/* Name */
				AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		/* Fixed flag values */
				AVP_TYPE_INTEGER32 		/* base type of data */
				};

		/* Create the Enumerated type, and then the AVP */
		FD_CHECK_dict_new(DICT_TYPE, &tdata, NULL, &type);

		for (i = 0; vals[i].enum_name; i++) {
			FD_CHECK_dict_new(DICT_ENUMVAL, &vals[i], type, NULL);
			FD_CHECK(dm_store_enumval(vals[i].enum_name, vals[i].enum_value.i32));
		}

		FD_CHECK_dict_new(DICT_AVP, &data, type, NULL);
	}

	return 0;
}


static int dm_register_custom_sip_avps(void)
{
	struct dict_object * UTF8String_type;
	int i;

	FD_CHECK_dict_search(DICT_TYPE, TYPE_BY_NAME, "UTF8String", &UTF8String_type);

	/* Sip-Method */
	{
		/*
			The Sip-Method AVP (AVP Code 204) is of type Enumerated, and
			its values are bitmasks for each SIP method, per the
			"enum request_method" structure in the OpenSIPS C code
		*/
		struct dict_object 	* 	type;
		struct dict_type_data 		tdata = {
			AVP_TYPE_INTEGER32, "Enumerated(Sip-Method)",
			NULL, NULL, NULL, NULL, NULL };
		struct dict_enumval_data 	vals[] = {
			{ "UNDEFINED", 	{ .i32 = 0 }},
			{ "INVITE", 	{ .i32 = 1 }},
			{ "CANCEL",		{ .i32 = 2 }},
			{ "ACK",		{ .i32 = 4 }},
			{ "BYE", 		{ .i32 = 8 }},
			{ "INFO",		{ .i32 = 15 }},
			{ "OPTIONS", 	{ .i32 = 32 }},
			{ "UPDATE", 	{ .i32 = 64 }},
			{ "REGISTER", 	{ .i32 = 128 }},
			{ "MESSAGE",	{ .i32 = 256 }},
			{ "SUBSCRIBE", 	{ .i32 = 512 }},
			{ "NOTIFY",		{ .i32 = 1024 }},
			{ "PRACK", 		{ .i32 = 2048 }},
			{ "REFER", 		{ .i32 = 4096 }},
			{ "PUBLISH", 	{ .i32 = 8192 }},
			{ "OTHER",		{ .i32 = 16384 }},
			{ NULL, {.i32 = 0} },
		};

		struct dict_avp_data 		data = {
				204, 				/* Code */
				0, 					/* Vendor */
				"Sip-Method",		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_INTEGER32 			/* base type of data */
				};

		/* Create the Enumerated type, and then the AVP */
		FD_CHECK_dict_new(DICT_TYPE, &tdata, NULL, &type);

		for (i = 0; vals[i].enum_name; i++) {
			FD_CHECK_dict_new(DICT_ENUMVAL, &vals[i], type, NULL);
			FD_CHECK(dm_store_enumval(vals[i].enum_name, vals[i].enum_value.i32));
		}

		FD_CHECK_dict_new(DICT_AVP, &data, type, NULL);
	}

	/* Sip-Response-Code */
	{
		/*
			The Sip-Method AVP (AVP Code 205) is of type Unsigned32, and
			represents the final status of the SIP transaction.
		*/
		struct dict_avp_data data = {
				205,					/* Code */
				0, 						/* Vendor */
				"Sip-Response-Code", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	/* Sip-From-Tag */
	{
		/*
			The Sip-From-Tag AVP (AVP Code 206) is of type UTF8String and
			represents the value of the SIP From header ";tag=" parameter
		*/
		struct dict_avp_data data = {
				206,				/* Code */
				0, 					/* Vendor */
				"Sip-From-Tag", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Sip-To-Tag */
	{
		/*
			The Sip-To-Tag AVP (AVP Code 207) is of type UTF8String and
			represents the value of the SIP To header ";tag=" parameter
		*/
		struct dict_avp_data data = {
				207,			/* Code */
				0, 				/* Vendor */
				"Sip-To-Tag", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Sip-Uri-User */
	{
		/*
			The Sip-Uri-User AVP (AVP Code 208) is of type UTF8String and
			represents the value of the Request-URI "user" production
		*/
		struct dict_avp_data data = {
				208,				/* Code */
				0, 					/* Vendor */
				"Sip-Uri-User", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Sip-Uri-Host */
	{
		/*
			The Sip-Uri-Host AVP (AVP Code 209) is of type UTF8String and
			represents the value of the Request-URI "host" production
		*/
		struct dict_avp_data data = {
				209,				/* Code */
				0, 					/* Vendor */
				"Sip-Uri-Host", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* SIP-AVP */
	{
		/*
			The SIP-AVP AVP (AVP Code 225) is of type UTF8String and
			represents a key/value mapping returned by the RADIUS server, to be
			automatically exported as an opensips.cfg $avp variable
		*/
		struct dict_avp_data data = {
				225,		/* Code */
				0, 			/* Vendor */
				"SIP-AVP", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	return 0;
}


static int dm_register_cdr_avps(void)
{
	/* Sip-Call-Duration */
	{
		/*
			The Sip-Call-Duration AVP (AVP Code 227) is of type Unsigned32 and
			represents the duration of the call in seconds, rounded up
		*/
		struct dict_avp_data data = {
				227, 					/* Code */
				0,						/* Vendor */
				"Sip-Call-Duration",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	/* Sip-Call-Setuptime */
	{
		/*
			The Sip-Call-Setuptime AVP (AVP Code 228) is of type Unsigned32 and
			represents the time required to set up the call (INVITE receipt vs.
			200 OK receipt), in seconds
		*/
		struct dict_avp_data data = {
				228, 					/* Code */
				0,						/* Vendor */
				"Sip-Call-Setuptime",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	/* Sip-Call-Created */
	{
		/*
			The Sip-Call-Created AVP (AVP Code 229) is of type Unsigned32 and
			represents the UNIX timestamp for the start of the call (time of
			the receipt of the 200 OK)
		*/
		struct dict_avp_data data = {
				229, 					/* Code */
				0,						/* Vendor */
				"Sip-Call-Created",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	/* Sip-Call-MSDuration */
	{
		/*
			The Sip-Call-MSDuration AVP (AVP Code 230) is of type Unsigned32
			and represents the duration of the call in milliseconds, rounded up
		*/
		struct dict_avp_data data = {
				230, 					/* Code */
				0,						/* Vendor */
				"Sip-Call-MSDuration",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	return 0;
}


/* all of these AVPs are included in the RADIUS AVP registry */
static int dm_register_digest_avps(void)
{
	struct dict_object *UTF8String_type;

	FD_CHECK_dict_search(DICT_TYPE, TYPE_BY_NAME, "UTF8String", &UTF8String_type);

	/* Digest-Response */
	{
		struct dict_avp_data data = {
				103, 				/* Code */
				0, 					/* Vendor */
				"Digest-Response", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Realm */
	{
		struct dict_avp_data data = {
				104, 				/* Code */
				0, 					/* Vendor */
				"Digest-Realm", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 	/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Nonce */
	{
		struct dict_avp_data data = {
				105, 				/* Code */
				0, 					/* Vendor */
				"Digest-Nonce", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Response-Auth */
	{
		struct dict_avp_data data = {
				106,					/* Code */
				0, 						/* Vendor */
				"Digest-Response-Auth",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Nextnonce */
	{
		struct dict_avp_data data = {
				107, 				/* Code */
				0, 					/* Vendor */
				"Digest-Nextnonce", /* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Method */
	{
		struct dict_avp_data data = {
				108, 				/* Code */
				0, 					/* Vendor */
				"Digest-Method", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-URI */
	{
		struct dict_avp_data data = {
				109, 				/* Code */
				0, 					/* Vendor */
				"Digest-URI", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Qop */
	{
		struct dict_avp_data data = {
				110,				/* Code */
				0, 					/* Vendor */
				"Digest-Qop", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Algorithm */
	{
		struct dict_avp_data data = {
				111, 				/* Code */
				0, 					/* Vendor */
				"Digest-Algorithm",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Entity-Body-Hash */
	{
		struct dict_avp_data data = {
				112,						/* Code */
				0, 							/* Vendor */
				"Digest-Entity-Body-Hash", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-CNonce */
	{
		struct dict_avp_data data = {
				113, 					/* Code */
				0, 					/* Vendor */
				"Digest-CNonce", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 			/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Nonce-Count */
	{
		struct dict_avp_data data = {
				114, 					/* Code */
				0,						/* Vendor */
				"Digest-Nonce-Count", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Username */
	{
		struct dict_avp_data data = {
				115, 				/* Code */
				0, 					/* Vendor */
				"Digest-Username", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Opaque */
	{
		struct dict_avp_data data = {
				116, 				/* Code */
				0, 					/* Vendor */
				"Digest-Opaque", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Auth-Param */
	{
		struct dict_avp_data data = {
				117,					/* Code */
				0, 						/* Vendor */
				"Digest-Auth-Param", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-AKA-Auts */
	{
		struct dict_avp_data data = {
				118, 				/* Code */
				0, 					/* Vendor */
				"Digest-AKA-Auts", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Domain */
	{
		struct dict_avp_data data = {
				119, 				/* Code */
				0, 					/* Vendor */
				"Digest-Domain", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Stale */
	{
		struct dict_avp_data data = {
				120, 				/* Code */
				0, 					/* Vendor */
				"Digest-Stale", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-HA1 */
	{
		struct dict_avp_data data = {
				121, 				/* Code */
				0, 					/* Vendor */
				"Digest-HA1", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* SIP-AOR */
	{
		struct dict_avp_data data = {
				122, 			/* Code */
				0, 				/* Vendor */
				"SIP-AOR", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	return 0;
}


static int dm_register_custom_vendors(void)
{
	struct dict_object *UTF8String_type;

	FD_CHECK_dict_search(DICT_TYPE, TYPE_BY_NAME, "UTF8String", &UTF8String_type);

	/* Cisco */
	{
		struct dict_vendor_data cisco_data = { 9, "Cisco" };
		FD_CHECK_dict_new(DICT_VENDOR, &cisco_data, NULL, NULL);
	}

	/* Cisco-AVPair */
	{
		struct dict_avp_data data = {
				1,				/* Code */
				9,				/* Vendor */
				"Cisco-AVPair", /* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	return 0;
}


/* Register the Diameter SIP Application (RFC 4740) commands, AVPs, etc. */
int dm_init_sip_application(void)
{
	struct dict_object *sip;
	struct dict_object * UTF8String_type;

	struct dict_application_data data =
		{ 	6, "Diameter Session Initiation Protocol (SIP) Application"	};
	FD_CHECK_dict_new(DICT_APPLICATION, &data, NULL, &sip);

	FD_CHECK_dict_search(DICT_TYPE, TYPE_BY_NAME, "UTF8String", &UTF8String_type);

	/* SIP-Server-URI */
	{
		/*
			The SIP-Server-URI AVP (AVP Code 371) is of type UTF8String.  This
			AVP contains a SIP or SIPS URI (as defined in RFC 3261 [RFC3261])
			that identifies a SIP server.
		*/
		struct dict_avp_data data = {
				369,				/* Code */
				0, 					/* Vendor */
				"SIP-Server-URI", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* SIP-Method */
	{
		/*
			The SIP-Method-AVP (AVP Code 393) is of type UTF8String and contains
			the method of the SIP request that triggered the Diameter message.
			The Diameter server MUST use this AVP solely for authorization of SIP
			requests, and MUST NOT use it to compute the Digest authentication.
			To compute the Digest authentication, the Diameter server MUST use
			the Digest-Method AVP instead.
		*/
		struct dict_avp_data data = {
				393, 			/* Code */
				0, 				/* Vendor */
				"SIP-Method", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* SIP-Number-Auth-Items */
	{
		/*
			The SIP-Number-Auth-Items AVP (AVP Code 382) is of type Unsigned32
			and indicates the number of authentication and/or authorization
			credentials that the Diameter server included in a Diameter message.

			When the AVP is present in a request, it indicates the number of
			SIP-Auth-Data-Items the Diameter client is requesting.  This can be
			used, for instance, when the SIP server is requesting several
			pre-calculated authentication credentials.  In the answer message,
			the SIP-Number-Auth-Items AVP indicates the actual number of items
			that the Diameter server included.
		*/
		struct dict_avp_data data = {
				382,						/* Code */
				0, 							/* Vendor */
				"SIP-Number-Auth-Items",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	/* SIP-Authentication-Scheme */
	{
		/*
			The SIP-Authentication-Scheme AVP (AVP Code 377) is of type
			Enumerated and indicates the authentication scheme used in the
			authentication of SIP services.  RFC 2617 identifies this value as an
			"auth-scheme" (see Section 1.2 of RFC 2617 [RFC2617]).  The only
			currently defined value is:

			o  DIGEST (0) to indicate HTTP Digest authentication as specified in
			RFC 2617 [RFC2617] Section 3.2.1.  Derivative work is also
			considered Digest authentication scheme, as long as the
			"auth-scheme" is identified as Digest in the SIP headers carrying
			the HTTP authentication.  This includes, e.g., the HTTP Digest
			authentication using AKA [RFC3310].

			Each HTTP Digest directive (parameter) is transported in a
			corresponding AVP, whose name follows the pattern Digest-*.  The
			Digest-* AVPs are RADIUS attributes imported from the RADIUS
			Extension for Digest Authentication [RFC4590] namespace, allowing a
			smooth transition between RADIUS and Diameter applications supporting
			SIP.  The Diameter SIP application goes a step further by grouping
			the Digest-* AVPs into the SIP-Authenticate, SIP-Authorization, and
			SIP-Authentication-Info grouped AVPs that correspond to the SIP WWW-
			Authenticate/Proxy-Authentication, Authorization/Proxy-Authorization,
			and Authentication-Info headers fields, respectively.

			Note: Due to the fact that HTTP Digest authentication [RFC2617] is
			the only mandatory authentication mechanism in SIP, this memo only
			provides support for HTTP Digest authentication and derivative
			work such as HTTP Digest authentication using AKA [RFC3310].
			Extensions to this memo can register new values and new AVPs to
			provide support for other authentication schemes or extensions to
			HTTP Digest authentication.

			Note: Although RFC 2617 [RFC2617] defines the Basic and Digest
			schemes for authenticating HTTP requests, RFC 3261 [RFC3261] only
			imports HTTP Digest as a mechanism to provide authentication in
			SIP.

			Due to syntactic requirements, HTTP Digest authentication has to
			escape quote characters in contents of HTTP Digest directives.  When
			translating directives into Digest-* AVPs, the Diameter client or
			server removes the surrounding quotes where present, as required by
			the syntax of the Digest-* attributes defined in the "RADIUS
			Extension for Digest Authentication" [RFC4590].

		*/
		#define enumval_def_u32( _val_, _str_ ) \
				{ _str_, 		{ .u32 = _val_ }}

		struct dict_object 	*type;
		struct dict_type_data 	 tdata = {
			AVP_TYPE_UNSIGNED32,	"Enumerated(SIP-Authentication-Scheme)",
				NULL, NULL, NULL, NULL, NULL};
		struct dict_enumval_data tvals[] = {
			enumval_def_u32( 0, "DIGEST")
		};
		struct dict_avp_data data = {
				377,							/* Code */
				0, 								/* Vendor */
				"SIP-Authentication-Scheme", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_UNSIGNED32			/* base type of data */
		};
		int i;
		/* Create the Enumerated type, enumerated values, and the AVP */
		FD_CHECK_dict_new(DICT_TYPE, &tdata, NULL, &type);
		for (i = 0; i < sizeof(tvals) / sizeof(tvals[0]); i++) {
			FD_CHECK_dict_new(DICT_ENUMVAL, &tvals[i], type, NULL);
		}
		FD_CHECK_dict_new(DICT_AVP, &data, type, NULL);
	}

	/* SIP-Item-Number */
	{
		/*
			The SIP-Item-Number (AVP Code 378) is of type Unsigned32 and is
			included in a SIP-Auth-Data-Item grouped AVP in circumstances where
			there are multiple occurrences of SIP-Auth-Data-Item AVPs and the
			order of processing is relevant.  The AVP indicates the order in
			which the Grouped SIP-Auth-Data-Item should be processed.  Lower
			values of the SIP-Item-Number AVP indicate that the whole
			SIP-Auth-Data-Item SHOULD be processed before other
			SIP-Auth-Data-Item AVPs that contain higher values in the
			SIP-Item-Number AVP.
		*/
		struct dict_avp_data data = {
				378, 					/* Code */
				0, 					/* Vendor */
				"SIP-Item-Number", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 			/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	/* SIP-Authorization */
	{
		/*
			The SIP-Authorization AVP (AVP Code 380) is of type Grouped and
			contains a reconstruction of either the SIP Authorization or
			Proxy-Authorization header fields specified in RFC 2617 [RFC2617] for
			the HTTP Digest authentication scheme.

			The SIP-Authorization AVP is defined as follows (per the
			grouped-avp-def of RFC 3588 [RFC3588]):

			SIP-Authorization ::= < AVP Header: 380 >
					    { Digest-Username }
					    { Digest-Realm }
					    { Digest-Nonce }
					    { Digest-URI }
					    { Digest-Response }
					    [ Digest-Algorithm ]
					    [ Digest-CNonce ]
					    [ Digest-Opaque ]
					    [ Digest-Qop ]
					    [ Digest-Nonce-Count ]
					    [ Digest-Method]
					    [ Digest-Entity-Body-Hash ]
					  * [ Digest-Auth-Param ]
					  * [ AVP ]
		*/
		struct dict_object *avp;
		struct dict_avp_data data = {
				380, 					/* Code */
				0,						/* Vendor */
				"SIP-Authorization", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_GROUPED 			/* base type of data */
				};
		struct local_rules_definition rules[] = {
			{ "Digest-Username",	RULE_REQUIRED, -1, 1 },
			{ "Digest-Realm",		RULE_REQUIRED, -1, 1 },
			{ "Digest-Nonce",		RULE_REQUIRED, -1, 1 },
			{ "Digest-URI",			RULE_REQUIRED, -1, 1 },
			{ "Digest-Response",	RULE_REQUIRED, -1, 1 },
			{ "Digest-Algorithm",	RULE_OPTIONAL, -1, 1 },
			{ "Digest-CNonce",		RULE_OPTIONAL, -1, 1 },
			{ "Digest-Opaque",		RULE_OPTIONAL, -1, 1 },
			{ "Digest-Qop",			RULE_OPTIONAL, -1, 1 },
			{ "Digest-Nonce-Count",	RULE_OPTIONAL, -1, 1 },
			{ "Digest-Method",		RULE_OPTIONAL, -1, 1 },
			{ "Digest-Entity-Body-Hash",	RULE_OPTIONAL, -1, 1 },
			{ "Digest-Auth-Param",	RULE_OPTIONAL, -1, -1 },
		};

		FD_CHECK_dict_new(DICT_AVP, &data, NULL, &avp);
		PARSE_loc_rules(rules, avp);
	}

	/* SIP-Auth-Data-Item */
	{
		/*
			The SIP-Auth-Data-Item (AVP Code 376) is of type Grouped and contains
			the authentication and/or authorization information pertaining to a
			user.

			When the Diameter server uses the grouped SIP-Auth-Data-Item AVP to
			include a SIP-Authenticate AVP, the Diameter server MUST send a
			maximum of one authentication data item (e.g., in case the SIP
			request contained several credentials).  Section 11 contains a
			detailed discussion and normative text of the case when a SIP request
			contains several credentials.

			The SIP-Auth-Data-Item AVP is defined as follows (per the
			grouped-avp-def of RFC 3588 [RFC3588]):

			SIP-Auth-Data-Item ::= < AVP Header: 376 >
			{ SIP-Authentication-Scheme }
				[ SIP-Item-Number ]
				[ SIP-Authenticate ]
				[ SIP-Authorization ]
				[ SIP-Authentication-Info ]
				* [ AVP ]
		*/
		struct dict_object * avp;
		struct dict_avp_data data = {
				376, 					/* Code */
				0,						/* Vendor */
				"SIP-Auth-Data-Item", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_GROUPED 			/* base type of data */
				};
		struct local_rules_definition rules[] = {
			{ "SIP-Authentication-Scheme",	RULE_REQUIRED, -1, 1 },
			{ "SIP-Item-Number",			RULE_OPTIONAL, -1, 1 },
			//{ "SIP-Authenticate",			RULE_OPTIONAL, -1, 1 },
			{ "SIP-Authorization",			RULE_OPTIONAL, -1, 1 },
			//{ "SIP-Authentication-Info",	RULE_OPTIONAL, -1, 1 },
		};

		FD_CHECK_dict_new(DICT_AVP, &data, NULL, &avp);
		PARSE_loc_rules(rules, avp);
	}

	/* Multimedia-Auth-Request (MAR) Command */
	{
		struct dict_object *cmd;
		struct dict_cmd_data data = {
				286,						/* Code */
				"Multimedia-Auth-Request", 	/* Name */
				CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
				CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
				};
		struct local_rules_definition rules[] =  {
			{ "Session-Id",				RULE_FIXED_HEAD, -1, 1 },
			{ "Auth-Application-Id",	RULE_REQUIRED,   -1, 1 },
			{ "Auth-Session-State", 	RULE_REQUIRED,   -1, 1 },
			{ "Origin-Host",			RULE_REQUIRED,   -1, 1 },
			{ "Origin-Realm", 			RULE_REQUIRED,   -1, 1 },
			{ "Destination-Realm",		RULE_REQUIRED,   -1, 1 },
			{ "SIP-AOR", 				RULE_REQUIRED,   -1, 1 },
			{ "SIP-Method", 			RULE_REQUIRED,   -1, 1 },
			{ "Destination-Host", 		RULE_OPTIONAL,   -1, 1 },
			{ "User-Name",				RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Server-URI", 		RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Number-Auth-Items",	RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Auth-Data-Item", 	RULE_OPTIONAL,   -1, 1 },
			{ "Proxy-Info",				RULE_OPTIONAL,   -1, -1 },
			{ "Route-Record", 			RULE_OPTIONAL,   -1, -1 },
		};

		FD_CHECK_dict_new(DICT_COMMAND, &data, sip, &cmd);
		PARSE_loc_rules(rules, cmd);
	}

	/* Multimedia-Auth-Answer (MAA) Command */
	{
		struct dict_object *cmd;
		struct dict_cmd_data data = {
				286,						/* Code */
				"Multimedia-Auth-Answer", 	/* Name */
				CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR, 	/* Fixed flags */
				CMD_FLAG_PROXIABLE 			/* Fixed flag values */
				};
		struct local_rules_definition rules[] = {
			{ "Session-Id",				RULE_FIXED_HEAD, -1, 1 },
			{ "Auth-Application-Id",	RULE_REQUIRED,   -1, 1 },
			{ "Result-Code",			RULE_REQUIRED,   -1, 1 },
			{ "Auth-Session-State",		RULE_REQUIRED,   -1, 1 },
			{ "Origin-Host",			RULE_REQUIRED,   -1, 1 },
			{ "Origin-Realm",			RULE_REQUIRED,   -1, 1 },
			{ "User-Name",				RULE_OPTIONAL,   -1, 1 },
			{ "SIP-AOR",				RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Number-Auth-Items",	RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Auth-Data-Item",		RULE_OPTIONAL,   -1, -1 },
			{ "Authorization-Lifetime",	RULE_OPTIONAL,   -1, 1 },
			{ "Auth-Grace-Period",		RULE_OPTIONAL,   -1, 1 },
			{ "Redirect-Host",			RULE_OPTIONAL,   -1, 1 },
			{ "Redirect-Host-Usage",	RULE_OPTIONAL,   -1, 1 },
			{ "Redirect-Max-Cache-Time",	RULE_OPTIONAL,   -1, 1 },
			{ "Proxy-Info",				RULE_OPTIONAL,   -1, -1 },
			{ "Route-Record",			RULE_OPTIONAL,   -1, -1 },
		};

		FD_CHECK_dict_new(DICT_COMMAND, &data, sip, &cmd);
		PARSE_loc_rules(rules, cmd);
	}

	return 0;
}


/*
 * Register a series of AVPs needed by OpenSIPS (some dating back from RADIUS,
 * and some purely custom / non-standardized).
 *
 * Note that these AVPs may be overridden in the freeDiameter-client.conf file
 */
int dm_register_osips_avps(void)
{
	FD_CHECK(dm_register_radius_avps());
	FD_CHECK(dm_register_custom_sip_avps());
	FD_CHECK(dm_register_cdr_avps());
	FD_CHECK(dm_register_digest_avps());
	FD_CHECK(dm_register_custom_vendors());

	return 0;
}


int dm_init_minimal(void)
{
	/* these functions are not immediately available via the
	 * libfdcore .h files, but who said we cannot use them? >:) */
	extern int fd_conf_init(void);
	extern int fd_dict_base_protocol(struct dictionary * dict);

	static struct fd_config g_conf;
	static char init_done;

	if (init_done)
		return 0;

	if (!(osips_enumvals = hash_init(8))) {
		LM_ERR("oom\n");
		return -1;
	}

	LM_INFO("initializing the Diameter object dictionary...\n");

	fd_g_config = &g_conf;

	FD_CHECK(fd_conf_init());
	FD_CHECK(fd_dict_base_protocol(fd_g_config->cnf_dict));
	FD_CHECK(dm_register_osips_avps());
	FD_CHECK(dm_init_sip_application());

	init_done = 1;
	return 0;
}


void dm_destroy(void)
{
	hash_destroy(osips_enumvals, NULL);
	osips_enumvals = NULL;
}


aaa_conn *dm_init_prot(str *aaa_url)
{
	aaa_prot_config parsed;

	if (aaa_parse_url(aaa_url, &parsed) != 0) {
		LM_ERR("bad AAA URL\n");
		return NULL;
	}

	if (strlen((char *)parsed.rest))
		dm_conf_filename = (char *)parsed.rest;

	if (dm_init_minimal() != 0) {
		LM_ERR("failed to init freeDiameter global dictionary\n");
		return NULL;
	}

	return DM_DUMMY_HANDLE;
}


int freeDiameter_init(void)
{
	extern int fd_conf_deinit(void);

	extern int fd_log_level;

	if (fd_log_level < FD_LOG_ANNOYING)
		fd_log_level = FD_LOG_ANNOYING;

	if (fd_log_level > FD_LOG_FATAL)
		fd_log_level = FD_LOG_FATAL;

	/* free the "minimal initialization" we've done at mod_init() */
	FD_CHECK(fd_conf_deinit());

	/* ... and now fully init the entire freeDiameter library */
	FD_CHECK(fd_core_initialize());

	fd_g_debug_lvl = fd_log_level;

	memset(&acc_dict, 0, sizeof acc_dict);

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Destination-Realm", &acc_dict.Destination_Realm, ENOENT));

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Accounting-Record-Type", &acc_dict.Accounting_Record_Type, ENOENT));
	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Accounting-Record-Number", &acc_dict.Accounting_Record_Number, ENOENT));
	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Event-Timestamp", &acc_dict.Event_Timestamp, ENOENT));

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Auth-Application-Id", &acc_dict.Auth_Application_Id, ENOENT));
	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Auth-Session-State", &acc_dict.Auth_Session_State, ENOENT));

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Route-Record", &acc_dict.Route_Record, ENOENT));

	tac_entry();

	return 0;
}


int dm_find(aaa_conn *con, aaa_map *map, int op)
{
	struct dict_object *obj;

	if (!con || !map) {
		LM_ERR("invalid arguments (%p %p)\n", con, map);
		return -1;
	}

	switch (op) {
	case AAA_DICT_FIND_ATTR: {
		struct dict_avp_data avp;

		if (map->type == 0) {
			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
			      map->name, &obj, ENOENT));
			FD_CHECK(fd_dict_getval(obj, &avp));
		} else {
			struct dict_avp_request_ex req;

			memset(&req, 0, sizeof req);
			req.avp_data.avp_name = map->name;
			req.avp_vendor.vendor_id = map->type;

			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_STRUCT,
			      &req, &obj, ENOENT));
			FD_CHECK(fd_dict_getval(obj, &avp));
		}

		map->value = avp.avp_code;
		return 0;
	}
	case AAA_DICT_FIND_VAL: {
		unsigned int entry;
		int *value;

		entry = hash_entry(osips_enumvals, *_str(map->name));
		value = (int *)hash_find(osips_enumvals, entry, *_str(map->name));
		if (!value) {
			LM_ERR("enum '%s' not found\n", map->name);
			return -1;
		}

		map->value = *value;
		/* TODO: map->type = ?? */
		return 0;
	}
	case AAA_DICT_FIND_VEND: {
		struct dict_vendor_data vendor;

		FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_VENDOR, VENDOR_BY_NAME,
		      map->name, &obj, ENOENT));
		FD_CHECK(fd_dict_getval(obj, &vendor));

		map->value = vendor.vendor_id;
		LM_DBG("found vendor '%s', id: %d\n", map->name, map->value);
		return 0;
	}}

	LM_ERR("failed to locate Diameter object: '%s'\n", map->name);
	return -1;
}


aaa_message *dm_create_message(aaa_conn *con, int msg_type)
{
	aaa_message *m;
	struct dm_message *dm;

	m = shm_malloc(sizeof *m);
	if (!m) {
		LM_ERR("oom\n");
		return NULL;
	}

	dm = shm_malloc(sizeof *dm);
	if (!dm) {
		shm_free(m);
		LM_ERR("oom\n");
		return NULL;
	}

	memset(m, 0, sizeof *m);
	m->type = msg_type;
	m->avpair = (void *)dm;

	memset(dm, 0, sizeof *dm);
	INIT_LIST_HEAD(&dm->avps);
	dm->am = m;

	return m;
}


int dm_avp_add(aaa_conn *con, aaa_message *msg, aaa_map *avp, void *val,
               int val_length, int vendor)
{
	struct {
		struct dm_avp davp;
		char buf[0];
	} *wrap;
	int len;

	if (!avp || !avp->name)
		return -1;
	len = strlen(avp->name);

	wrap = shm_malloc(sizeof *wrap + len + 1 +
				(val_length < 0 ? 0 : val_length) + 1);
	if (!wrap) {
		LM_ERR("oom\n");
		return -1;
	}

	memset(&wrap->davp, 0, sizeof wrap->davp);
	INIT_LIST_HEAD(&wrap->davp.subavps);

	wrap->davp.name.s = wrap->buf;
	wrap->davp.name.len = len;
	strcpy(wrap->buf, avp->name);
	wrap->davp.vendor_id = vendor;

	/* TODO: does Diameter properly handle empty-string values? */
	if (val_length >= 0) {
		wrap->davp.value.s = wrap->buf + len + 1;
		wrap->davp.value.len = val_length;
		memcpy(wrap->davp.value.s, val, val_length);
		wrap->davp.value.s[val_length] = '\0';
	} else {
		/* the (void *) value is actually a 32-bit unsigned integer! */
		wrap->davp.value.s = (char *)(unsigned long)*(uint32_t *)val;
		wrap->davp.value.len = val_length;
	}

	list_add_tail(&wrap->davp.list,
			&((struct dm_message *)(msg->avpair))->avps);

	return 0;
}


int dm_send_message(aaa_conn *con, aaa_message *req, aaa_message **reply)
{
	if (!con || !req)
		return -1;

	/* we cannot provide the reply right now, since we're asynchronous <3 */
	if (reply)
		*reply = NULL;

	req->last_found = DM_MSG_SENT;

	pthread_mutex_lock(msg_send_lk);

	list_add_tail(&((struct dm_message *)(req->avpair))->list, msg_send_queue);
	pthread_cond_signal(msg_send_cond);

	pthread_mutex_unlock(msg_send_lk);

	return 0;
}


void _dm_destroy_message(aaa_message *msg)
{
	struct list_head *it, *aux;
	struct dm_avp *avp;

	if (!msg)
		return;

	list_for_each_safe (it, aux, &((struct dm_message *)(msg->avpair))->avps) {
		avp = list_entry(it, struct dm_avp, list);
		/* TODO: clean up any sub-AVPs, if applicable?! */
		shm_free(avp);
	}

	shm_free(msg->avpair);
	shm_free(msg);
}

int dm_destroy_message(aaa_conn *conn, aaa_message *msg)
{
	if (!msg)
		return 0;

	/* let the peer process be the one who cleans it up */
	if (msg->last_found == DM_MSG_SENT)
		return 0;

	_dm_destroy_message(msg);
	return 0;
}
