/*********************************************************************************************************
* Software License Agreement (BSD License)                                                               *
* Author: Liviu Chircu <liviu@opensips.org>								 *
*													 *
* Copyright (c) 2021, OpenSIPS Solutions								 *
* All rights reserved.											 *
* 													 *
* Redistribution and use of this software in source and binary forms, with or without modification, are  *
* permitted provided that the following conditions are met:						 *
* 													 *
* * Redistributions of source code must retain the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer.										 *
*    													 *
* * Redistributions in binary form must reproduce the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer in the documentation and/or other						 *
*   materials provided with the distribution.								 *
* 													 *
* * Neither the name of the WIDE Project or NICT nor the 						 *
*   names of its contributors may be used to endorse or 						 *
*   promote products derived from this software without 						 *
*   specific prior written permission of WIDE Project and 						 *
*   NICT.												 *
* 													 *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED *
* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A *
* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR *
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 	 *
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 	 *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR *
* TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF   *
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.								 *
*********************************************************************************************************/

#include <freeDiameter/extension.h>

#include "ctype.h"

#include "avps.h"


/* when building this file into a fD app, ignore the OpenSIPS startup logic */
#ifndef PKG_MALLOC
#define dm_store_enumval(...) 0
#else
extern int dm_store_enumval(const char *name, int value);
#endif

#ifdef PKG_MALLOC
#include "../../../dprint.h"
#define LOG_DBG LM_DBG
#define LOG_ERROR LM_ERR
#else
#define LOG_DBG fd_log_debug
#define LOG_ERROR fd_log_error
#endif


#define STR_L(s) s, strlen(s)
#define avp_type2str(t) ( \
	t == AVP_TYPE_OCTETSTRING ? "string" : \
	t == AVP_TYPE_UNSIGNED64 ? "unsigned64" : \
	t == AVP_TYPE_UNSIGNED32 ? "unsigned32" : \
	t == AVP_TYPE_INTEGER64 ? "integer64" : \
	t == AVP_TYPE_INTEGER32 ? "integer32" : \
	t == AVP_TYPE_FLOAT64 ? "float64" : \
	t == AVP_TYPE_FLOAT32 ? "float32" : \
	t == AVP_TYPE_GROUPED ? "grouped" : ("unknown?? "#t))

struct dm_avp_def {
	char name[64 + 1];
	int name_len;
	enum rule_position pos;
	int max_repeats;
};

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
				0,				/* Fixed flags */
				0,				/* Fixed flag values */
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
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
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

	/* Transaction-Id */
	{
		/*
			The Transaction-Id AVP (AVP Code 231) is of type UTF8String
			and represents a unique ID of the transaction, to facilitate
			reply matching
		*/
		struct dict_avp_data data = {
				231, 					/* Code */
				0,						/* Vendor */
				"Transaction-Id",		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,			/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
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
				AVP_FLAG_VENDOR,		/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 	/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	return 0;
}


int register_osips_avps(void)
{
	FD_CHECK(dm_register_radius_avps());
	FD_CHECK(dm_register_custom_sip_avps());
	FD_CHECK(dm_register_cdr_avps());
	FD_CHECK(dm_register_custom_vendors());

	return 0;
}


static int parse_avp_def(struct dm_avp_def *avps, int *avp_count, char *line, int len)
{
	char *p = line, *avp_name;

	avp_name = p;
	while (*p && !isspace(*p)) { p++; len--; }
	avps[*avp_count].name_len = p - avp_name;

	if (avps[*avp_count].name_len > 64) {
		LOG_ERROR("AVP max name length exceeded (64)\n");
		return -1;
	}

	memcpy(&avps[*avp_count].name, avp_name, avps[*avp_count].name_len);
	avps[*avp_count].name[avps[*avp_count].name_len] = '\0';

	while (isspace(*p)) { p++; len--; }

	if (*p != '|')
		goto error;

	p++; len--;
	while (isspace(*p)) { p++; len--; }

	switch (*p) {
	case 'F':
		if (len < strlen("FIXED_HEAD") || memcmp(p, "FIXED_HEAD", 10))
			goto error;

		avps[*avp_count].pos = RULE_FIXED_HEAD;
		p += 10;
		len -= 10;
		break;

	case 'R':
		if (len < strlen("REQUIRED") || memcmp(p, "REQUIRED", 8))
			goto error;

		avps[*avp_count].pos = RULE_REQUIRED;
		p += 8;
		len -= 8;
		break;

	case 'O':
		if (len < strlen("OPTIONAL") || memcmp(p, "OPTIONAL", 8))
			goto error;

		avps[*avp_count].pos = RULE_OPTIONAL;
		p += 8;
		len -= 8;
		break;

	default:
		LOG_ERROR("bad AVP flag in: '... | %s'\n", p);
		goto error;
	}

	while (isspace(*p)) { p++; len--; }

	if (*p != '|')
		goto error;

	p++; len--;
	while (isspace(*p)) { p++; len--; }

	avps[*avp_count].max_repeats = (int)strtol(p, NULL, 10);
	if (avps[*avp_count].max_repeats < -1) {
		LOG_ERROR("bad AVP max count: '... | %s'\n", p);
		goto error;
	}

	LOG_DBG("AVP def: %.*s | %d | %d\n", avps[*avp_count].name_len,
	        avps[*avp_count].name, avps[*avp_count].pos,
	        avps[*avp_count].max_repeats);

	(*avp_count)++;
	return 0;

error:
	LOG_ERROR("failed to parse line: '%s'\n", line);
	return -1;
}

int parse_attr_def(char *line, FILE *fp)
{
	struct dm_avp_def avps[128];
	int avp_count = 0;
	unsigned int vendor_id = -1;
	size_t buflen = strlen(line);
	int i, len = buflen, attr_len = strlen("ATTRIBUTE"), name_len, avp_code;
	char *name, *nt_name, *newp, *p = line, *end = p + len;
	enum dict_avp_basetype avp_type;
	enum dict_avp_enc_type enc_type = AVP_ENC_TYPE_NONE;

	if (len < attr_len || strncasecmp(p, "ATTRIBUTE", attr_len))
		return 1;

	p += attr_len;
	len -= attr_len;

	while (isspace(*p)) { p++; len--; }
	if (p >= end)
		goto error;

	name = p; name_len = 0;
	while (!isspace(*p)) { p++; len--; name_len++; }
	if (p >= end)
		goto error;

	nt_name = malloc(name_len + 1);
	memcpy(nt_name, name, name_len);
	nt_name[name_len] = '\0';

	while (isspace(*p)) { p++; len--; }
	if (p >= end)
		goto error;

	avp_code = strtol(p, &newp, 10);
	if (avp_code == 0)
		goto error;

	len -= newp - p;
	p = newp;

	while (isspace(*p)) { p++; len--; }

	if (p >= end) {
		avp_type = AVP_TYPE_OCTETSTRING;
	} else {
		if ((len >= strlen("ip") && !strncasecmp(p, STR_L("ip")))) {
			avp_type = AVP_TYPE_OCTETSTRING;
			enc_type = AVP_ENC_TYPE_IP;
		} else if ((len >= strlen("hex") && !strncasecmp(p, STR_L("hex")))
		        || (len >= strlen("hexstring") && !strncasecmp(p, STR_L("hexstring")))) {
			avp_type = AVP_TYPE_OCTETSTRING;
			enc_type = AVP_ENC_TYPE_HEX;
		} else if ((len >= strlen("utf8string") && !strncasecmp(p, STR_L("utf8string")))
		        || (len >= strlen("string") && !strncasecmp(p, STR_L("string"))))
			avp_type = AVP_TYPE_OCTETSTRING;
		else if ((len >= strlen("unsigned64") && !strncasecmp(p, STR_L("unsigned64"))))
			avp_type = AVP_TYPE_UNSIGNED64;
		else if ((len >= strlen("unsigned") && !strncasecmp(p, STR_L("unsigned"))))
			avp_type = AVP_TYPE_UNSIGNED32;
		else if ((len >= strlen("integer64") && !strncasecmp(p, STR_L("integer64"))))
			avp_type = AVP_TYPE_INTEGER64;
		else if ((len >= strlen("integer") && !strncasecmp(p, STR_L("integer"))))
			avp_type = AVP_TYPE_INTEGER32;
		else if ((len >= strlen("float64") && !strncasecmp(p, STR_L("float64"))))
			avp_type = AVP_TYPE_FLOAT64;
		else if ((len >= strlen("float") && !strncasecmp(p, STR_L("float"))))
			avp_type = AVP_TYPE_FLOAT32;
		else if ((len >= strlen("grouped") && !strncasecmp(p, STR_L("grouped"))))
			avp_type = AVP_TYPE_GROUPED;
		else
			goto error;
	}

	/* skip over the type */
	while (len > 0 && !isspace(*p)) { p++; len--; }

	if (len > 0 && *p != '\r' && *p != '\n') {
		vendor_id = strtol(p, &newp, 10);
		if (vendor_id < 0)
			goto error;

		len -= newp - p;
		p = newp;
	}

	if (avp_type != AVP_TYPE_GROUPED)
		goto create_avp;

	/* parse the grouped AVP definition (curly braces part) */

	while (getline(&line, &buflen, fp) >= 0) {
		p = line;
		len = strlen(p);

		while (isspace(*p)) { p++; len--; }

		if (*p == '{')
			continue;

		if (*p == '}' || !strlen(p))
			goto create_avp;

		if (avp_count >= 128) {
			LOG_ERROR("max AVP count exceeded (128)\n");
			return -1;
		}

		if (parse_avp_def(avps, &avp_count, p, len) != 0) {
			LOG_ERROR("failed to parse Grouped sub-AVP line: '%s'\n", line);
			return -1;
		}
	}

create_avp:;
	struct dict_object *parent, *avp_ref, **pref;

	if (enc_type != AVP_ENC_TYPE_NONE &&
			dm_enc_add((vendor_id != -1?vendor_id:0), avp_code, enc_type) != 0) {
		LOG_ERROR("failed to add encoding type\n");
		return -1;
	}

	pref = NULL;
	parent = NULL;
	switch (avp_type) {
	case AVP_TYPE_OCTETSTRING:
		FD_CHECK_dict_search(DICT_TYPE, TYPE_BY_NAME, "UTF8String", &parent);
		break;
	case AVP_TYPE_GROUPED:
		pref = &avp_ref;
		break;
	default:
		break;
	}

	struct dict_avp_data data = {
		avp_code, 	/* Code */
		(vendor_id != -1?vendor_id:0),			/* Vendor */
		nt_name,	/* Name */
		AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
		(vendor_id != -1?AVP_FLAG_VENDOR:0)|AVP_FLAG_MANDATORY, /* Fixed flag values */
		avp_type 	/* base type of data */
	};

	FD_CHECK_dict_new(DICT_AVP, &data, parent, pref);

	for (i = 0; i < avp_count; i++) {
		struct dict_rule_data data = {NULL, avps[i].pos,
			(avps[i].pos == RULE_FIXED_HEAD), -1, avps[i].max_repeats};

		FD_CHECK(fd_dict_search(fd_g_config->cnf_dict,
			DICT_AVP, AVP_BY_NAME_ALL_VENDORS, avps[i].name, &data.rule_avp, 0));

		if (!data.rule_avp) {
			LOG_ERROR("failed to locate AVP: %s\n", avps[i].name);
			return -1;
		}

		FD_CHECK_dict_new(DICT_RULE, &data, avp_ref, NULL);
	}

	LOG_DBG("registered custom AVP (%s, code %d, type %s, enc %s, sub-avps: %d, vendor: %d)\n",
			nt_name, avp_code, avp_type2str(avp_type), enc_type2str(enc_type), avp_count, vendor_id);

	free(nt_name);
	return 0;
error:
	LOG_ERROR("failed to parse line: %s\n", line);
	return -1;
}

int parse_app_vendor(char *line, FILE *fp)
{
	unsigned int vendor_id = -1;
	int len = strlen(line);
	char *p = line, *newp, *vendor_name;

	if (len < strlen("VENDOR") || memcmp(p, "VENDOR", 6))
		return 1;

	p += 6;
	len -= 6;

	while (isspace(*p)) { p++; len--; }

	vendor_id = (unsigned int)strtoul(p, &newp, 10);
	if (vendor_id < 0) {
		LOG_ERROR("bad Vendor ID: '... | %s'\n", p);
		return -1;
	}

	len -= newp - p;
	p = newp;

	if (len <= 0) {
		LOG_ERROR("empty Vendor Name not allowed\n");
		return -1;
	}

	vendor_name = p;
	p += len - 1;

	while (p > vendor_name && isspace(*p)) { p--; }
	*(++p) = '\0';

	struct dict_vendor_data vendor_reg = {vendor_id, vendor_name};
	FD_CHECK_dict_new(DICT_VENDOR, &vendor_reg, NULL, NULL);

	LOG_DBG("registered Vendor %d (%s)\n", vendor_id, vendor_name);

	return 1;
}


struct _app_defs app_defs[64];
unsigned int n_app_ids;

int parse_app_def(char *line, FILE *fp)
{
	unsigned int app_id = -1;
	unsigned int vendor_id = -1;
	unsigned char is_auth = 0;
	int i, len = strlen(line);
	char *p = line, *newp, *app_name;
	struct dict_object *vendor_dict;

	if (n_app_ids >= 64) {
		LOG_ERROR("max allowed Applications reached (64)\n");
		return -1;
	}

	if (len < strlen("APPLICATION") || memcmp(p, "APPLICATION", 11))
		return 1;

	p += 11;
	len -= 11;

	while (isspace(*p)) { p++; len--; }

	if (len >= strlen("-AUTH") && memcmp(p, "-AUTH", 5) == 0) {
		is_auth = 1;

		p += 5;
		len -= 5;
		while (isspace(*p)) { p++; len--; }
	} else if (len >= strlen("-ACC") && memcmp(p, "-ACC", 4) == 0) {
		is_auth = 0;

		p += 4;
		len -= 4;
		while (isspace(*p)) { p++; len--; }
	}

	app_id = (unsigned int)strtoul(p, &newp, 10);
	if (app_id < 0) {
		LOG_ERROR("bad Application ID: '... | %s'\n", p);
		return -1;
	}

	len -= newp - p;
	p = newp;

	while (isspace(*p)) { p++; len--; }
	if (*p == '/') {

		/* Vendor ID is specified as well */
		p++;
		len--;
		while (isspace(*p)) { p++; len--; }

		vendor_id = (unsigned int)strtoul(p, &newp, 10);
		if (vendor_id < 0) {
			LOG_ERROR("bad Vendor ID: '... | %s'\n", p);
			return -1;
		}

		len -= newp - p;
		p = newp;

		while (isspace(*p)) { p++; len--; }

		FD_CHECK_dict_search(DICT_VENDOR, VENDOR_BY_ID,
				&vendor_id, &vendor_dict);
	} else {
		vendor_dict = NULL;
	}

	if (len <= 0) {
		LOG_ERROR("empty Application Name not allowed\n");
		return -1;
	}

	app_name = p;
	p += len - 1;

	while (p > app_name && isspace(*p)) { p--; }
	*(++p) = '\0';

	struct dict_application_data app_reg = {app_id, app_name};
	FD_CHECK_dict_new(DICT_APPLICATION, &app_reg, vendor_dict, NULL);

	LOG_DBG("registered Application %d (%s)\n", app_id, app_name);

	/* store the App ID so OpenSIPS can register a reply cb later */
	for (i = 0; i < n_app_ids; i++)
		if (app_defs[i].id == app_id)
			return 1;

	app_defs[n_app_ids].auth = is_auth;
	app_defs[n_app_ids].vendor = vendor_id;
	app_defs[n_app_ids++].id = app_id;
	return 1;
}


#define CMD_REQUEST 1
#define CMD_ANSWER  2
int parse_command_def(char *line, FILE *fp, int cmd_type)
{
	struct dict_object *cmd = NULL;
	unsigned int cmd_code = -1;
	char *p = line, cmd_name[128 + 1], *bkp, *newp;
	size_t buflen = strlen(line);
	int i, len = buflen, cmd_name_len = -1, avp_count = 0;
	struct dm_avp_def avps[128];

	switch (cmd_type) {
	case CMD_REQUEST:
		if (len < strlen("REQUEST") || memcmp(p, "REQUEST", 7))
			return 1;

		p += 7;
		len -= 7;
		break;

	case CMD_ANSWER:
		if (len < strlen("ANSWER") || memcmp(p, "ANSWER", 6))
			return 1;

		p += 6;
		len -= 6;
		break;
	}

	cmd_code = (unsigned int)strtoul(p, &newp, 10);
	if (cmd_code < 0) {
		LOG_ERROR("bad AVP cmd code: '... | %s'\n", p);
		return -1;
	}

	len -= newp - p;
	p = newp;

	while (isspace(*p)) { p++; len--; }

	bkp = p;
	p += len - 1;

	while (p > bkp && isspace(*p)) { p--; }
	p++;

	cmd_name_len = p - bkp;
	if (cmd_name_len > 128) {
		LOG_ERROR("max Command Name length exceeded (128)\n");
		return -1;
	}

	memcpy(cmd_name, bkp, cmd_name_len);
	cmd_name[cmd_name_len] = '\0';

	LOG_DBG("parsed Cmd-Code %d (%s)\n", cmd_code, cmd_name);

	while (getline(&line, &buflen, fp) >= 0) {
		p = line;
		len = strlen(p);

		while (isspace(*p)) { p++; len--; }

		if (*p == '{')
			continue;

		if (*p == '}' || !strlen(p))
			goto define_req;

		if (avp_count >= 128) {
			LOG_ERROR("max AVP count exceeded (128)\n");
			return -1;
		}

		if (parse_avp_def(avps, &avp_count, p, len) != 0) {
			LOG_ERROR("failed to parse Command AVP line: '%s'\n", line);
			return -1;
		}
	}

define_req:
	LOG_DBG("defining request (%d AVPs in total)...\n", avp_count);

	struct dict_cmd_data req_data = {
			cmd_code,
			cmd_name,
			CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
				| (cmd_type == CMD_REQUEST ? CMD_FLAG_ERROR : 0),	/* Fixed flags */
			(cmd_type == CMD_REQUEST ? CMD_FLAG_REQUEST : 0)
				| CMD_FLAG_PROXIABLE	/* Fixed flag values */
		};

	FD_CHECK(fd_dict_new(fd_g_config->cnf_dict, DICT_COMMAND, &req_data, NULL, &cmd));

	for (i = 0; i < avp_count; i++) {
		struct dict_rule_data data = {NULL, avps[i].pos,
			(avps[i].pos == RULE_FIXED_HEAD), -1, avps[i].max_repeats};

		FD_CHECK(fd_dict_search(fd_g_config->cnf_dict,
			DICT_AVP, AVP_BY_NAME_ALL_VENDORS, avps[i].name, &data.rule_avp, 0));

		if (!data.rule_avp) {
			LOG_ERROR("failed to locate AVP: %s\n", avps[i].name);
			return -1;
		}

		FD_CHECK_dict_new(DICT_RULE, &data, cmd, NULL);
	}

	{
		/* all custom requests and replies MUST include Transaction-Id
		 * but only if they they don't require a Session-Id already */
		struct dict_rule_data data = {NULL, RULE_REQUIRED, 0, -1, 1};

		FD_CHECK(fd_dict_search(fd_g_config->cnf_dict,
			DICT_AVP, AVP_BY_NAME, "Session-Id", &data.rule_avp, 0));
		if (!data.rule_avp) {
			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict,
				DICT_AVP, AVP_BY_NAME, "Transaction-Id", &data.rule_avp, 0));

			if (!data.rule_avp) {
				LOG_ERROR("failed to locate Transaction-Id AVP\n");
				return -1;
			}

			FD_CHECK_dict_new(DICT_RULE, &data, cmd, NULL);
		}
	}

	/* all replies MUST include a Result-Code
	 * but only if they they don't require an Experimental-Result already */
	if (cmd_type == CMD_ANSWER) {
		struct dict_rule_data data = {NULL, RULE_REQUIRED, 0, -1, 1};

		FD_CHECK(fd_dict_search(fd_g_config->cnf_dict,
			DICT_AVP, AVP_BY_NAME, "Experimental-Result", &data.rule_avp, 0));
		if (!data.rule_avp) {
			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict,
				DICT_AVP, AVP_BY_NAME, "Result-Code", &data.rule_avp, 0));

			if (!data.rule_avp) {
				LOG_ERROR("failed to locate Result-Code AVP\n");
				return -1;
			}

			FD_CHECK_dict_new(DICT_RULE, &data, cmd, NULL);
		}
	}

	return 0;
}


int parse_extra_avps(const char *extra_avps_file)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int answers_needed = 0, rc, ret = 0;

	if (!extra_avps_file)
		return 0;

	fp = fopen(extra_avps_file, "r");
	if (!fp)
		return -1;

	while ((read = getline(&line, &len, fp)) != -1) {
		char *p = line;

		while (isspace(*p))
			p++;

		// comment or empty line
		if (*p == '#' || p - line >= read)
			continue;

		rc = parse_app_vendor(p, fp);
		if (rc < 0) {
			ret = -1;
			goto out;
		} else if (rc == 0) {
			continue;
		}

		rc = parse_attr_def(p, fp);
		if (rc < 0) {
			ret = -1;
			goto out;
		} else if (rc == 0) {
			continue;
		}

		rc = parse_app_def(p, fp);
		if (rc < 0) {
			ret = -1;
			goto out;
		} else if (rc == 0) {
			continue;
		}

		rc = parse_command_def(p, fp, CMD_REQUEST);
		if (rc < 0) {
			ret = -1;
			goto out;
		} else if (rc == 0) {
			answers_needed++;
			continue;
		}

		rc = parse_command_def(p, fp, CMD_ANSWER);
		if (rc < 0) {
			ret = -1;
			goto out;
		} else if (rc == 0) {
			answers_needed--;
			continue;
		}

		// unknown line... ignoring
	}

	if (answers_needed > 0) {
		LOG_ERROR("bad config file, at least one Diameter Answer "
		       "definition is missing\n");
		ret = -1;
	}

out:
	fclose(fp);
	free(line);

	return ret;
}
