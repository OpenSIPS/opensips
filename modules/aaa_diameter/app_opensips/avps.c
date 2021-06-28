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

#include "../peer.h"
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
#else
#define LOG_DBG fd_log_debug
#endif

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


int parse_attr_line(char *line, ssize_t len)
{
	int attr_len = strlen("ATTRIBUTE"), avp_len, avp_code;
	char *avp_name, *newp, *p = line, *end = p + len;
	enum dict_avp_basetype avp_type;

	if (len < attr_len || strncasecmp(p, "ATTRIBUTE", attr_len))
		goto error;

	p += attr_len;
	len -= attr_len;

	while (isspace(*p)) { p++; len--; }
	if (p >= end)
		goto error;

	avp_name = p; avp_len = 0;
	while (!isspace(*p)) { p++; len--; avp_len++; }
	if (p >= end)
		goto error;

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
		if ((len >= strlen("integer")
		        && !strncasecmp(p, "integer", strlen("integer"))) ||
		    (len >= strlen("unsigned32")
		        && !strncasecmp(p, "unsigned32", strlen("unsigned32"))))
			avp_type = AVP_TYPE_UNSIGNED32;
		else if ((len >= strlen("string")
		        && !strncasecmp(p, "string", strlen("string"))) ||
		    (len >= strlen("utf8string")
		        && !strncasecmp(p, "utf8string", strlen("utf8string"))))
			avp_type = AVP_TYPE_OCTETSTRING;
		else
			goto error;
	}

	char *nt_name = malloc(avp_len + 1);
	memcpy(nt_name, avp_name, avp_len);
	nt_name[avp_len] = '\0';

	struct dict_avp_data data = {
		avp_code, 	/* Code */
		0,			/* Vendor */
		nt_name,	/* Name */
		AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
		AVP_FLAG_MANDATORY,			/* Fixed flag values */
		avp_type 	/* base type of data */
	};
	FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);

	LOG_DBG("registered custom AVP (%s, code %d, type %s)\n",
			nt_name, avp_code, avp_type == AVP_TYPE_UNSIGNED32 ?
				"integer" : "string");

	free(nt_name);
	return 0;
error:
	printf("ERROR: failed to parse line: %s\n", line);
	return -1;
}


int parse_extra_avps(const char *extra_avps_file)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

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

		if (parse_attr_line(p, read - (p - line)) == 0)
			continue;

		// unknown line... ignoring
	}

	fclose(fp);
	free(line);

	return 0;
}
