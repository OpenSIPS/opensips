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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 *
 * History
 * --------
 * 2009-07-20    First version (Irina Stanescu)
 */


/*
 * Generic AAA Interface
 *
 * This is a generic interface for modules that need to use AAA protocols.
 * The interface is independent of the underlying AAA protocol that implements
 * it and it should be used by all modules that use AAA features.
 * For other information, check out the documentation.
 */

#ifndef _AAA_H_
#define _AAA_H_

#include <stdio.h>
#include "../dprint.h"
#include "../mem/mem.h"
#include "../str.h"
#include "../sr_module.h"
#include "aaa_avp.h"

#define AAA_DICT_FIND_VAL 1
#define AAA_DICT_FIND_ATTR 2
#define AAA_DICT_FIND_VEND 3
#define AAA_AUTH 4
#define AAA_ACCT 5
#define AAA_RECV 6
#define AAA_GET_FROM_START 7
#define AAA_GET_FROM_CURRENT 8


/* Generic structure for an AVP */
typedef struct _aaa_map {
	char *name;
	int value;
	int type;
} aaa_map;

/*
	Generic structure for a message sent or received by the AAA protocol.

	avpair - the list of AVPs contained by the message
	last_found - a pointer in the list of AVPs used to store the last
   					element found by a search, this is needed by the find
					function in case a AAA_GET_FROM_CURRENT type of search
					is wanted
	type - the type of message (AAA_AUTH or AAA_ACCT)

 */
typedef struct _aaa_message {
	void* avpair;
	void* last_found;
	int type;
} aaa_message;


/*
	Generic AAA connection

	This is a type definition for a generic AAA connection.
	The implementation for a connection variable is protocol dependent.
 */
typedef void aaa_conn;


/*
	Creates a generic AAA message

	This function creates a structure for a message.
	The function takes two parameters:
	- the address of a AAA connection variable
 	- a flag representing the type of message (for authentication or accounting)
	The return value is a pointer to the AAA message structure.
*/
typedef aaa_message* (create_message_f)(aaa_conn*, int);


/*
	Destroys an AAA message

	This function destroys the AVP list contained by the message, and then
	releases the memory allocated for the message.
	The return value is an error code.
 */
typedef int (destroy_message_f)(aaa_conn*, aaa_message*);


/*
	Sends an AAA message

	This function sends a message on a specified connection.
	The function takes three parameters:
	- a pointer to the connection variable
	- the address of a message to be sent
	- pointer to the address of a message to be received (may be NULL)
	The return value is an error code.
 */
typedef int (send_request_f)(aaa_conn*, aaa_message*, aaa_message**);


/*
	Search in dictionary

	This function searches a certain value for a name in the dictionary of
	AVPs loaded at protcol intialization.
	The result is returned in the value field of the aaa_map structure.
	The third parameter represents the type of search wanted: for a value,
	for an attribute or for a vendor dictionary entry.
	The return value is an error code.
 */
typedef int (find_f)(aaa_conn*, aaa_map*, int);


/*
	Add AVP to a message

	This function adds a AVP to a specified AAA message.

	The first two parameters are the connection handle and the message.
	The last three parameters have the following meaning:
	- a pointer to the value to be added
	- the value length
	- the vendorpec

	Depending on the implementation, some of these values may be empty.
	The return value is an error code.
 */
typedef int (avp_add_f)(aaa_conn*, aaa_message*, aaa_map*, void*, int, int);


/*
	Get AVP from a message

	This function gets a AVP from a specified AAA message.

	The first two parameters are the connection handle and the message.

	The last three parameters have the following meaning:
	- a pointer to the location where the value should be placed
	- a pointer to the location where the value length should be placed
	- a flag specifying the type of search in the AVPs list (from the start or
	from the current position)

	The return value is an error code.
 */
typedef int (avp_get_f)(aaa_conn*, aaa_message*, aaa_map*, void**, int*, int);


/*
	Initialize AAA protocol implementation

	This function initializes the protocol and returns a pointer to the
	connection variable that represents it.
	The return value is a pointer to a connection variable.
 */
typedef aaa_conn* (init_prot_f)(str*);


/*
	AAA API module callbacks

	This structure is a collection of callbacks provided by the modules
	that implement this generic AAA interface.
	A variable of this type will be filled when a bind call is made, and
	therefore it cannot be used before aaa_prot_bind.
 */
typedef struct _aaa_prot {
	init_prot_f* 		init_prot;				/*initializes a protocol implementation*/
	create_message_f* 	create_aaa_message;		/*creates a request*/
	destroy_message_f*	destroy_aaa_message;	/*destroys a message*/
	send_request_f* 	send_aaa_request;		/*sends a request*/
	find_f* 			dictionary_find;		/*searches a name in a dictionary*/
	avp_add_f* 			avp_add;				/*adds a AVP to a message*/
	avp_get_f* 			avp_get;				/*gets the value of a AVP in a message*/
} aaa_prot;


/*
	Bind AAA module functions

	This is the function called by a module that wishes to use an
	implementation for an AAA protocol.
	The first parameter is the protocol URL.
	The second parameter represents the address where the structure for
	the protocol callback functions should be stored.
 	The return value is an error code.
 */
int aaa_prot_bind(str*, aaa_prot*);


/*
	Type definition for a bind function.
 */
typedef int (*aaa_bind_api_f)(aaa_prot*);


/*
	Protocol configuration structure

	The configuration structure for an AAA protocol. It contains
	- the protocol name extracted from the URL
	- a pointer to the location of what is left of the URL string
	This information can be used by the module that implements the
	interface as it pleases.
 */
typedef struct _aaa_prot_config {
	str *prot_name;
	void *rest;
} aaa_prot_config;


/*
	AAA URL parser

   This function parses a string representing the URL given through the
	configuration file and returns a configuration structure for the
	protocol implementation.

	An example for a URL for anAAA Radius Module is:
	"radius:/etc/radiusclient-ng/radiusclient.conf"

 */
int aaa_parse_url(str*, aaa_prot_config*);


/*
	Dictionary initialization macro

	This macro initializes an array of AVPs with the corresponding
	information from the protocol dictionary.
 */
#define INIT_AV(ap, rh, at, nr_at, vl, nr_vl, fn, e1, e2) \
{									\
	int i;						\
	for (i = 0; i < nr_at; i++) {	\
		if (at[i].name == NULL)		\
			continue;				\
		if (ap.dictionary_find(rh, &at[i], AAA_DICT_FIND_ATTR) < 0) {	\
			LM_ERR("%s: can't get code for the "					\
				   "%s attribute\n", fn, at[i].name);					\
			return e1;					\
		}								\
	}									\
	for (i = 0; i < nr_vl; i++) {		\
		if (vl[i].name == NULL)			\
			continue;					\
		if (ap.dictionary_find(rh, &vl[i], AAA_DICT_FIND_VAL) < 0) {	\
			LM_ERR("%s: can't get code for the "	\
				   "%s attribute value\n", fn, vl[i].name);\
			return e2;					\
		}							\
	}								\
}


#endif
