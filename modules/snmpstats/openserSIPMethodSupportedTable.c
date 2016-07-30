/*
 * SNMPStats Module
 * Copyright (C) 2006 SOMA Networks, INC.
 * Written by: Jeffrey Magder (jmagder@somanetworks.com)
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 *
 * History:
 * --------
 * 2006-11-23 initial version (jmagder)
 *
 * Originally Generated with mib2c using mib2c.array-user.conf
 *
 * The file implements the openserSIPMethodSupportedTable.  The table is
 * populated by looking to see which modules are loaded, and guessing what SIP
 * Methods they  provide.  It is quite possible that this initial implementation
 * is not very good at guessing.  This should be fixed in future releases as
 * more information becomes available.
 *
 * For full details, please see the OPENSER-SIP-COMMON-MIB.
 *
 */

#include "../../sr_module.h"
#include "../../mem/mem.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/library/snmp_assert.h>

#include "openserSIPMethodSupportedTable.h"

static netsnmp_handler_registration *my_handler = NULL;
static netsnmp_table_array_callbacks cb;

oid    openserSIPMethodSupportedTable_oid[] =
	{ openserSIPMethodSupportedTable_TABLE_OID };

size_t openserSIPMethodSupportedTable_oid_len =
	OID_LENGTH(openserSIPMethodSupportedTable_oid);


/* Create a row at the given index, containing stringToRegister, and insert it
 * into the table.  Note that stringToRegister will be copied, so it is not
 * necessary to pre-allocate this string anywhere. */
void createRow(int index, char *stringToRegister) {

	openserSIPMethodSupportedTable_context *theRow;

	oid  *OIDIndex;
	char *copiedString;
	int  stringLength;

	theRow = SNMP_MALLOC_TYPEDEF(openserSIPMethodSupportedTable_context);

	if (theRow == NULL) {
		LM_ERR("failed to create a row for openserSIPMethodSupportedTable\n");
		return;
	}

	OIDIndex = pkg_malloc(sizeof(oid));

	if (OIDIndex == NULL) {
		free(theRow);
		LM_ERR("failed to create a row for openserSIPMethodSupportedTable\n");
		return;
	}

	stringLength = strlen(stringToRegister);

	copiedString = pkg_malloc((stringLength + 1) * sizeof(char));

	if (copiedString == NULL) {
		LM_ERR("failed to create a row for openserSIPMethodSupportedTable\n");
		return;
	}

	strcpy(copiedString, stringToRegister);

	OIDIndex[0] = index;

	theRow->index.len  = 1;
	theRow->index.oids = OIDIndex;
	theRow->openserSIPMethodSupportedIndex = index;

	theRow->openserSIPMethodName     = (unsigned char*) copiedString;
	theRow->openserSIPMethodName_len = stringLength;

	CONTAINER_INSERT(cb.container, theRow);
}


/* Initializes the openserSIPMethodSupportedTable, and populates the tables
 * contents */
void init_openserSIPMethodSupportedTable(void)
{
	initialize_table_openserSIPMethodSupportedTable();

	/* Tables is defined as follows:
	 *
	 * 	1)  METHOD_INVITE
	 *  	2)  METHOD_CANCEL
	 *	3)  METHOD_ACK
	 *	4)  METHOD_BYE
	 *	5)  METHOD_INFO
	 *	6)  METHOD_OPTIONS
	 *	7)  METHOD_UPDATE
	 *	8)  METHOD_REGISTER
	 *	9)  METHOD_MESSAGE
	 *	10) METHOD_SUBSCRIBE
	 *	11) METHOD_NOTIFY
	 *	12) METHOD_PRACK
	 *	13) METHOD_REFER
	 *	14) METHOD_PUBLISH
	 *
	 * We should keep these indices fixed.  For example if we don't support
	 * METHOD_REGISTER but we do support METHOD_MESSAGE, then METHOD_MESSAGE
	 * should still be at index 9.
	 *
	 * NOTE: My way of checking what METHODS we support is probably wrong.
	 * Please feel free to correct it! */

	if (module_loaded("sl")) {
		createRow(1, "METHOD_INVITE");
		createRow(2, "METHOD_CANCEL");
		createRow(3, "METHOD_ACK");
	}

	if (module_loaded("tm")) {
		createRow(4, "METHOD_BYE");
	}

	if (module_loaded("options")) {
		createRow(6, "METHOD_OPTIONS");
	}

	if (module_loaded("dialog")) {
		createRow(7, "METHOD_UPDATE");
	}

	if (module_loaded("registrar")) {
		createRow(8, "METHOD_REGISTER");
		createRow(10, "METHOD_SUBSCRIBE");
		createRow(11, "METHOD_NOTIFY");
	}

	createRow(5,  "METHOD_INFO");
	createRow(9,  "METHOD_MESSAGE");

	/* I'm not sure what these guys are, so saying we support them by
	 * default.  */
	createRow(12, "METHOD_PRACK");
	createRow(13, "METHOD_REFER");
	createRow(14, "METHOD_PUBLISH");
}


/* Initialize the openserSIPMethodSupportedTable by defining its structure and
 * callback mechanisms */
void initialize_table_openserSIPMethodSupportedTable(void)
{
	netsnmp_table_registration_info *table_info;

	if(my_handler) {
		snmp_log(LOG_ERR, "initialize_table_openserSIPMethodSupported"
				"Table_handler called again\n");
		return;
	}

	memset(&cb, 0x00, sizeof(cb));

	/** create the table structure itself */
	table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);

	my_handler =
		netsnmp_create_handler_registration(
			"openserSIPMethodSupportedTable",
			netsnmp_table_array_helper_handler,
			openserSIPMethodSupportedTable_oid,
			openserSIPMethodSupportedTable_oid_len,
			HANDLER_CAN_RONLY);

	if (!my_handler || !table_info) {
		snmp_log(LOG_ERR, "malloc failed in initialize_table_openser"
				"SIPMethodSupportedTable_handler\n");
		return;
	}

	netsnmp_table_helper_add_index(table_info, ASN_UNSIGNED);

	table_info->min_column = openserSIPMethodSupportedTable_COL_MIN;
	table_info->max_column = openserSIPMethodSupportedTable_COL_MAX;

	/***************************************************
	 * registering the table with the master agent
	 */
	cb.get_value = openserSIPMethodSupportedTable_get_value;
	cb.container =
		netsnmp_container_find("openserSIPMethodSupportedTable_primary:"
			"openserSIPMethodSupportedTable:" "table_container");

	DEBUGMSGTL(("initialize_table_openserSIPMethodSupportedTable",
				"Registering table openserSIPMethodSupportedTable"
				"as a table array\n"));

	netsnmp_table_container_register(my_handler, table_info, &cb,
			cb.container, 1);

}

/*
 * This routine is called to process get requests for elements of the table.
 *
 * The function is pretty much left as is from the auto-generated code.
 */
int openserSIPMethodSupportedTable_get_value(
			netsnmp_request_info *request,
			netsnmp_index *item,
			netsnmp_table_request_info *table_info )
{
	netsnmp_variable_list *var = request->requestvb;

	openserSIPMethodSupportedTable_context *context =
		(openserSIPMethodSupportedTable_context *)item;

	switch(table_info->colnum)
	{
		case COLUMN_OPENSERSIPMETHODNAME:

			/** SnmpAdminString = ASN_OCTET_STR */
			snmp_set_var_typed_value(var, ASN_OCTET_STR,
					(unsigned char*)
					context->openserSIPMethodName,
					context->openserSIPMethodName_len );
			break;

		default: /** We shouldn't get here */
			snmp_log(LOG_ERR, "unknown column in openserSIPMethod"
					"SupportedTable_get_value\n");
			return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}

/*
 * openserSIPMethodSupportedTable_get_by_idx is an auto-generated function.
 */
const openserSIPMethodSupportedTable_context *
	openserSIPMethodSupportedTable_get_by_idx(netsnmp_index * hdr)
{
	return (const openserSIPMethodSupportedTable_context *)
		CONTAINER_FIND(cb.container, hdr );
}


