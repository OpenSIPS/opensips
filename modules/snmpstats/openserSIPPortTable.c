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
 * This file implements the openserSIPPortTable.  For a full description of the table,
 * please see the OPENSER-SIP-COMMON-MIB.
 *
 */

#include "snmpstats_globals.h"
#include "../../socket_info.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/library/snmp_assert.h>

#include "openserSIPPortTable.h"
#include "../../statistics.h"
#include "../../mem/mem.h"

static     netsnmp_handler_registration *my_handler = NULL;
static     netsnmp_table_array_callbacks cb;

oid    openserSIPPortTable_oid[]   = { openserSIPPortTable_TABLE_OID };
size_t openserSIPPortTable_oid_len = OID_LENGTH(openserSIPPortTable_oid);


/* Returns a new OID with the following structure:
 *
 * 	ipType.NUM_IP_OCTETS.ipAddress[0].ipAddress[1]...ipAddress[NUM_IP_OCTETS].portNumber
 *
 * sizeOfOID will be assigned the length of the oid.
 *
 * Note: This function returns a newly allocated block of memory.  Make sure to
 * deallocate the memory when you no longer need it.
 */
oid *createIndex(int ipType, int *ipAddress, int *sizeOfOID)
{
	oid *currentOIDIndex;
	int i;

	/* The size needs to be large enough such that it can store the ipType
	 * (one octet), the prefixed length (one octet), the number of
	 * octets to the IP Address (NUM_IP_OCTETS), and the port. */
	*sizeOfOID = NUM_IP_OCTETS + 3;

	/* Allocate space for the OID Index.  */
	currentOIDIndex = pkg_malloc((*sizeOfOID) * sizeof(oid));

	if (currentOIDIndex == NULL) {
		LM_ERR("failed to create a row for openserSIPPortTable\n");
		*sizeOfOID = 0;
		return NULL;
	}

	/* Assign the OID Index */
	currentOIDIndex[0] = ipType;
	currentOIDIndex[1] = NUM_IP_OCTETS;

	for (i = 0; i < NUM_IP_OCTETS; i++) {
		currentOIDIndex[i+2] = ipAddress[i];
	}

	/* Extract out the port number */
	currentOIDIndex[NUM_IP_OCTETS+2] = ipAddress[NUM_IP_OCTETS];

	return currentOIDIndex;
}


/* Will return an existing row indexed by the parameter list if one exists, and
 * return a new one otherwise.  If the row is new, then the provided index will be
 * assigned to the new row.
 *
 * Note: NULL will be returned on an error
 */
openserSIPPortTable_context *getRow(int ipType, int *ipAddress)
{
	int lengthOfOID;
	oid *currentOIDIndex = createIndex(ipType, ipAddress, &lengthOfOID);

	if (currentOIDIndex == NULL)
	{
		return NULL;
	}

	netsnmp_index theIndex;

	theIndex.oids = currentOIDIndex;
	theIndex.len  = lengthOfOID;

	openserSIPPortTable_context *rowToReturn;

	/* Lets check to see if there is an existing row. */
	rowToReturn = CONTAINER_FIND(cb.container, &theIndex);

	/* We found an existing row, so there is no need to create a new one.
	 * Let's return it to the caller. */
	if (rowToReturn != NULL)
	{
		/* We don't need the index we allocated anymore, because the
		 * existing row already has its own copy, so free the memory */
		pkg_free(currentOIDIndex);

		return rowToReturn;
	}

	/* If we are here then the row doesn't exist yet.  So lets create it. */
	rowToReturn = SNMP_MALLOC_TYPEDEF(openserSIPPortTable_context);

	/* Not enough memory to create the new row. */
	if (rowToReturn == NULL) {
		pkg_free(currentOIDIndex);
		return NULL;
	}

	/* Assign the Container Index. */
	rowToReturn->index.len  = lengthOfOID;
	rowToReturn->index.oids = currentOIDIndex;

	memcpy(rowToReturn->openserSIPStringIndex, currentOIDIndex, NUM_IP_OCTETS + 3);
	rowToReturn->openserSIPStringIndex_len = NUM_IP_OCTETS + 3;

	/* Insert the new row into the table */
	CONTAINER_INSERT(cb.container, rowToReturn);

	return rowToReturn;
}


/*
 * Will create rows for this table from theList.  The final parameter snmpIndex
 * can point to any integer >= zero.  All rows created by this function will be
 * indexed starting at snmpIndex++.  The parameter is implemented as a pointer
 * to an integer so that if the function is called again with another
 * 'protocol', we can continue from the last index.
 */
void createRowsFromIPList(int *theList, int listSize, int protocol,
		int *snmpIndex) {

	openserSIPPortTable_context *currentRow;

	int curIndexOfIP;
	int curSocketIdx;
	int valueToAssign;

	if (protocol == PROTO_UDP)
	{
		valueToAssign = TC_TRANSPORT_PROTOCOL_UDP;
	}
	else if (protocol == PROTO_TCP)
	{
		valueToAssign = TC_TRANSPORT_PROTOCOL_TCP;
	}
	else if (protocol == PROTO_TLS)
	{
		valueToAssign = TC_TRANSPORT_PROTOCOL_TLS;
	}
	else
	{
		valueToAssign = TC_TRANSPORT_PROTOCOL_OTHER;
	}

	/* Create all rows with respect to the given protocol */
	for (curSocketIdx=0; curSocketIdx < listSize; curSocketIdx++) {

		curIndexOfIP   = (NUM_IP_OCTETS + 1) * curSocketIdx;

		/* Retrieve an existing row, or a new row if one doesn't
		 * allready exist. */
		currentRow = getRow(1, &theList[curIndexOfIP]);

		if (currentRow == NULL) {
			LM_ERR("failed to create all the "
					"rows for the openserSIPPortTable\n");
			return;
		}

		currentRow->openserSIPTransportRcv[0]  |= valueToAssign;
		currentRow->openserSIPTransportRcv_len = 1;
	}
}

/*
 * Initializes the openserSIPPortTable module.
 *
 * Specifically, this function will define the tables structure, and then
 * populate it with the ports and transports that OpenSIPS is listening on.
 *
 */
void init_openserSIPPortTable(void)
{
	int curSNMPIndex = 0;

	initialize_table_openserSIPPortTable();

	int *UDPList = NULL;
	int *TCPList = NULL;
	int *TLSList = NULL;

	int numUDPSockets;
	int numTCPSockets;
	int numTLSSockets;

	/* Retrieve the list of the number of UDP and TCP sockets. */
	numUDPSockets = get_socket_list_from_proto(&UDPList, PROTO_UDP);
	numTCPSockets = get_socket_list_from_proto(&TCPList, PROTO_TCP);
	numTLSSockets = get_socket_list_from_proto(&TLSList, PROTO_TLS);

	/* Generate all rows, using all retrieved interfaces. */
	createRowsFromIPList(UDPList, numUDPSockets, PROTO_UDP, &curSNMPIndex);

	curSNMPIndex = 0;

	createRowsFromIPList(TCPList, numTCPSockets, PROTO_TCP, &curSNMPIndex);

	curSNMPIndex = 0;
	createRowsFromIPList(TLSList, numTLSSockets, PROTO_TLS, &curSNMPIndex);
}


/* Initialize the openserSIPPortTable table by defining how it is structured */
void initialize_table_openserSIPPortTable(void)
{
	netsnmp_table_registration_info *table_info;

	if(my_handler) {
		snmp_log(LOG_ERR, "initialize_table_openserSIPPortTable_handler"
				"called again\n");
		return;
	}

	memset(&cb, 0x00, sizeof(cb));

	/* create the table structure itself */
	table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);

	my_handler = netsnmp_create_handler_registration("openserSIPPortTable",
			netsnmp_table_array_helper_handler,
			openserSIPPortTable_oid,
			openserSIPPortTable_oid_len,
			HANDLER_CAN_RONLY);

	if (!my_handler || !table_info) {
		snmp_log(LOG_ERR, "malloc failed in "
			 "initialize_table_openserSIPPortTable_handler\n");
		return; /** mallocs failed */
	}

	/* Set up the table's structural definition */

	/* index: openserSIPPortIndex */
	netsnmp_table_helper_add_index(table_info, ASN_OCTET_STR);

	table_info->min_column = openserSIPPortTable_COL_MIN;
	table_info->max_column = openserSIPPortTable_COL_MAX;

	/* register the table with the master agent */
	cb.get_value = openserSIPPortTable_get_value;
	cb.container = netsnmp_container_find("openserSIPPortTable_primary:"
			"openserSIPPortTable:"
			"table_container");


	DEBUGMSGTL(("initialize_table_openserSIPPortTable",
				"Registering table openserSIPPortTable "
				"as a table array\n"));

	netsnmp_table_container_register(my_handler, table_info, &cb,
			cb.container, 1);
}

/*
 * This routine is called to process get requests for elements of the table.
 *
 * The function is mostly left in its auto-generated form
 */
int openserSIPPortTable_get_value(netsnmp_request_info *request,
		netsnmp_index *item,
		netsnmp_table_request_info *table_info )
{
	netsnmp_variable_list *var = request->requestvb;

	openserSIPPortTable_context *context =
		(openserSIPPortTable_context *)item;

	switch(table_info->colnum)
	{

		case COLUMN_OPENSERSIPTRANSPORTRCV:
			/** OpenSERSIPTransportProtocol = ASN_OCTET_STR */
			snmp_set_var_typed_value(var, ASN_OCTET_STR,
					(unsigned char *)
					&context->openserSIPTransportRcv,
					context->openserSIPTransportRcv_len );
			break;

		default: /** We shouldn't get here */
			snmp_log(LOG_ERR, "unknown column in "
					"openserSIPPortTable_get_value\n");
			return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}

/* Auto-generated function */
const openserSIPPortTable_context *
openserSIPPortTable_get_by_idx(netsnmp_index * hdr)
{
	return (const openserSIPPortTable_context *)
		CONTAINER_FIND(cb.container, hdr );
}


