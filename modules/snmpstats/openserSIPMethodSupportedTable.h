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
 * 2007-02-16 Moved all OID registrations from the experimental branch to
 *            OpenSER's IANA assigned enterprise branch. (jmagder)
 *
 * Originally Generated with Mib2c using mib2c.array-user.conf.
 *
 * This file defines the prototypes used to define the
 * openserSIPMethodSupportedTable.  For full details, please see the
 * OPENSER-SIP-COMMON-MIB.
 */

#ifndef OPENSERSIPMETHODSUPPORTEDTABLE_H
#define OPENSERSIPMETHODSUPPORTEDTABLE_H

#ifdef __cplusplus
extern "C" {
#endif


#include <net-snmp/net-snmp-config.h>
#include <net-snmp/library/container.h>
#include <net-snmp/agent/table_array.h>

#include "../../config.h"

/*
 * This strucutre represents a single row in the SNMP table, and is mostly
 * auto-generated.
 */
typedef struct openserSIPMethodSupportedTable_context_s {

	netsnmp_index index;

	/** OpenSERSIPMethodIdentifier = ASN_UNSIGNED */
	unsigned long openserSIPMethodSupportedIndex;

	/** SnmpAdminString = ASN_OCTET_STR */
	unsigned char *openserSIPMethodName;

	long openserSIPMethodName_len;

	void * data;

} openserSIPMethodSupportedTable_context;


/* Initializes the openserSIPMethodSupportedTable, and populates the tables
 * contents */
void init_openserSIPMethodSupportedTable(void);

/* Defines openserSIPMethodSupportedTable's structure and callback mechanisms */
void initialize_table_openserSIPMethodSupportedTable(void);


/*
 * This routine is called to process get requests for elements of the table.
 *
 * The function is pretty much left as is from the auto-generated code.
 */
int openserSIPMethodSupportedTable_get_value(netsnmp_request_info *,
		netsnmp_index *, netsnmp_table_request_info *);

const openserSIPMethodSupportedTable_context *
	openserSIPMethodSupportedTable_get_by_idx(netsnmp_index *);

const openserSIPMethodSupportedTable_context *
	openserSIPMethodSupportedTable_get_by_idx_rs(netsnmp_index *,
			int row_status);

/*
 * oid declarations
 */
extern oid    openserSIPMethodSupportedTable_oid[];
extern size_t openserSIPMethodSupportedTable_oid_len;

#define openserSIPMethodSupportedTable_TABLE_OID OPENSER_OID,3,1,1,1,1,7

/*
 * column number definitions for table openserSIPMethodSupportedTable
 */
#define COLUMN_OPENSERSIPMETHODSUPPORTEDINDEX  1
#define COLUMN_OPENSERSIPMETHODNAME            2

#define openserSIPMethodSupportedTable_COL_MIN 2
#define openserSIPMethodSupportedTable_COL_MAX 2


#ifdef __cplusplus
}
#endif

#endif /** OPENSERSIPMETHODSUPPORTEDTABLE_H */
