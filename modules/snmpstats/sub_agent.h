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
 * This file defines all functions required to establish a relationship with a
 * master agent.
 */

#ifndef _SNMPSTATS_SUB_AGENT_
#define _SNMPSTATS_SUB_AGENT_

#define AGENT_PROCESS_NAME   "snmpstats_sub_agent"

/* Run the AgentX sub-agent as a separate process.  The child will
 * insulate itself from the rest of OpenSIPS by overriding most of signal
 * handlers. */
void agentx_child(int rank);

/* This function opens up a connection with the master agent specified in
 * the snmpstats modules configuration file */
void register_with_master_agent(char *name_to_register_under);

#endif
