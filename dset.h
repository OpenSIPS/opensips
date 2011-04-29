/*
 * $Id$
 *
 * Copyright (C) 2001-2004 FhG FOKUS
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*!
 * \file
 * \brief Destination set handling functions
 */


#ifndef _DSET_H
#define _DSET_H

#include "ip_addr.h"
#include "qvalue.h"

struct sip_msg;

extern unsigned int nr_branches;


/*! \brief 
 * Add a new branch to current transaction 
 */
int append_branch(struct sip_msg* msg, str* uri, str* dst_uri, str* path,
		qvalue_t q, unsigned int flags, struct socket_info* force_socket);



/* ! \brief
 * Updates an already created branches
 */
int update_branch(unsigned int idx, str** uri, str** dst_uri, str** path,
		qvalue_t* q, unsigned int* flags, struct socket_info** force_socket);


/*! \brief
 * Get the next branch in the current transaction
 */
char* get_branch( unsigned int idx, int* len, qvalue_t* q, str* dst_uri,
		str* path, unsigned int *flags, struct socket_info** force_socket);


/*! \brief
 * Removes a given branch in the current transaction
 */
int remove_branch( unsigned int idx);


/*! \brief
 * Disable/Enables parallel branch usage (read and write)
 */
void set_dset_state(unsigned char enable);


/*! \brief
 * Empty the array of branches
 */
void clear_branches(void);


/*! \brief
 * Create a Contact header field from the
 * list of current branches
 */
char* print_dset(struct sip_msg* msg, int* len);


/*! \brief 
 * Set the q value of the Request-URI
 */
void set_ruri_q(qvalue_t q);


/*! \brief 
 * Get the q value of the Request-URI
 */
qvalue_t get_ruri_q(void);

int branch_uri2dset( str *new_uri );


/*! \brief
 * Get/set the per branch flags for the RURI (branch 0)
 */
unsigned int getb0flags();
unsigned int setb0flags(unsigned int flags);


/*! \brief
 * Set the per branch flag
 */
int setbflag(unsigned int b_idx, unsigned int mask);


/*! \brief
 * Test the per branch flag
 */
int isbflagset(unsigned int b_idx, unsigned int mask);


/*! \brief
 * Reset the per branch flag
 */
int resetbflag(unsigned int b_idx, unsigned int mask);


#endif /* _DSET_H */
