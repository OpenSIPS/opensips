/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

/*!
 * \file
 * \brief Destination set handling functions
 */


#ifndef _DSET_H
#define _DSET_H

#include "ip_addr.h"
#include "qvalue.h"
#include "str.h"
#include "usr_avp.h"


struct msg_branch
{
	str tag;

	str uri;

	str dst_uri;

	str path;

	int q; /* Preference of the contact among contact within the array */

	const struct socket_info* force_send_socket;

	unsigned int bflags;

	struct usr_avp *attrs;
};


struct sip_msg;



int get_dset_size(void);

/*! \brief
 * To be called in the startup phase of OpenSIPS
 */
int init_dset(void);


/*! \brief
 * Disable/Enables parallel branch usage (read and write)
 */
void set_dset_state(unsigned char enable);


/*! \brief
 * Empty the array of branches
 */
void clear_dset(void);


/*! \brief
 * Create a Contact header field from the
 * list of current branches
 */
char* print_dset(struct sip_msg* msg, int* len);





/*! \brief
 * Add a new branch to current transaction
 */
int append_msg_branch(struct msg_branch *branch);


/* ! \brief
 * Updates an already created branches
 */
int update_msg_branch_uri(unsigned int idx, str *val);
int update_msg_branch_dst_uri(unsigned int idx, str *val);
int update_msg_branch_path(unsigned int idx, str *val);
int update_msg_branch_q(unsigned int idx, int val);
int update_msg_branch_socket(unsigned int idx, const struct socket_info* val);
int update_msg_branch_bflags(unsigned int idx, unsigned int val);


/*! \brief
 * Get the next branch in the current transaction
 */
struct msg_branch* get_msg_branch( unsigned int idx);


/*! \brief
 * Removes a given branch in the current transaction
 */
int remove_msg_branch( unsigned int idx);


int msg_branch_uri2dset( str *new_uri );


/*! \brief
 * Moves the branch index idx into the SIP request msg.
 */
int move_msg_branch_to_ruri(int idx, struct sip_msg *msg);


/*! \brief
 * Swaps two branches between. Index -1 means MSG branch
 */
int swap_msg_branches(struct sip_msg *msg, int src_idx, int dst_idx);




/*! \brief
 * Set the per branch flag
 */
int setbflag(struct sip_msg *msg, unsigned int b_idx, unsigned int mask);


/*! \brief
 * Test the per branch flag
 */
int isbflagset(struct sip_msg *msg, unsigned int b_idx, unsigned int mask);


/*! \brief
 * Reset the per branch flag
 */
int resetbflag(struct sip_msg *msg, unsigned int b_idx, unsigned int mask);


/*! \brief
 * Move a branch over another existing one. Index -1 means MSG branch
 * If "keep_src", the source branch will not be deleted -> copy
 */
int move_msg_branch(struct sip_msg *msg, int src_idx, int dst_idx,
		int keep_src);


int get_msg_branch_attr(unsigned int b_idx, int name_id,
		unsigned short *flags, int_str *val);

int set_msg_branch_attr(unsigned int b_idx, int name_id,
		unsigned short flags, int_str val);

struct usr_avp **ruri_branch_attrs_head(void);

#endif /* _DSET_H */
