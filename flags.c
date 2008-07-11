/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice Sistem SRL
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
 *
 * History:
 * --------
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2006-12-22  added script flags (bogdan)
 */

/*!
 * \file
 * \brief OpenSIPS configuration flag functions.
 */


#include "sr_module.h"
#include "dprint.h"
#include "parser/msg_parser.h"
#include "flags.h"

/*********************** msg flags ****************************/

int setflag( struct sip_msg* msg, flag_t flag ) {
	msg->flags |= 1 << flag;
	return 1;
}

int resetflag( struct sip_msg* msg, flag_t flag ) {
	msg->flags &= ~ (1 << flag);
	return 1;
}

int isflagset( struct sip_msg* msg, flag_t flag ) {
	return (msg->flags & (1<<flag)) ? 1 : -1;
}

int flag_in_range( flag_t flag ) {
	if ( flag > MAX_FLAG ) {
		LM_ERR("message flag (%d) must be in range %d..%d\n",
			flag, 1, MAX_FLAG );
		return 0;
	}
	return 1;
}

int flag_idx2mask(int *flag)
{
	if (*flag<0) {
		*flag = 0;
	} else if (*flag>(int)MAX_FLAG) {
		LM_ERR("flag %d out of range\n",*flag);
		return -1;
	} else {
		*flag = 1<<(*flag);
	}
	return 0;
}



/*********************** script flags ****************************/

static unsigned int sflags = 0;

unsigned int fixup_flag(unsigned int idx)
{
	if (idx>MAX_FLAG) {
		LM_ERR("flag (%d) out of range %d..%d\n",
			idx, 0, MAX_FLAG );
		return 0;
	}
	return (1<<idx);
}

int setsflagsval( unsigned int val )
{
	sflags = val;
	return 1;
}

int setsflag( unsigned int mask )
{
	sflags |= mask;
	return 1;
}

int resetsflag( unsigned int mask )
{
	sflags &= ~ mask;
	return 1;
}

int issflagset( unsigned int mask )
{
	return ( sflags & mask) ? 1 : -1;
}

unsigned int getsflags(void)
{
	return sflags;
}


