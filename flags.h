/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * \brief Flag management
 */


#ifndef _FLAGS_H
#define _FLAGS_H

#include <limits.h>

typedef unsigned int flag_t;

#define MAX_FLAG  ((unsigned int)( sizeof(flag_t) * CHAR_BIT - 1 ))

struct sip_msg;

int flag_in_range( flag_t flag );

int setflag( struct sip_msg* msg, flag_t flag );
int resetflag( struct sip_msg* msg, flag_t flag );
int isflagset( struct sip_msg* msg, flag_t flag );
int flag_idx2mask(int *flag);


unsigned int fixup_flag(unsigned int idx);

int setsflagsval( unsigned int val );
int setsflag( unsigned int mask );
int resetsflag( unsigned int mask );
int issflagset( unsigned int mask );
unsigned int getsflags();

#endif
