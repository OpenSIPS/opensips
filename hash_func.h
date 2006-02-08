/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 *---------
 *
 * 2006-01-20 - new_hash1() added; support for configurable hash size
 *              added (bogdan)
 */



#ifndef _HASH_H
#define _HASH_H

#include "str.h"

/* always use a power of 2 for hash table size */
#define T_TABLE_POWER    16 
#define TABLE_ENTRIES    (1 << (T_TABLE_POWER))

int new_hash2( str  call_id, str cseq_nr, unsigned int size );

int new_hash1( str s, unsigned int size);

#define hash( cid, cseq) new_hash2( cid, cseq , TABLE_ENTRIES)
#define hash1( s )       new_hash1( cid, TABLE_ENTRIES)


#endif
