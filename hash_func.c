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
 *
 * History:
 *---------
 *
 * 2006-01-20 - new_hash1() added; support for configurable hash size
 *              added (bogdan)

 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash_func.h"
#include "dprint.h"
#include "ut.h"


int new_hash2( str call_id, str cseq_nr, unsigned int size )
{
#define h_inc h+=v^(v>>3)
	char* p;
	register unsigned v;
	register unsigned h;
	
	h=0;
	
	
	for (p=call_id.s; p<=(call_id.s+call_id.len-4); p+=4){
		v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
		h_inc;
	}
	v=0;
	for (;p<(call_id.s+call_id.len); p++){ v<<=8; v+=*p;}
	h_inc;
	
	for (p=cseq_nr.s; p<=(cseq_nr.s+cseq_nr.len-4); p+=4){
		v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
		h_inc;
	}
	v=0;
	for (;p<(cseq_nr.s+cseq_nr.len); p++){ v<<=8; v+=*p;}
	h_inc;
	
	h=((h)+(h>>11))+((h>>13)+(h>>23));
	return (h)&(size-1);
}


int new_hash1( str s, unsigned int size )
{
#define h_inc h+=v^(v>>3)
	char* p;
	register unsigned v;
	register unsigned h;
	
	h=0;
	
	for (p=s.s; p<=(s.s+s.len-4); p+=4){
		v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
		h_inc;
	}
	v=0;
	for (;p<(s.s+s.len); p++){ v<<=8; v+=*p;}
	h_inc;
	
	h=((h)+(h>>11))+((h>>13)+(h>>23));
	return (h)&(size-1);
}




