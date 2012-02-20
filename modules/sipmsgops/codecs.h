/*
 * $Id: codecs.h 7144 2010-08-19 11:32:40Z andreidragus $
 *
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Andrei Dragus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * History:
 * ---------
 *  2009-07-23  first version (andreidragus)
 */

#ifndef _CODECS_H
#define	_CODECS_H



int codec_init();

int fixup_codec(void** param, int param_no);
int fixup_codec_regexp(void** param, int param_no);

int codec_find (struct sip_msg* msg, char* str1 );
int codec_delete (struct sip_msg* msg, char* str1 );
int codec_move_up (struct sip_msg* msg, char* str1 );
int codec_move_down (struct sip_msg* msg, char* str1 );

int codec_find_re (struct sip_msg* msg, char* str1);
int codec_delete_re (struct sip_msg* msg, char* str1);
int codec_delete_except_re (struct sip_msg* msg, char* str1);
int codec_move_up_re (struct sip_msg* msg, char* str1 );
int codec_move_down_re (struct sip_msg* msg, char* str1 );

int codec_find_clock (struct sip_msg* msg, char* str1,char * str2 );
int codec_delete_clock (struct sip_msg* msg, char* str1,char * str2 );
int codec_move_up_clock (struct sip_msg* msg, char* str1,char * str2 );
int codec_move_down_clock (struct sip_msg* msg, char* str1,char * str2 );




#endif	/* _CODECS_H */

