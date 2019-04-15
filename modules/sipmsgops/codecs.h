/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef _CODECS_H
#define	_CODECS_H



int codec_init();

int codec_find(struct sip_msg* msg, str* codec, str* clock);
int codec_delete(struct sip_msg* msg, str* codec, str* clock);
int codec_move_up(struct sip_msg* msg, str* codec, str* clock);
int codec_move_down(struct sip_msg* msg, str* codec, str* clock);

int codec_find_re (struct sip_msg* msg, regex_t* re);
int codec_delete_re(struct sip_msg* msg, regex_t* re);
int codec_delete_except_re(struct sip_msg* msg, regex_t* re);
int codec_move_up_re(struct sip_msg* msg, regex_t* re);
int codec_move_down_re(struct sip_msg* msg, regex_t* re);

int stream_find(struct sip_msg* msg, regex_t* re);
int stream_delete(struct sip_msg* msg, regex_t* re);



#endif	/* _CODECS_H */

