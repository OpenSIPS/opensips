/*
 * Copyright (C) 2007 Voice Sistem SRL
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
 *
 * History:
 * ---------
 *  2007-06-25  first version (ancuta)
 */

#ifndef _MI_DATAGRAM_WRITER_H_
#define _MI_DATAGRAM_WRITER_H_

#include <stdio.h>

int  mi_datagram_writer_init( unsigned int size, char *ident);

int mi_datagram_write_tree( datagram_stream * dtgram, struct mi_root *tree);
int mi_datagram_flush_tree( datagram_stream * dtgram, struct mi_root *tree);

#endif /* _MI_DATAGRAM_WRITER_H_ */


