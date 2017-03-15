/*
 * Copyright (C) 2006 Voice Sistem SRL
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
 *  2006-09-25  first version (bogdan)
 */


#ifndef _MI_WRITER_H_
#define _MI_WRITER_H_

#include <stdio.h>

int  mi_writer_init( unsigned int size, char *ident);
void mi_writer_destroy(void);

int mi_write_tree( FILE *stream, struct mi_root *tree, int cmd_is_traced);
int mi_flush_tree(FILE *stream, struct mi_root *tree);

#endif /* _MI_WRITER_H_ */

