/*
 * Header file for PIKE MI functions
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2006-12-05  created (bogdan)
 */


#ifndef _PIKE_MI_H_
#define _PIKE_MI_H_

#include "../../mi/mi.h"

#define MI_PIKE_LIST      "pike_list"
#define MI_PIKE_RM        "pike_rm"

struct mi_root* mi_pike_list(struct mi_root* cmd_tree, void* param);
struct mi_root* mi_pike_rm(struct mi_root *cmd, void *param);

#endif


