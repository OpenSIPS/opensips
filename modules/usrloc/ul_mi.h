/*
 * Header file for USRLOC MI functions
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
 */

/*! \file
 *  \brief USRLOC - Usrloc MI functions
 *  \ingroup usrloc
 */


#ifndef _USRLOC_MI_H_
#define _USRLOC_MI_H_

#include "../../mi/mi.h"

#define MI_USRLOC_RM           "ul_rm"
#define MI_USRLOC_RM_CONTACT   "ul_rm_contact"
#define MI_USRLOC_DUMP         "ul_dump"
#define MI_USRLOC_FLUSH        "ul_flush"
#define MI_USRLOC_ADD          "ul_add"
#define MI_USRLOC_SHOW_CONTACT "ul_show_contact"
#define MI_USRLOC_SYNC         "ul_sync"



struct mi_root* mi_usrloc_rm_aor(struct mi_root *cmd, void *param);

struct mi_root* mi_usrloc_rm_contact(struct mi_root *cmd, void *param);

struct mi_root* mi_usrloc_dump(struct mi_root *cmd, void *param);

struct mi_root* mi_usrloc_flush(struct mi_root *cmd, void *param);

struct mi_root* mi_usrloc_add(struct mi_root *cmd, void *param);

struct mi_root* mi_usrloc_show_contact(struct mi_root *cmd, void *param);
struct mi_root* mi_usrloc_sync(struct mi_root *cmd, void *param);


#endif
