/*
 *
 * Header file for blackwhite MI functions
 *
 * Copyright (C) 2016 ipport.net
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


#ifndef _BLACKWHITE_MI_H_
#define _BLACKWHITE_MI_H_


#include "../../mi/mi.h"


#define MI_BW_RELOAD "bw_reload"
#define MI_BW_DUMP "bw_dump"


struct mi_root* mi_bw_reload(struct mi_root *cmd, void *param);

struct mi_root* mi_bw_dump(struct mi_root *cmd, void *param);


#endif
