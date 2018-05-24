/*
 * Path handling for intermediate proxies.
 *
 * Copyright (C) 2006 Inode GmbH (Andreas Granig <andreas.granig@inode.info>)
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
 */


#ifndef __PATH_H
#define __PATH_H

#include "../parser/msg_parser.h"

#define PATH_PREFIX		"Path: <sip:"
#define PATH_PREFIX_LEN		(sizeof(PATH_PREFIX)-1)

#define PATH_LR_PARAM		";lr"
#define PATH_LR_PARAM_LEN	(sizeof(PATH_LR_PARAM)-1)

#define PATH_RC_PARAM		";received="
#define PATH_RC_PARAM_LEN	(sizeof(PATH_RC_PARAM)-1)

#define PATH_TRANS_PARAM	";transport="
#define PATH_TRANS_PARAM_LEN	(sizeof(PATH_TRANS_PARAM)-1)

#define PATH_ESC_TRANS_PARAM	"\%3btransport\%3d"
#define PATH_ESC_TRANS_PARAM_LEN	(sizeof(PATH_ESC_TRANS_PARAM)-1)

#define	PATH_CRLF		">\r\n"
#define PATH_CRLF_LEN		(sizeof(PATH_CRLF)-1)

#define PATH_R2 ";r2=on"
#define PATH_R2_LEN (sizeof(PATH_R2)-1)

int prepend_path(struct sip_msg* _m, str *user, int recv, int double_path);

#endif /* __PATH_H */
