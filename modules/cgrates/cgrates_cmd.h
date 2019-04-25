/*
 * Copyright (C) 2017 Răzvan Crainea <razvan@opensips.org>
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

#ifndef _CGRATES_CMD_H_
#define _CGRATES_CMD_H_

/*
 * Sends a generic command to CGRateS
 * Input:
 *  - account
 *  - destination (optional)
 * Returns:
 *  -  1: user is allowed to call
 *  - -1: internal error
 *  - -2: cgrates error
 *  - -3: no suitable cgrates server found
 */
int w_cgr_cmd(struct sip_msg* msg, str* cmd, str *tag_c);

/* async version of w_cgr_auth */
int w_acgr_cmd(struct sip_msg* msg, async_ctx *actx, str* cmd, str *tag_c);

#endif /* _CGRATES_CMD_H_ */

