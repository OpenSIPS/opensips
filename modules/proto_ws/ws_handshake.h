/*
 * Copyright (C) 2015 - OpenSIPS Foundation
 * Copyright (C) 2001-2003 FhG Fokus
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
 *
 *
 * History:
 * -------
 *  2015-02-xx  first version (razvanc)
 */

#ifndef _WS_HANDSHAKE_H_
#define _WS_HANDSHAKE_H_

#include "../../net/net_tcp.h"


struct ws_hs {
	//str resource;					/*!< HTTP resource */
	str key;						/*!< WebSocket Handshake key */
	unsigned version_major;			/*!< WebSocket major version */
	unsigned version_minor;			/*!< WebSocket minor version */
};

int ws_handshake(struct tcp_connection *con);
void ws_hs_clean(struct ws_hs *hs);

#endif /* _WS_HANDSHAKE_H_ */
