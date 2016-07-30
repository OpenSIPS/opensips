/*
 * Copyright (C) 2009 Sippy Software, Inc., http://www.sippysoft.com
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

/*
 * This is a mechanism to register per-message callback handlers
 * to be called at certain points of the message lifecycle.
 *
 * Apart from the sip_msg structure, each handler is passed a
 * pointer to a handler type-specific structure from the core
 * and pointer to an opaque structure allocated by the module.
 *
 * The following callback types are supported:
 *
 * REQ_PRE_FORWARD - called before the request is getting reassembled
 * for delively. Can be used to apply some last-minute transformations.
 * Depending on the script structure this handler may not be called for
 * a particular message at all or can be called multiple times. Core will
 * pass "struct proxy *" to the handler describing destination for the
 * current request.
 *
 * MSG_DESTROY - called when the message is being freed. Can be used to
 * release any module-specific per-message resources, including any
 * dynamic structures passed to the msg_callback_add(). Once
 * registered, this handler is guranteed to be invoked exactly once for
 * each message.
 *
 * To avoid memory leaks, code that allocates dynamic structures for use
 * in the callback handlers should always register MSG_DESTROY handler
 * and free all memory in there.
 */


#ifndef _MSG_CALLBACKS_H
#define _MSG_CALLBACKS_H

#include "parser/msg_parser.h"

typedef enum {REQ_PRE_FORWARD, MSG_DESTROY} cb_type_t;

typedef void (*cb_func_t) (struct sip_msg *, cb_type_t, void *, void *);

int msg_callback_add(struct sip_msg *, cb_type_t, cb_func_t, void *);
void msg_callback_process(struct sip_msg *, cb_type_t, void *);
int msg_callback_check(struct sip_msg *, cb_type_t, cb_func_t);

#endif
