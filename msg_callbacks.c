/*
 * Copyright (C) 2010 Sippy Software, Inc., http://www.sippysoft.com
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

#include "parser/msg_parser.h"
#include "mem/mem.h"
#include "msg_callbacks.h"

struct msg_callback {
    cb_type_t cb_type;
    cb_func_t cb_func;
    void *cb_arg;
    struct msg_callback *next;
};

int
msg_callback_add(struct sip_msg *msg, cb_type_t cb_type, cb_func_t cb_func, void *cb_arg)
{
    struct msg_callback *msg_cb;

    switch (cb_type) {
    case REQ_PRE_FORWARD:
        if (msg->first_line.type == SIP_REQUEST)
            break;
        LM_ERR("programmatic error - REQ_PRE_FORWARD can only be registered on requests!");
        return (-1);

    default:
        break;
    }

    msg_cb = pkg_malloc(sizeof(*msg_cb));
    if (msg_cb == NULL) {
        LM_ERR("can't allocate memory\n");
        return (-1);
    }
    msg_cb->cb_type = cb_type;
    msg_cb->cb_func = cb_func;
    msg_cb->cb_arg = cb_arg;
    msg_cb->next = msg->msg_cb;
    msg->msg_cb = msg_cb;
    return 0;
}

void
msg_callback_process(struct sip_msg *msg, cb_type_t cb_type, void *core_arg)
{
    struct msg_callback *msg_cb;
    struct msg_callback *msg_cb_pre;

    for (msg_cb = msg->msg_cb; msg_cb != NULL; msg_cb = msg_cb->next) {
        if (msg_cb->cb_type != cb_type) {
            continue;
        }
        /* Execute callback */
        msg_cb->cb_func(msg, cb_type, msg_cb->cb_arg, core_arg);
    }
    if (cb_type != MSG_DESTROY)
        return;
    for (msg_cb_pre = msg->msg_cb; msg_cb_pre != NULL; msg_cb_pre = msg_cb) {
        msg_cb = msg_cb_pre->next;
        pkg_free(msg_cb_pre);
    }
    msg->msg_cb = NULL;
}

int
msg_callback_check(struct sip_msg *msg, cb_type_t cb_type, cb_func_t cb_func)
{
    struct msg_callback *msg_cb;

    for (msg_cb = msg->msg_cb; msg_cb != NULL; msg_cb = msg_cb->next) {
        if (msg_cb->cb_func == cb_func && msg_cb->cb_type == cb_type)
            return (1);
    }
    return (0);
}
