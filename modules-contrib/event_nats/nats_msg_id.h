/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 */

/*
 * nats_msg_id.h -- the Nats-Msg-Id header of a JetStream publish.
 *
 * JetStream drops a message whose Nats-Msg-Id it has already stored
 * within the stream's duplicate window.  event_nats sets the id of every
 * JetStream publish:
 *   - an EVI event with a msg_id rule ("EVENT: param, param, ...") gets
 *     "EVENT:value:value..." built from those event parameters, so the
 *     same event raised twice (for example by two servers) is stored once;
 *   - nats_publish() takes the id as its optional third parameter;
 *   - any other publish gets a generated id, unique per message, so a
 *     resend after a lost ack is not stored twice.
 *
 * Pure functions (no OpenSIPS runtime): unit-tested by
 * test/test_msg_id.c.
 */

#ifndef NATS_MSG_ID_H
#define NATS_MSG_ID_H

#include <stdint.h>
#include "../../evi/evi_params.h"

/* longest id, in bytes; buffers are NATS_MSG_ID_BUF with the NUL */
#define NATS_MSG_ID_MAX        255
#define NATS_MSG_ID_BUF        (NATS_MSG_ID_MAX + 1)
#define NATS_MSG_ID_MAX_PARAMS 8
/* most msg_id rules (one per event) */
#define NATS_MSG_ID_MAX_RULES  32

#define NATS_MSG_ID_EMISSING   (-2)   /* a rule parameter is not in the event */
#define NATS_MSG_ID_ETOOLONG   (-3)   /* the id would exceed NATS_MSG_ID_MAX */

/* A parsed msg_id rule.  The str fields point into the modparam string,
 * which lives as long as the process. */
typedef struct nats_msg_id_rule {
	str event;
	int nparams;
	str params[NATS_MSG_ID_MAX_PARAMS];
} nats_msg_id_rule;

/* Parse "EVENT: param, param, ..." (spaces around names allowed).
 * Returns 0, or -1 for: no ':', an empty or space-containing name, no
 * parameter, an empty parameter, more than NATS_MSG_ID_MAX_PARAMS, or a
 * parameter named twice. */
int nats_msg_id_rule_parse(const char *spec, int len, nats_msg_id_rule *r);

/* Write the id of an event raised with @params into @out (@size bytes,
 * NUL-terminated): the event name, then ':' and each rule parameter's
 * value, in the rule's order.  Integers are written in decimal; in
 * strings, ':', '%' and bytes outside 0x21..0x7e are written as %XX.
 * Returns the id length, NATS_MSG_ID_EMISSING or NATS_MSG_ID_ETOOLONG. */
int nats_msg_id_build(const nats_msg_id_rule *r, const evi_params_t *params,
		char *out, int size);

/* An id given by the script: 1..NATS_MSG_ID_MAX bytes, each in 0x21..0x7e
 * (no space, no control byte, no CR/LF that would end the header).
 * Returns 0 or -1. */
int nats_msg_id_check(const char *id, int len);

/* The generated id "<prefix as 16 hex digits>-<seq in decimal>" into @out.
 * Returns the length, or -1 if @size is too small. */
int nats_msg_id_generated(uint64_t prefix, uint64_t seq, char *out, int size);

#endif /* NATS_MSG_ID_H */
