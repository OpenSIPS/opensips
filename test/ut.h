/*
 * utility functions for writing SIP tests
 *
 * Copyright (C) 2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __TEST_UT_H__
#define __TEST_UT_H__

#include "../parser/msg_parser.h"

/**
 * mk_sip_req - build a SIP message and parse it, thus populating @msg
 * @method: the SIP method
 * @ruri: the SIP Request-URI
 * @msg: output parameter, the parsed message
 *
 * Return: 0 on success, -1 otherwise
 *
 * Note: the returned data is part of a static buffer, so do _not_ reuse the
 * pointers returned by this function concurrently!
 */
int mk_sip_req(const char *method, const char *ruri, struct sip_msg *msg);

#endif /* __TEST_UT_H__ */
