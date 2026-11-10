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
 *
 * Unit tests of the event_nats module ("make test-event_nats").  The
 * suite's opensips.cfg points the module at a port nothing listens on: it
 * starts degraded, and the tests put a fake nats module API and libnats
 * (en_ut_fake.c) in place of the bound ones for the length of a scenario.
 */

#include <tap.h>

#include "en_ut.h"

void mod_tests(void)
{
	en_ut_shared_params();   /* first: what the startup forwarded */
	en_ut_degraded();
	en_ut_msg_id();
	en_ut_stats();
	en_ut_publish();
	en_ut_inbound();
	en_ut_subscription();
	en_ut_mi_commands();
	en_ut_mi_seq();
}
