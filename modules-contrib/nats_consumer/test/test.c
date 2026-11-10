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
 * Unit tests of the nats_consumer module ("make test-nats_consumer").
 */

#include <tap.h>

#include "../nats_handle_registry.h"
#include "../nats_consumer_proc_internal.h"

#include "nc_ut.h"

void mod_tests(void)
{
	nc_ut_parser();
	nc_ut_parser_adversarial();
	nc_ut_ack_token();
	nc_ut_rpc_ipc_pack();
	nc_ut_slot_prefix_copy();
	nc_ut_consumer_config();
	nc_ut_module();
	nc_ut_reconcile();
	nc_ut_fetch();
	nc_ut_rpc_tunables();
	nc_ut_bind_bounds();
	nc_ut_boot_retry();
	nc_ut_rpc_subject();
	nc_ut_msg_ref();
	nc_ut_ring();   /* private rings: no hold needed */
	nc_ut_ring_spin();
	nc_ut_ack_ipc_actions();
	nc_ut_rpc_wake_ipc();   /* this process's own wake table */
	nc_ut_request();
	nc_ut_push();
	nc_ut_mi();
	nc_ut_doc_bind_examples();

	/* from here on the shared registry, rings and RPC slots are the
	 * suite's alone: the consumer process holds between iterations */
	ok(nc_ut_hold_consumer(1) == 0, "suite: the consumer process holds");
	nc_ut_registry();
	nc_ut_rpc_slot_lifecycle();
	nc_ut_rpc_slot_reaper();
	nc_ut_rpc_ipc_generation();
	nc_ut_rpc_inbox();
	nc_ut_rpc_publish();
	nc_ut_resume();
	nc_ut_request_async();
	nc_ut_mi_stats();
	ok(nc_ut_hold_consumer(0) == 0, "suite: the consumer process goes on");
}
