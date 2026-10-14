/*
 * Copyright (C) 2026 OpenSIPS Solutions
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

#include <tap.h>

#include "../../../str.h"
#include "../../../mem/mem.h"
#include "../../../mem/shm_mem.h"
#include "../../../context.h"
#include "../../../cmds.h"
#include "../../../sr_module.h"
#include "../../../parser/msg_parser.h"

#include "../../proto_hep/hep.h"
#include "../../proto_hep/hep_cb.h"


typedef int (*relay_f)(struct sip_msg *msg);

/* run hep_relay() for a HEPv3 message carrying a @payload_len payload */
static int relay_hepv3(int payload_len)
{
	static char dst[] = "sip:127.0.0.1:9062";
	const cmd_export_t *cmd;
	proto_hep_api_t api;
	load_hep_f load_hep;
	struct hep_context *hctx;
	struct sip_msg msg;
	context_p ctx;
	char *payload;
	int ret;

	cmd = find_cmd_export_t("hep_relay", 0);
	load_hep = (load_hep_f)find_export("load_hep", 0);
	if (!cmd || !load_hep || load_hep(&api) < 0)
		return -2;

	hctx = shm_malloc(sizeof *hctx);
	payload = pkg_malloc(payload_len);
	ctx = context_alloc(CONTEXT_GLOBAL);
	if (!hctx || !payload || !ctx)
		return -2;
	memset(hctx, 0, sizeof *hctx);
	memset(payload, 'a', payload_len);
	memset(ctx, 0, context_size(CONTEXT_GLOBAL));

	hctx->h.version = 3;
	hctx->h.u.hepv3.payload_chunk.chunk.type_id = HEP_PAYLOAD;
	hctx->h.u.hepv3.payload_chunk.chunk.length =
		payload_len + sizeof(hep_chunk_t);
	hctx->h.u.hepv3.payload_chunk.data = payload;

	context_put_ptr(CONTEXT_GLOBAL, ctx, api.get_hep_ctx_id(), hctx);
	set_global_context(ctx);

	memset(&msg, 0, sizeof msg);
	msg.dst_uri.s = dst;
	msg.dst_uri.len = sizeof dst - 1;

	ret = ((relay_f)cmd->function)(&msg);

	set_global_context(NULL);
	pkg_free(payload);
	shm_free(hctx);
	return ret;
}


static void test_hep_relay_size(void)
{
	ok(relay_hepv3(100) == 1, "small HEPv3 packet is relayed");
	ok(relay_hepv3(40000) == 1,
		"HEPv3 packet larger than the capture payload buffer is relayed");
	/* the payload chunk alone takes the whole 16 bit HEPv3 length */
	ok(relay_hepv3(65535 - sizeof(hep_chunk_t)) < 0,
		"HEPv3 packet longer than a HEP frame is not relayed");
}


void mod_tests(void)
{
	test_hep_relay_size();
}
