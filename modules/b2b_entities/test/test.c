/*
 * Copyright (C) 2026 Alejandro Pacheco
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
#include <stdio.h>

#include "../../../str.h"
#include "../../../mem/shm_mem.h"
#include "../../../parser/msg_parser.h"
#include "../../../parser/parse_methods.h"
#include "../../tm/h_table.h"
#include "../../tm/t_hooks.h"
#include "../dlg.h"
#include "../b2b_entities.h"

static char reply_180[] =
	"SIP/2.0 180 Ringing\r\n"
	"Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK1\r\n"
	"From: <sip:a@127.0.0.1>;tag=ftag1\r\n"
	"To: <sip:b@127.0.0.2>;tag=ttag1\r\n"
	"Call-ID: %.*s\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:b@127.0.0.2>\r\n"
	"Content-Length: 0\r\n\r\n";

/* insert an early client dialog pinned by a reference (a request being
 * processed, or one being sent, with the entity lock dropped), deleted or
 * not meanwhile, and run b2b_tm_cback() with the first provisional reply
 * of its INVITE; returns the pinned dialog, with the bucket locked */
static b2b_dlg_t *pinned_early_reply(int id, unsigned int hash_index,
		int deleted, struct cell *t)
{
	static str ftag = str_init("ftag1");
	static str contact = str_init("sip:b2b@127.0.0.1");
	static str inv = str_init("INVITE");
	struct tmcb_params ps;
	struct sip_msg msg;
	b2b_dlg_t *dlg;
	str *key, key_copy;
	void *param;
	char buf[1024], kbuf[B2B_MAX_KEY_SIZE];
	int len;

	dlg = shm_malloc(sizeof *dlg);
	if (!dlg)
		return NULL;
	memset(dlg, 0, sizeof *dlg);
	dlg->tag[CALLER_LEG] = ftag;
	dlg->contact[CALLER_LEG] = contact;
	dlg->state = B2B_NEW;
	dlg->last_method = METHOD_INVITE;
	dlg->id = id;
	dlg->db_flag = NO_UPDATEDB_FLAG;

	key = b2b_htable_insert(client_htable, dlg, hash_index, NULL,
		B2B_CLIENT, 0, 0, 0);
	if (!key)
		return NULL;
	memcpy(kbuf, key->s, key->len);
	key_copy.s = kbuf;
	key_copy.len = key->len;
	dlg->callid = key_copy;

	memset(t, 0, sizeof *t);
	t->method = inv;
	dlg->uac_tran = t;
	/* pinned, as b2b_prescript_f() and b2b_send_req() leave it */
	dlg->ref = 1;
	dlg->deleted = deleted;

	len = snprintf(buf, sizeof buf, reply_180, key_copy.len, key_copy.s);
	memset(&msg, 0, sizeof msg);
	msg.buf = buf;
	msg.len = len;
	if (parse_msg(buf, len, &msg) != 0)
		return NULL;

	memset(&ps, 0, sizeof ps);
	ps.code = 180;
	ps.rpl = &msg;
	param = &key_copy;
	ps.param = &param;

	b2b_tm_cback(t, client_htable, &ps);

	B2BE_LOCK_GET(client_htable, hash_index);
	return dlg;
}

/* the pinned dialog is replaced in the table, but must stay allocated,
 * marked deleted, for the holder of the reference to release it */
static void test_early_reply_keeps_pinned_dlg(void)
{
	unsigned int hash_index = 1;
	struct cell t;
	b2b_dlg_t *dlg, *it;
	int found = 0;

	dlg = pinned_early_reply(7, hash_index, 0, &t);
	if (!dlg) {
		ok(0, "early reply on a pinned dialog");
		return;
	}

	for (it = client_htable[hash_index].first; it; it = it->next)
		if (it != dlg && it->id == 7)
			found = 1;
	ok(found, "the early dialog is replaced in the table on the first reply");
	ok(dlg->deleted && !dlg->uac_tran,
		"the pinned dialog is kept, marked deleted, without its transaction");

	/* the last unref of the holder frees it */
	dlg->ref = 0;
	shm_free(dlg);
	B2BE_LOCK_RELEASE(client_htable, hash_index);
}

/* a dialog deleted while pinned is not replaced (brought back) */
static void test_early_reply_keeps_deleted_dlg(void)
{
	unsigned int hash_index = 2;
	struct cell t;
	b2b_dlg_t *dlg, *it;
	int self = 0, other = 0;

	dlg = pinned_early_reply(8, hash_index, 1, &t);
	if (!dlg) {
		ok(0, "early reply on a deleted pinned dialog");
		return;
	}

	for (it = client_htable[hash_index].first; it; it = it->next) {
		if (it == dlg)
			self = 1;
		else if (it->id == 8)
			other = 1;
	}
	ok(self && !other, "a deleted pinned dialog is not replaced");

	/* the last unref of the holder deletes it */
	dlg->uac_tran = NULL;
	dlg->ref = 0;
	b2b_delete_record(dlg, client_htable, hash_index);
	B2BE_LOCK_RELEASE(client_htable, hash_index);
}

void mod_tests(void)
{
	test_early_reply_keeps_pinned_dlg();
	test_early_reply_keeps_deleted_dlg();
}
