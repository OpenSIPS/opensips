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

#include "../../../ip_addr.h"
#include "../../../test/ut.h"

#include "../../../net/trans.h"
#include "../ipsec.h"
#include "../ipsec_user.h"

void ipsec_ctx_timer(unsigned int ticks, void* param);

static str impi = str_init("user@ims.example.org");
static str impu = str_init("sip:user@ims.example.org");

static int test_ip(char *addr, struct ip_addr *ip)
{
	str s;
	struct ip_addr *p;

	init_str(&s, addr);
	p = str2ip(&s);
	if (!p)
		p = str2ip6(&s);
	if (!p)
		return -1;
	*ip = *p;
	return 0;
}

static struct ipsec_user *find_user(struct ip_addr *ip)
{
	struct ipsec_user *user = ipsec_find_user(ip, &impi, &impu);

	/* only the identity is checked: drop the lookup reference */
	if (user)
		ipsec_release_user(user);
	return user;
}

static struct socket_info *test_ipsec_socket(unsigned short port)
{
	struct socket_info_full *it;

	for (it = protos[PROTO_IPSEC].listeners; it; it = it->next)
		if (it->socket_info.port_no == port)
			return &it->socket_info;
	return NULL;
}

static struct ipsec_ctx *test_ipsec_ctx(struct ipsec_user **user,
		enum ipsec_state state)
{
	str ck = str_init("0123456789abcdef0123456789abcdef");
	str ik = str_init("fedcba9876543210fedcba9876543210");
	struct socket_info *ss, *sc;
	struct ipsec_ctx *ctx;
	sec_agree_body_t sa;
	struct ip_addr ip;

	ss = test_ipsec_socket(5100);
	sc = test_ipsec_socket(5101);
	if (!ss || !sc || test_ip("127.0.0.1", &ip) < 0)
		return NULL;

	memset(&sa, 0, sizeof sa);
	sa.mechanism = SEC_AGREE_MECHANISM_IPSEC_3GPP;
	sa.ts3gpp.alg_str = str_init("hmac-sha-1-96");
	sa.ts3gpp.spi_c = 1111;
	sa.ts3gpp.spi_s = 2222;
	sa.ts3gpp.port_c = 6100;
	sa.ts3gpp.port_s = 6101;

	ctx = ipsec_ctx_new(&sa, &ip, ss, sc, &ck, &ik, 0, 0);
	if (!ctx)
		return NULL;
	*user = ipsec_get_user(&ip, &impi, &impu);
	if (!*user) {
		IPSEC_CTX_UNREF(ctx);
		return NULL;
	}
	/* the creation reference stays ours, the user (and tmp) list add theirs */
	ipsec_ctx_push_user(*user, ctx, state);
	return ctx;
}

/* every ctx lookup hands a reference to the caller: releasing it must leave
 * the references of the user list and of the tmp list in place */
static void test_ipsec_ctx_lookup_ref(void)
{
	struct ipsec_user *user;
	struct ipsec_ctx *ctx, *found;
	struct receive_info ri;
	struct ip_addr ip;
	int ref, n;

	ctx = test_ipsec_ctx(&user, IPSEC_STATE_TMP);
	ok(ctx != NULL, "tmp ctx created");
	if (!ctx)
		return;
	ref = ctx->ref;

	memset(&ri, 0, sizeof ri);
	ri.src_port = ctx->ue.port_c;
	ri.dst_port = ctx->me.port_s;

	for (n = 0; n < ref + 1; n++) {
		found = ipsec_get_ctx_user(user, &ri);
		if (found != ctx || ctx->ref != ref + 1) {
			if (found)
				IPSEC_CTX_UNREF(found);
			break;
		}
		IPSEC_CTX_UNREF(found);
		if (ctx->ref != ref)
			break;
	}
	ok(n == ref + 1, "user lookup by received ports holds a reference "
			"(%d of %d lookups)", n, ref + 1);

	found = ipsec_get_ctx_ip_port(&ctx->ue.ip, ctx->ue.port_s);
	ok(found == ctx && ctx->ref == ref + 1,
			"lookup by UE address holds a reference");
	if (found)
		IPSEC_CTX_UNREF(found);
	ok(ctx->ref == ref, "releasing the lookups keeps the lists' references");

	/* an expired tmp association leaves the user and the tmp list */
	ipsec_ctx_timer(get_ticks() + ipsec_tmp_timeout + 1, NULL);
	ok(ctx->state == IPSEC_STATE_INVALID && ctx->ref == 1,
			"expired tmp ctx is invalid and only referenced by its owner");
	found = ipsec_get_ctx_user(user, &ri);
	ok(found == NULL, "expired tmp ctx is not found in the user");
	if (found)
		IPSEC_CTX_UNREF(found);

	ip = ctx->ue.ip;
	IPSEC_CTX_UNREF(ctx);
	ipsec_release_user(user);
	ok(find_user(&ip) == NULL, "user released with its last ctx");
}

/* an unprotected REGISTER drops the user's temporary associations */
static void test_ipsec_ctx_release_tmp(void)
{
	struct ipsec_user *user;
	struct ipsec_ctx *ctx, *found;
	struct receive_info ri;
	struct ip_addr ip;

	ctx = test_ipsec_ctx(&user, IPSEC_STATE_TMP);
	ok(ctx != NULL, "tmp ctx created");
	if (!ctx)
		return;

	ipsec_ctx_release_tmp_user(user);
	ok(ctx->ref == 1, "released tmp ctx is only referenced by its owner");
	memset(&ri, 0, sizeof ri);
	ri.src_port = ctx->ue.port_c;
	ri.dst_port = ctx->me.port_s;
	found = ipsec_get_ctx_user(user, &ri);
	ok(found == NULL, "released tmp ctx is not found in the user");
	if (found)
		IPSEC_CTX_UNREF(found);

	/* nothing is left for the timer */
	ipsec_ctx_timer(get_ticks() + ipsec_tmp_timeout + 1, NULL);
	ok(ctx->ref == 1, "timer leaves the released tmp ctx alone");

	ip = ctx->ue.ip;
	IPSEC_CTX_UNREF(ctx);
	ipsec_release_user(user);
	ok(find_user(&ip) == NULL, "user released with its last ctx");
}

/* an association confirmed before its tmp entry is removed stays in its user */
static void test_ipsec_ctx_confirmed_tmp(void)
{
	struct ipsec_user *user;
	struct ipsec_ctx *ctx, *found;
	struct receive_info ri;
	struct ip_addr ip;

	ctx = test_ipsec_ctx(&user, IPSEC_STATE_TMP);
	ok(ctx != NULL, "tmp ctx created");
	if (!ctx)
		return;

	lock_get(&ctx->lock);
	ctx->state = IPSEC_STATE_OK;
	lock_release(&ctx->lock);
	ipsec_ctx_timer(get_ticks() + ipsec_tmp_timeout + 1, NULL);
	ok(ctx->state == IPSEC_STATE_OK && ctx->ref == 2,
			"timer drops only the tmp reference of a confirmed ctx");

	memset(&ri, 0, sizeof ri);
	ri.src_port = ctx->ue.port_c;
	ri.dst_port = ctx->me.port_s;
	found = ipsec_get_ctx_user(user, &ri);
	ok(found == ctx, "confirmed ctx is still found in the user");
	if (found)
		IPSEC_CTX_UNREF(found);

	ok(ipsec_ctx_unlink(user, ctx->ue.port_c) == 1 && ctx->ref == 1,
			"confirmed ctx is removed with its list reference");
	ip = ctx->ue.ip;
	IPSEC_CTX_UNREF(ctx);
	ipsec_release_user(user);
	ok(find_user(&ip) == NULL, "user released with its last ctx");
}

/* an SA shared by several contacts of the user is removed only once */
static void test_ipsec_ctx_unlink_shared(void)
{
	struct ipsec_user *user;
	struct ipsec_ctx *ctx, *found;
	struct receive_info ri;
	struct ip_addr ip;
	int ref;

	ctx = test_ipsec_ctx(&user, IPSEC_STATE_OK);
	ok(ctx != NULL, "ctx created");
	if (!ctx)
		return;
	ref = ctx->ref;

	ok(ipsec_ctx_unlink(user, ctx->ue.port_c) == 1 && ctx->ref == ref - 1,
			"first contact removes the SA and its list reference");
	ok(ipsec_ctx_unlink(user, ctx->ue.port_c) == 0 && ctx->ref == ref - 1,
			"second contact finds no SA and keeps our reference");

	memset(&ri, 0, sizeof ri);
	ri.src_port = ctx->ue.port_c;
	ri.dst_port = ctx->me.port_s;
	found = ipsec_get_ctx_user(user, &ri);
	ok(found == NULL, "removed SA is not found in the user");
	if (found)
		IPSEC_CTX_UNREF(found);

	ip = ctx->ue.ip;
	IPSEC_CTX_UNREF(ctx);
	ipsec_release_user(user);
	ok(find_user(&ip) == NULL, "user released with its last ctx");
}

void mod_tests(void)
{
	test_ipsec_ctx_lookup_ref();
	test_ipsec_ctx_release_tmp();
	test_ipsec_ctx_confirmed_tmp();
	test_ipsec_ctx_unlink_shared();
}
