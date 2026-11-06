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

#include "../ipsec_user.h"

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

/* create a user on each address, then release them one by one: every
 * user left must still be found, and a released one must be gone */
static void test_ipsec_users(char *addr1, char *addr2)
{
	struct ipsec_user *u1, *u2;
	struct ip_addr ip1, ip2;

	if (test_ip(addr1, &ip1) < 0 || test_ip(addr2, &ip2) < 0) {
		ok(0, "bad test address %s/%s", addr1, addr2);
		return;
	}

	u1 = ipsec_get_user(&ip1, &impi, &impu);
	ok(u1 != NULL, "user created for %s", addr1);
	u2 = ipsec_get_user(&ip2, &impi, &impu);
	ok(u2 != NULL && u2 != u1, "distinct user created for %s", addr2);
	if (!u1 || !u2)
		return;

	ok(find_user(&ip1) == u1, "user found for %s", addr1);
	ok(find_user(&ip2) == u2, "user found for %s", addr2);

	ipsec_release_user(u1);
	ok(find_user(&ip1) == NULL, "user released for %s", addr1);
	ok(find_user(&ip2) == u2, "user still found for %s after removing %s",
			addr2, addr1);

	ipsec_release_user(u2);
	ok(find_user(&ip2) == NULL, "user released for %s", addr2);

	/* the emptied map takes new users again */
	u1 = ipsec_get_user(&ip1, &impi, &impu);
	ok(u1 != NULL && find_user(&ip1) == u1, "user created again for %s", addr1);
	if (u1)
		ipsec_release_user(u1);
}

/* three siblings under one node: removing the middle one keeps the others */
static void test_ipsec_middle(char *addr1, char *addr2, char *addr3)
{
	struct ipsec_user *u1, *u2, *u3;
	struct ip_addr ip1, ip2, ip3;

	if (test_ip(addr1, &ip1) < 0 || test_ip(addr2, &ip2) < 0 ||
			test_ip(addr3, &ip3) < 0) {
		ok(0, "bad test address %s/%s/%s", addr1, addr2, addr3);
		return;
	}

	u1 = ipsec_get_user(&ip1, &impi, &impu);
	u2 = ipsec_get_user(&ip2, &impi, &impu);
	u3 = ipsec_get_user(&ip3, &impi, &impu);
	ok(u1 && u2 && u3, "users created for %s, %s and %s", addr1, addr2, addr3);
	if (!u1 || !u2 || !u3)
		return;

	ipsec_release_user(u2);
	ok(find_user(&ip2) == NULL, "user released for %s", addr2);
	ok(find_user(&ip1) == u1 && find_user(&ip3) == u3,
			"users still found for %s and %s", addr1, addr3);

	ipsec_release_user(u1);
	ipsec_release_user(u3);
	ok(find_user(&ip1) == NULL && find_user(&ip3) == NULL,
			"users released for %s and %s", addr1, addr3);
}

/* two users on one address: releasing one keeps the other */
static void test_ipsec_same_ip(char *addr)
{
	str impu2 = str_init("sip:other@ims.example.org");
	struct ipsec_user *u1, *u2;
	struct ip_addr ip;

	if (test_ip(addr, &ip) < 0) {
		ok(0, "bad test address %s", addr);
		return;
	}

	u1 = ipsec_get_user(&ip, &impi, &impu);
	u2 = ipsec_get_user(&ip, &impi, &impu2);
	ok(u1 && u2 && u1 != u2, "two users created for %s", addr);
	if (!u1 || !u2)
		return;

	ipsec_release_user(u1);
	ok(find_user(&ip) == NULL, "first user released for %s", addr);
	u1 = ipsec_find_user(&ip, &impi, &impu2);
	ok(u1 == u2, "second user still found for %s", addr);
	if (u1)
		ipsec_release_user(u1);

	ipsec_release_user(u2);
	u1 = ipsec_find_user(&ip, &impi, &impu2);
	ok(u1 == NULL, "second user released for %s", addr);
	if (u1)
		ipsec_release_user(u1);
}

void mod_tests(void)
{
	/* same parent node, then different parents */
	test_ipsec_users("192.0.2.10", "192.0.2.11");
	test_ipsec_users("192.0.2.10", "192.0.3.10");
	test_ipsec_users("192.0.3.10", "192.0.2.10");
	test_ipsec_users("2001:db8::10", "2001:db8::11");
	test_ipsec_users("2001:db8::10", "2001:db8:1::10");
	test_ipsec_middle("192.0.2.10", "192.0.2.11", "192.0.2.12");
	test_ipsec_middle("2001:db8::10", "2001:db8:1::10", "2001:db8:2::10");
	test_ipsec_same_ip("192.0.2.10");
	test_ipsec_same_ip("2001:db8::10");
}
