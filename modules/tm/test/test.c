/*
 * tm module unit tests
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 * See the project's COPYING file for licensing details.
 */

#include <tap.h>
#include <limits.h>
#include <string.h>

#include "../h_table.h"

/* transactions as a slab allocator places them, @stride apart: every set
 * within half and 1.5 times the average over 64 cells per set, and every
 * run of 8 cells per set reaching half the sets */
static int timer_set_spread(unsigned long base, unsigned long stride,
		int shift, unsigned short sets)
{
	unsigned int cnt[16], win[16], i, used;
	unsigned long n = 64UL * sets, k;
	unsigned short s;

	memset(cnt, 0, sizeof cnt);
	for (k = 0; k < n; k += 8UL * sets) {
		memset(win, 0, sizeof win);
		for (i = 0; i < 8U * sets; i++) {
			s = tm_timer_set_of((void *)(base + (k + i) * stride), shift,
				sets);
			if (s >= sets)
				return 0;
			win[s]++;
			cnt[s]++;
		}
		for (i = 0, used = 0; i < sets; i++)
			used += win[i] != 0;
		if (used * 2 < sets)
			return 0;
	}
	for (i = 0; i < sets; i++)
		if (cnt[i] * 2 < 64 || cnt[i] * 2 > 3 * 64)
			return 0;
	return 1;
}

static void test_timer_set_spread(void)
{
	static const unsigned long base[] = { 0x40001000UL, 0xb6c01040UL,
#if ULONG_MAX > 0xffffffffUL
		0x7f3a12345000UL, 0x55aa00201a40UL,
#endif
	};
	static const unsigned long stride[] = { 64, 128, 1088 };
	static const unsigned short sets[] = { 4, 8, 16 };
	unsigned int b, st, ts, sh, bad = 0, runs = 0;

	for (b = 0; b < sizeof base / sizeof base[0]; b++)
		for (st = 0; st < sizeof stride / sizeof stride[0]; st++)
			for (ts = 0; ts < sizeof sets / sizeof sets[0]; ts++)
				for (sh = 2; sh <= 3; sh++) {
					runs++;
					if (!timer_set_spread(base[b], stride[st], (int)sh,
					        sets[ts])) {
						bad++;
						diag("timer sets: base %lx stride %lu shift %u "
							"sets %u uneven", base[b], stride[st], sh,
							sets[ts]);
					}
				}
	ok(bad == 0, "transactions a fixed stride apart spread over all timer "
		"sets (%u of %u layouts uneven)", bad, runs);
}

void mod_tests(void)
{
	test_timer_set_spread();
}
