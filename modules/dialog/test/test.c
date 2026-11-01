/*
 * Dialog module unit tests
 *
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 * See the project's COPYING file for licensing details.
 */

#include <tap.h>
#include <limits.h>
#include <string.h>

#include "../dlg_vals.h"
#include "../dlg_db_handler.h"
#include "../dlg_profile.h"

static void test_dlg_val_bool(void)
{
	static str true_name = {"bool_true", sizeof("bool_true") - 1};
	static str false_name = {"bool_false", sizeof("bool_false") - 1};
	struct dlg_cell dlg = {0};
	struct dlg_cell restored = {0};
	pv_param_t param = {0};
	pv_value_t val;
	int type;
	int_str isval;
	str *serialized;

	dlg.vals_lock = lock_init_rw();
	ok(dlg.vals_lock != NULL, "initialized dialog value lock");
	if (!dlg.vals_lock)
		return;

	ctx_dialog_set(&dlg);
	param.pvn.type = PV_NAME_INTSTR;
	param.pvn.u.isname.type = AVP_NAME_STR;

	param.pvn.u.isname.name.s = true_name;
	val = pv_true;
	val.flags |= PV_VAL_BOOL;
	ok(pv_set_dlg_val(NULL, &param, 0, &val) == 0,
		"stored boolean true in dialog value");
	memset(&val, 0, sizeof val);
	ok(pv_get_dlg_val(NULL, &param, &val) == 0,
		"fetched boolean true from dialog value");
	ok(val.flags & PV_VAL_BOOL,
		"dialog value true retains its boolean type");
	ok((val.flags & PV_VAL_STR) && val.rs.len == 4 &&
		memcmp(val.rs.s, "true", 4) == 0,
		"dialog value true retains its string representation");

	param.pvn.u.isname.name.s = false_name;
	val = pv_false;
	val.flags |= PV_VAL_BOOL;
	ok(pv_set_dlg_val(NULL, &param, 0, &val) == 0,
		"stored boolean false in dialog value");
	memset(&val, 0, sizeof val);
	ok(pv_get_dlg_val(NULL, &param, &val) == 0,
		"fetched boolean false from dialog value");
	ok(val.flags & PV_VAL_BOOL,
		"dialog value false retains its boolean type");
	ok((val.flags & PV_VAL_STR) && val.rs.len == 5 &&
		memcmp(val.rs.s, "false", 5) == 0,
		"dialog value false retains its string representation");

	serialized = write_dialog_vars(&dlg);
	ok(serialized != NULL, "serialized boolean dialog values");
	restored.vals_lock = lock_init_rw();
	ok(restored.vals_lock != NULL, "initialized restored dialog value lock");
	if (serialized && restored.vals_lock) {
		read_dialog_vars(serialized->s, serialized->len, &restored);
		ok(fetch_dlg_value(&restored, &true_name, &type, &isval, 0) == 0 &&
			type == DLG_VAL_TYPE_INT && isval.n == 1,
			"legacy dialog API exposes boolean values as integers");
		ok(fetch_dlg_value_typed(&restored, &true_name, &type,
			&isval, 0) == 0 &&
			type == DLG_VAL_TYPE_BOOL && isval.n == 1,
			"persisted dialog true retains its boolean type");
		ok(fetch_dlg_value_typed(&restored, &false_name, &type,
			&isval, 0) == 0 &&
			type == DLG_VAL_TYPE_BOOL && isval.n == 0,
			"persisted dialog false retains its boolean type");
	}

	val.flags = PV_VAL_INT|PV_TYPE_INT;
	val.ri = 7;
	ok(pv_set_dlg_val(NULL, &param, 0, &val) == 0,
		"overwrote dialog boolean with plain integer");
	memset(&val, 0, sizeof val);
	ok(pv_get_dlg_val(NULL, &param, &val) == 0 &&
		!(val.flags & PV_VAL_BOOL) && val.ri == 7,
		"plain integer assignment clears dialog boolean type");

	pv_set_dlg_val(NULL, &param, 0, NULL);
	param.pvn.u.isname.name.s = true_name;
	pv_set_dlg_val(NULL, &param, 0, NULL);
	ctx_dialog_set(NULL);
	lock_destroy_rw(dlg.vals_lock);
	if (restored.vals_lock) {
		store_dlg_value(&restored, &true_name, NULL,
			DLG_VAL_TYPE_NONE);
		store_dlg_value(&restored, &false_name, NULL,
			DLG_VAL_TYPE_NONE);
		lock_destroy_rw(restored.vals_lock);
	}
}

/* dialogs @stride apart in a profile without values: every bucket within
 * half and 1.5 times the average over 64 dialogs per bucket, and every run
 * of 8 dialogs per bucket reaching half the buckets */
static int profile_bucket_spread(unsigned long base, unsigned long stride,
		unsigned int size)
{
	unsigned int cnt[64], win[64], i, b, used;
	unsigned long n = 64UL * size, k;

	memset(cnt, 0, sizeof cnt);
	for (k = 0; k < n; k += 8UL * size) {
		memset(win, 0, sizeof win);
		for (i = 0; i < 8 * size; i++) {
			b = dlg_profile_ptr_bucket((void *)(base + (k + i) * stride),
				size);
			if (b >= size)
				return 0;
			win[b]++;
			cnt[b]++;
		}
		for (i = 0, used = 0; i < size; i++)
			used += win[i] != 0;
		if (used * 2 < size)
			return 0;
	}
	for (i = 0; i < size; i++)
		if (cnt[i] * 2 < 64 || cnt[i] * 2 > 3 * 64)
			return 0;
	return 1;
}

static void test_dlg_profile_buckets(void)
{
	static const unsigned long base[] = { 0x40001000UL, 0xb6c01040UL,
#if ULONG_MAX > 0xffffffffUL
		0x7f3a12345000UL, 0x55aa00201a40UL,
#endif
	};
	static const unsigned long stride[] = { 8, 64, 576 };
	static const unsigned int size[] = { 16, 64 };
	unsigned int b, st, sz, bad = 0, runs = 0;

	for (b = 0; b < sizeof base / sizeof base[0]; b++)
		for (st = 0; st < sizeof stride / sizeof stride[0]; st++)
			for (sz = 0; sz < sizeof size / sizeof size[0]; sz++) {
				runs++;
				if (!profile_bucket_spread(base[b], stride[st], size[sz])) {
					bad++;
					diag("profile buckets: base %lx stride %lu size %u "
						"uneven", base[b], stride[st], size[sz]);
				}
			}
	ok(bad == 0, "dialogs a fixed stride apart spread over all buckets of a "
		"profile without values (%u of %u layouts uneven)", bad, runs);
}

void mod_tests(void)
{
	test_dlg_val_bool();
	test_dlg_profile_buckets();
}
