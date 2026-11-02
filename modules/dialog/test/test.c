/*
 * Dialog module unit tests
 *
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 * See the project's COPYING file for licensing details.
 */

#include <tap.h>

#include "../dlg_vals.h"
#include "../dlg_db_handler.h"

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

void mod_tests(void)
{
	test_dlg_val_bool();
}
