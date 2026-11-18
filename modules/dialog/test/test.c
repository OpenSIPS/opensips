/*
 * Dialog module unit tests
 *
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 * See the project's COPYING file for licensing details.
 */

#include <stdlib.h>
#include <limits.h>
#include <tap.h>

#include "../dlg_vals.h"
#include "../dlg_db_handler.h"
#include "../dlg_timer.h"

#ifndef FAKE_DIALOG_TL
#define FAKE_DIALOG_TL ((struct dlg_tl*)-1)
#endif
#include "../dlg_timer_wheel.h"

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

/*
 * Lifetime timer wheel (dlg_timer_wheel.h), checked against a plain model:
 * every entry is due at one second and must come out of the timer at the
 * first look at or after that second, exactly once, unless it was removed
 * or moved before.
 */
struct wheel_ent {
	struct dlg_tl tl;   /* first: an entry is found from its tl */
	unsigned int due;
	int in;
	unsigned int out;   /* the second it came out at, in w_run() */
	int outs;           /* and how many times it did */
};

static struct dlg_timer w_timer;
static struct wheel_ent *w_ent;
static unsigned int w_n, w_in;
static int w_bad;
static unsigned long long w_rs = 88172645463325252ULL;

static unsigned int w_rnd(void)
{
	w_rs ^= w_rs << 13; w_rs ^= w_rs >> 7; w_rs ^= w_rs << 17;
	return (unsigned int)(w_rs >> 11);
}

#define W_FAIL(...) do { if (!w_bad++) diag(__VA_ARGS__); } while (0)

static void w_setup(unsigned int entries, unsigned int now)
{
	w_n = entries; w_in = 0; w_bad = 0;
	w_ent = calloc(entries, sizeof *w_ent);
	w_timer.wheel = malloc(DLG_WHEEL_SIZE * sizeof(struct dlg_tl));
	dlg_wheel_init(w_timer.wheel);
	w_timer.wheel_done = now;
}

static void w_teardown(void)
{
	free(w_ent);
	free(w_timer.wheel);
	w_timer.wheel = NULL;
}

/* lifetimes as a switch sees them: one second, the 32 s of an
 * unacknowledged 200 OK, a minute, an hour, four hours, zero, anything up
 * to past a turn of the wheel */
static unsigned int w_lifetime(void)
{
	unsigned int r = w_rnd() % 100;

	if (r < 30) return 32;
	if (r < 45) return 1;
	if (r < 60) return 61;
	if (r < 70) return 3600;
	if (r < 82) return 14400;
	if (r < 85) return 0;
	if (r < 95) return 1 + w_rnd() % 120;
	return w_rnd() % (3 * DLG_WHEEL_SIZE);
}

static void w_put(struct wheel_ent *x, unsigned int timeout)
{
	x->tl.timeout = timeout;
	dlg_wheel_insert(&w_timer, &x->tl);
	/* only a second that was looked at already moves, to the next one */
	if (x->tl.timeout != timeout &&
			(DLG_TICK_AFTER(timeout, w_timer.wheel_done) ||
			x->tl.timeout != w_timer.wheel_done + 1))
		W_FAIL("insert changed timeout %u to %u", timeout, x->tl.timeout);
	x->due = x->tl.timeout;
	x->in = 1; w_in++;
}

static void w_take(struct wheel_ent *x)
{
	/* as remove_dlg_timer_unsafe() and its caller do */
	x->tl.prev->next = x->tl.next;
	x->tl.next->prev = x->tl.prev;
	x->tl.next = FAKE_DIALOG_TL; x->tl.prev = NULL; x->tl.timeout = 0;
	x->in = 0; w_in--;
}

/* the timer routine at <now> */
static void w_look(unsigned int now)
{
	struct dlg_tl *tl = dlg_wheel_expired(&w_timer, now), *c;
	unsigned int i;

	while (tl != FAKE_DIALOG_TL) {
		struct wheel_ent *x = (struct wheel_ent *)tl;

		c = tl; tl = tl->next;
		if (!x->in)
			W_FAIL("an entry that is not in the timer came out");
		else if (DLG_TICK_AFTER(x->due, now))
			W_FAIL("an entry came out %u s early", x->due - now);
		if (c->prev != NULL || c->timeout != 0)
			W_FAIL("an entry came out without the expired marks");
		x->in = 0; w_in--;
		c->next = NULL;
	}
	if (w_timer.wheel_done != now)
		W_FAIL("the wheel did not note the second it looked at");
	for (i = 0; i < w_n; i++)
		if (w_ent[i].in && !DLG_TICK_AFTER(w_ent[i].due, now)) {
			W_FAIL("an entry due at %u is still in at %u", w_ent[i].due, now);
			break;
		}
}

static void w_shape(void)
{
	unsigned int s, count = 0;

	for (s = 0; s < DLG_WHEEL_SIZE; s++) {
		struct dlg_tl *h = &w_timer.wheel[s], *t;

		for (t = h->next; t != h; t = t->next) {
			if (t->next->prev != t || t->prev->next != t) {
				W_FAIL("a list of the wheel is broken");
				return;
			}
			if ((t->timeout & DLG_WHEEL_MASK) != s)
				W_FAIL("an entry hangs on the wrong list");
			count++;
		}
	}
	if (count != w_in)
		W_FAIL("the wheel holds %u entries, the model %u", count, w_in);
}

static void test_dlg_wheel_model(const char *name, unsigned int start,
		unsigned int entries, unsigned int seconds, unsigned int per_second)
{
	unsigned int now = start, s, k, i;

	w_setup(entries, now);
	for (s = 0; s < seconds && !w_bad; s++) {
		for (k = 0; k < per_second; k++) {
			struct wheel_ent *x = &w_ent[w_rnd() % entries];

			if (!x->in) {
				w_put(x, now + w_lifetime());
			} else if (w_rnd() % 2) {
				w_take(x);
			} else {   /* update_dlg_timer() */
				w_take(x);
				x->tl.next = NULL;
				w_put(x, now + w_lifetime());
			}
		}
		/* the clock: a second, a few, or more than a turn of the wheel */
		i = w_rnd() % 1000;
		now += i < 960 ? 1 : i < 995 ? 2 + w_rnd() % 30 :
			i < 999 ? DLG_WHEEL_SIZE / 2 + w_rnd() % DLG_WHEEL_SIZE :
			2 * DLG_WHEEL_SIZE + w_rnd() % 100;
		/* the timer routine runs nearly every second, sometimes later */
		if (w_rnd() % 10)
			w_look(now);
		if (s % 257 == 0)
			w_shape();
	}
	w_look(now);
	w_shape();
	now += 4 * DLG_WHEEL_SIZE;
	w_look(now);
	ok(!w_bad && w_in == 0, "dialog timer wheel: %s", name);
	w_teardown();
}

/* A timeout written in place (as the DB sync of a known dialog does) instead
 * of through update_dlg_timer(): a later one must not be served a turn of
 * the wheel late, an earlier one no later than its old second. */
static void test_dlg_wheel_in_place_change(void)
{
	unsigned int now = 5000, t;
	struct wheel_ent *later, *earlier;
	unsigned int later_out = 0, earlier_out = 0;
	struct dlg_tl *tl;

	w_setup(2, now);
	later = &w_ent[0];
	earlier = &w_ent[1];
	w_put(later, now + 100);
	w_put(earlier, now + 200);
	later->tl.timeout = later->due = now + 5000;
	earlier->tl.timeout = earlier->due = now + 50;

	for (t = now + 1; t <= now + 6000; t++) {
		for (tl = dlg_wheel_expired(&w_timer, t); tl != FAKE_DIALOG_TL;
				tl = tl->next) {
			if (tl == &later->tl)
				later_out = t;
			else if (tl == &earlier->tl)
				earlier_out = t;
		}
	}
	ok(later_out == now + 5000,
		"dialog timer wheel: a timeout raised in place expires on time");
	ok(earlier_out >= now + 50 && earlier_out <= now + 200,
		"dialog timer wheel: a timeout lowered in place expires by its old second");
	w_teardown();
}

/* the timer routine at every second from <from> to <to>, noting for each
 * entry when it came out */
static void w_run(unsigned int from, unsigned int to)
{
	struct dlg_tl *tl;
	unsigned int t;

	for (t = from; ; t++) {
		for (tl = dlg_wheel_expired(&w_timer, t); tl != FAKE_DIALOG_TL;
				tl = tl->next) {
			((struct wheel_ent *)tl)->out = t;
			((struct wheel_ent *)tl)->outs++;
		}
		if (t == to)
			break;
	}
}

#define W_OUT_AT(_x, _t) ((_x)->outs == 1 && (_x)->out == (_t))

/* The tick counter wrapping around: the entries on both sides of the wrap
 * come out at their second, and the wheel goes on turning after it. */
static void test_dlg_wheel_wrap(void)
{
	unsigned int now = UINT_MAX - 10;

	w_setup(5, now);
	w_put(&w_ent[0], now + 8);                    /* before the wrap */
	w_put(&w_ent[1], now + 10);                   /* the last tick */
	w_put(&w_ent[2], now + 11);                   /* tick 0 */
	w_put(&w_ent[3], now + 16);                   /* tick 5 */
	w_put(&w_ent[4], now + 16 + DLG_WHEEL_SIZE);  /* its list, a turn later */
	w_run(now + 1, now + 16 + DLG_WHEEL_SIZE + 5);
	ok(W_OUT_AT(&w_ent[0], now + 8) && W_OUT_AT(&w_ent[1], UINT_MAX) &&
		W_OUT_AT(&w_ent[2], 0) && W_OUT_AT(&w_ent[3], 5) &&
		W_OUT_AT(&w_ent[4], 5 + DLG_WHEEL_SIZE),
		"dialog timer wheel: entries around the wrap of the tick counter expire on time");
	w_teardown();

	/* the last list looked at is the one of the last tick */
	w_setup(1, UINT_MAX);
	w_put(&w_ent[0], 5);
	w_run(0, 10);
	ok(W_OUT_AT(&w_ent[0], 5) && w_timer.wheel_done == 10,
		"dialog timer wheel: the wheel turns on after the last tick of the counter");
	w_teardown();
}

void mod_tests(void)
{
	test_dlg_val_bool();
	test_dlg_wheel_model("few entries, every second checked", 1000,
		300, 100000, 6);
	test_dlg_wheel_model("thousands of dialogs in progress", 1000,
		20000, 20000, 900);
	test_dlg_wheel_model("across the wrap of the tick counter",
		UINT_MAX - 20000, 300, 100000, 6);
	test_dlg_wheel_in_place_change();
	test_dlg_wheel_wrap();
}
