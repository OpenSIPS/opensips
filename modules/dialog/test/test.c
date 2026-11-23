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

extern struct dlg_timer *d_timer;

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
	w_timer.first.next = w_timer.first.prev = &w_timer.first;
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

/* A timeout that is given as the tick it ends at (the DB sync of a dialog
 * the node knows already), through update_dlg_timer_deadline() on a timer
 * of our own: a dialog that waits in the timer expires at its new second,
 * whether that is before or after the old one. */
static void test_dlg_timer_deadline(void)
{
	struct dlg_timer *saved = d_timer;
	unsigned int now = 1000;
	struct wheel_ent *cut, *raised, *kept, *extended, *past, *idle, *gone;
	int rc_cut, rc_raised, rc_kept, rc_extended, rc_past;

	w_setup(7, now);
	w_timer.lock = lock_alloc();
	if (w_timer.lock == NULL || lock_init(w_timer.lock) == 0) {
		ok(0, "dialog timer deadline: no lock for the timer of the test");
		w_teardown();
		return;
	}
	d_timer = &w_timer;

	cut = &w_ent[0]; raised = &w_ent[1]; kept = &w_ent[2];
	extended = &w_ent[3]; past = &w_ent[4]; idle = &w_ent[5];
	gone = &w_ent[6];

	/* four hours left, and then 30 seconds */
	w_put(cut, now + 14400);
	rc_cut = update_dlg_timer_deadline(&cut->tl, now + 30, 0);
	/* to past a turn of the wheel */
	w_put(raised, now + 100);
	rc_raised = update_dlg_timer_deadline(&raised->tl, now + 20000, 0);
	/* the longest of the two is kept: an earlier one changes nothing */
	w_put(kept, now + 4000);
	rc_kept = update_dlg_timer_deadline(&kept->tl, now + 2000, 1);
	w_put(extended, now + 4000);
	rc_extended = update_dlg_timer_deadline(&extended->tl, now + 6000, 1);
	/* an end that has passed already: the next second */
	w_put(past, now + 8000);
	rc_past = update_dlg_timer_deadline(&past->tl, now - 100, 0);
	ok(rc_cut == 0 && rc_raised == 0 && rc_kept == 0 && rc_extended == 0 &&
		rc_past == 0,
		"dialog timer deadline: a dialog in the timer stays in the timer");

	/* a moved dialog is in the timer for the others: it can be removed, and
	 * then it is left alone */
	w_put(gone, now + 3000);
	update_dlg_timer_deadline(&gone->tl, now + 50, 0);
	ok(remove_dlg_timer(&gone->tl) == 0 &&
		update_dlg_timer_deadline(&gone->tl, now + 60, 0) == -1 &&
		gone->tl.timeout == 0 && gone->tl.prev == NULL,
		"dialog timer deadline: a dialog removed from the timer is not put back");

	/* not in the timer: the value is stored, nothing is linked */
	ok(update_dlg_timer_deadline(&idle->tl, now + 500, 0) == 1 &&
		idle->tl.timeout == now + 500 &&
		update_dlg_timer_deadline(&idle->tl, now + 400, 1) == 1 &&
		idle->tl.timeout == now + 500 &&
		update_dlg_timer_deadline(&idle->tl, now + 600, 1) == 1 &&
		idle->tl.timeout == now + 600 &&
		idle->tl.next == NULL && idle->tl.prev == NULL,
		"dialog timer deadline: a dialog that is not in the timer only has the value stored");

	w_run(now + 1, now + 21000);

	ok(W_OUT_AT(cut, now + 30),
		"dialog timer deadline: four hours cut to 30 s expire after 30 s (at %u, %d time(s))",
		cut->out, cut->outs);
	ok(W_OUT_AT(raised, now + 20000),
		"dialog timer deadline: a timeout raised past a turn of the wheel expires on time");
	ok(W_OUT_AT(kept, now + 4000),
		"dialog timer deadline: the longest is kept, an earlier end changes nothing");
	ok(W_OUT_AT(extended, now + 6000),
		"dialog timer deadline: the longest is kept, a later end replaces it");
	ok(W_OUT_AT(past, now + 1),
		"dialog timer deadline: an end that passed already expires at the next second");
	ok(gone->outs == 0 && idle->outs == 0,
		"dialog timer deadline: only the dialogs in the timer expire");

	/* handed to the timer routine: its marks are kept */
	ok(update_dlg_timer_deadline(&cut->tl, now + 30000, 0) == -1 &&
		cut->tl.timeout == 0 && cut->tl.prev == NULL,
		"dialog timer deadline: an expired dialog is not put back");

	d_timer = saved;
	lock_destroy(w_timer.lock);
	lock_dealloc(w_timer.lock);
	w_timer.lock = NULL;
	w_teardown();
}

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
	test_dlg_timer_deadline();
	test_dlg_wheel_wrap();
}
