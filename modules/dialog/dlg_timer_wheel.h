/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _DIALOG_DLG_TIMER_WHEEL_H_
#define _DIALOG_DLG_TIMER_WHEEL_H_

/*
 * A timing wheel for the dialog lifetime timer.
 *
 * The timer kept its dialogs in one list sorted by expiry and found the
 * place of a new one by walking back from the far end with the timer's lock
 * held. That is one step when every dialog has the same lifetime, and a walk
 * past every dialog that expires later when it has not: a lifetime set from
 * the script that is shorter than the others' (a per-call limit, a short
 * wait for the ACK) walked past all calls in progress, for every call, under
 * the one lock every worker needs. The cost of a call grew with the number
 * of calls in progress.
 *
 * Here the dialogs hang on a wheel of DLG_WHEEL_SIZE lists, one per second:
 * a dialog due at second T is appended to list T modulo the size. Inserting
 * and removing are a few pointer writes whatever the lifetimes are. Each
 * second the timer looks at one list and takes the entries that are due; an
 * entry more than a turn of the wheel away stays where it is for a later
 * turn (the size is above four hours, the default dialog lifetime, so that
 * is rare). An entry found on a list that is not its own (its timeout was
 * written directly instead of through update_dlg_timer()) is moved to its
 * own list then, so it expires on time if its new timeout is later; if it
 * is earlier, it expires when its old list is looked at, as it did in the
 * sorted list.
 *
 * An entry is linked as in the sorted list (next and prev both set while it
 * is in the timer) and leaves it marked the same way, so the code around
 * these functions is unchanged. All of them are called with the timer's
 * lock held. They need struct dlg_tl, struct dlg_timer and FAKE_DIALOG_TL.
 */

#define DLG_WHEEL_BITS  14
#define DLG_WHEEL_SIZE  (1U << DLG_WHEEL_BITS)
#define DLG_WHEEL_MASK  (DLG_WHEEL_SIZE - 1)

/*
 * Seconds are compared by their distance on the tick counter and not by
 * value, so the order holds when the counter wraps around: <_a> is after
 * <_b> when it is ahead of it by less than half the range of the counter.
 * The lists need nothing for that, the range being a multiple of the size
 * of the wheel.
 */
#define DLG_TICK_AFTER(_a, _b) \
	((int)((unsigned int)(_a) - (unsigned int)(_b)) > 0)

static inline void dlg_wheel_init(struct dlg_tl *wheel)
{
	unsigned int i;

	for (i = 0; i < DLG_WHEEL_SIZE; i++) {
		wheel[i].next = wheel[i].prev = &wheel[i];
		wheel[i].timeout = 0;
	}
}

/* tl->timeout holds the second the entry is due */
static inline void dlg_wheel_insert(struct dlg_timer *timer, struct dlg_tl *tl)
{
	struct dlg_tl *head;

	/* the list of that second has been looked at already (a zero interval,
	 * or the timer routine running late): due at the next second */
	if (!DLG_TICK_AFTER(tl->timeout, timer->wheel_done))
		tl->timeout = timer->wheel_done + 1;

	head = &timer->wheel[tl->timeout & DLG_WHEEL_MASK];
	tl->prev = head->prev;
	tl->next = head;
	head->prev->next = tl;
	head->prev = tl;
}

/* Takes every entry due at <time> or before out of the wheel and returns
 * them chained by next and ended by FAKE_DIALOG_TL, each marked expired
 * (prev and timeout zero), as the sorted list hands them over;
 * FAKE_DIALOG_TL when none is due. */
static inline struct dlg_tl *dlg_wheel_expired(struct dlg_timer *timer,
		unsigned int time)
{
	struct dlg_tl *head, *tl, *next;
	struct dlg_tl *ret = FAKE_DIALOG_TL, *last = NULL;
	unsigned int t;

	if (!DLG_TICK_AFTER(time, timer->wheel_done))
		return FAKE_DIALOG_TL;

	t = timer->wheel_done + 1;
	/* a turn of the wheel or more behind: every list, once */
	if (time - t >= DLG_WHEEL_SIZE)
		t = time - DLG_WHEEL_MASK;

	for (;; t++) {
		head = &timer->wheel[t & DLG_WHEEL_MASK];
		for (tl = head->next; tl != head; tl = next) {
			next = tl->next;
			if (DLG_TICK_AFTER(tl->timeout, time)) {
				/* not due yet: a later turn of the wheel, or an entry whose
				 * timeout was changed in place (the DB sync of a known
				 * dialog writes tl.timeout directly) and which belongs to
				 * another list now - move it there */
				if ((tl->timeout & DLG_WHEEL_MASK) != (t & DLG_WHEEL_MASK)) {
					tl->prev->next = tl->next;
					tl->next->prev = tl->prev;
					dlg_wheel_insert(timer, tl);
				}
				continue;
			}
			tl->prev->next = tl->next;
			tl->next->prev = tl->prev;
			tl->prev = 0;
			tl->timeout = 0;
			tl->next = FAKE_DIALOG_TL;
			if (last)
				last->next = tl;
			else
				ret = tl;
			last = tl;
		}
		if (t == time)
			break;
	}
	timer->wheel_done = time;

	return ret;
}

#endif
