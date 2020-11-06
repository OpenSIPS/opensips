/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2020 OpenSIPS Solutions
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

#include "../../locking.h"
#include "../../lib/list.h"

#include "ul_timer.h"
#include "ul_evi.h"
#include "ul_mi.h"
#include "dlist.h"

int timer_interval = 60;              /*!< Timer interval in seconds */
int ct_refresh_timer;

static struct list_head *pending_refreshes;
static gen_lock_t *ul_refresh_lock;

static void synchronize_all_udomains(unsigned int ticks, void* param);


int ul_init_timers(void)
{
	/* cache -> DB timer */
	if (register_timer("ul-timer", synchronize_all_udomains, 0, timer_interval,
	                   TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	pending_refreshes = shm_malloc(sizeof *pending_refreshes);
	if (!pending_refreshes) {
		LM_ERR("oom\n");
		return -1;
	}

	if (!(ul_refresh_lock = lock_alloc())) {
		LM_ERR("oom\n");
		return -1;
	}

	INIT_LIST_HEAD(pending_refreshes);
	lock_init(ul_refresh_lock);

	/* contact refresh event timer */
	if (ct_refresh_timer &&
	    register_timer("ul-refresh-timer", trigger_ct_refreshes, 0,
		               1, TIMER_FLAG_SKIP_ON_DELAY) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	return 0;
}


/*! \brief
 * Timer handler
 */
static void synchronize_all_udomains(unsigned int ticks, void* param)
{
	if (sync_lock)
		lock_start_read(sync_lock);
	if (_synchronize_all_udomains() != 0) {
		LM_ERR("synchronizing cache failed\n");
	}
	if (sync_lock)
		lock_stop_read(sync_lock);
}


void start_refresh_timer(ucontact_t *ct)
{
	struct list_head *el, *_;
	ucontact_t *c;

	lock_get(ul_refresh_lock);
	if (!list_empty(&ct->refresh_list))
		list_del(&ct->refresh_list);

	/* insert into sorted list (ascending) */
	list_for_each_safe (el, _, pending_refreshes) {
		c = list_entry(el, ucontact_t, refresh_list);
		if (ct->refresh_time < c->refresh_time) {
			list_add_tail(&ct->refresh_list, &c->refresh_list);
			goto done;
		}
	}

	list_add_tail(&ct->refresh_list, pending_refreshes);

done:
	lock_release(ul_refresh_lock);
}


void stop_refresh_timer(ucontact_t *ct)
{
	lock_get(ul_refresh_lock);
	if (!list_empty(&ct->refresh_list))
		list_del(&ct->refresh_list);
	lock_release(ul_refresh_lock);
}


void trigger_ct_refreshes(unsigned int ticks, void *param)
{
	static const str reg_refresh_reason = str_init("reg-refresh");
	struct list_head *el, *_;
	ucontact_t *ct;
	int now = time(NULL);

	lock_get(ul_refresh_lock);
	list_for_each_safe (el, _, pending_refreshes) {
		ct = list_entry(el, ucontact_t, refresh_list);

		if (ct->refresh_time > now)
			break;

		LM_DBG("raising refresh event for aor: '%.*s', ct: '%.*s'\n",
		       ct->aor->len, ct->aor->s, ct->c.len, ct->c.s);
		ul_raise_ct_refresh_event(ct, &reg_refresh_reason, NULL);
		list_del(&ct->refresh_list);
		INIT_LIST_HEAD(&ct->refresh_list);
	}

	lock_release(ul_refresh_lock);
}
