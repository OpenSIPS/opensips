/*
 * Copyright (C) 2020 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef __EBR_API_H__
#define __EBR_API_H__

#include "../../str.h"

#include "ebr_data.h"

typedef void (*ebr_notify_cb) (void);

struct ebr_api {
	/**
	 * get_ebr_event() - look up the ebr_event corresponding to the given @name
	 *
	 * Return: non-NULL on success, NULL on internal error
	 */
	ebr_event *(*get_ebr_event) (const str *name);

	/**
	 * notify_on_event() - subscribe to the @event given by @filters
	 * @event: an EBR event obtained with api.get_ebr_event()
	 * @filters: a list of filters (either event param value matching, or
	 *            event param SIP URI param value matching)
	 * @pack_params_cb: optional callback where the EVI param data may be
	 *                  changed.  Specify NULL in order to simply have the
	 *                  event data unchanged and simply passed further
	 * @notify_cb: mandatory callback, a hook where to take action once the
	 *             desired event takes place
	 *
	 * Return: 0 on successful registration, -1 otherwise
	 *
	 * When the event is triggered, the @pack_params_cb callback gets invoked
	 * first, so the event parameters can be changed.  Finally, the @notify_cb
	 * callback is invoked, so the user can perform some transactional-related
	 * actions related to the event (for now, only tm.t_inject_branch())
	 */
	int (*notify_on_event) (const ebr_event *event, const ebr_filter *filters,
	               struct usr_avp *(*pack_params_cb) (evi_params_t *params),
	               void (*notify_cb) (void), int timeout);
};

#endif /* __EBR_API_H__ */
