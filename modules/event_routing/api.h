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

typedef struct ebr_api {
	/**
	 * get_ebr_event() - look up the ebr_event corresponding to the given @name
	 *
	 * Return: non-NULL on success, NULL on internal error
	 */
	ebr_event *(*get_ebr_event) (const str *name);

	/**
	 * notify_on_event() - subscribe to the @event given by @filters
	 *
	 * @msg: the SIP msg currently being processed
	 * @event: an EBR event obtained with api.get_ebr_event()
	 * @filters: a list of filters (either event param value matching, or
	 *            event param SIP URI param value matching)
	 * @pack_params: optional callback where the EVI param data may be
	 *               changed.  Specify NULL in order to simply have the
	 *               event data unchanged and packed as AVPs named according
	 *               to the event parameter names
	 * @notify: mandatory callback, a hook where to take action once the
	 *          desired event takes place
	 * @timeout: lifetime of the subscription (seconds)
	 *
	 * Return: 0 on successful registration, -1 otherwise
	 *
	 * When the event is triggered, the @pack_params callback, if set, gets
	 * invoked first, so the event parameters can be prepared.  Finally, the
	 * @notify callback is invoked, so the user can perform some
	 * transactional-related actions related to the event
	 * (for now, only tm.t_inject_branch())
	 */
	int (*notify_on_event) (struct sip_msg *msg, ebr_event *event,
	                        const ebr_filter *filters,
	                        ebr_pack_params_cb pack_params,
	                        ebr_notify_cb notify, int timeout);

	/**
	 * async_wait_for_event() - subscribe to the @event given by @filters.
	 *     Only meant to be called from an async script function, such that an
	 *     async @ctx is available.  The @ctx will be filled in here.
	 *
	 * @msg: the SIP request currently being processed
	 * @ctx: the context of your async function
	 * @event: an EBR event obtained with api.get_ebr_event()
	 * @filters: a list of filters (either event param value matching, or
	 *            event param SIP URI param value matching)
	 * @pack_params: optional callback where the EVI param data may be
	 *               changed.  Specify NULL in order to simply have the
	 *               event data unchanged and packed as AVPs named according
	 *               to the event parameter names
	 *
	 * Return: 0 on successful async setup, -1 otherwise
	 *
	 * When the event is triggered, the @pack_params callback, if set, gets
	 * invoked first, so the event parameters can be prepared and made
	 * available within the async resume route.
	 */
	int (*async_wait_for_event) (struct sip_msg *msg, async_ctx *ctx,
	                             ebr_event *event, const ebr_filter *filters,
	                             ebr_pack_params_cb pack_params, int timeout);
} ebr_api_t;

typedef int (*ebr_bind_f)(ebr_api_t *api);

static inline int load_ebr_api(ebr_api_t *api)
{
	ebr_bind_f ebr_bind;

	ebr_bind = (ebr_bind_f)find_export("ebr_bind", 0);
	if (!ebr_bind) {
		LM_ERR("failed to bind EBR API\n");
		return -1;
	}

	ebr_bind(api);
	return 0;
}

#endif /* __EBR_API_H__ */
