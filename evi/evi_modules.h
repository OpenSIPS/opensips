/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */

#ifndef _EVI_MODULES_H_
#define _EVI_MODULES_H_

#include "../str.h"
#include "event_interface.h"

struct sip_msg;

/* functions used by modules */

/*
 * Used to register a new event
 * Parameters:
 *  + Event name
 *
 * Returns:
 *  - event id if successful or EVI_ERROR on error
 */
event_id_t evi_publish_event(str event_name);


/*
 * Used to raise an event
 * Parameters:
 *  + event id
 *  + parameters
 *
 * Returns:
 *  - 0 on success or negative on error
 */
int evi_raise_event(event_id_t id, evi_params_t* params);

/*
 * Used to raise an event that uses the message attached
 * Parameters:
 *  + message
 *  + event id
 *  + parameters
 *
 * Returns:
 *  - 0 on success or negative on error
 */
int evi_raise_event_msg(struct sip_msg *msg, event_id_t id, evi_params_t* params);


/*
 * Used to raise an event from script
 * Parameters:
 *  + message
 *  + event id
 *  + params attributes
 *  + params values
 *
 * Returns:
 *  - 0 on success or negative on error
 */
int evi_raise_script_event(struct sip_msg *msg, event_id_t id, void * attrs, void * vals);


/*
 * Used to subscribe for an event
 * Parameter:
 *  + event name
 *  + socket name
 *  + expire
 *  + unsubscription
 *
 * Returns:
 *  - -1 on parameters error
 *  - 0 on internal error
 *  - 1 on success
 */
int evi_event_subscribe(str , str , unsigned , unsigned );




/*
 * Used to check if there are subscribers
 * Parameters:
 *  + event id
 *
 * Returns:
 *  - 0 if there is no subscriber for this event
 *  - positive if there are subscribers listening
 */
int evi_probe_event(event_id_t id);


/*
 * Used to return the event id of an event
 * Parameters:
 *  + event name
 *
 * Returns:
 *  - event_id or error
 */
event_id_t evi_get_id(str *name);

/*
 * Used to return an event with a specific name
 * Parameters:
 *  + event name
 *
 * Returns:
 *  - event_id or error
 */
evi_event_p evi_get_event(str *name);

#endif /* _EVI_MODULES_H_ */
