/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2004-03-16  created (bogdan)
 */

/*! \file
 *  \brief USRLOC - Module callbacks
 *  \ingroup usrloc
 */

#ifndef _UL_CALLBACKS_H
#define _UL_CALLBACKS_H

#include "ucontact.h"
#include "urecord.h"
#include "../../lib/list.h"

#define UL_CONTACT_INSERT      (1<<0)
#define UL_CONTACT_UPDATE      (1<<1)
#define UL_CONTACT_DELETE      (1<<2) /* exclusive with EXPIRE */
#define UL_CONTACT_EXPIRE      (1<<3) /* exclusive with DELETE */
#define UL_AOR_INSERT          (1<<4)
#define UL_AOR_UPDATE          (1<<5)
#define UL_AOR_DELETE          (1<<6) /* exclusive with EXPIRE */
#define UL_AOR_EXPIRE          (1<<7) /* exclusive with DELETE */
#define ULCB_MAX               ((1<<8)-1)

#define is_contact_cb(type) \
	(type & \
	(UL_CONTACT_INSERT|UL_CONTACT_UPDATE|UL_CONTACT_DELETE|UL_CONTACT_EXPIRE))

#define is_aor_cb(type) \
	(type & \
	(UL_AOR_INSERT|UL_AOR_UPDATE|UL_AOR_DELETE|UL_AOR_EXPIRE))

/*! \brief callback function prototype
 *
 * @binding: depending on the registered type,
 *             it should be casted to either (ucontact_t *) or (urecord_t *)
 * @type:    type of the callback
 * @data:    writable holder where data may be attached to the binding
 *            and processed during subsequent callbacks triggered for the
 *            same binding
 */
typedef void (ul_cb) (void *binding, int type, void **data);
/*! \brief register callback function prototype */
typedef int (*register_ulcb_t)(int cb_types, ul_cb f, int *data_idx);


struct ul_callback {
	int id;                      /*!< id of this callback - useless */
	int types;                   /*!< types of events that trigger the callback*/
	ul_cb* callback;             /*!< callback function */
	int has_data;                /*!< requests additional storage */
	struct list_head list;
};

struct ulcb_head_list {
	struct list_head first;
	int reg_types;
};


extern struct ulcb_head_list*  ulcb_list;


#define exists_ulcb_type(_types_) \
	( (ulcb_list->reg_types)&(_types_) )


int init_ulcb_list();

void destroy_ulcb_list();


/*! \brief register a callback for several types of events
 *
 * @types:       mask of callback types
 * @f:           registered function
 * @data_idx:    if given, the concerned contact / record
 *                 structures will be extended to hold additional data,
 *                 and the resulting "data_idx" can used to access it
 */
int register_ulcb(int types, ul_cb f, int *data_idx);

/*! \brief run all transaction callbacks for an event type
 *
 * @type: the callback type
 * @binding: value to be passed to the callback
 *    - an (ucontact_t *) for contact callbacks
 *    - an (urecord_t *) for AoR callbacks
 */
static inline void run_ul_callbacks(int type, void *binding)
{
	struct list_head *ele;
	struct ul_callback *cbp;
	int ct_extra_idx = 0, aor_extra_idx = 0;

	list_for_each(ele, &ulcb_list->first) {
		cbp = list_entry(ele, struct ul_callback, list);
		if (cbp->types & type) {
			LM_DBG("contact=%p, callback type %d/%d, id %d entered\n",
			       binding, type, cbp->types, cbp->id);

			if (is_contact_cb(type)) {
				if (cbp->has_data) {
					cbp->callback(binding, type,
					    ((ucontact_t *)binding)->attached_data + ct_extra_idx);
					ct_extra_idx++;
				} else {
					cbp->callback(binding, type, NULL);
				}
			} else if (is_aor_cb(type)) {
				if (cbp->has_data) {
					cbp->callback(binding, type,
					    ((urecord_t *)binding)->attached_data + aor_extra_idx);
					aor_extra_idx++;
				} else {
					cbp->callback(binding, type, NULL);
				}
			}
		}
	}
}

/*
 * Additional bytes attached to an (ucontact_t), as private data
 */
static inline size_t get_att_ct_data_sz(void)
{
	extern int att_ct_items;

	return att_ct_items * sizeof(void *);
}

/*
 * Additional bytes attached to an (urecord_t), as private data
 */
static inline size_t get_att_aor_data_sz(void)
{
	extern int att_aor_items;

	return att_aor_items * sizeof(void *);
}

#endif
