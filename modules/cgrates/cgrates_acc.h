/*
 * Copyright (C) 2016 Razvan Crainea <razvan@opensips.org>
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
 */

#ifndef _CGRATES_ACC_H_
#define _CGRATES_ACC_H_

/*
 * Starts a CGR accounting session
 * Input:
 *  - account
 *  - destination (optional)
 * Returns:
 *  -  1: user is allowed to call
 *  - -1: internal error
 *  - -2: cgrates error
 *  - -3: invalid message type
 *  - -4: invalid message
 */
int w_cgr_acc(struct sip_msg* msg, char *flag_c, char* acc_c, char *dst_c);

struct cgr_acc_ctx {

	int ref_no;
	gen_lock_t ref_lock;

	unsigned flags;

	/* all branches info */
	str acc;
	str dst;
	time_t time;
	unsigned int duration;

	/* variables */
	struct list_head *kv_store;
};

struct cgr_acc_ctx *cgr_tryget_acc_ctx(void);

#define CGRF_DO_CDR		(1<<0)
#define CGRF_DO_MISSED	(1<<1)

#endif /* _CGRATES_ACC_H_ */

