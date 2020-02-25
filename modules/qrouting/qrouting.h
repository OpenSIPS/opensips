/*
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __QROUTING_H__
#define __QROUTING_H__

typedef enum qr_algo {
	QR_ALGO_INVALID,
	QR_ALGO_DYNAMIC_WEIGHTS,
	QR_ALGO_BEST_DEST_FIRST,
} qr_algo_t;
#define qr_str2algo(s) ( \
		!strcasecmp(s, "dynamic-weights") ? QR_ALGO_DYNAMIC_WEIGHTS : \
		!strcasecmp(s, "best-dest-first") ? QR_ALGO_BEST_DEST_FIRST : \
		QR_ALGO_INVALID)

extern double event_bad_dst_threshold;
extern qr_algo_t qr_algorithm;
extern int qr_interval_list_sz;

#endif /* __QROUTING_H__ */
