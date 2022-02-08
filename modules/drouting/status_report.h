/*
 * Copyright (C) 2022 OpenSIPS Solutions
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

#ifndef _DROUTONG_STATUS_REPORT_H_
#define _DROUTING_STATUS_REPORT_H_

#include "../../status_report.h"

/* status-report group for DR partitions */
extern void *dr_srg;

enum dr_sr_statuses {
	DR_STATUS_NO_DATA		=- 2,
	DR_STATUS_LOADING		= -1,
	DR_STATUS_RESERVED		=  0,
	DR_STATUS_READY			=  1,
	DR_STATUS_RELOADING		=  2,
};


#define dr_sr_set_status( _identifier, _status, _txt) \
	sr_set_status( dr_srg, _identifier.s, _identifier.len, \
		_status, CHAR_LEN(_txt), 0 /*not public*/ )

#define dr_sr_add_report( _identifier, _report) \
	sr_add_report( dr_srg, _identifier.s, _identifier.len, \
		CHAR_LEN(_report), 0 /*not public*/ )

#define dr_sr_add_report_cl( _identifier, _report_s, _report_len) \
	sr_add_report( dr_srg, _identifier.s, _identifier.len, \
		_report_s, _report_len, 0 /*not public*/ )


#endif

