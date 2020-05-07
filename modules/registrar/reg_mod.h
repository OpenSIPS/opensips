/*
 * registrar module interface
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *
 * 2005-07-11  added sip_natping_flag for nat pinging with SIP method
 *             instead of UDP package (bogdan)
 * 2006-11-28  Added statistics tracking for the number of accepted/rejected
 *             registrations, as well as for the max expiry time, max contacts,
 *             and default expiry time. (Jeffrey Magder - SOMA Networks)
 * 2007-02-24  sip_natping_flag moved into branch flags, so migrated to
 *             nathelper module (bogdan)
 */

/*!
 * \file
 * \brief SIP registrar module - interface
 * \ingroup registrar
 */


#ifndef REG_MOD_H
#define REG_MOD_H

#include "../../parser/msg_parser.h"
#include "../../qvalue.h"
#include "../../usr_avp.h"
#include "../usrloc/usrloc.h"
#include "../signaling/signaling.h"
#include "../tm/tm_load.h"

extern int case_sensitive;
extern int nat_flag;
extern int received_avp;
extern float def_q;

extern int retry_after;
extern str sock_hdr_name;

extern struct sig_binds sigb;

extern stat_var *accepted_registrations;
extern stat_var *rejected_registrations;

#endif /* REG_MOD_H */
