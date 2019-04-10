/*
 * Copyright (C) 2006 Voice Sistem SRL
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
 * History:
 * ---------
 *  2006-01-23  first version (bogdan)
 *  2006-11-28  Added statistics for the number of bad URI's, methods, and
 *              proxy requests (Jeffrey Magder - SOMA Networks)
 *  2009-04-23  NET and PKG statistics added (bogdan)
 */

/*!
 * \file
 * \brief  OpenSIPS statistics
 */


#ifndef _CORE_STATS_H_
#define _CORE_STATS_H_

#include "mem/mem.h"
#include "statistics.h"

#ifdef STATISTICS
extern stat_export_t core_stats[];
extern stat_export_t net_stats[];

/*! \brief received requests */
extern stat_var* rcv_reqs;

/*! \brief received replies */
extern stat_var* rcv_rpls;

/*! \brief forwarded requests */
extern stat_var* fwd_reqs;

/*! \brief forwarded replies */
extern stat_var* fwd_rpls;

/*! \brief dropped requests */
extern stat_var* drp_reqs;

/*! \brief dropped replies */
extern stat_var* drp_rpls;

/*! \brief error requests */
extern stat_var* err_reqs;

/*! \brief error replies */
extern stat_var* err_rpls;

/*! \brief Set in parse_uri() */
extern stat_var* bad_URIs;

/*! \brief Set in parse_method() */
extern stat_var* unsupported_methods;

/*! \brief Set in get_hdr_field(). */
extern stat_var* bad_msg_hdr;

/*! \brief SIP message processing which exceeded 'threshold' duration */
extern stat_var* slow_msgs;

#ifdef PKG_MALLOC
int init_pkg_stats(int no_procs);
#endif

#endif /*STATISTICS*/

#endif /*_CORE_STATS_H_*/
