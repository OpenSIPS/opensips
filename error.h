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
 */

/*!
 * \file
 * \brief Error definitions
 */


#ifndef error_h
#define error_h

#define E_UNSPEC            -1
#define E_OUT_OF_MEM        -2
#define E_BAD_RE            -3
/* #define E_BAD_ADDRESS -4 */
#define E_BUG               -5
#define E_CFG               -6
#define E_NO_SOCKET         -7
#define E_BAD_VIA           -8		/*!< unresolvable topmost Via */
#define E_BAD_TUPEL         -9		/*!< incomplete transaction tuple */
#define E_SCRIPT            -10		/*!< script programming error */
#define E_EXEC              -11		/*!< error in execution of external tools*/
#define E_TOO_MANY_BRANCHES -12		/*!< too many branches demanded */
#define E_BAD_TO            -13
#define E_INVALID_PARAMS    -14		/*!< invalid params */
#define E_Q_INV_CHAR        -15		/*!< Invalid character in q */
#define E_Q_EMPTY           -16		/*!< Empty q */
#define E_Q_TOO_BIG         -17		/*!< q too big (> 1) */
#define E_NO_DESTINATION    -18		/*!< No available destination */

/* opensips specific error codes */
#define E_IP_BLOCKED      -473		/*!< destination filtered */
#define E_BAD_PROTO       -474		/*!< bad protocol, like */
#define E_BAD_URI         -475		/*!< unparseable URI */
#define E_BAD_ADDRESS     -476		/*!< unresolvable next-hop address */
#define E_SEND            -477		/*!< generic send error */

#define E_BAD_REQ         -400		/*!< generic malformed request */

#define E_BAD_SERVER	  -500		/*!< error in server */

/*
 * portable macro which prevents "unused variable" compiler warnings
 * when defining certain flags, e.g. NO_LOG, NO_DEBUG
 */
#define UNUSED(x) (void)(x)

#define MAX_REASON_LEN	128

#include "str.h"

/*! \brief processing status of the last command */
extern int ser_error;
extern int prev_ser_error;

struct sip_msg;

/*! \brief ser error -> SIP error */
int err2reason_phrase( int ser_error, int *sip_error,
                char *phrase, int etl, char *signature );

/*! \brief SIP error core -> SIP text */
char *error_text( int code );

/*! \brief return pkg_malloc-ed reply status in status->s */
void get_reply_status( str *status, struct sip_msg *reply, int code );

#endif
