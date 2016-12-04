/*
 * Registrar errno
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2016 OpenSIPS Solutions
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

#include "../../str.h"

#include "rerrno.h"

rerr_t rerrno;

str error_info[] = {
	{EI_R_FINE,       sizeof(EI_R_FINE) - 1},
	{EI_R_UL_DEL_R,   sizeof(EI_R_UL_DEL_R) - 1},
	{EI_R_UL_GET_R,   sizeof(EI_R_UL_GET_R) - 1},
	{EI_R_UL_NEW_R,   sizeof(EI_R_UL_NEW_R) - 1},
	{EI_R_INV_CSEQ,   sizeof(EI_R_INV_CSEQ) - 1},
	{EI_R_UL_INS_C,   sizeof(EI_R_UL_INS_C) - 1},
	{EI_R_UL_INS_R,   sizeof(EI_R_UL_INS_R) - 1},
	{EI_R_UL_DEL_C,   sizeof(EI_R_UL_DEL_C) - 1},
	{EI_R_UL_UPD_C,   sizeof(EI_R_UL_UPD_C) - 1},
	{EI_R_TO_USER,    sizeof(EI_R_TO_USER) - 1},
	{EI_R_AOR_LEN,    sizeof(EI_R_AOR_LEN) - 1},
	{EI_R_AOR_PARSE,  sizeof(EI_R_AOR_PARSE) - 1},
	{EI_R_INV_EXP,    sizeof(EI_R_INV_EXP) - 1},
	{EI_R_INV_Q,      sizeof(EI_R_INV_Q) - 1},
	{EI_R_PARSE,      sizeof(EI_R_PARSE) - 1},
	{EI_R_TO_MISS,    sizeof(EI_R_TO_MISS) - 1},
	{EI_R_CID_MISS,   sizeof(EI_R_CID_MISS) - 1},
	{EI_R_CS_MISS,    sizeof(EI_R_CS_MISS) - 1},
	{EI_R_PARSE_EXP,  sizeof(EI_R_PARSE_EXP) - 1},
	{EI_R_PARSE_CONT, sizeof(EI_R_PARSE_CONT) - 1},
	{EI_R_STAR_EXP,   sizeof(EI_R_STAR_EXP) - 1},
	{EI_R_STAR_CONT,  sizeof(EI_R_STAR_CONT) - 1},
	{EI_R_OOO,        sizeof(EI_R_OOO) - 1},
	{EI_R_RETRANS,    sizeof(EI_R_RETRANS) - 1},
	{EI_R_UNESCAPE,   sizeof(EI_R_UNESCAPE) - 1},
	{EI_R_TOO_MANY,   sizeof(EI_R_TOO_MANY) - 1},
	{EI_R_CONTACT_LEN,sizeof(EI_R_CONTACT_LEN) - 1},
	{EI_R_CALLID_LEN, sizeof(EI_R_CALLID_LEN) - 1},
	{EI_R_PARSE_PATH, sizeof(EI_R_PARSE_PATH) - 1},
	{EI_R_PATH_UNSUP, sizeof(EI_R_PATH_UNSUP) - 1}
};

int rerr_codes[] = {
	200, /* R_FINE */
	500, /* R_UL_DEL_R */
	500, /* R_UL_GET */
	500, /* R_UL_NEW_R */
	400, /* R_INV_CSEQ */
	500, /* R_UL_INS_C */
	500, /* R_UL_INS_R */
	500, /* R_UL_DEL_C */
	500, /* R_UL_UPD_C */
	400, /* R_TO_USER */
	500, /* R_AOR_LEN */
	400, /* R_AOR_PARSE */
	400, /* R_INV_EXP */
	400, /* R_INV_Q */
	400, /* R_PARSE */
	400, /* R_TO_MISS */
	400, /* R_CID_MISS */
	400, /* R_CS_MISS */
	400, /* R_PARSE_EXP */
	400, /* R_PARSE_CONT */
	400, /* R_STAR_EXP */
	400, /* R_STAR_CONT */
	200, /* R_OOO */
	200, /* R_RETRANS */
	400, /* R_UNESCAPE */
	503, /* R_TOO_MANY */
	400, /* R_CONTACT_LEN */
	400, /* R_CALLID_LEN */
	400, /* R_PARSE_PATH */
	420  /* R_PATH_UNSUP */
};
