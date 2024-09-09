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

#ifndef __LIB_REG_RERRNO_H__
#define __LIB_REG_RERRNO_H__

#define MSG_200 "OK"
#define MSG_400 "Bad Request"
#define MSG_420 "Bad Extension"
#define MSG_500 "Server Internal Error"
#define MSG_501 "Not Implemented"
#define MSG_503 "Service Unavailable"
#define MSG_555 "Push Notification Service Not Supported"

#define EI_R_FINE       "No problem"                                /* R_FINE */
#define EI_R_INTERNAL   "Server Internal Error"                     /* R_INTERNAL */
#define EI_R_NOT_IMPL   "Method Not Implemented"                    /* R_NOT_IMPL */
#define EI_R_UL_DEL_R   "usrloc_record_delete failed"               /* R_UL_DEL_R */
#define EI_R_UL_GET_R   "usrloc_record_get failed"                  /* R_UL_GET */
#define EI_R_UL_NEW_R   "usrloc_record_new failed"                  /* R_UL_NEW_R */
#define EI_R_INV_CSEQ   "Invalid CSeq number"                       /* R_INV_CSEQ */
#define EI_R_UL_INS_C   "usrloc_contact_insert failed"              /* R_UL_INS_C */
#define EI_R_UL_INS_R   "usrloc_record_insert failed"               /* R_UL_INS_R */
#define EI_R_UL_DEL_C   "usrloc_contact_delete failed"              /* R_UL_DEL_C */
#define EI_R_UL_UPD_C   "usrloc_contact_update failed"              /* R_UL_UPD_C */
#define EI_R_TO_USER    "No username in To URI"                     /* R_TO_USER */
#define EI_R_AOR_LEN    "Address Of Record too long"                /* R_AOR_LEN */
#define EI_R_AOR_PARSE  "Error while parsing AOR"                   /* R_AOR_PARSE */
#define EI_R_INV_EXP    "Invalid expires param in contact"          /* R_INV_EXP */
#define EI_R_INV_Q      "Invalid q param in contact"                /* R_INV_Q */
#define EI_R_PARSE      "Message parse error"                       /* R_PARSE */
#define EI_R_TO_MISS    "To header not found"                       /* R_TO_MISS */
#define EI_R_CID_MISS   "Call-ID header not found"                  /* R_CID_MISS */
#define EI_R_CS_MISS    "CSeq header not found"                     /* R_CS_MISS */
#define EI_R_PARSE_EXP  "Expires parse error"                       /* R_PARSE_EXP */
#define EI_R_PARSE_CONT "Contact parse error"                       /* R_PARSE_CONT */
#define EI_R_STAR_EXP   "* used in contact and expires is not zero" /* R_STAR__EXP */
#define EI_R_STAR_CONT  "* used in contact and more than 1 contact" /* R_STAR_CONT */
#define EI_R_OOO        "Out of order request"                      /* R_OOO */
#define EI_R_RETRANS    "Retransmission"                            /* R_RETRANS */
#define EI_R_UNESCAPE   "Error while unescaping username"           /* R_UNESCAPE */
#define EI_R_TOO_MANY   "Too many registered contacts"              /* R_TOO_MANY */
#define EI_R_CONTACT_LEN "Contact/received too long"                /* R_CONTACT_LEN */
#define EI_R_CALLID_LEN  "Callid too long"                          /* R_CALLID_LEN */
#define EI_R_PARSE_PATH  "Path parse error"                         /* R_PARSE_PATH */
#define EI_R_PATH_UNSUP  "No support for found Path indicated"      /* R_PATH_UNSUP */
#define EI_R_PNS_UNSUP   MSG_555                                    /* R_PNS_UNSUP */

typedef enum rerr {
	R_FINE = 0,   /*!< Everything went OK */
	R_INTERNAL,   /*!< Internal Error */
	R_NOT_IMPL,   /*!< Not Implemented */
	R_UL_DEL_R,   /*!< Usrloc record delete failed */
	R_UL_GET_R,   /*!< Usrloc record get failed */
	R_UL_NEW_R,   /*!< Usrloc new record failed */
	R_INV_CSEQ,   /*!< Invalid CSeq value */
	R_UL_INS_C,   /*!< Usrloc insert contact failed */
	R_UL_INS_R,   /*!< Usrloc insert record failed */
	R_UL_DEL_C,   /*!< Usrloc contact delete failed */
	R_UL_UPD_C,   /*!< Usrloc contact update failed */
	R_TO_USER,    /*!< No username part in To URI */
	R_AOR_LEN,    /*!< Address Of Record too long */
	R_AOR_PARSE,  /*!< Error while parsing Address Of Record */
	R_INV_EXP,    /*!< Invalid expires parameter in contact */
	R_INV_Q,      /*!< Invalid q parameter in contact */
	R_PARSE,      /*!< Error while parsing message */
	R_TO_MISS,    /*!< Missing To header field */
	R_CID_MISS,   /*!< Missing Call-ID header field */
	R_CS_MISS,    /*!< Missing CSeq header field */
	R_PARSE_EXP,  /*!< Error while parsing Expires */
	R_PARSE_CONT, /*!< Error while parsing Contact */
	R_STAR_EXP,   /*!< star and expires != 0 */
	R_STAR_CONT,  /*!< star and more contacts */
	R_OOO,        /*!< Out-Of-Order request */
	R_RETRANS,    /*!< Request is retransmission */
	R_UNESCAPE,   /*!< Error while unescaping username */
	R_TOO_MANY,   /*!< Too many contacts */
	R_CONTACT_LEN,/*!< Contact URI or RECEIVED too long */
	R_CALLID_LEN, /*!< Callid too long */
	R_PARSE_PATH, /*!< Error while parsing Path */
	R_PATH_UNSUP, /*!< Path not supported by UAC */
	R_PNS_UNSUP,  /*!< Unrecognized Push Notification Service */
} rerr_t;

extern str error_info[];
extern int rerr_codes[];
extern rerr_t rerrno;

#endif /* __RERRNO_H__ */
