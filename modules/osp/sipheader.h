/*
 * opensips osp module.
 *
 * This module enables opensips to communicate with an Open Settlement
 * Protocol (OSP) server.  The Open Settlement Protocol is an ETSI
 * defined standard for Inter-Domain VoIP pricing, authorization
 * and usage exchange.  The technical specifications for OSP
 * (ETSI TS 101 321 V4.1.1) are available at www.etsi.org.
 *
 * Uli Abend was the original contributor to this module.
 *
 * Copyright (C) 2001-2005 Fhg Fokus
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

#ifndef _OSP_MOD_SIPHEADER_H_
#define _OSP_MOD_SIPHEADER_H_

#include <osp/osp.h>
#include "../../parser/msg_parser.h"

#define OSP_TOKEN_HEADER    "P-OSP-Auth-Token"
#define OSP_HEADER_SIZE     16

#define OSP_RN_NAME         "rn"
#define OSP_RN_SIZE         2
#define OSP_CIC_NAME        "cic"
#define OSP_CIC_SIZE        3
#define OSP_NPDI_NAME       "npdi"
#define OSP_NPDI_SIZE       4
#define OSP_SPID_NAME       "spid"
#define OSP_SPID_SIZE       4
#define OSP_OCN_NAME        "ocn"
#define OSP_OCN_SIZE        3
#define OSP_SPN_NAME        "spn"
#define OSP_SPN_SIZE        3
#define OSP_ALTSPN_NAME     "altspn"
#define OSP_ALTSPN_SIZE     6
#define OSP_MCC_NAME        "mcc"
#define OSP_MCC_SIZE        3
#define OSP_MNC_NAME        "mnc"
#define OSP_MNC_SIZE        3

void ospCopyStrToBuffer(str* source, char* buffer, int bufsize);
int ospGetFromUserpart(struct sip_msg* msg, char* fromuser, int bufsize);
int ospGetRpidUserpart(struct sip_msg* msg, char* rpiduser, int bufsize);
int ospGetPaiUserpart(struct sip_msg* msg, char* paiuser, int bufsize);
int ospGetPChargeInfoUserpart(struct sip_msg* msg, char* paiuser, int bufsize);
int ospGetToUserpart(struct sip_msg* msg, char* touser, int bufsize);
int ospGetToHostpart(struct sip_msg* msg, char* tohost, int bufsize);
int ospGetUriUserpart(struct sip_msg* msg, char* uriuser, int bufsize);
int ospAddOspHeader(struct sip_msg* msg, unsigned char* token, unsigned int tokensize);
int ospGetOspHeader(struct sip_msg* msg, unsigned char* token, unsigned int* tokensize);
int ospGetViaAddress(struct sip_msg* msg, char* srcaddr, int bufsize);
int ospGetSourceDevice(struct sip_msg* msg, char* srcaddr, int bufsize);
int ospGetSource(struct sip_msg* msg, char* srcaddr, int bufsize);
int ospGetCallId(struct sip_msg* msg, OSPT_CALL_ID** callid);
int ospGetRouteParameters(struct sip_msg* msg, char* routeparams, int bufsize);
int ospRebuildDestionationUri(str* newuri, osp_dest* dest, int format);
int ospGetNextHop(struct sip_msg* msg, char* nexthop, int bufsize);
int ospGetNpParameters(struct sip_msg* msg, char* rn, int rnbufsize, char* cic, int cicbufsize, int* npdi);
int ospGetOperatorName(struct sip_msg* msg, OSPE_OPERATOR_NAME type, char* name, int namebufsize);
int ospGetDiversion(struct sip_msg* msg, char* user, int userbufsize, char* host, int hostbufsize);

#endif /* _OSP_MOD_SIPHEADER_H_ */

