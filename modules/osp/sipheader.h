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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef _OSP_MOD_SIPHEADER_H_
#define _OSP_MOD_SIPHEADER_H_

#include <osp/osp.h>
#include "../../parser/msg_parser.h"

#define OSP_TOKENHEADER_NAME    "P-OSP-Auth-Token"
#define OSP_TOKENHEADER_SIZE    16

#define OSP_DATEHEADER_NAME     "Date"
#define OSP_DATEHEADER_SIZE     4
#define OSP_DATEHEADER_FORMAT   "%a, %d %b %Y %H:%M:%S GMT"

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
#define OSP_ICID_NAME       "icid-value"
#define OSP_ICID_SIZE       10

int ospGetAVP(int avpid, unsigned short avptype, char* avpstr, int bufsize);
void ospCopyStrToBuffer(str* source, char* buffer, int bufsize);
int ospGetLocalAddress(struct sip_msg*, char*, char*);
int ospGetFromDisplay(struct sip_msg* msg, char* fromdisplay, int bufsize);
int ospGetFromUser(struct sip_msg* msg, char* fromuser, int bufsize);
int ospGetFrom(struct sip_msg* msg, char* from, int bufsize);
int ospGetToDisplay(struct sip_msg* msg, char* todisplay, int bufsize);
int ospGetToUser(struct sip_msg* msg, char* touser, int bufsize);
int ospGetToHost(struct sip_msg* msg, char* tohost, int bufsize);
int ospGetTo(struct sip_msg* msg, char* to, int bufsize);
int ospGetPaiUser(struct sip_msg* msg, char* paiuser, int bufsize);
int ospGetPaiHost(struct sip_msg* msg, char* paihost, int bufsize);
int ospGetPai(struct sip_msg* msg, char* pai, int bufsize);
int ospGetRpidUser(struct sip_msg* msg, char* rpiduser, int bufsize);
int ospGetRpidHost(struct sip_msg* msg, char* rpidhost, int bufsize);
int ospGetPciUser(struct sip_msg* msg, char* paiuser, int bufsize);
int ospGetPciHost(struct sip_msg* msg, char* paihost, int bufsize);
int ospGetDiversion(struct sip_msg* msg, char* user, int userbufsize, char* host, int hostbufsize);
int ospGetPcvIcid(struct sip_msg* msg, char* pcvicid, int bufsize);
int ospGetUriUser(struct sip_msg* msg, char* uriuser, int bufsize);
int ospGetIdentity(struct sip_msg* msg, char* identity, int bufsize);
int ospGetContactHost(struct sip_msg* msg, char* contacthost, int bufsize);
int ospAddOspToken(struct sip_msg* msg, unsigned char* token, unsigned int tokensize);
int ospGetOspToken(struct sip_msg* msg, unsigned char* token, unsigned int* tokensize);
int ospGetViaAddress(struct sip_msg* msg, char* srcaddr, int bufsize);
int ospGetSrcDev(struct sip_msg* msg, char* srcaddr, int bufsize);
int ospGetSource(struct sip_msg* msg, char* srcaddr, int bufsize);
int ospGetCallId(struct sip_msg* msg, OSPT_CALL_ID** callid);
int ospGetRouteParam(struct sip_msg* msg, char* routeparams, int bufsize);
int ospRebuildDestUri(str* newuri, osp_dest* dest);
int ospGetNextHop(struct sip_msg* msg, char* nexthop, int bufsize);
int ospGetNpParam(struct sip_msg* msg, char* rn, int rnbufsize, char* cic, int cicbufsize, int* npdi);
int ospGetOperatorName(struct sip_msg* msg, OSPE_OPERATOR_NAME type, char* name, int namebufsize);
int ospGetUserAgent(struct sip_msg* msg, char* useragent, int bufsize);
int ospSetRequestDate(struct sip_msg* msg, char*, char*);

#endif /* _OSP_MOD_SIPHEADER_H_ */

