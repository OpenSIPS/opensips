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
 *
 * History:
 * ---------
 *  2006-03-13  RR functions are loaded via API function (bogdan)
 */

#include <osp/osp.h>
#include "../rr/api.h"
#include "../../socket_info.h"
#include "../../usr_avp.h"
#include "../../mod_fix.h"
#include "destination.h"
#include "usage.h"
#include "osptoolkit.h"
#include "sipheader.h"

#define OSP_ORIG_COOKIE         "osp-o"
#define OSP_TERM_COOKIE         "osp-t"

#define OSP_RELEASE_ORIG        0
#define OSP_RELEASE_TERM        1

/* The up case tags for the destinations may corrupt OSP cookies */
#define OSP_COOKIE_TRANSID      't'
#define OSP_COOKIE_TRANSIDUP    'T'
#define OSP_COOKIE_SRCIP        'i'
#define OSP_COOKIE_SRCIPUP      'I'
#define OSP_COOKIE_AUTHTIME     'a'
#define OSP_COOKIE_AUTHTIMEUP   'A'
#define OSP_COOKIE_DCOUNT       'c'
#define OSP_COOKIE_DCOUNTUP     'C'
#define OSP_COOKIE_SNID         's'
#define OSP_COOKIE_SNIDUP       'S'
#define OSP_COOKIE_DNID         'd'
#define OSP_COOKIE_DNIDUP       'D'

/* Flags for OSP cookies */
#define OSP_COOKIEHAS_TRANSID   (1 << 0)
#define OSP_COOKIEHAS_SRCIP     (1 << 1)
#define OSP_COOKIEHAS_AUTHTIME  (1 << 2)
#define OSP_COOKIEHAS_DSTCOUNT  (1 << 3)
#define OSP_COOKIEHAS_ORIGALL   (OSP_COOKIEHAS_TRANSID | OSP_COOKIEHAS_SRCIP | OSP_COOKIEHAS_AUTHTIME | OSP_COOKIEHAS_DSTCOUNT)
#define OSP_COOKIEHAS_TERMALL   (OSP_COOKIEHAS_TRANSID | OSP_COOKIEHAS_SRCIP | OSP_COOKIEHAS_AUTHTIME)

/* Flags for reporting network ID */
#define OSP_REPORT_SNID         (1<<0)
#define OSP_REPORT_DNID         (1<<1)

#define OSP_OPENSIPS            "opensips"

extern int _osp_report_nid;
extern int _osp_origdest_avpid;
extern char _osp_in_device[];
extern char _osp_out_device[];
extern OSPTPROVHANDLE _osp_provider;
extern str OSP_ORIGDEST_NAME;
extern struct rr_binds osp_rr;

static void ospRecordTransaction(struct sip_msg* msg, osp_inbound* inbound, osp_dest* dest, int isorig);
static int ospBuildUsageFromDestination(OSPTTRANHANDLE transaction, osp_inbound* inbound, osp_dest* dest, int lastcode);
static int ospReportUsageFromDestination(OSPTTRANHANDLE transaction, osp_inbound* inbound, osp_dest* dest);
static int ospReportUsageFromCookie(struct sip_msg* msg, char* cooky, OSPT_CALL_ID* callid, int release, OSPE_ROLE type);

/*
 * Create OSP cookie and insert it into Record-Route header
 * param msg SIP message
 * param tansid Transaction ID
 * param inbound Inbound info
 * param dest Destination
 * param isorig Originate / Terminate
 */
static void ospRecordTransaction(
    struct sip_msg* msg,
    osp_inbound* inbound,
    osp_dest* dest,
    int isorig)
{
    str cookie;
    char buffer1[OSP_STRBUF_SIZE];
    char buffer2[OSP_STRBUF_SIZE];

    if (osp_rr.add_rr_param == 0) {
        LM_WARN("add_rr_param function is not found, cannot record information about the OSP transaction\n");
        return;
    }

    cookie.s = buffer1;

    if (isorig == 1) {
        cookie.len = snprintf(
            buffer1,
            sizeof(buffer1),
            ";%s=%c%llu_%c%s_%c%d_%c%d",
            OSP_ORIG_COOKIE,
            OSP_COOKIE_TRANSID,
            dest->transid,
            OSP_COOKIE_SRCIP,
            inbound->srcdev,
            OSP_COOKIE_AUTHTIME,
            (unsigned int)inbound->authtime,
            OSP_COOKIE_DCOUNT,
            dest->destcount);
    } else {
        cookie.len = snprintf(
            buffer1,
            sizeof(buffer1),
            ";%s=%c%llu_%c%s_%c%d",
            OSP_TERM_COOKIE,
            OSP_COOKIE_TRANSID,
            dest->transid,
            OSP_COOKIE_SRCIP,
            inbound->source,
            OSP_COOKIE_AUTHTIME,
            (unsigned int)inbound->authtime);
    }
    if ((_osp_report_nid & OSP_REPORT_SNID) && inbound->snid[0]) {
        cookie.len = snprintf(
            buffer2,
            sizeof(buffer2),
            "%s_%c%s",
            buffer1,
            OSP_COOKIE_SNID,
            inbound->snid);
        strncpy(buffer1, buffer2, sizeof(buffer1));
        buffer1[sizeof(buffer1) - 1] = '\0';
    }
    if ((_osp_report_nid & OSP_REPORT_DNID) && dest->dnid[0]) {
        cookie.len = snprintf(
            buffer2,
            sizeof(buffer2),
            "%s_%c%s",
            buffer1,
            OSP_COOKIE_DNID,
            dest->dnid);
        strncpy(buffer1, buffer2, sizeof(buffer1));
        buffer1[sizeof(buffer1) - 1] = '\0';
    }

    if (cookie.len < 0) {
        LM_ERR("failed to create OSP cookie\n");
        return;
    }

    LM_DBG("adding RR parameter '%s'\n", buffer1);
    osp_rr.add_rr_param(msg, &cookie);
}

/*
 * Create OSP originate cookie and insert it into Record-Route header
 * param msg SIP message
 * param inbound Inbound info
 * param dest Destination
 */
void ospRecordOrigTransaction(
    struct sip_msg* msg,
    osp_inbound* inbound,
    osp_dest* dest)
{
    int isorig = 1;

    ospRecordTransaction(msg, inbound, dest, isorig);
}

/*
 * Create OSP terminate cookie and insert it into Record-Route header
 * param msg SIP message
 * param inbound Inbound info
 * param dest Destination
 */
void ospRecordTermTransaction(
    struct sip_msg* msg,
    osp_inbound* inbound,
    osp_dest* dest)
{
    int isorig = 0;

    ospRecordTransaction(msg, inbound, dest, isorig);
}

/*
 * Report OSP usage from OSP cookie
 * param msg SIP message
 * param cookie OSP cookie (buffer owned by ospReportUsage, can be modified)
 * param callid Call ID
 * param release Who releases the call first. 0 orig, 1 term
 * param type Usage type
 * return
 */
static int ospReportUsageFromCookie(
    struct sip_msg* msg,
    char* cookie,
    OSPT_CALL_ID* callid,
    OSPE_RELEASE release,
    OSPE_ROLE type)
{
    char* tmp;
    char* token;
    char tag;
    char* value;
    unsigned long long transid = 0;
    time_t authtime = 0;
    unsigned destcount = 0;
    time_t duration = 0;
    time_t endtime = time(NULL);
    int cookieflags = 0;
    unsigned releasecode;
    char firstvia[OSP_STRBUF_SIZE];
    char fromdisplay[OSP_STRBUF_SIZE];
    char fromuser[OSP_STRBUF_SIZE];
    char todisplay[OSP_STRBUF_SIZE];
    char touser[OSP_STRBUF_SIZE];
    char paiuser[OSP_STRBUF_SIZE];
    char paihost[OSP_STRBUF_SIZE];
    char rpiduser[OSP_STRBUF_SIZE];
    char rpidhost[OSP_STRBUF_SIZE];
    char pciuser[OSP_STRBUF_SIZE];
    char pcihost[OSP_STRBUF_SIZE];
    char divuser[OSP_STRBUF_SIZE];
    char divhost[OSP_STRBUF_SIZE];
    char pcvicid[OSP_STRBUF_SIZE];
    char contacthost[OSP_STRBUF_SIZE];
    char nexthop[OSP_STRBUF_SIZE];
    char* snid = NULL;
    char* dnid = NULL;
    char* display;
    char* calling;
    char* called;
    char* originator = NULL;
    char* terminator;
    char source[OSP_STRBUF_SIZE];
    char dest[OSP_STRBUF_SIZE];
    char srcdev[OSP_STRBUF_SIZE];
    char receive[OSP_STRBUF_SIZE];
    char* ingress = NULL;
    char* egress = NULL;
    OSPTTRANHANDLE transaction = -1;
    int errorcode;

    LM_DBG("cookie '%s' type '%d'\n", cookie == NULL ? "NULL" : cookie, type);

    if (cookie != NULL) {
        for (token = strtok_r(cookie, "_", &tmp);
            token;
            token = strtok_r(NULL, "_", &tmp))
        {
            tag = *token;
            value= token + 1;

            switch (tag) {
                case OSP_COOKIE_TRANSID:
                case OSP_COOKIE_TRANSIDUP:
                    transid = atoll(value);
                    cookieflags |= OSP_COOKIEHAS_TRANSID;
                    break;
                case OSP_COOKIE_AUTHTIME:
                case OSP_COOKIE_AUTHTIMEUP:
                    authtime = atoi(value);
                    duration = endtime - authtime;
                    cookieflags |= OSP_COOKIEHAS_AUTHTIME;
                    break;
                case OSP_COOKIE_SRCIP:
                case OSP_COOKIE_SRCIPUP:
                    originator = value;
                    cookieflags |= OSP_COOKIEHAS_SRCIP;
                    break;
                case OSP_COOKIE_DCOUNT:
                case OSP_COOKIE_DCOUNTUP:
                    destcount = (unsigned)atoi(value);
                    cookieflags |= OSP_COOKIEHAS_DSTCOUNT;
                    break;
                case OSP_COOKIE_SNID:
                case OSP_COOKIE_SNIDUP:
                    snid = value;
                    break;
                case OSP_COOKIE_DNID:
                case OSP_COOKIE_DNIDUP:
                    dnid = value;
                    break;
                default:
                    LM_ERR("unexpected tag '%c' / value '%s'\n", tag, value);
                    break;
            }
        }
    }

    switch (type) {
        case OSPC_ROLE_DESTINATION:
            if (cookieflags == OSP_COOKIEHAS_TERMALL) {
                releasecode = 10016;
            } else {
                releasecode = 9016;
            }
            break;
        case OSPC_ROLE_SOURCE:
        case OSPC_ROLE_OTHER:
        case OSPC_ROLE_UNDEFINED:
        default:
            if (cookieflags == OSP_COOKIEHAS_ORIGALL) {
                releasecode = 10016;
            } else {
                releasecode = 9016;
            }
            break;
    }

    if (releasecode == 9016) {
        transid = 0;
        originator = NULL;
        authtime = 0;
        duration = 0;
        destcount = 0;
    }

    if(msg->rcv.bind_address && msg->rcv.bind_address->address_str.s) {
        ospCopyStrToBuffer(&msg->rcv.bind_address->address_str, receive, sizeof(receive));
    }

    ospGetViaAddress(msg, firstvia, sizeof(firstvia));
    ospGetFromDisplay(msg, fromdisplay, sizeof(fromdisplay));
    ospGetFromUser(msg, fromuser, sizeof(fromuser));
    ospGetToDisplay(msg, todisplay, sizeof(todisplay));
    ospGetToUser(msg, touser, sizeof(touser));
    ospGetPaiUser(msg, paiuser, sizeof(paiuser));
    ospGetPaiHost(msg, paihost, sizeof(paihost));
    ospGetRpidUser(msg, rpiduser, sizeof(rpiduser));
    ospGetRpidHost(msg, rpidhost, sizeof(rpidhost));
    ospGetPciUser(msg, pciuser, sizeof(pciuser));
    ospGetPciHost(msg, pcihost, sizeof(pcihost));
    ospGetDiversion(msg, divuser, sizeof(divuser), divhost, sizeof(divhost));
    ospGetPcvIcid(msg, pcvicid, sizeof(pcvicid));
    ospGetContactHost(msg, contacthost, sizeof(contacthost));
    ospGetNextHop(msg, nexthop, sizeof(nexthop));

    LM_DBG("first via '%s' from '%s' to '%s' next hop '%s'\n",
        firstvia,
        fromuser,
        touser,
        nexthop);

    if (release == OSPC_RELEASE_DESTINATION) {
        LM_DBG("term '%s' released the call, call_id '%.*s' transaction_id '%llu'\n",
            firstvia,
            callid->Length,
            callid->Value,
            transid);
        if (originator == NULL) {
            originator = nexthop;
        }
        display = todisplay;
        calling = touser;
        called = fromuser;
        terminator = firstvia;
        egress = receive;
    } else {
        if (release == OSPC_RELEASE_SOURCE) {
            LM_DBG("orig '%s' released the call, call_id '%.*s' transaction_id '%llu'\n",
                firstvia,
                callid->Length,
                callid->Value,
                transid);
        } else {
            LM_DBG("unknown '%s' released the call, call_id '%.*s' transaction_id '%llu'\n",
                firstvia,
                callid->Length,
                callid->Value,
                transid);
        }
        if (originator == NULL) {
            originator = firstvia;
        }
        display = fromdisplay;
        calling = fromuser;
        called = touser;
        terminator = nexthop;
        ingress = receive;
    }

    errorcode = OSPPTransactionNew(_osp_provider, &transaction);

    LM_DBG("created transaction handle '%d' (%d)\n", transaction, errorcode);

    switch (type) {
        case OSPC_ROLE_DESTINATION:
            srcdev[0] = '\0';
            ospConvertToOutAddress(originator, source, sizeof(source));
            strncpy(dest, _osp_out_device, sizeof(dest));
            dest[sizeof(dest) - 1] = '\0';
            break;
        case OSPC_ROLE_SOURCE:
        case OSPC_ROLE_OTHER:
        case OSPC_ROLE_UNDEFINED:
        default:
            ospConvertToOutAddress(originator, srcdev, sizeof(srcdev));
            strncpy(source, _osp_out_device, sizeof(source));
            source[sizeof(source) - 1] = '\0';
            ospConvertToOutAddress(terminator, dest, sizeof(dest));
            break;
    }

    /* RoleInfo must be set before BuildUsageFromScratch */
    OSPPTransactionSetRoleInfo(transaction, OSPC_RSTATE_STOP, OSPC_RFORMAT_OSP, OSPC_RVENDOR_OPENSIPS);

    errorcode = OSPPTransactionBuildUsageFromScratch(
        transaction,
        transid,
        type,
        source,
        dest,
        srcdev,
        "",
        calling,
        OSPC_NFORMAT_E164,
        called,
        OSPC_NFORMAT_E164,
        callid->Length,
        callid->Value,
        0,
        NULL,
        NULL);

    LM_DBG("built usage handle '%d' (%d)\n", transaction, errorcode);

    if ((errorcode == OSPC_ERR_NO_ERROR) && (destcount > 0)) {
        errorcode = OSPPTransactionSetDestinationCount(
            transaction,
            destcount);

        errorcode = OSPPTransactionSetTotalSetupAttempts(
            transaction,
            destcount);
    }

    if (errorcode == OSPC_ERR_NO_ERROR) {
        OSPPTransactionSetProtocol(transaction, OSPC_PROTTYPE_SOURCE, OSPC_PROTNAME_SIP);
        OSPPTransactionSetProtocol(transaction, OSPC_PROTTYPE_DESTINATION, OSPC_PROTNAME_SIP);

        OSPPTransactionSetSrcNetworkId(transaction, snid);
        OSPPTransactionSetDestNetworkId(transaction, dnid);

        OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_FROM, OSPC_NFORMAT_DISPLAYNAME, display);

        OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_RPID, OSPC_NFORMAT_E164, rpiduser);
        OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_RPID, OSPC_NFORMAT_TRANSPORT, rpidhost);
        OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_PAI, OSPC_NFORMAT_E164, paiuser);
        OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_PAI, OSPC_NFORMAT_TRANSPORT, paihost);
        OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_PCI, OSPC_NFORMAT_E164, pciuser);
        OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_PCI, OSPC_NFORMAT_TRANSPORT, pcihost);
        OSPPTransactionSetDiversion(transaction, divuser, divhost);
        OSPPTransactionSetChargingVector(transaction, pcvicid, NULL, NULL, NULL);
        OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_CONTACT, OSPC_NFORMAT_TRANSPORT, contacthost);

        OSPPTransactionSetProxyIngressAddr(transaction, ingress);
        OSPPTransactionSetProxyEgressAddr(transaction, egress);

        OSPPTransactionSetCDRProxy(transaction, _osp_in_device, OSP_OPENSIPS, NULL);

        ospReportUsageWrapper(
            transaction,
            releasecode,
            duration,
            authtime,
            endtime,
            0,
            0,
            0,
            0,
            release);
    }

    return errorcode;
}

/*
 * Report OSP usage
 * param msg SIP message
 * param whorelease Who releases the call first, 0 orig, 1 term
 * param ignore2
 * return MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure
 */
int ospReportUsage(
    struct sip_msg* msg,
    int* whorelease)
{
    OSPE_RELEASE release;
    char* tmp;
    char* token;
    char parameters[OSP_HEADERBUF_SIZE];
    OSPT_CALL_ID* callid = NULL;
    int result = MODULE_RETURNCODE_FALSE;

    ospGetCallId(msg, &callid);

    if (callid != NULL) {
        /* Who releases the call first, 0 orig, 1 term */
            release = *whorelease;
            if (((release != OSPC_RELEASE_SOURCE) && (release != OSPC_RELEASE_DESTINATION))) {
                release = OSPC_RELEASE_UNKNOWN;
            }
            LM_DBG("who releases the call first '%d'\n", release);

            if (ospGetRouteParam(msg, parameters, sizeof(parameters)) == 0) {
                for (token = strtok_r(parameters, ";", &tmp);
                     token;
                     token = strtok_r(NULL, ";", &tmp))
                {
                    if ((strncmp(token, OSP_ORIG_COOKIE, strlen(OSP_ORIG_COOKIE)) == 0) &&
                        (token[strlen(OSP_ORIG_COOKIE)] == '='))
                    {
                        LM_INFO("report orig duration for call_id '%.*s'\n",
                            callid->Length,
                            callid->Value);
                        ospReportUsageFromCookie(msg, token + strlen(OSP_ORIG_COOKIE) + 1, callid, release, OSPC_ROLE_SOURCE);
                        result = MODULE_RETURNCODE_TRUE;
                    } else if ((strncmp(token, OSP_TERM_COOKIE, strlen(OSP_TERM_COOKIE)) == 0) &&
                        (token[strlen(OSP_TERM_COOKIE)] == '='))
                    {
                        LM_INFO("report term duration for call_id '%.*s'\n",
                            callid->Length,
                            callid->Value);
                        ospReportUsageFromCookie(msg, token + strlen(OSP_TERM_COOKIE) + 1, callid, release, OSPC_ROLE_DESTINATION);
                        result = MODULE_RETURNCODE_TRUE;
                    } else {
                        LM_DBG("ignoring parameter '%s'\n", token);
                    }
                }
            }

            if (result == MODULE_RETURNCODE_FALSE) {
                LM_DBG("without orig or term OSP information\n");
                LM_INFO("report other duration for call_id '%.*s'\n",
                   callid->Length,
                   callid->Value);
                ospReportUsageFromCookie(msg, NULL, callid, release, OSPC_ROLE_SOURCE);
                result = MODULE_RETURNCODE_TRUE;
            }

        OSPPCallIdDelete(&callid);
    }

    if (result == MODULE_RETURNCODE_FALSE) {
        LM_ERR("failed to report usage\n");
    }

    return result;
}

/*
 * Build OSP usage from destination
 * param transaction OSP transaction handle
 * param inbound Inbound info
 * param dest Destination
 * param lastcode Destination status
 * return 0 success, others failure
 */
static int ospBuildUsageFromDestination(
    OSPTTRANHANDLE transaction,
    osp_inbound* inbound,
    osp_dest* dest,
    int lastcode)
{
    int errorcode;
    char srcdev[OSP_STRBUF_SIZE];
    char source[OSP_STRBUF_SIZE];
    char host[OSP_STRBUF_SIZE];
    char destdev[OSP_STRBUF_SIZE];

    ospConvertToOutAddress(inbound->srcdev, srcdev, sizeof(srcdev));
    ospConvertToOutAddress(inbound->source, source, sizeof(source));
    ospConvertToOutAddress(dest->host, host, sizeof(host));
    ospConvertToOutAddress(dest->destdev, destdev, sizeof(destdev));

    /* Must be called before BuildUsageFromScratch */
    OSPPTransactionSetSrcSwitchId(transaction, inbound->swid);

    errorcode = OSPPTransactionBuildUsageFromScratch(
        transaction,
        dest->transid,
        dest->type,
        source,
        host,
        srcdev,
        destdev,
        dest->calling,
        OSPC_NFORMAT_E164,
        inbound->called,    /* Report original called number */
        OSPC_NFORMAT_E164,
        dest->callidsize,
        dest->callid,
        lastcode,
        NULL,
        NULL);

    OSPPTransactionSetSrcNetworkId(transaction, inbound->snid);
    OSPPTransactionSetDestNetworkId(transaction, dest->dnid);

    OSPPTransactionSetDestSwitchId(transaction, dest->swid);

    OSPPTransactionSetDestAudioAddr(transaction, dest->destmedia);

    OSPPTransactionSetProxyEgressAddr(transaction, dest->egress);

    if (dest->starttime && dest->endtime && (dest->starttime <= dest->endtime)) {
        OSPPTransactionSetProviderPDD(transaction, (dest->endtime - dest->starttime) * 1000);
    }

    return errorcode;
}

/*
 * Report OSP usage from destination
 * param transaction OSP transaction handle
 * param inbound Inbound info
 * param dest Destination
 * return 0 success
 */
static int ospReportUsageFromDestination(
    OSPTTRANHANDLE transaction,
    osp_inbound* inbound,
    osp_dest* dest)
{
    OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_FROM, OSPC_NFORMAT_DISPLAYNAME, inbound->fromdisplay);

    OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_RPID, OSPC_NFORMAT_E164, inbound->rpiduser);
    OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_RPID, OSPC_NFORMAT_TRANSPORT, inbound->rpidhost);
    OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_PAI, OSPC_NFORMAT_E164, inbound->paiuser);
    OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_PAI, OSPC_NFORMAT_TRANSPORT, inbound->paihost);
    OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_PCI, OSPC_NFORMAT_E164, inbound->pciuser);
    OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_PCI, OSPC_NFORMAT_TRANSPORT, inbound->pcihost);
    OSPPTransactionSetDiversion(transaction, inbound->divuser, inbound->divhost);
    OSPPTransactionSetSIPHeader(transaction, OSPC_SIPHEADER_CONTACT, OSPC_NFORMAT_TRANSPORT, inbound->contacthost);

    OSPPTransactionSetChargingVector(transaction, inbound->pcvicid, NULL, NULL, NULL);

    OSPPTransactionSetSrcAudioAddr(transaction, inbound->srcmedia);

    OSPPTransactionSetProxyIngressAddr(transaction, inbound->ingressaddr);

    OSPPTransactionSetSrcServiceProvider(transaction, inbound->sp);

    OSPPTransactionSetCallPartyInfo(transaction, OSPC_CPARTY_SOURCE, NULL, inbound->userid, inbound->usergroup);

    OSPPTransactionSetCDRProxy(transaction, _osp_in_device, OSP_OPENSIPS, NULL);

    ospReportUsageWrapper(
        transaction,                                            /* In - Transaction handle */
        dest->lastcode,                                         /* In - Release Code */
        0,                                                      /* In - Length of call */
        inbound->authtime,                                      /* In - Call start time */
        0,                                                      /* In - Call end time */
        dest->time180,                                          /* In - Call alert time */
        dest->time200,                                          /* In - Call connect time */
        dest->time180 ? 1 : 0,                                  /* In - Is PDD Info present */
        dest->time180 ? dest->time180 - inbound->authtime : 0,  /* In - Post Dial Delay */
        ((dest->lastcode == 200) || (dest->lastcode == 300)) ? OSPC_RELEASE_UNKNOWN : OSPC_RELEASE_INTERNAL);

    return 0;
}

/*
 * Report originate call setup usage
 */
void ospReportOrigSetupUsage(void)
{
    osp_inbound* inbound = ospGetInboundInfo();
    struct usr_avp* destavp = NULL;
    int_str destval;
    osp_dest* dest = NULL;
    osp_dest* lastused = NULL;
    OSPTTRANHANDLE trans = -1;
    int lastcode = 0;
    OSPE_ROLE_STATE rstate;
    int errcode;

    errcode = OSPPTransactionNew(_osp_provider, &trans);
    if (errcode != OSPC_ERR_NO_ERROR) {
        return;
    }

    if (inbound == NULL) {
        return;
    }

    for (destavp = search_first_avp(AVP_VAL_STR, _osp_origdest_avpid, NULL, 0);
        destavp != NULL;
        destavp = search_next_avp(destavp, NULL))
    {
        get_avp_val(destavp, &destval);

        /* OSP destination is wrapped in a string */
        dest = (osp_dest*)destval.s.s;

        if (dest->used == 1) {
            LM_DBG("iterating through used destination\n");

            if (dest->reported == 1) {
                LM_DBG("orig setup already reported\n");
                break;
            } else {
                dest->reported = 1;
                ospDumpDestination(dest);
                lastused = dest;
                if (dest->lastcode == 200) {
                    rstate = OSPC_RSTATE_START;
                } else if (dest->lastcode == 300) {
                    rstate = OSPC_RSTATE_REDIRECT;
                } else {
                    rstate = OSPC_RSTATE_STOP;
                }
                /* RoleInfo must be set before BuildUsageFromScratch */
                OSPPTransactionSetRoleInfo(trans, rstate, OSPC_RFORMAT_OSP, OSPC_RVENDOR_OPENSIPS);
                ospBuildUsageFromDestination(trans, inbound, dest, lastcode);
                OSPPTransactionSetProtocol(trans, OSPC_PROTTYPE_SOURCE, OSPC_PROTNAME_SIP);
                OSPPTransactionSetProtocol(trans, OSPC_PROTTYPE_DESTINATION, dest->protocol);
                lastcode = dest->lastcode;
            }
        } else {
            LM_DBG("destination has not been used, breaking out\n");
            break;
        }
    }

    if (lastused) {
        LM_INFO("report orig setup for call_id '%.*s' transaction_id '%llu'\n",
            lastused->callidsize,
            lastused->callid,
            lastused->transid);
        ospReportUsageFromDestination(trans, inbound, lastused);
    } else {
        /* If a Toolkit transaction handle was created, but we did not find
         * any destinations to report, we need to release the handle. Otherwise,
         * the ospReportUsageFromDestination will release it.
         */
        OSPPTransactionDelete(trans);
    }
}

/*
 * Report terminate call setup usage
 */
void ospReportTermSetupUsage(void)
{
    osp_inbound* inbound = ospGetInboundInfo();
    osp_dest* dest = ospGetTermDestination();
    OSPTTRANHANDLE trans = -1;
    OSPE_ROLE_STATE rstate;
    int errorcode;

    if (inbound != NULL) {
        if (dest != NULL) {
            if (dest->reported == 0) {
                dest->reported = 1;
                LM_INFO("report term setup for call_id '%.*s' transaction_id '%llu'\n",
                    dest->callidsize,
                    dest->callid,
                    dest->transid);
                errorcode = OSPPTransactionNew(_osp_provider, &trans);
                if (errorcode == OSPC_ERR_NO_ERROR) {
                    if (dest->lastcode == 200) {
                        rstate = OSPC_RSTATE_START;
                    } else if (dest->lastcode == 300) {
                        rstate = OSPC_RSTATE_REDIRECT;
                    } else {
                        rstate = OSPC_RSTATE_STOP;
                    }
                    /* RoleInfo must be set before BuildUsageFromScratch */
                    OSPPTransactionSetRoleInfo(trans, rstate, OSPC_RFORMAT_OSP, OSPC_RVENDOR_OPENSIPS);
                    ospBuildUsageFromDestination(trans, inbound, dest, 0);
                    OSPPTransactionSetProtocol(trans, OSPC_PROTTYPE_DESTINATION, OSPC_PROTNAME_SIP);
                    ospReportUsageFromDestination(trans, inbound, dest);
                }
            } else {
                LM_DBG("term setup already reported\n");
            }
        } else {
            LM_ERR("without term setup to report\n");
        }
    } else {
        LM_ERR("internal error\n");
    }
}
