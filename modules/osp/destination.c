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

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../str.h"
#include "../../dprint.h"
#include "../../usr_avp.h"
#include "destination.h"
#include "usage.h"

extern int _osp_inbound_avpid;
extern int _osp_origdest_avpid;
extern int _osp_termdest_avpid;
extern int _osp_calling_avpid;
extern int _osp_destmedia_avpid;
extern unsigned short _osp_destmedia_avptype;

/* Name of AVP of OSP */
static str OSP_INBOUND_NAME = {"_osp_inbound_", 13};
static str OSP_ORIGDEST_NAME = {"_osp_orig_dests_", 16};
static str OSP_TERMDEST_NAME = {"_osp_term_dests_", 16};
static str OSP_CALLING_NAME = {"_osp_calling_translated_", 24};

static int ospSaveDestination(osp_dest* dest, int avpid);
static void ospRecordCode(int code, osp_dest* dest);
static int ospIsToReportUsage(int code);

/*
 * Parses avps used by this module
 * return 0 success, -1 failure
 */
int ospParseAvps(void)
{
    if (parse_avp_spec(&OSP_INBOUND_NAME, &_osp_inbound_avpid)) {
        LM_ERR("cannot get INBOUND AVP id\n");
        return -1;
    }

    if (parse_avp_spec(&OSP_ORIGDEST_NAME, &_osp_origdest_avpid)) {
        LM_ERR("cannot get ORIGDEST AVP id\n");
        return -1;
    }

    if (parse_avp_spec(&OSP_TERMDEST_NAME, &_osp_termdest_avpid)) {
        LM_ERR("cannot get TERMDEST AVP id\n");
        return -1;
    }

    if (parse_avp_spec(&OSP_CALLING_NAME, &_osp_calling_avpid)) {
        LM_ERR("cannot get CALLING AVP id\n");
        return -1;
    }

    return 0;
}

/*
 * Initialize inbound info structure
 * param inbound Inbound info data structure
 */
void ospInitInboundInfo(
    osp_inbound* inbound)
{
    memset(inbound, 0, sizeof(osp_inbound));
}

/*
 * Save inbound info as an AVP
 *     avpid - osp_inbound_avpid
 *     value - osp_inbound wrapped in a string
 * param inbound Inbound info structure
 * return 0 success, -1 failure
 */
int ospSaveInboundInfo(
    osp_inbound* inbound)
{
    str wrapper;
    int result = -1;

    wrapper.s = (char*)inbound;
    wrapper.len = sizeof(osp_inbound);

    /*
     * add_avp will make a private copy of both the avpid and value in shared
     * memory which will be released by TM at the end of the transaction
     */
    if (add_avp(AVP_VAL_STR, _osp_inbound_avpid, (int_str)wrapper) == 0) {
        LM_DBG("inbound info saved\n");
        result = 0;
    } else {
        LM_ERR("failed to save inbound info\n");
    }

    return result;
}

/*
 * Retrieved the inbound info from an AVP
 *     avpid - osp_inbound_avpid
 *     value - osp_inbound wrapped in a string
 *  return NULL on failure
 */
osp_inbound* ospGetInboundInfo(void)
{
    int_str inboundval;
    osp_inbound* inbound = NULL;

    if (search_first_avp(AVP_VAL_STR, _osp_inbound_avpid, &inboundval, 0) != NULL) {
        /* OSP inbound info is wrapped in a string */
        inbound = (osp_inbound*)inboundval.s.s;

        LM_DBG("inbound info found\n");
    }

    return inbound;
}

/*
 * Initialize destination structure
 * param dest Destination data structure
 * return initialized destination sturcture
 */
osp_dest* ospInitDestination(
    osp_dest* dest)
{
    memset(dest, 0, sizeof(osp_dest));

    dest->callidsize = sizeof(dest->callid);
    dest->tokensize = sizeof(dest->token);

    LM_DBG("callidsize '%d' tokensize '%d'\n", dest->callidsize, dest->tokensize);

    return dest;
}

/*
 * Save destination as an AVP
 *     avpid - osp_origdest_avpid / osp_termdest_avpid
 *     value - osp_dest wrapped in a string
 * param dest Destination structure
 * param avpid ID of AVP
 * return 0 success, -1 failure
 */
static int ospSaveDestination(
    osp_dest* dest,
    int avpid)
{
    str wrapper;
    int result = -1;

    wrapper.s = (char*)dest;
    wrapper.len = sizeof(osp_dest);

    /*
     * add_avp will make a private copy of both the avpid and value in shared
     * memory which will be released by TM at the end of the transaction
     */
    if (add_avp(AVP_VAL_STR, avpid, (int_str)wrapper) == 0) {
        LM_DBG("destination saved\n");
        result = 0;
    } else {
        LM_ERR("failed to save destination\n");
    }

    return result;
}

/*
 * Save originate destination
 * param dest Originate destination structure
 * return 0 success, -1 failure
 */
int ospSaveOrigDestination(
    osp_dest* dest)
{
    return ospSaveDestination(dest, _osp_origdest_avpid);
}

/*
 * Save terminate destination
 * param dest Terminate destination structure
 * return 0 success, -1 failure
 */
int ospSaveTermDestination(
    osp_dest* dest)
{
    return ospSaveDestination(dest, _osp_termdest_avpid);
}

/*
 * Check if there is an unused and supported originate destination from an AVP
 *     avpid - osp_origdest_avpid
 *     value - osp_dest wrapped in a string
 *     search unused (used==0) & supported (support==1)
 * return 0 success, -1 failure
 */
int ospCheckOrigDestination(void)
{
    struct usr_avp* destavp = NULL;
    int_str destval;
    osp_dest* dest = NULL;
    int result = -1;

    for (destavp = search_first_avp(AVP_VAL_STR, _osp_origdest_avpid, NULL, 0);
        destavp != NULL;
        destavp = search_next_avp(destavp, NULL))
    {
        get_avp_val(destavp, &destval);

        /* OSP destintaion is wrapped in a string */
        dest = (osp_dest*)destval.s.s;

        if (dest->used == 0) {
            if (dest->supported == 1) {
                LM_DBG("orig dest exist\n");
                result = 0;
                break;
            } else {
                /* Make it looks like used */
                dest->used = 1;
                /* 111 means wrong protocol */
                dest->lastcode = 111;
                LM_DBG("destination does not been supported\n");
            }
        } else {
            LM_DBG("destination has already been used\n");
        }
    }

    if (result == -1) {
        LM_DBG("there is not unused destination\n");
        ospReportOrigSetupUsage();
    }

    return result;
}

/*
 * Retrieved an unused and supported originate destination from an AVP
 *     avpid - osp_origdest_avpid
 *     value - osp_dest wrapped in a string
 *     There can be 0, 1 or more originate destinations.
 *     Find the 1st unused destination (used==0) & supported (support==1),
 *     return it, and mark it as used (used==1).
 * return NULL on failure
 */
osp_dest* ospGetNextOrigDestination(void)
{
    struct usr_avp* destavp = NULL;
    int_str destval;
    osp_dest* dest = NULL;
    osp_dest* result = NULL;

    for (destavp = search_first_avp(AVP_VAL_STR, _osp_origdest_avpid, NULL, 0);
        destavp != NULL;
        destavp = search_next_avp(destavp, NULL))
    {
        get_avp_val(destavp, &destval);

        /* OSP destintaion is wrapped in a string */
        dest = (osp_dest*)destval.s.s;

        if (dest->used == 0) {
            if (dest->supported == 1) {
                LM_DBG("orig dest found\n");
                dest->used = 1;
                result = dest;
                break;
            } else {
                /* Make it looks like used */
                dest->used = 1;
                /* 111 means wrong protocol */
                dest->lastcode = 111;
                LM_DBG("destination does not been supported\n");
            }
        } else {
            LM_DBG("destination has already been used\n");
        }
    }

    if (result == NULL) {
        LM_DBG("there is not unused destination\n");
    }

    return result;
}

/*
 * Retrieved the last used originate destination from an AVP
 *    avpid - osp_origdest_avpid
 *    value - osp_dest wrapped in a string
 *    There can be 0, 1 or more destinations.
 *    Find the last used destination (used==1) & supported (support==1),
 *    and return it.
 *    In normal condition, this one is the current destination. But it may
 *    be wrong for loop condition.
 *  return NULL on failure
 */
osp_dest* ospGetLastOrigDestination(void)
{
    struct usr_avp* destavp = NULL;
    int_str destval;
    osp_dest* dest = NULL;
    osp_dest* lastdest = NULL;

    for (destavp = search_first_avp(AVP_VAL_STR, _osp_origdest_avpid, NULL, 0);
        destavp != NULL;
        destavp = search_next_avp(destavp, NULL))
    {
        get_avp_val(destavp, &destval);

        /* OSP destination is wrapped in a string */
        dest = (osp_dest*)destval.s.s;

        if (dest->used == 1) {
            if (dest->supported == 1) {
                lastdest = dest;
                LM_DBG("curent destination '%s'\n", lastdest->host);
            }
        } else {
            break;
        }
    }

    return lastdest;
}

/*
 * Retrieved the terminate destination from an AVP
 *     avpid - osp_termdest_avpid
 *     value - osp_dest wrapped in a string
 *     There can be 0 or 1 term destinations. Find and return it.
 *  return NULL on failure (no terminate destination)
 */
osp_dest* ospGetTermDestination(void)
{
    int_str destval;
    osp_dest* dest = NULL;

    if (search_first_avp(AVP_VAL_STR, _osp_termdest_avpid, &destval, 0) != NULL) {
        /* OSP destination is wrapped in a string */
        dest = (osp_dest*)destval.s.s;

        LM_DBG("term dest found\n");
    }

    return dest;
}

/*
 * Record destination status
 * param code Destination status
 * param dest Destination
 */
static void ospRecordCode(
    int code,
    osp_dest* dest)
{
    struct usr_avp* destmediaavp = NULL;
    int_str destmediaval;

    LM_DBG("code '%d'\n", code);
    dest->lastcode = code;

    switch (code) {
        case 100:
            if (!dest->time100) {
                dest->time100 = time(NULL);
            } else {
                LM_DBG("100 already recorded\n");
            }
            break;
        case 180:
        case 181:
        case 182:
        case 183:
            if (!dest->time180) {
                dest->time180 = time(NULL);

                if (!dest->endtime) {
                    dest->endtime = time(NULL);
                } else {
                    LM_DBG("180, 181, 182 or 183 end already recorded\n");
                }
            } else {
                LM_DBG("180, 181, 182 or 183 already recorded\n");
            }
            break;
        case 200:
        case 202:
            if (!dest->time200) {
                dest->time200 = time(NULL);

                if ((_osp_destmedia_avpid >= 0) &&
                    ((destmediaavp = search_first_avp(_osp_destmedia_avptype, _osp_destmedia_avpid, &destmediaval, 0)) != NULL) &&
                    (destmediaavp->flags & AVP_VAL_STR) && (destmediaval.s.s && destmediaval.s.len))
                {
                    snprintf(dest->destmedia, sizeof(dest->destmedia), "%.*s", destmediaval.s.len, destmediaval.s.s);
                } else {
                    dest->destmedia[0] = '\0';
                }
            } else {
                LM_DBG("200 or 202 already recorded\n");
            }
            break;
        case 408:
        case 487:
            if (!dest->endtime) {
                dest->endtime = time(NULL);
            } else {
                LM_DBG("408 or 487 end already recorded\n");
            }
            break;
        default:
            /* It may overwrite existing end time, it is the expected behavior */
            if ((code >= 400) && (code <= 699)) {
                dest->endtime = time(NULL);
            }
    }
}

/*
 * Check destination status for reporting usage
 * param code Destination status
 * return 1 should report, 0 should not report
 */
static int ospIsToReportUsage(
    int code)
{
    int istime = 0;

    LM_DBG("code '%d'\n", code);
    if (code >= 200) {
        istime = 1;
    }

    return istime;
}

/*
 * Report call setup usage for both client and server side
 * param clientcode Client status
 * param servercode Server status
 */
void ospRecordEvent(
    int clientcode,
    int servercode)
{
    osp_dest* dest;

    LM_DBG("client status '%d'\n", clientcode);
    if ((clientcode != 0) && (dest = ospGetLastOrigDestination())) {
        ospRecordCode(clientcode, dest);

        if (ospIsToReportUsage(servercode) == 1) {
            ospReportOrigSetupUsage();
        }
    }

    LM_DBG("server status '%d'\n", servercode);
    if ((servercode != 0) && (dest = ospGetTermDestination())) {
        ospRecordCode(servercode, dest);

        if (ospIsToReportUsage(servercode) == 1) {
            ospReportTermSetupUsage();
        }
    }
}

/*
 * Dump destination information
 * param dest Destination
 */
void ospDumpDestination(
    osp_dest* dest)
{
    LM_DBG("dest->host..........'%s'\n", dest->host);
    LM_DBG("dest->used..........'%d'\n", dest->used);
    LM_DBG("dest->lastcode......'%d'\n", dest->lastcode);
    LM_DBG("dest->time100.......'%d'\n", (unsigned int)dest->time100);
    LM_DBG("dest->time180.......'%d'\n", (unsigned int)dest->time180);
    LM_DBG("dest->time200.......'%d'\n", (unsigned int)dest->time200);
}

/*
 * Dump all destination information
 */
void ospDumpAllDestination(void)
{
    struct usr_avp* destavp = NULL;
    int_str destval;
    osp_dest* dest = NULL;
    int count = 0;

    for (destavp = search_first_avp(AVP_VAL_STR, _osp_origdest_avpid, NULL, 0);
        destavp != NULL;
        destavp = search_next_avp(destavp, NULL))
    {
        get_avp_val(destavp, &destval);

        /* OSP destination is wrapped in a string */
        dest = (osp_dest*)destval.s.s;

        LM_DBG("....originate '%d'....\n", count++);

        ospDumpDestination(dest);
    }
    if (count == 0) {
        LM_DBG("there is not originate destination AVP\n");
    }

    if (search_first_avp(AVP_VAL_STR, _osp_termdest_avpid, &destval, 0) != NULL) {
        /* OSP destination is wrapped in a string */
        dest = (osp_dest*)destval.s.s;

        LM_DBG("....terminate....\n");

        ospDumpDestination(dest);
    } else {
        LM_DBG("there is not terminate destination AVP\n");
    }
}

/*
 * Convert "address:port" to "[x.x.x.x]:port" or "hostname:port" format
 * param src Source address string
 * param dest Destination address string
 * param bufsize Size of dest buffer
 */
void ospConvertToOutAddress(
    const char* src,
    char* dest,
    int bufsize)
{
    struct in_addr inp;
    char buffer[OSP_STRBUF_SIZE];
    char* port;
    int size;

    if ((src != NULL) && (*src != '\0')) {
        size = sizeof(buffer);
        strncpy(buffer, src, size);
        buffer[size - 1] = '\0';

        if((port = strchr(buffer, ':')) != NULL) {
            *port = '\0';
            port++;
        }

        if (inet_pton(AF_INET, buffer, &inp) == 1) {
            if (port != NULL) {
                snprintf(dest, bufsize, "[%s]:%s", buffer, port);
            } else {
                snprintf(dest, bufsize, "[%s]", buffer);
            }
        } else {
            strncpy(dest, src, bufsize);
            dest[bufsize - 1] = '\0';
        }
    } else {
        *dest = '\0';
    }
}

/*
 * Convert "[x.x.x.x]:port" or "hostname:prot" to "address:port" format
 * param src Source address string
 * param dest Destination address string
 * param bufsize Size of dest buffer
 */
void ospConvertToInAddress(
    const char* src,
    char* dest,
    int bufsize)
{
    char buffer[OSP_STRBUF_SIZE];
    char* end;
    char* port;
    int size;

    if ((src != NULL) && (*src != '\0')) {
        size = sizeof(buffer);
        strncpy(buffer, src, size);
        buffer[size - 1] = '\0';

        if (buffer[0] == '[') {
            if((port = strchr(buffer + 1, ':')) != NULL) {
                *port = '\0';
                port++;
            }

            if ((end = strchr(buffer + 1, ']')) != NULL) {
                *end = '\0';
            }

            if (port != NULL) {
                snprintf(dest, bufsize, "%s:%s", buffer + 1, port);
            } else {
                strncpy(dest, buffer + 1, bufsize);
                dest[bufsize - 1] = '\0';
            }
        } else {
            strncpy(dest, src, bufsize);
            dest[bufsize - 1] = '\0';
        }
    } else {
        *dest = '\0';
    }
}

