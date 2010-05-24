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

#include <string.h>
#include <osp/osp.h>
#include "../../dset.h"
#include "../../usr_avp.h"
#include "../../mem/mem.h"
#include "../auth/api.h"
#include "orig_transaction.h"
#include "destination.h"
#include "osptoolkit.h"
#include "sipheader.h"
#include "usage.h"

extern int _osp_service_type;
extern char _osp_in_device[];
extern char _osp_out_device[];
extern int _osp_max_dests;
extern int _osp_redir_uri;
extern int_str _osp_snid_avpname;
extern unsigned short _osp_snid_avptype;
extern int_str _osp_cinfo_avpname;
extern unsigned short _osp_cinfo_avptype;
extern OSPTPROVHANDLE _osp_provider;
extern auth_api_t osp_auth;

const int OSP_FIRST_ROUTE = 1;
const int OSP_NEXT_ROUTE = 0;
const int OSP_MAIN_ROUTE = 1;
const int OSP_BRANCH_ROUTE = 0;
const str OSP_CALLING_NAME = {"_osp_calling_translated_", 24};

static int ospLoadRoutes(OSPTTRANHANDLE transaction, int destcount, char* source, char* srcdev, char* origcalled, time_t authtime);
static int ospPrepareDestination(struct sip_msg* msg, int isfirst, int type, int format);
static int ospSetCalling(struct sip_msg* msg, osp_dest* dest);

/*
 * Get routes from AuthRsp
 * param transaction Transaction handle
 * param destcount Expected destination count
 * param source Source IP
 * param srcdev Source device IP
 * param origcalled Original called number
 * param authtime Request authorization time
 * return 0 success, -1 failure
 */
static int ospLoadRoutes(
    OSPTTRANHANDLE transaction,
    int destcount,
    char* source,
    char* srcdev,
    char* origcalled,
    time_t authtime)
{
    int count;
    int errorcode;
    osp_dest* dest;
    osp_dest dests[OSP_DEF_DESTS];
    char host[OSP_STRBUF_SIZE];
    char destdev[OSP_STRBUF_SIZE];
    OSPE_OPERATOR_NAME type;
    OSPE_DEST_PROTOCOL protocol;
    OSPE_DEST_OSPENABLED enabled;
    int result = 0;

    for (count = 0; count < destcount; count++) {
        /* This is necessary because we will save destinations in reverse order */
        dest = ospInitDestination(&dests[count]);

        if (dest == NULL) {
            result = -1;
            break;
        }

        dest->destcount = count + 1;
        strncpy(dest->origcalled, origcalled, sizeof(dest->origcalled) - 1);

        if (count == 0) {
            errorcode = OSPPTransactionGetFirstDestination(
                transaction,
                sizeof(dest->validafter),
                dest->validafter,
                dest->validuntil,
                &dest->timelimit,
                &dest->callidsize,
                (void*)dest->callid,
                sizeof(dest->called),
                dest->called,
                sizeof(dest->calling),
                dest->calling,
                sizeof(host),
                host,
                sizeof(destdev),
                destdev,
                &dest->tokensize,
                dest->token);
        } else {
            errorcode = OSPPTransactionGetNextDestination(
                transaction,
                0,
                sizeof(dest->validafter),
                dest->validafter,
                dest->validuntil,
                &dest->timelimit,
                &dest->callidsize,
                (void*)dest->callid,
                sizeof(dest->called),
                dest->called,
                sizeof(dest->calling),
                dest->calling,
                sizeof(host),
                host,
                sizeof(destdev),
                destdev,
                &dest->tokensize,
                dest->token);
        }

        if (errorcode != OSPC_ERR_NO_ERROR) {
            LM_ERR("failed to load routes (%d) expected '%d' current '%d'\n",
                errorcode,
                destcount,
                count);
            result = -1;
            break;
        }

        ospConvertToInAddress(host, dest->host, sizeof(dest->host));

        errorcode = OSPPTransactionGetNumberPortabilityParameters(transaction,
            sizeof(dest->nprn),
            dest->nprn,
            sizeof(dest->npcic),
            dest->npcic,
            &dest->npdi);
        if (errorcode != OSPC_ERR_NO_ERROR) {
            LM_DBG("cannot get number portability parameters (%d)\n", errorcode);
            dest->nprn[0] = '\0';
            dest->npcic[0] = '\0';
            dest->npdi = 0;
        }

        for (type = OSPC_OPNAME_START; type < OSPC_OPNAME_NUMBER; type++) {
            errorcode = OSPPTransactionGetOperatorName(transaction,
                type,
                sizeof(dest->opname[type]),
                dest->opname[type]);
            if (errorcode != OSPC_ERR_NO_ERROR) {
                LM_DBG("cannot get operator name '%d' (%d)\n", type, errorcode);
                dest->opname[type][0] = '\0';
            }
        }

        errorcode = OSPPTransactionGetDestProtocol(transaction, &protocol);
        if (errorcode != OSPC_ERR_NO_ERROR) {
            /* This does not mean an ERROR. The OSP server may not support OSP 2.1.1 */
            LM_DBG("cannot get dest protocol (%d)\n", errorcode);
            protocol = OSPC_DPROT_SIP;
        }
        switch (protocol) {
            case OSPC_DPROT_Q931:
            case OSPC_DPROT_LRQ:
            case OSPC_DPROT_IAX:
            case OSPC_DPROT_T37:
            case OSPC_DPROT_T38:
            case OSPC_DPROT_SKYPE:
            case OSPC_DPROT_SMPP:
            case OSPC_DPROT_XMPP:
                dest->supported = 0;
                break;
            case OSPC_DPROT_SIP:
            case OSPC_DPROT_UNDEFINED:
            case OSPC_DPROT_UNKNOWN:
            default:
                dest->supported = 1;
                break;
        }

        errorcode = OSPPTransactionIsDestOSPEnabled(transaction, &enabled);
        if (errorcode != OSPC_ERR_NO_ERROR) {
            /* This does not mean an ERROR. The OSP server may not support OSP 2.1.1 */
            LM_DBG("cannot get dest OSP version (%d)\n", errorcode);
        } else if (enabled == OSPC_DOSP_FALSE) {
            /* Destination device does not support OSP. Do not send token to it */
            dest->token[0] = '\0';
            dest->tokensize = 0;
        }

        errorcode = OSPPTransactionGetDestinationNetworkId(transaction, sizeof(dest->networkid), dest->networkid);
        if (errorcode != OSPC_ERR_NO_ERROR) {
            /* This does not mean an ERROR. The OSP server may not support OSP 2.1.1 */
            LM_DBG("cannot get dest network ID (%d)\n", errorcode);
            dest->networkid[0] = '\0';
        }

        strncpy(dest->source, source, sizeof(dest->source) - 1);
        strncpy(dest->srcdev, srcdev, sizeof(dest->srcdev) - 1);
        dest->type = OSPC_ROLE_SOURCE;
        dest->transid = ospGetTransactionId(transaction);
        dest->authtime = authtime;

        LM_INFO("get destination '%d': "
            "valid after '%s' "
            "valid until '%s' "
            "time limit '%d' seconds "
            "call id '%.*s' "
            "calling '%s' "
            "called '%s' "
            "host '%s' "
            "nprn '%s' "
            "npcic '%s' "
            "npdi '%d' "
            "spid '%s' "
            "ocn '%s' "
            "spn '%s' "
            "altspn '%s' "
            "mcc '%s' "
            "mnc '%s' "
            "supported '%d' "
            "network id '%s' "
            "token size '%d'\n",
            count,
            dest->validafter,
            dest->validuntil,
            dest->timelimit,
            dest->callidsize,
            dest->callid,
            dest->calling,
            dest->called,
            host,
            dest->nprn,
            dest->npcic,
            dest->npdi,
            dest->opname[OSPC_OPNAME_SPID],
            dest->opname[OSPC_OPNAME_OCN],
            dest->opname[OSPC_OPNAME_SPN],
            dest->opname[OSPC_OPNAME_ALTSPN],
            dest->opname[OSPC_OPNAME_MCC],
            dest->opname[OSPC_OPNAME_MNC],
            dest->supported,
            dest->networkid,
            dest->tokensize);
    }

    /*
     * Save destination in reverse order,
     * when we start searching avps the destinations
     * will be in order
     */
    if (result == 0) {
        for(count = destcount -1; count >= 0; count--) {
            if (ospSaveOrigDestination(&dests[count]) == -1) {
                LM_ERR("failed to save originate destination\n");
                /* Report terminate CDR */
                ospRecordEvent(0, 500);
                result = -1;
                break;
            }
        }
    }

    return result;
}

/*
 * Request OSP authorization and routeing
 * param msg SIP message
 * param ignore1
 * param ignore2
 * return MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure, MODULE_RETURNCODE_ERROR error
 */
int ospRequestRouting(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    int errorcode;
    time_t authtime;
    char calling[OSP_STRBUF_SIZE];
    char called[OSP_STRBUF_SIZE];
    char rn[OSP_STRBUF_SIZE];
    char cic[OSP_STRBUF_SIZE];
    int npdi;
    OSPE_OPERATOR_NAME type;
    char opname[OSPC_OPNAME_NUMBER][OSP_STRBUF_SIZE];
    char source[OSP_STRBUF_SIZE];
    char sourcebuf[OSP_STRBUF_SIZE];
    char srcdev[OSP_STRBUF_SIZE];
    char srcdevbuf[OSP_STRBUF_SIZE];
    char divuser[OSP_STRBUF_SIZE];
    char divhost[OSP_STRBUF_SIZE];
    char divhostbuf[OSP_STRBUF_SIZE];
    struct usr_avp* snidavp = NULL;
    int_str snidval;
    char snid[OSP_STRBUF_SIZE];
    struct usr_avp* cinfoavp = NULL;
    int_str cinfoval;
    unsigned int cinfonum = 0, i;
    char cinfo[OSP_DEF_CINFOS][OSP_STRBUF_SIZE];
    char cinfostr[OSP_STRBUF_SIZE];
    unsigned int callidnumber = 1;
    OSPT_CALL_ID* callids[callidnumber];
    unsigned int logsize = 0;
    char* detaillog = NULL;
    char tohost[OSP_STRBUF_SIZE];
    char tohostbuf[OSP_STRBUF_SIZE];
    const char* preferred[2] = { NULL };
    unsigned int destcount;
    OSPTTRANHANDLE transaction = -1;
    int result = MODULE_RETURNCODE_FALSE;

    if ((errorcode = OSPPTransactionNew(_osp_provider, &transaction)) != OSPC_ERR_NO_ERROR) {
        LM_ERR("failed to create new OSP transaction (%d)\n", errorcode);
    } else if ((ospGetRpidUserpart(msg, calling, sizeof(calling)) != 0) && (ospGetFromUserpart(msg, calling, sizeof(calling)) != 0)) {
        LM_ERR("failed to extract calling number\n");
    } else if ((ospGetUriUserpart(msg, called, sizeof(called)) != 0) && (ospGetToUserpart(msg, called, sizeof(called)) != 0)) {
        LM_ERR("failed to extract called number\n");
    } else if (ospGetCallId(msg, &(callids[0])) != 0) {
        LM_ERR("failed to extract call id\n");
    } else if (ospGetSource(msg, source, sizeof(source)) != 0) {
        LM_ERR("failed to extract source address\n");
    } else if (ospGetSourceDevice(msg, srcdev, sizeof(srcdev)) != 0) {
        LM_ERR("failed to extract source deivce address\n");
    } else {
        authtime = time(NULL);

        ospConvertToOutAddress(source, sourcebuf, sizeof(sourcebuf));
        ospConvertToOutAddress(srcdev, srcdevbuf, sizeof(srcdevbuf));

        switch (_osp_service_type) {
        case 1:
            OSPPTransactionSetServiceType(transaction, OSPC_SERVICE_NPQUERY);

            ospGetToHostpart(msg, tohost, sizeof(tohost));
            ospConvertToOutAddress(tohost, tohostbuf, sizeof(tohostbuf));
            preferred[0] = tohostbuf;

            destcount = 1;
            break;
        case 0:
        default:
            OSPPTransactionSetServiceType(transaction, OSPC_SERVICE_VOICE);

            destcount = _osp_max_dests;
            break;
        }

        if (ospGetNpParameters(msg, rn, sizeof(rn), cic, sizeof(cic), &npdi) == 0) {
            OSPPTransactionSetNumberPortability(transaction, rn, cic, npdi);
        }

        for (type = OSPC_OPNAME_START; type < OSPC_OPNAME_NUMBER; type++) {
            if (ospGetOperatorName(msg, type, opname[type], sizeof(opname[type])) == 0) {
                OSPPTransactionSetOperatorName(transaction, type, opname[type]);
            }
        }

        if (ospGetDiversion(msg, divuser, sizeof(divuser), divhost, sizeof(divhost)) == 0) {
            ospConvertToOutAddress(divhost, divhostbuf, sizeof(divhostbuf));
        } else {
            divhostbuf[0] = '\0';
        }
        OSPPTransactionSetDiversion(transaction, divuser, divhostbuf);

        if ((_osp_snid_avpname.n != 0) &&
            ((snidavp = search_first_avp(_osp_snid_avptype, _osp_snid_avpname, &snidval, 0)) != NULL) &&
            (snidavp->flags & AVP_VAL_STR) && (snidval.s.s && snidval.s.len))
        {
            snprintf(snid, sizeof(snid), "%.*s", snidval.s.len, snidval.s.s);
            snid[sizeof(snid) - 1] = '\0';
            OSPPTransactionSetNetworkIds(transaction, snid, "");
        } else {
            snid[0] = '\0';
        }

        if (_osp_cinfo_avpname.n != 0) {
            for (i = 0, cinfoavp = search_first_avp(_osp_cinfo_avptype, _osp_cinfo_avpname, NULL, 0);
                ((i < OSP_DEF_CINFOS) && (cinfoavp != NULL));
                i++, cinfoavp = search_next_avp(cinfoavp, NULL))
            {
                get_avp_val(cinfoavp, &cinfoval);
                if ((cinfoavp->flags & AVP_VAL_STR) && (cinfoval.s.s && cinfoval.s.len)) {
                    snprintf(cinfo[i], sizeof(cinfo[i]), "%.*s", cinfoval.s.len, cinfoval.s.s);
                    cinfo[i][sizeof(cinfo[i]) - 1] = '\0';
                } else {
                    cinfo[i][0] = '\0';
                }
            }
            cinfonum = i;

            cinfostr[0] = '\0';
            for (i = 0; i < cinfonum; i++) {
                if (cinfo[cinfonum - i - 1][0] != '\0') {
                    OSPPTransactionSetCustomInfo(transaction, i, cinfo[cinfonum - i - 1]);
                    snprintf(cinfostr + strlen(cinfostr), sizeof(cinfostr) - strlen(cinfostr), "custom_info%d '%s' ", i + 1, cinfo[cinfonum - i - 1]);
                }
            }
            cinfostr[sizeof(cinfostr) - 1] = '\0';
        }

        LM_INFO("request auth and routing for: "
            "service_type '%d' "
            "source '%s' "
            "source_dev '%s' "
            "source_networkid '%s' "
            "calling '%s' "
            "called '%s' "
            "preferred '%s' "
            "nprn '%s' "
            "npcic '%s' "
            "npdi '%d' "
            "spid '%s' "
            "ocn '%s' "
            "spn '%s' "
            "altspn '%s' "
            "mcc '%s' "
            "mnc '%s' "
            "diversion_user '%s' "
            "diversion_host '%s' "
            "call_id '%.*s' "
            "dest_count '%d' "
            "%s\n",
            _osp_service_type,
            sourcebuf,
            srcdevbuf,
            snid,
            calling,
            called,
            (preferred[0] == NULL) ? "" : preferred[0],
            rn,
            cic,
            npdi,
            opname[OSPC_OPNAME_SPID],
            opname[OSPC_OPNAME_OCN],
            opname[OSPC_OPNAME_SPN],
            opname[OSPC_OPNAME_ALTSPN],
            opname[OSPC_OPNAME_MCC],
            opname[OSPC_OPNAME_MNC],
            divuser,
            divhostbuf,
            callids[0]->ospmCallIdLen,
            callids[0]->ospmCallIdVal,
            destcount,
            cinfostr);

        /* try to request authorization */
        errorcode = OSPPTransactionRequestAuthorisation(
            transaction,       /* transaction handle */
            sourcebuf,         /* from the configuration file */
            srcdevbuf,         /* source device of call, protocol specific, in OSP format */
            calling,           /* calling number in nodotted e164 notation */
            OSPC_NFORMAT_E164, /* calling number format */
            called,            /* called number */
            OSPC_NFORMAT_E164, /* called number format */
            "",                /* optional username string, used if no number */
            callidnumber,      /* number of call ids, here always 1 */
            callids,           /* sized-1 array of call ids */
            preferred,         /* preferred destinations */
            &destcount,        /* max destinations, after call dest_count */
            &logsize,          /* size allocated for detaillog (next param) 0=no log */
            detaillog);        /* memory location for detaillog to be stored */

        if ((errorcode == OSPC_ERR_NO_ERROR) &&
            (ospLoadRoutes(transaction, destcount, source, srcdev, called, authtime) == 0))
        {
            LM_INFO("there are '%d' OSP routes, call_id '%.*s'\n",
                destcount,
                callids[0]->ospmCallIdLen,
                callids[0]->ospmCallIdVal);
            result = MODULE_RETURNCODE_TRUE;
        } else {
            LM_ERR("failed to request auth and routing (%d), call_id '%.*s'\n",
                errorcode,
                callids[0]->ospmCallIdLen,
                callids[0]->ospmCallIdVal);
            switch (errorcode) {
                case OSPC_ERR_TRAN_ROUTE_BLOCKED:
                    result = -403;
                    break;
                case OSPC_ERR_TRAN_ROUTE_NOT_FOUND:
                    result = -404;
                    break;
                case OSPC_ERR_NO_ERROR:
                    /* AuthRsp ok but ospLoadRoutes fails */
                    result = MODULE_RETURNCODE_ERROR;
                    break;
                default:
                    result = MODULE_RETURNCODE_FALSE;
                    break;
            }
        }
    }

    if (callids[0] != NULL) {
        OSPPCallIdDelete(&(callids[0]));
    }

    if (transaction != -1) {
        OSPPTransactionDelete(transaction);
    }

    return result;
}

/*
 * Check if there is a route
 * param msg SIP message
 * param ignore1
 * param ignore2
 * return MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure
 */
int ospCheckRoute(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    if (ospCheckOrigDestination() == 0) {
        return MODULE_RETURNCODE_TRUE;
    } else {
        return MODULE_RETURNCODE_FALSE;
    }
}

/*
 * Set calling number if translated
 * param msg SIP message
 * param dest Destination structure
 * return 0 success, 1 calling number same or not support calling number translation, -1 failure
 */
static int ospSetCalling(
    struct sip_msg* msg,
    osp_dest* dest)
{
    str rpid;
    int_str val;
    char calling[OSP_STRBUF_SIZE];
    char buffer[OSP_STRBUF_SIZE];
    int result;

    if ((ospGetRpidUserpart(msg, calling, sizeof(calling)) != 0) && (ospGetFromUserpart(msg, calling, sizeof(calling)) != 0)) {
        LM_ERR("failed to extract calling number\n");
        result = -1;
    } else if (strcmp(calling, dest->calling) == 0) {
        LM_DBG("calling number does not been translated\n");
        result = 1;
    } else if ((osp_auth.rpid_avp.s.s == NULL) || (osp_auth.rpid_avp.s.len == 0)) {
        LM_WARN("rpid_avp is not foune, cannot set rpid avp\n");
        result = -1;
    } else {
        snprintf(buffer,
            sizeof(buffer),
            "\"%s\" <sip:%s@%s>",
            dest->calling,
            dest->calling,
            dest->source);
        buffer[sizeof(buffer) - 1] = '\0';

        rpid.s = buffer;
        rpid.len = strlen(buffer);
        add_avp(osp_auth.rpid_avp_type | AVP_VAL_STR, (int_str)osp_auth.rpid_avp, (int_str)rpid);

        result = 0;
    }

    if (result == 0) {
        val.n = 1;
    } else {
        val.n = 0;
    }
    add_avp(AVP_NAME_STR, (int_str)OSP_CALLING_NAME, val);

    return result;
}

/*
 * Check if the calling number is translated.
 *     This function checks the avp set by ospPrepareDestination.
 * param msg SIP message
 * param ignore1
 * param ignore2
 * return MODULE_RETURNCODE_TRUE calling number translated MODULE_RETURNCODE_FALSE without transaltion
 */
int ospCheckCalling(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    int_str callingval;
    int result = MODULE_RETURNCODE_FALSE;

    if (search_first_avp(AVP_NAME_STR, (int_str)OSP_CALLING_NAME, &callingval, 0) != NULL) {
        if (callingval.n == 0) {
            LM_DBG("the calling number does not been translated\n");
        } else {
            LM_DBG("the calling number is translated\n");
            result = MODULE_RETURNCODE_TRUE;
        }
    } else {
        LM_ERR("there is not calling translation avp\n");
    }

    return result;
}

/*
 * Build SIP message for destination
 * param msg SIP message
 * param isfirst Is first destination
 * param type Main or branch route block
 * param format URI format
 * return MODULE_RETURNCODE_TRUE success MODULE_RETURNCODE_FALSE failure
 */
static int ospPrepareDestination(
    struct sip_msg* msg,
    int isfirst,
    int type,
    int format)
{
    char buffer[OSP_HEADERBUF_SIZE];
    str newuri = { buffer, sizeof(buffer) };
    osp_dest* dest = ospGetNextOrigDestination();
    int result = MODULE_RETURNCODE_FALSE;

    if (dest != NULL) {
        ospRebuildDestionationUri(&newuri, dest, format);

        LM_INFO("prepare route to URI '%.*s' for call_id '%.*s' transaction_id '%llu'\n",
            newuri.len,
            newuri.s,
            dest->callidsize,
            dest->callid,
            dest->transid);

        if (type == OSP_MAIN_ROUTE) {
            if (isfirst == OSP_FIRST_ROUTE) {
                set_ruri(msg, &newuri);
            } else {
                append_branch(msg, &newuri, NULL, NULL, Q_UNSPECIFIED, 0, NULL);
            }
            /* Do not add route specific OSP information */
            result = MODULE_RETURNCODE_TRUE;
        } else if (type == OSP_BRANCH_ROUTE) {
            /* For branch route, add route specific OSP information */

            /* Update the Request-Line */
            set_ruri(msg, &newuri);

            /* Add OSP token header */
            ospAddOspHeader(msg, dest->token, dest->tokensize);

            /* Add branch-specific OSP Cookie */
            ospRecordOrigTransaction(msg, dest->transid, dest->srcdev, dest->calling, dest->called, dest->authtime, dest->destcount);

            /* Handle calling number translation */
            ospSetCalling(msg, dest);

            result = MODULE_RETURNCODE_TRUE;
        } else {
            LM_ERR("unsupported route block type\n");
        }
    } else {
        LM_DBG("there is no more routes\n");
        ospReportOrigSetupUsage();
    }

    return result;
}

/*
 * Prepare OSP route
 *     This function only works in branch route block.
 *     This function is only for OpenSIPS.
 * param msg SIP message
 * param ignore1
 * param ignore2
 * return MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure
 */
int ospPrepareRoute(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    int result = MODULE_RETURNCODE_TRUE;

    /* The first parameter will be ignored */
    result = ospPrepareDestination(msg, OSP_FIRST_ROUTE, OSP_BRANCH_ROUTE, 0);

    return result;
}

/*
 * Prepare all OSP routes
 *     This function does not work in branch route block.
 * param msg SIP message
 * param ignore1
 * param ignore2
 * return MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure
 */
int ospPrepareAllRoutes(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    int result = MODULE_RETURNCODE_TRUE;

    for(result = ospPrepareDestination(msg, OSP_FIRST_ROUTE, OSP_MAIN_ROUTE, _osp_redir_uri);
        result == MODULE_RETURNCODE_TRUE;
        result = ospPrepareDestination(msg, OSP_NEXT_ROUTE, OSP_MAIN_ROUTE, _osp_redir_uri))
    {
    }

    return MODULE_RETURNCODE_TRUE;
}

