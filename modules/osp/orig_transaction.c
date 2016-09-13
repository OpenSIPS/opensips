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
#include <sys/time.h>

#include <osp/osp.h>
#include <osp/ospb64.h>
#include "../../dset.h"
#include "../../usr_avp.h"
#include "../../mem/mem.h"
#include "../auth/api.h"
#include "orig_transaction.h"
#include "destination.h"
#include "osptoolkit.h"
#include "sipheader.h"
#include "timeapi.h"
#include "usage.h"

#ifndef timersub
#define timersub(a, b, result)							\
{														\
	(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
	(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;	\
	if ((result)->tv_usec < 0) {						\
		--(result)->tv_sec;								\
		(result)->tv_usec += 1000000;					\
	}													\
}
#endif

extern int _osp_calling_avpid;
extern int _osp_service_type;
extern char _osp_in_device[];
extern char _osp_out_device[];
extern int _osp_non_sip;
extern int _osp_max_dests;
extern int _osp_snid_avpid;
extern unsigned short _osp_snid_avptype;
extern int _osp_swid_avpid;
extern unsigned short _osp_swid_avptype;
extern int _osp_cinfo_avpid;
extern unsigned short _osp_cinfo_avptype;
extern int _osp_cnam_avpid;
extern unsigned short _osp_cnam_avptype;
extern int _osp_srcmedia_avpid;
extern unsigned short _osp_srcmedia_avptype;
extern int _osp_reqdate_avpid;
extern unsigned short _osp_reqdate_avptype;
extern int _osp_sdpfp_avpid;
extern unsigned short _osp_sdpfp_avptype;
extern int _osp_idsign_avpid;
extern unsigned short _osp_idsign_avptype;
extern int _osp_idalg_avpid;
extern unsigned short _osp_idalg_avptype;
extern int _osp_idinfo_avpid;
extern unsigned short _osp_idinfo_avptype;
extern int _osp_idtype_avpid;
extern unsigned short _osp_idtype_avptype;
extern int _osp_idcanon_avpid;
extern unsigned short _osp_idcanon_avptype;
extern OSPTPROVHANDLE _osp_provider;
extern auth_api_t osp_auth;

const int OSP_FIRST_ROUTE = 1;
const int OSP_NEXT_ROUTE = 0;
const int OSP_MAIN_ROUTE = 1;
const int OSP_BRANCH_ROUTE = 0;

static int ospSetIdentity(OSPTTRANHANDLE trans);
static int ospReportIdentity(OSPTTRANHANDLE trans);
static int ospLoadRoutes(OSPTTRANHANDLE trans, int destcount, osp_inbound* inbound);
static int ospPrepareDestination(struct sip_msg* msg, int isfirst, int route, int response, int* rsptype);
static int ospSetCalling(struct sip_msg* msg, osp_inbound* inbound, osp_dest* dest);

/*
 * Set Identity header
 * param trans Transaction handle
 * return 0 success, -1 failure
 */
static int ospSetIdentity(
    OSPTTRANHANDLE trans)
{
    char encoded[OSP_SIGNBUF_SIZE];
    unsigned encodedsize = sizeof(encoded);
    unsigned char sign[OSP_SIGNBUF_SIZE];
    unsigned signsize = sizeof(sign);
    char alg[OSP_ALGBUF_SIZE];
    char info[OSP_STRBUF_SIZE];
    char type[OSP_STRBUF_SIZE];
    unsigned char canon[OSP_STRBUF_SIZE];
    unsigned canonsize = sizeof(canon);
    str value;
    int result = -1;

    if (OSPPTransactionGetIdentity(trans, &signsize, sign, sizeof(alg), alg, sizeof(info), info, sizeof(type), type, &canonsize, canon) == OSPC_ERR_NO_ERROR) {
        if (signsize != 0) {
            if (OSPPBase64Encode(sign, signsize, (unsigned char*)encoded, &encodedsize) == OSPC_ERR_NO_ERROR) {
                value.s = encoded;
                value.len = encodedsize;
                add_avp(_osp_idsign_avptype | AVP_VAL_STR, _osp_idsign_avpid, (int_str)value);
            }
        }

        if (alg[0] != '\0') {
            value.s = alg;
            value.len = strlen(alg);
            add_avp(_osp_idalg_avptype | AVP_VAL_STR, _osp_idalg_avpid, (int_str)value);
        }

        if (info[0] != '\0') {
            value.s = info;
            value.len = strlen(info);
            add_avp(_osp_idinfo_avptype | AVP_VAL_STR, _osp_idinfo_avpid, (int_str)value);
        }

        if (type[0] != '\0') {
            value.s = type;
            value.len = strlen(type);
            add_avp(_osp_idtype_avptype | AVP_VAL_STR, _osp_idtype_avpid, (int_str)value);
        }

        if (canonsize != 0) {
            if (OSPPBase64Encode(canon, canonsize, (unsigned char*)encoded, &encodedsize) == OSPC_ERR_NO_ERROR) {
                value.s = encoded;
                value.len = encodedsize;
                add_avp(_osp_idcanon_avptype | AVP_VAL_STR, _osp_idcanon_avpid, (int_str)value);
            }
        }

        result = 0;
    } 

    return result;
}

/*
 * Report Identity header
 * param trans Transaction handle
 * return 0 success, -1 failure
 */
static int ospReportIdentity(
    OSPTTRANHANDLE trans)
{
    char encoded[OSP_SIGNBUF_SIZE];
    unsigned signsize;
    unsigned char sign[OSP_SIGNBUF_SIZE];
    char alg[OSP_ALGBUF_SIZE];
    char info[OSP_STRBUF_SIZE];
    char type[OSP_STRBUF_SIZE];
    unsigned canonsize;
    unsigned char canon[OSP_STRBUF_SIZE];
    int result = 0;

    if (ospGetAVP(_osp_idsign_avpid, _osp_idsign_avptype, encoded, sizeof(encoded)) == 0) {
        signsize = sizeof(sign);
        if (OSPPBase64Decode(encoded, strlen(encoded), sign, &signsize) != OSPC_ERR_NO_ERROR) {
            signsize = 0;
        }
    } else {
        signsize = 0;
    }

    if (ospGetAVP(_osp_idalg_avpid, _osp_idalg_avptype, alg, sizeof(alg)) != 0) {
        alg[0] = '\0';
    }

    if (ospGetAVP(_osp_idinfo_avpid, _osp_idinfo_avptype, info, sizeof(info)) != 0) {
        info[0] = '\0';
    }

    if (ospGetAVP(_osp_idtype_avpid, _osp_idtype_avptype, type, sizeof(type)) != 0) {
        type[0] = '\0';
    }

    if (ospGetAVP(_osp_idcanon_avpid, _osp_idcanon_avptype, encoded, sizeof(encoded)) == 0) {
        canonsize = sizeof(canon);
        if (OSPPBase64Decode(encoded, strlen(encoded), canon, &canonsize) != OSPC_ERR_NO_ERROR) {
            canonsize = 0;
        }
    } else {
        canonsize = 0;
    }

    if (OSPPTransactionSetIdentity(trans, signsize, sign, alg, info, type, canonsize, canon) != OSPC_ERR_NO_ERROR) {
        result = -1;
    }

    return result;
}

/*
 * Get routes from AuthRsp
 * param transaction Transaction handle
 * param destcount Expected destination count
 * param inbound Inbound info
 * return 0 success, -1 failure
 */
static int ospLoadRoutes(
    OSPTTRANHANDLE trans,
    int destcount,
    osp_inbound* inbound)
{
    int count;
    int errcode;
    osp_dest* dest;
    osp_dest dests[OSP_DEF_DESTS];
    char host[OSP_STRBUF_SIZE];
    char destdev[OSP_STRBUF_SIZE];
    OSPE_OPERATOR_NAME type;
    OSPE_DEST_OSPENABLED enabled;
    int result = 0;

    ospSetIdentity(trans);

    for (count = 0; count < destcount; count++) {
        /* This is necessary because we will save destinations in reverse order */
        dest = ospInitDestination(&dests[count]);

        if (dest == NULL) {
            result = -1;
            break;
        }

        dest->destcount = count + 1;

        if (count == 0) {
            errcode = OSPPTransactionGetFirstDestination(
                trans,
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
            errcode = OSPPTransactionGetNextDestination(
                trans,
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

        if (errcode != OSPC_ERR_NO_ERROR) {
            LM_ERR("failed to load routes (%d) expected '%d' current '%d'\n",
                errcode,
                destcount,
                count);
            result = -1;
            break;
        }

        ospConvertToInAddress(host, dest->host, sizeof(dest->host));

        errcode = OSPPTransactionGetNumberPortabilityParameters(trans,
            sizeof(dest->nprn),
            dest->nprn,
            sizeof(dest->npcic),
            dest->npcic,
            &dest->npdi);
        if (errcode != OSPC_ERR_NO_ERROR) {
            LM_DBG("cannot get number portability parameters (%d)\n", errcode);
            dest->nprn[0] = '\0';
            dest->npcic[0] = '\0';
            dest->npdi = 0;
        }

        for (type = OSPC_OPNAME_START; type < OSPC_OPNAME_NUMBER; type++) {
            errcode = OSPPTransactionGetOperatorName(trans,
                type,
                sizeof(dest->opname[type]),
                dest->opname[type]);
            if (errcode != OSPC_ERR_NO_ERROR) {
                LM_DBG("cannot get operator name '%d' (%d)\n", type, errcode);
                dest->opname[type][0] = '\0';
            }
        }

        errcode = OSPPTransactionGetDestProtocol(trans, &dest->protocol);
        if (errcode != OSPC_ERR_NO_ERROR) {
            /* This does not mean an ERROR. The OSP server may not support OSP 2.1.1 */
            LM_DBG("cannot get dest protocol (%d)\n", errcode);
            dest->protocol = OSPC_PROTNAME_SIP;
        }
        switch (dest->protocol) {
            case OSPC_PROTNAME_Q931:
            case OSPC_PROTNAME_LRQ:
            case OSPC_PROTNAME_IAX:
            case OSPC_PROTNAME_T37:
            case OSPC_PROTNAME_T38:
            case OSPC_PROTNAME_SKYPE:
            case OSPC_PROTNAME_SMPP:
            case OSPC_PROTNAME_XMPP:
                if (_osp_non_sip) {
                    dest->supported = 1;
                } else {
                    dest->supported = 0;
                }
                break;
            case OSPC_PROTNAME_SIP:
            case OSPC_PROTNAME_UNDEFINED:
            case OSPC_PROTNAME_UNKNOWN:
            default:
                dest->supported = 1;
                break;
        }

        errcode = OSPPTransactionIsDestOSPEnabled(trans, &enabled);
        if (errcode != OSPC_ERR_NO_ERROR) {
            /* This does not mean an ERROR. The OSP server may not support OSP 2.1.1 */
            LM_DBG("cannot get dest OSP version (%d)\n", errcode);
        } else if (enabled == OSPC_DOSP_FALSE) {
            /* Destination device does not support OSP. Do not send token to it */
            dest->token[0] = '\0';
            dest->tokensize = 0;
        }

        errcode = OSPPTransactionGetDestinationNetworkId(trans, sizeof(dest->dnid), dest->dnid);
        if (errcode != OSPC_ERR_NO_ERROR) {
            /* This does not mean an ERROR. The OSP server may not support OSP 2.1.1 */
            LM_DBG("cannot get dest network ID (%d)\n", errcode);
            dest->dnid[0] = '\0';
        }

        errcode = OSPPTransactionGetDestSwitchId(trans, sizeof(dest->swid), dest->swid);
        if (errcode != OSPC_ERR_NO_ERROR) {
            /* This does not mean an ERROR. The OSP server may not support OSP 2.1.1 */
            LM_DBG("cannot get dest switch ID (%d)\n", errcode);
            dest->swid[0] = '\0';
        }

        errcode = OSPPTransactionGetCNAM(trans, sizeof(dest->cnam), dest->cnam);
        if (errcode != OSPC_ERR_NO_ERROR) {
            LM_DBG("cannot get CNAM (%d)\n", errcode);
            dest->cnam[0] = '\0';
        }

        OSPPTransactionGetServiceType(trans, &dest->srvtype);

        dest->type = OSPC_ROLE_SOURCE;
        dest->transid = ospGetTransactionId(trans);

        LM_INFO("get destination '%d': "
            "validafter '%s' "
            "validuntil '%s' "
            "timelimit '%d' seconds "
            "callid '%.*s' "
            "calling '%s' "
            "called '%s' "
            "host '%s' "
            "nprn '%s' "
            "npcic '%s' "
            "npdi '%d' "
            /*
            "spid '%s' "
            "ocn '%s' "
            "spn '%s' "
            "altspn '%s' "
            "mcc '%s' "
            "mnc '%s' "
            */
            "cnam '%s' "
            "service '%d' "
            "protocol '%d' "
            "supported '%d' "
            "networkid '%s' "
            "switchid '%s' "
            "tokensize '%d'\n",
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
            /*
            dest->opname[OSPC_OPNAME_SPID],
            dest->opname[OSPC_OPNAME_OCN],
            dest->opname[OSPC_OPNAME_SPN],
            dest->opname[OSPC_OPNAME_ALTSPN],
            dest->opname[OSPC_OPNAME_MCC],
            dest->opname[OSPC_OPNAME_MNC],
            */
            dest->cnam,
            dest->srvtype,
            dest->protocol,
            dest->supported,
            dest->dnid,
            dest->swid,
            dest->tokensize);
    }

    /*
     * Save destination in reverse order,
     * when we start searching avps the destinations
     * will be in order
     */
    if (result == 0) {
        if (ospSaveInboundInfo(inbound) == -1) {
            ospRecordEvent(0, 500);
            result = -1;
        } else {
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
    }

    return result;
}

/*
 * Request OSP authorization and routeing
 * param msg SIP message
 * param ignore1
 * param ignore2
 * return MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure, others error
 */
int ospRequestRouting(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    int i, errcode;
    char rn[OSP_STRBUF_SIZE];
    char cic[OSP_STRBUF_SIZE];
    int npdi;
    OSPE_OPERATOR_NAME type;
    char opname[OSPC_OPNAME_NUMBER][OSP_STRBUF_SIZE];
    osp_inbound inbound;
    char sourcebuf[OSP_STRBUF_SIZE];
    char srcdevbuf[OSP_STRBUF_SIZE];
    char divhostbuf[OSP_STRBUF_SIZE];
    char useragent[OSP_STRBUF_SIZE];
    struct usr_avp* avp = NULL;
    int_str avpval;
    unsigned int cinfonum = 0;
    char cinfo[OSP_DEF_CINFONUM][OSP_STRBUF_SIZE];
    char cinfostr[OSP_STRBUF_SIZE];
    unsigned int callidnumber = 1;
    OSPT_CALL_ID* callids[callidnumber];
    unsigned int logsize = 0;
    char* detaillog = NULL;
    char tohost[OSP_STRBUF_SIZE];
    char tohostbuf[OSP_STRBUF_SIZE];
    const char* preferred[2] = { NULL };
    unsigned int destcount;
    struct timeval ts, te, td;
    char datebuf[OSP_STRBUF_SIZE];
    unsigned int sdpfpnum = 0;
    char sdpfp[OSP_DEF_SDPFPNUM][OSP_STRBUF_SIZE];
    char* sdpfpstr[OSP_DEF_SDPFPNUM];
    OSPTTRANHANDLE trans = -1;
    int result = MODULE_RETURNCODE_FALSE;

    ospInitInboundInfo(&inbound);

    if ((errcode = OSPPTransactionNew(_osp_provider, &trans)) != OSPC_ERR_NO_ERROR) {
        LM_ERR("failed to create new OSP transaction (%d)\n", errcode);
    } else if (ospGetCallId(msg, &(callids[0])) != 0) {
        LM_ERR("failed to extract call id\n");
    } else if (ospGetFromUser(msg, inbound.calling, sizeof(inbound.calling)) != 0) {
        LM_ERR("failed to extract calling number\n");
    } else if ((ospGetUriUser(msg, inbound.called, sizeof(inbound.called)) != 0) && (ospGetToUser(msg, inbound.called, sizeof(inbound.called)) != 0)) {
        LM_ERR("failed to extract called number\n");
    } else if (ospGetSource(msg, inbound.source, sizeof(inbound.source)) != 0) {
        LM_ERR("failed to extract source address\n");
    } else if (ospGetSrcDev(msg, inbound.srcdev, sizeof(inbound.srcdev)) != 0) {
        LM_ERR("failed to extract source deivce address\n");
    } else {
        inbound.authtime = time(NULL);

        if(msg->rcv.bind_address && msg->rcv.bind_address->address_str.s) {
            ospCopyStrToBuffer(&msg->rcv.bind_address->address_str, inbound.ingressaddr, sizeof(inbound.ingressaddr));
        }

        ospConvertToOutAddress(inbound.source, sourcebuf, sizeof(sourcebuf));
        ospConvertToOutAddress(inbound.srcdev, srcdevbuf, sizeof(srcdevbuf));

        switch (_osp_service_type) {
        case 1:
        case 2:
            OSPPTransactionSetServiceType(trans, (_osp_service_type == 1) ? OSPC_SERVICE_NPQUERY : OSPC_SERVICE_CNAMQUERY);

            ospGetToHost(msg, tohost, sizeof(tohost));
            ospConvertToOutAddress(tohost, tohostbuf, sizeof(tohostbuf));
            preferred[0] = tohostbuf;

            destcount = 1;
            break;
        case 0:
        default:
            OSPPTransactionSetServiceType(trans, OSPC_SERVICE_VOICE);

            destcount = _osp_max_dests;
            break;
        }

        if (ospGetNpParam(msg, rn, sizeof(rn), cic, sizeof(cic), &npdi) == 0) {
            OSPPTransactionSetNumberPortability(trans, rn, cic, npdi);
        }

        for (type = OSPC_OPNAME_START; type < OSPC_OPNAME_NUMBER; type++) {
            if (ospGetOperatorName(msg, type, opname[type], sizeof(opname[type])) == 0) {
                OSPPTransactionSetOperatorName(trans, type, opname[type]);
            }
        }

        if (ospGetFromDisplay(msg, inbound.fromdisplay, sizeof(inbound.fromdisplay)) == 0) {
            OSPPTransactionSetSIPHeader(trans, OSPC_SIPHEADER_FROM, OSPC_NFORMAT_DISPLAYNAME, inbound.fromdisplay);
        }

        if (ospGetFromUri(msg, inbound.fromuri, sizeof(inbound.fromuri)) == 0) {
            OSPPTransactionSetSIPHeader(trans, OSPC_SIPHEADER_FROM, OSPC_NFORMAT_URL, inbound.fromuri);
        }

        if (ospGetToUri(msg, inbound.touri, sizeof(inbound.touri)) == 0) {
            OSPPTransactionSetSIPHeader(trans, OSPC_SIPHEADER_TO, OSPC_NFORMAT_URL, inbound.touri);
        }

        if (ospGetRpidUser(msg, inbound.rpiduser, sizeof(inbound.rpiduser)) == 0) {
            OSPPTransactionSetSIPHeader(trans, OSPC_SIPHEADER_RPID, OSPC_NFORMAT_E164, inbound.rpiduser);
        }

        if (ospGetPaiUser(msg, inbound.paiuser, sizeof(inbound.paiuser)) == 0) {
            OSPPTransactionSetSIPHeader(trans, OSPC_SIPHEADER_PAI, OSPC_NFORMAT_E164, inbound.paiuser);
        }

        if (ospGetPciUser(msg, inbound.pciuser, sizeof(inbound.pciuser)) == 0) {
            OSPPTransactionSetSIPHeader(trans, OSPC_SIPHEADER_PCI, OSPC_NFORMAT_E164, inbound.pciuser);
        }

        if (ospGetDiversion(msg, inbound.divuser, sizeof(inbound.divuser), inbound.divhost, sizeof(inbound.divhost)) == 0) {
            ospConvertToOutAddress(inbound.divhost, divhostbuf, sizeof(divhostbuf));
        } else {
            divhostbuf[0] = '\0';
        }
        OSPPTransactionSetDiversion(trans, inbound.divuser, divhostbuf);

        if (ospGetPcvIcid(msg, inbound.pcvicid, sizeof(inbound.pcvicid)) == 0) {
            OSPPTransactionSetChargingVector(trans, inbound.pcvicid, NULL, NULL, NULL);
        }

        if (ospGetUserAgent(msg, useragent, sizeof(useragent)) == 0) {
            OSPPTransactionSetUserAgent(trans, useragent);
        }

        OSPPTransactionSetProtocol(trans, OSPC_PROTTYPE_SOURCE, OSPC_PROTNAME_SIP);

        if (ospGetAVP(_osp_snid_avpid, _osp_snid_avptype, inbound.snid, sizeof(inbound.snid)) == 0) {
            OSPPTransactionSetNetworkIds(trans, inbound.snid, "");
        } else {
            inbound.snid[0] = '\0';
        }

        if (ospGetAVP(_osp_swid_avpid, _osp_swid_avptype, inbound.swid, sizeof(inbound.swid)) == 0) {
            OSPPTransactionSetSrcSwitchId(trans, inbound.swid);
        } else {
            inbound.swid[0] = '\0';
        }

        if (_osp_cinfo_avpid >= 0) {
            for (i = 0, avp = search_first_avp(_osp_cinfo_avptype, _osp_cinfo_avpid, NULL, 0);
                ((i < OSP_DEF_CINFONUM) && (avp != NULL));
                i++, avp = search_next_avp(avp, NULL))
            {
                get_avp_val(avp, &avpval);
                if ((avp->flags & AVP_VAL_STR) && (avpval.s.s && avpval.s.len)) {
                    snprintf(cinfo[i], sizeof(cinfo[i]), "%.*s", avpval.s.len, avpval.s.s);
                } else {
                    cinfo[i][0] = '\0';
                }
            }
            cinfonum = i;

            cinfostr[0] = '\0';
            for (i = 0; i < cinfonum; i++) {
                if (cinfo[cinfonum - i - 1][0] != '\0') {
                    OSPPTransactionSetCustomInfo(trans, i, cinfo[cinfonum - i - 1]);
                    snprintf(cinfostr + strlen(cinfostr), sizeof(cinfostr) - strlen(cinfostr), "custom_info%d '%s' ", i + 1, cinfo[cinfonum - i - 1]);
                }
            }
        }

        if (ospGetAVP(_osp_srcmedia_avpid, _osp_srcmedia_avptype, inbound.srcmedia, sizeof(inbound.srcmedia)) == 0) {
            OSPPTransactionSetSrcAudioAddr(trans, inbound.srcmedia);
        } else {
            inbound.srcmedia[0] = '\0';
        }

        inbound.date = 0;
        if (ospGetAVP(_osp_reqdate_avpid, _osp_reqdate_avptype, datebuf, sizeof(datebuf)) == 0) {
            if (ospStrToTime(datebuf, &inbound.date) == 0) {
                OSPPTransactionSetRequestDate(trans, inbound.date);
            }
        }

        if (_osp_sdpfp_avpid >= 0) {
            for (i = 0, avp = search_first_avp(_osp_sdpfp_avptype, _osp_sdpfp_avpid, NULL, 0);
                ((i < OSP_DEF_SDPFPNUM) && (avp != NULL));
                i++, avp = search_next_avp(avp, NULL))
            {
                get_avp_val(avp, &avpval);
                if ((avp->flags & AVP_VAL_STR) && (avpval.s.s && avpval.s.len)) {
                    snprintf(sdpfp[i], sizeof(sdpfp[i]), "%.*s", avpval.s.len, avpval.s.s);
                } else {
                    sdpfp[i][0] = '\0';
                }
            }
            sdpfpnum = i;

            for (i = 0; i < sdpfpnum; i++) {
                sdpfpstr[i] = sdpfp[sdpfpnum - i - 1];
            }

            OSPPTransactionSetFingerPrint(trans, sdpfpnum, (const char**)sdpfpstr);
        }

        ospReportIdentity(trans);

        LM_INFO("request auth and routing for: "
            "service '%d' "
            "source '%s' "
            "srcdev '%s' "
            "snid '%s' "
            "swid '%s' "
            "calling '%s' "
            "called '%s' "
            "preferred '%s' "
            "nprn '%s' "
            "npcic '%s' "
            "npdi '%d' "
            /*
            "spid '%s' "
            "ocn '%s' "
            "spn '%s' "
            "altspn '%s' "
            "mcc '%s' "
            "mnc '%s' "
            */
            "fromdisplay '%s' "
            "paiuser '%s' "
            "rpiduser '%s' "
            "pciuser '%s' "
            "divuser '%s' "
            "divhost '%s' "
            "pcvicid '%s' "
            "srcmedia '%s' "
            "callid '%.*s' "
            "destcount '%d' "
            "%s\n",
            _osp_service_type,
            sourcebuf,
            srcdevbuf,
            inbound.snid,
            inbound.swid,
            inbound.calling,
            inbound.called,
            (preferred[0] == NULL) ? "" : preferred[0],
            rn,
            cic,
            npdi,
            /*
            opname[OSPC_OPNAME_SPID],
            opname[OSPC_OPNAME_OCN],
            opname[OSPC_OPNAME_SPN],
            opname[OSPC_OPNAME_ALTSPN],
            opname[OSPC_OPNAME_MCC],
            opname[OSPC_OPNAME_MNC],
            */
            inbound.fromdisplay,
            inbound.paiuser,
            inbound.rpiduser,
            inbound.pciuser,
            inbound.divuser,
            divhostbuf,
            inbound.pcvicid,
            inbound.srcmedia,
            callids[0]->Length,
            callids[0]->Value,
            destcount,
            cinfostr);

        gettimeofday(&ts, NULL);

        /* try to request authorization */
        errcode = OSPPTransactionRequestAuthorisation(
            trans,             /* transaction handle */
            sourcebuf,         /* from the configuration file */
            srcdevbuf,         /* source device of call, protocol specific, in OSP format */
            inbound.calling,   /* calling number in nodotted e164 notation */
            OSPC_NFORMAT_E164, /* calling number format */
            inbound.called,    /* called number */
            OSPC_NFORMAT_E164, /* called number format */
            "",                /* optional username string, used if no number */
            callidnumber,      /* number of call ids, here always 1 */
            callids,           /* sized-1 array of call ids */
            preferred,         /* preferred destinations */
            &destcount,        /* max destinations, after call dest_count */
            &logsize,          /* size allocated for detaillog (next param) 0=no log */
            detaillog);        /* memory location for detaillog to be stored */

        gettimeofday(&te, NULL);

        timersub(&te, &ts, &td);
        LM_INFO("authreq cost = %lu.%06lu for call-id '%.*s'\n", td.tv_sec, td.tv_usec, callids[0]->Length, callids[0]->Value);

        if ((errcode == OSPC_ERR_NO_ERROR) &&
            (ospLoadRoutes(trans, destcount, &inbound) == 0))
        {
            LM_INFO("there are '%d' OSP routes, call_id '%.*s'\n",
                destcount,
                callids[0]->Length,
                callids[0]->Value);
            result = MODULE_RETURNCODE_TRUE;
        } else {
            LM_ERR("failed to request auth and routing (%d), call_id '%.*s'\n",
                errcode,
                callids[0]->Length,
                callids[0]->Value);
            switch (errcode) {
                case OSPC_ERR_HTTP_BAD_REQUEST:
                    result = -4000;
                    break;
                case OSPC_ERR_TRAN_BAD_REQUEST:
                    result = -4001;
                    break;
                case OSPC_ERR_HTTP_UNAUTHORIZED:
                    result = -4010;
                    break;
                case OSPC_ERR_TRAN_UNAUTHORIZED:
                    result = -4011;
                    break;
                case OSPC_ERR_TRAN_ROUTE_BLOCKED:
                    result = -4030;
                    break;
                case OSPC_ERR_TRAN_ROUTE_NOT_FOUND:
                    result = -4040;
                    break;
                case OSPC_ERR_TRAN_MAY_NOT_ORIGINATE:
                    result = -4050;
                    break;
                case OSPC_ERR_TRAN_CALLING_INVALID:
                    result = -4280;
                    break;
                case OSPC_ERR_SOCK_CONNECT_FAILED:
                    result = -4800;
                    break;
                case OSPC_ERR_SOCK_SELECT_FAILED:
                    result = -4801;
                    break;
                case OSPC_ERR_HTTP_SERVER_NOT_READY:
                    result = -4802;
                    break;
                case OSPC_ERR_TRAN_CALLED_FILTERING:
                    result = -4840;
                    break;
                case OSPC_ERR_HTTP_SERVICE_UNAVAILABLE:
                    result = -5030;
                    break;
                case OSPC_ERR_TRAN_DECLINE:
                    result = -6030;
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

    if (trans != -1) {
        OSPPTransactionDelete(trans);
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
 * param inbound Inbound info
 * param dest Destination structure
 * return 0 success, 1 calling number same or not support calling number translation, -1 failure
 */
static int ospSetCalling(
    struct sip_msg* msg,
    osp_inbound* inbound,
    osp_dest* dest)
{
    str rpid;
    int_str val;
    char buffer[OSP_STRBUF_SIZE];
    int result;

    if (strcmp(inbound->calling, dest->calling) == 0) {
        LM_DBG("calling number does not been translated\n");
        result = 1;
    } else if (osp_auth.rpid_avp < 0) {
        LM_WARN("rpid_avp is not found, cannot set rpid avp\n");
        result = -1;
    } else {
        snprintf(buffer,
            sizeof(buffer),
            "\"%s\" <sip:%s@%s>",
            dest->calling,
            dest->calling,
            inbound->source);

        rpid.s = buffer;
        rpid.len = strlen(buffer);
        add_avp(osp_auth.rpid_avp_type | AVP_VAL_STR, osp_auth.rpid_avp, (int_str)rpid);

        result = 0;
    }

    if (result == 0) {
        val.n = 1;
    } else {
        val.n = 0;
    }
    add_avp(0, _osp_calling_avpid, val);

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

    if (search_first_avp(0, _osp_calling_avpid, &callingval, 0) != NULL) {
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
 * param route Main or branch route block
 * param response Is for response
 * param rsptype SIP response type
 * return MODULE_RETURNCODE_TRUE success MODULE_RETURNCODE_FALSE failure
 */
static int ospPrepareDestination(
    struct sip_msg* msg,
    int isfirst,
    int route,
    int response,
    int* rsptype)
{
    str cnam;
    char buffer[OSP_HEADERBUF_SIZE];
    str newuri = { buffer, sizeof(buffer) };
    osp_inbound* inbound = ospGetInboundInfo();
    osp_dest* dest = ospGetNextOrigDestination();
    int result = MODULE_RETURNCODE_TRUE;

    if (inbound != NULL) {
        if (dest != NULL) {
            if (response) {
                /* SIP 300 or 380 response */
                if (route == OSP_MAIN_ROUTE) {
                    if (dest->srvtype == OSPC_SERVICE_CNAMQUERY) {
                        LM_INFO("prepare CNAM for call_id '%.*s' transaction_id '%llu'\n",
                            dest->callidsize,
                            dest->callid,
                            dest->transid);

                        if (dest->cnam[0] != '\0') {
                            cnam.s = dest->cnam;
                            cnam.len = strlen(dest->cnam);
                            add_avp(_osp_cnam_avptype | AVP_VAL_STR, _osp_cnam_avpid, (int_str)cnam);
                        }

                        dest->lastcode = 380;

                        *rsptype = 380;
                    } else {
                        /* For default service, voice service or ported number query service */
                        ospRebuildDestUri(&newuri, dest);

                        LM_INFO("prepare route to URI '%.*s' for call_id '%.*s' transaction_id '%llu'\n",
                            newuri.len,
                            newuri.s,
                            dest->callidsize,
                            dest->callid,
                            dest->transid);

                        if (isfirst == OSP_FIRST_ROUTE) {
                            set_ruri(msg, &newuri);
                        } else {
                            append_branch(msg, &newuri, NULL, NULL, Q_UNSPECIFIED, 0, NULL);
                        }

                        /* Do not add route specific OSP information */

                        dest->lastcode = 300;

                        *rsptype = 300;
                    }
                } else {
                    LM_ERR("unsupported route block type\n");
                    result = MODULE_RETURNCODE_FALSE;
                }
            } else {
                /* Single destination or all destinations */
                ospRebuildDestUri(&newuri, dest);

                LM_INFO("prepare route to URI '%.*s' for call_id '%.*s' transaction_id '%llu'\n",
                    newuri.len,
                    newuri.s,
                    dest->callidsize,
                    dest->callid,
                    dest->transid);

                if (route == OSP_MAIN_ROUTE) {
                    if (isfirst == OSP_FIRST_ROUTE) {
                        set_ruri(msg, &newuri);
                    } else {
                        append_branch(msg, &newuri, NULL, NULL, Q_UNSPECIFIED, 0, NULL);
                    }

                    /* Do not add route specific OSP information */
                } else if (route == OSP_BRANCH_ROUTE) {
                    /* For branch route, add route specific OSP information */

                    /* Update the Request-Line */
                    set_ruri(msg, &newuri);

                    /* Add OSP token header */
                    ospAddOspToken(msg, dest->token, dest->tokensize);

                    /* Add branch-specific OSP Cookie */
                    ospRecordOrigTransaction(msg, inbound, dest);

                    /* Handle calling number translation */
                    ospSetCalling(msg, inbound, dest);

                    /* Set call attempt start time */
                    dest->starttime = time(NULL);
                } else {
                    LM_ERR("unsupported route block type\n");
                    result = MODULE_RETURNCODE_FALSE;
                }
            }
        } else {
            LM_DBG("there is no more routes\n");
            if (!response) {
                ospReportOrigSetupUsage();
            }
            result = MODULE_RETURNCODE_FALSE;
        }
    } else {
        LM_ERR("internal error\n");
        result = MODULE_RETURNCODE_FALSE;
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
    int tmp = 0;
    int result = MODULE_RETURNCODE_TRUE;

    /* The first parameter will be ignored */
    result = ospPrepareDestination(msg, OSP_FIRST_ROUTE, OSP_BRANCH_ROUTE, 0, &tmp);

    return result;
}

/*
 * Prepare response
 *     This function does not work in branch route block.
 * param msg SIP message
 * param ignore1
 * param ignore2
 * return 300 or 380 success, MODULE_RETURNCODE_FALSE failure
 */
int ospPrepareResponse(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    int tmp;
    int rsptype = 0;
    int result = MODULE_RETURNCODE_TRUE;

    for(result = ospPrepareDestination(msg, OSP_FIRST_ROUTE, OSP_MAIN_ROUTE, 1, &rsptype);
        result == MODULE_RETURNCODE_TRUE;
        result = ospPrepareDestination(msg, OSP_NEXT_ROUTE, OSP_MAIN_ROUTE, 1, &tmp))
    {
    }

    return rsptype;
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
    int tmp = 0;
    int result = MODULE_RETURNCODE_TRUE;

    for(result = ospPrepareDestination(msg, OSP_FIRST_ROUTE, OSP_MAIN_ROUTE, 0, &tmp);
        result == MODULE_RETURNCODE_TRUE;
        result = ospPrepareDestination(msg, OSP_NEXT_ROUTE, OSP_MAIN_ROUTE, 0, &tmp))
    {
    }

    return MODULE_RETURNCODE_TRUE;
}

