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

#include <osp/osp.h>
#include <osp/ospb64.h>
#include "../../forward.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_diversion.h"
#include "../../parser/parse_rpid.h"
#include "../../parser/parse_pai.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../parser/contact/parse_contact.h"
#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "osp_mod.h"
#include "destination.h"
#include "timeapi.h"
#include "sipheader.h"

extern int _osp_work_mode;
extern char _osp_in_device[];
extern int _osp_use_np;
extern int _osp_export_np;
extern int _osp_append_userphone;
extern int _osp_dnid_location;
extern char* _osp_dnid_param;
extern int _osp_swid_location;
extern char* _osp_swid_param;
extern int _osp_paramstr_location;
extern char* _osp_paramstr_value;
extern int _osp_srcdev_avpid;
extern unsigned short _osp_srcdev_avptype;
extern int _osp_reqdate_avpid;
extern unsigned short _osp_reqdate_avptype;

char* PCHARGEINFO = "P-Charge-Info";
char* PCHARGINGVECTOR = "P-Charging-Vector";
char* IDENTITY = "Identity";

static void ospTrim(char* source, char* buffer, int bufsize);
static void ospSkipUserParam(char* userinfo);
static int ospAppendHeader(struct sip_msg* msg, str* header);

/*
 * Trim leading and trailing space
 * param source Source string
 * param buffer Destiantion string buffer
 * param bufsize Destination string buffer size
 */
void ospTrim(
    char* source,
    char* buffer,
    int bufsize)
{
    char* start = source;
    char* end = NULL;

    if(bufsize != 0) {
        while(isspace(*start)) { 
            start++; 
        }

        if(*start == 0) {
          *buffer = '\0';
        } else {
            end = start + strlen(start) - 1;
            while(isspace(*end)) {
                *end = '\0';
                end--;
            }
            snprintf(buffer, bufsize, "%s", start);
        }
    }
}

/*
 * Get AVP value
 * param avpid AVP ID
 * param avptype AVP type
 * param avpstr AVP string
 * param bufsize AVP string buffer size
 * return 0 success, -1 failure
 */
int ospGetAVP(
    int avpid,
    unsigned short avptype,
    char* avpstr,
    int bufsize)
{
    struct usr_avp* avp = NULL;
    int_str avpval;
    char tmp[OSP_STRBUF_SIZE];
    int result = -1;

    if ((avpid >= 0) &&
        ((avp = search_first_avp(avptype, avpid, &avpval, 0)) != NULL) &&
        (avp->flags & AVP_VAL_STR) && (avpval.s.s && avpval.s.len))
    {
        snprintf(tmp, sizeof(tmp), "%.*s", avpval.s.len, avpval.s.s);
        destroy_avp(avp);
        ospTrim(tmp, avpstr, bufsize);
        result = 0;
    }

    return result;
}

/*
 * Copy str to buffer and check overflow
 * param source Str
 * param buffer Buffer
 * param bufsize Size of buffer
 */
void ospCopyStrToBuffer(
    str* source,
    char* buffer,
    int bufsize)
{
    int copybytes;

    if (source->len >= bufsize) {
        LM_ERR("buffer for copying '%.*s' is too small, will copy the first '%d' bytes\n",
            source->len,
            source->s,
            bufsize - 1);
        copybytes = bufsize;
    } else {
        copybytes = source->len + 1;
    }

    if (source->s != NULL) {
        strncpy(buffer, source->s, copybytes);
        buffer[copybytes - 1] = '\0';
    } else {
        buffer[0] = '\0';
    }
}

/*
 * Get local egress address
 * param ignore1
 * param ignore2
 * return  MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure MODULE_RETURNCODE_ERROR error
 */
int ospGetLocalAddress(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    osp_dest* dest;

    if(msg->rcv.bind_address && msg->rcv.bind_address->address_str.s) {
        if ((dest = ospGetLastOrigDestination())) {
            ospCopyStrToBuffer(&msg->rcv.bind_address->address_str, dest->egress, sizeof(dest->egress));
        }
    }

    return MODULE_RETURNCODE_TRUE;
}

/*
 * Get display name from From header
 * param msg SIP message
 * param fromdisplay Display name of From header
 * param bufsize Size of fromdisplay buffer
 * return 0 success, -1 failure
 */
int ospGetFromDisplay(
    struct sip_msg* msg,
    char* fromdisplay,
    int bufsize)
{
    struct to_body* from;
    int result = -1;

    if ((fromdisplay != NULL) && (bufsize > 0)) {
        fromdisplay[0] = '\0';
        if (msg->from != NULL) {
            if (parse_from_header(msg) == 0) {
                from = get_from(msg);
                if ((from->display.s != NULL) && (from->display.len > 0)) {
                    ospCopyStrToBuffer(&from->display, fromdisplay, bufsize);
                    result = 0;
                }
            } else {
                LM_ERR("failed to parse From header\n");
            }
        } else {
            LM_ERR("failed to find From header\n");
        }
    } else {
        LM_ERR("bad parameters to parse display name from From header\n");
    }

    return result;
}

/*
 * Remove user parameters from userinfo
 * param userinfo User info
 */
static void ospSkipUserParam(
    char* userinfo)
{
    char* delim = NULL;

    if ((delim = strchr(userinfo, ';')) != NULL) {
        *delim = '\0';
    }
    if ((delim = strchr(userinfo, ':')) != NULL) {
        *delim = '\0';
    }
}

/*
 * Get user part from From header
 * param msg SIP message
 * param fromuser User part of From header
 * param bufsize Size of fromuser buffer
 * return 0 success, -1 failure
 */
int ospGetFromUser(
    struct sip_msg* msg,
    char* fromuser,
    int bufsize)
{
    struct to_body* from;
    struct sip_uri uri;
    int result = -1;

    if ((fromuser != NULL) && (bufsize > 0)) {
        fromuser[0] = '\0';
        if (msg->from != NULL) {
            if (parse_from_header(msg) == 0) {
                from = get_from(msg);
                if (parse_uri(from->uri.s, from->uri.len, &uri) == 0) {
                    ospCopyStrToBuffer(&uri.user, fromuser, bufsize);
                    ospSkipUserParam(fromuser);
                    result = 0;
                } else {
                    LM_ERR("failed to parse From uri\n");
                }
            } else {
                LM_ERR("failed to parse From header\n");
            }
        } else {
            LM_ERR("failed to find From header\n");
        }
    } else {
        LM_ERR("bad parameters to parse user part from From header\n");
    }

    return result;
}

/*
 * Get From header
 * param msg SIP message
 * param from From header
 * param bufsize Size of from header buffer
 * return 0 success, -1 failure
 */
int ospGetFrom(
    struct sip_msg* msg,
    char* from,
    int bufsize)
{
    int result = -1;

    if ((from!= NULL) && (bufsize > 0)) {
        from[0] = '\0';
        if (msg->from != NULL) {
            ospCopyStrToBuffer(&msg->from->body, from, bufsize);
            result = 0;
        } else {
            LM_ERR("failed to find From header\n");
        }
    } else {
        LM_ERR("bad parameters to parse From header\n");
    }

    return result;
}

/*
 * Get display name from To header
 * param msg SIP message
 * param todisplay Display name of To header
 * param bufsize Size of todisplay buffer
 * return 0 success, -1 failure
 */
int ospGetToDisplay(
    struct sip_msg* msg,
    char* todisplay,
    int bufsize)
{
    struct to_body* to;
    int result = -1;

    if ((todisplay != NULL) && (bufsize > 0)) {
        todisplay[0] = '\0';
        if (msg->to != NULL) {
            if (parse_headers(msg, HDR_TO_F, 0) == 0) {
                to = get_to(msg);
                if ((to->display.s != NULL) && (to->display.len > 0)) {
                    ospCopyStrToBuffer(&to->display, todisplay, bufsize);
                    result = 0;
                }
            } else {
                LM_ERR("failed to parse To header\n");
            }
        } else {
            LM_ERR("failed to find To header\n");
        }
    } else {
        LM_ERR("bad parameters to parse display name from To header\n");
    }

    return result;
}

/*
 * Get user part from To header
 * param msg SIP message
 * param touser User part of To header
 * param bufsize Size of touser buffer
 * return 0 success, -1 failure
 */
int ospGetToUser(
    struct sip_msg* msg,
    char* touser,
    int bufsize)
{
    struct to_body* to;
    struct sip_uri uri;
    int result = -1;

    if ((touser != NULL) && (bufsize > 0)) {
        touser[0] = '\0';
        if (msg->to != NULL) {
            if (parse_headers(msg, HDR_TO_F, 0) == 0) {
                to = get_to(msg);
                if (parse_uri(to->uri.s, to->uri.len, &uri) == 0) {
                    ospCopyStrToBuffer(&uri.user, touser, bufsize);
                    ospSkipUserParam(touser);
                    result = 0;
                } else {
                    LM_ERR("failed to parse To uri\n");
                }
            } else {
                LM_ERR("failed to parse To header\n");
            }
        } else {
            LM_ERR("failed to find To header\n");
        }
    } else {
        LM_ERR("bad parameters to parse user part from To header\n");
    }

    return result;
}

/*
 * Get host info from To header
 * param msg SIP message
 * param tohost Host part of To header
 * param bufsize Size of tohost buffer
 * return 0 success, -1 failure
 */
int ospGetToHost(
    struct sip_msg* msg,
    char* tohost,
    int bufsize)
{
    struct to_body* to;
    struct sip_uri uri;
    int result = -1;

    if ((tohost != NULL) && (bufsize > 0)) {
        tohost[0] = '\0';
        if (msg->to != NULL) {
            if (parse_headers(msg, HDR_TO_F, 0) == 0) {
                to = get_to(msg);
                if (parse_uri(to->uri.s, to->uri.len, &uri) == 0) {
                    if (uri.port_no != 0) {
                        snprintf(tohost, bufsize, "%.*s:%d", uri.host.len, uri.host.s, uri.port_no);
                    } else {
                        ospCopyStrToBuffer(&uri.host, tohost, bufsize);
                    }
                    result = 0;
                } else {
                    LM_ERR("failed to parse To uri\n");
                }
            } else {
                LM_ERR("failed to parse To header\n");
            }
        } else {
            LM_ERR("failed to find To header\n");
        }
    } else {
        LM_ERR("bad parameters to parse hsto info from To header\n");
    }

    return result;
}

/*
 * Get To header
 * param msg SIP message
 * param to To header
 * param bufsize Size of to header buffer
 * return 0 success, -1 failure
 */
int ospGetTo(
    struct sip_msg* msg,
    char* to,
    int bufsize)
{
    int result = -1;

    if ((to!= NULL) && (bufsize > 0)) {
        to[0] = '\0';
        if (msg->to != NULL) {
            ospCopyStrToBuffer(&msg->to->body, to, bufsize);
            result = 0;
        } else {
            LM_ERR("failed to find To header\n");
        }
    } else {
        LM_ERR("bad parameters to parse To header\n");
    }

    return result;
}

/*
 * Get user part from P-Asserted-Identity header
 * param msg SIP message
 * param user User part of P-Asserted-Identity header
 * param bufsize Size of fromuser buffer
 * return 0 success, 1 without PAI, -1 failure
 */
int ospGetPaiUser(
    struct sip_msg* msg,
    char* paiuser,
    int bufsize)
{
    struct to_body* pai;
    struct sip_uri uri;
    int result = -1;

    if ((paiuser != NULL) && (bufsize > 0)) {
        paiuser[0] = '\0';
        if (msg->pai != NULL) {
            if (parse_pai_header(msg) == 0) {
                pai = get_pai(msg);
                if (parse_uri(pai->uri.s, pai->uri.len, &uri) == 0) {
                    ospCopyStrToBuffer(&uri.user, paiuser, bufsize);
                    ospSkipUserParam(paiuser);
                    result = 0;
                } else {
                    LM_ERR("failed to parse PAI uri\n");
                }
            } else {
                LM_ERR("failed to parse PAI uri\n");
            }
        } else {
            LM_DBG("without PAI header\n");
            result = 1;
        }
    } else {
        LM_ERR("bad parameters to parse user part from PAI\n");
    }

    return result;
}

/*
 * Get host part from P-Asserted-Identity header
 * param msg SIP message
 * param host Host part of P-Asserted-Identity header
 * param bufsize Size of fromuser buffer
 * return 0 success, 1 without PAI, -1 failure
 */
int ospGetPaiHost(
    struct sip_msg* msg,
    char* paihost,
    int bufsize)
{
    struct to_body* pai;
    struct sip_uri uri;
    int result = -1;

    if ((paihost != NULL) && (bufsize > 0)) {
        paihost[0] = '\0';
        if (msg->pai != NULL) {
            if (parse_pai_header(msg) == 0) {
                pai = get_pai(msg);
                if (parse_uri(pai->uri.s, pai->uri.len, &uri) == 0) {
                    ospCopyStrToBuffer(&uri.host, paihost, bufsize);
                    result = 0;
                } else {
                    LM_ERR("failed to parse PAI uri\n");
                }
            } else {
                LM_ERR("failed to parse PAI uri\n");
            }
        } else {
            LM_DBG("without PAI header\n");
            result = 1;
        }
    } else {
        LM_ERR("bad parameters to parse host part from PAI\n");
    }

    return result;
}

/*
 * Get P-Asserted-Identity header
 * param msg SIP message
 * param pai P-Asserted-Identity header
 * param bufsize Size of pai header buffer
 * return 0 success, 1 without PAI, -1 failure
 */
int ospGetPai(
    struct sip_msg* msg,
    char* pai,
    int bufsize)
{
    int result = -1;

    if ((pai!= NULL) && (bufsize > 0)) {
        pai[0] = '\0';
        if (msg->pai != NULL) {
           ospCopyStrToBuffer(&msg->pai->body, pai, bufsize);
           result = 0;
        } else {
            LM_DBG("without PAI header\n");
            result = 1;
        }
    } else {
        LM_ERR("bad parameters to parse PAI header\n");
    }

    return result;
}

/*
 * Get user part from Remote-Party-ID header
 * param msg SIP message
 * param user User part of Remote-Party-ID header
 * param bufsize Size of fromuser buffer
 * return 0 success, 1 without RPID, -1 failure
 */
int ospGetRpidUser(
    struct sip_msg* msg,
    char* rpiduser,
    int bufsize)
{
    struct to_body* rpid;
    struct sip_uri uri;
    int result = -1;

    if ((rpiduser != NULL) && (bufsize > 0)) {
        rpiduser[0] = '\0';
        if (msg->rpid != NULL) {
            if (parse_rpid_header(msg) == 0) {
                rpid = get_rpid(msg);
                if (parse_uri(rpid->uri.s, rpid->uri.len, &uri) == 0) {
                    ospCopyStrToBuffer(&uri.user, rpiduser, bufsize);
                    ospSkipUserParam(rpiduser);
                    result = 0;
                } else {
                    LM_ERR("failed to parse RPID uri\n");
                }
            } else {
                LM_ERR("failed to parse RPID uri\n");
            }
        } else {
            LM_DBG("without RPID header\n");
            result = 1;
        }
    } else {
        LM_ERR("bad parameters to parse user part from RPID\n");
    }

    return result;
}

/*
 * Get host part from Remote-Party-ID header
 * param msg SIP message
 * param host Host part of Remote-Party-ID header
 * param bufsize Size of fromuser buffer
 * return 0 success, 1 without RPID, -1 failure
 */ 
int ospGetRpidHost(
    struct sip_msg* msg,
    char* rpidhost,
    int bufsize)
{
    struct to_body* rpid;
    struct sip_uri uri;
    int result = -1;

    if ((rpidhost!= NULL) && (bufsize > 0)) {
        rpidhost[0] = '\0';
        if (msg->rpid != NULL) {
            if (parse_rpid_header(msg) == 0) {
                rpid = get_rpid(msg);
                if (parse_uri(rpid->uri.s, rpid->uri.len, &uri) == 0) {
                    ospCopyStrToBuffer(&uri.host, rpidhost, bufsize);
                    result = 0;
                } else {
                    LM_ERR("failed to parse RPID uri\n");
                }
            } else {
                LM_ERR("failed to parse RPID uri\n");
            }
        } else {
            LM_DBG("without RPID header\n");
            result = 1;
        }
    } else {
        LM_ERR("bad parameters to parse host part from RPID\n");
    }

    return result;
}

/*
 * Get user part from P-Charge-Info header
 * param msg SIP message
 * param user User part of P-Charge-Info header
 * param bufsize Size of fromuser buffer
 * return 0 success, 1 without P-Charge-Info, -1 failure
 */
int ospGetPciUser(
    struct sip_msg* msg,
    char* pciuser,
    int bufsize)
{
    struct to_body body;
    struct to_body* pci = NULL;
    struct hdr_field* hf;
    struct sip_uri uri;
    int result = -1;

    if ((pciuser != NULL) && (bufsize > 0)) {
        pciuser[0] = '\0';
        if (parse_headers(msg, HDR_EOH_F, 0) == 0) {
            hf = get_header_by_name(msg, PCHARGEINFO, strlen(PCHARGEINFO));
            if (hf) {
                if (!(pci = hf->parsed)) {
                    pci = &body;
                    parse_to(hf->body.s, hf->body.s + hf->body.len + 1, pci);
                }
                if (pci->error != PARSE_ERROR) {
                    if (parse_uri(pci->uri.s, pci->uri.len, &uri) == 0) {
                        ospCopyStrToBuffer(&uri.user, pciuser, bufsize);
                        ospSkipUserParam(pciuser);
                        result = 0;
                    } else {
                        LM_ERR("failed to parse P-Charge-Info uri\n");
                    }
                    if (pci == &body) {
                        free_to_params(pci);
                    }
                } else {
                    LM_ERR("bad P-Charge-Info header\n");
                }
            } else {
                LM_DBG("without P-Charge-Info header\n");
                result = 1;
            }
        } else {
            LM_ERR("failed to parse message\n");
        }
    } else {
        LM_ERR("bad parameters to parse user part from PAI\n");
    }

    return result;
}

/*
 * Get host part from P-Charge-Info header
 * param msg SIP message
 * param host Host part of P-Charge-Info header
 * param bufsize Size of fromuser buffer
 * return 0 success, 1 without P-Charge-Info, -1 failure
 */
int ospGetPciHost(
    struct sip_msg* msg,
    char* pcihost,
    int bufsize)
{
    struct to_body body;
    struct to_body* pci = NULL;
    struct hdr_field* hf;
    struct sip_uri uri;
    int result = -1;

    if ((pcihost != NULL) && (bufsize > 0)) {
        pcihost[0] = '\0';
        if (parse_headers(msg, HDR_EOH_F, 0) == 0) {
            hf = get_header_by_name(msg, PCHARGEINFO, strlen(PCHARGEINFO));
            if (hf) {
                if (!(pci = hf->parsed)) {
                    pci = &body;
                    parse_to(hf->body.s, hf->body.s + hf->body.len + 1, pci);
                }
                if (pci->error != PARSE_ERROR) {
                    if (parse_uri(pci->uri.s, pci->uri.len, &uri) == 0) {
                        ospCopyStrToBuffer(&uri.host, pcihost, bufsize);
                        result = 0;
                    } else {
                        LM_ERR("failed to parse P-Charge-Info uri\n");
                    }
                    if (pci == &body) {
                        free_to_params(pci);
                    }
                } else {
                    LM_ERR("bad P-Charge-Info header\n");
                }
            } else {
                LM_DBG("without P-Charge-Info header\n");
                result = 1;
            }
        } else {
            LM_ERR("failed to parse message\n");
        }
    } else {
        LM_ERR("bad parameters to parse user part from PAI\n");
    }

    return result;
}

/*
 * Get number and domain from Diversion header
 * param msg SIP message
 * param user User part of Diversion header
 * param userbufsize Size of user buffer
 * param host Host part of Diversion header
 * param hostbufsize Size of host buffer
 * return 0 success, 1 without Diversion, -1 failure
 */
int ospGetDiversion(
    struct sip_msg* msg,
    char* user,
    int userbufsize,
    char* host,
    int hostbufsize)
{
    struct to_body* diversion;
    struct sip_uri uri;
    int result = -1;

    if (((user != NULL) && (userbufsize > 0)) && ((host != NULL) && (hostbufsize > 0))){
        user[0] = '\0';
        host[0] = '\0';
        if (msg->diversion != NULL) {
            if (parse_diversion_header(msg) == 0) {
                diversion = get_diversion(msg);
                if (parse_uri(diversion->uri.s, diversion->uri.len, &uri) == 0) {
                    ospCopyStrToBuffer(&uri.user, user, userbufsize);
                    ospSkipUserParam(user);
                    if (uri.port_no != 0) {
                        snprintf(host, hostbufsize, "%.*s:%d", uri.host.len, uri.host.s, uri.port_no);
                    } else {
                        ospCopyStrToBuffer(&uri.host, host, hostbufsize);
                    }
                    result = 0;
                } else {
                    LM_ERR("failed to parse Diversion uri\n");
                }
            } else {
                LM_ERR("failed to parse Diversion header\n");
            }
        } else {
            LM_DBG("without Diversion header\n");
            result = 1;
        }
    } else {
        LM_ERR("bad paraneters to parse number from Diversion\n");
    }

    return result;
}

/*
 * Get all parameters of P-Charging-Vector header
 * param msg SIP message
 * param pcvicid ICID value of P-Charging-Vector header
 * param bufsize Size of ICID value buffer
 * return 0 success, 1 without P-Charging-Vector, -1 failure
 */
int ospGetPcvIcid(
    struct sip_msg* msg, 
    char* pcvicid, 
    int bufsize)
{
    struct hdr_field* hf;
    param_hooks_t phooks;
    param_t* params = NULL;
    param_t* pit;
    int result = -1;

    if ((pcvicid != NULL) && (bufsize > 0)) {
        pcvicid[0] = '\0';
        if (parse_headers(msg, HDR_EOH_F, 0) == 0) {
            hf = get_header_by_name(msg, PCHARGINGVECTOR, strlen(PCHARGINGVECTOR));
            if (hf) {
                if (parse_params(&(hf->body), CLASS_ANY, &phooks, &params) == 0) {
                    for (pit = params; pit; pit = pit->next) {
                        if ((pit->name.len == OSP_ICID_SIZE) &&
                            (strncasecmp(pit->name.s, OSP_ICID_NAME, OSP_ICID_SIZE) == 0) &&
                            (pcvicid[0] == '\0'))
                        {
                            ospCopyStrToBuffer(&pit->body, pcvicid, bufsize);
                            result = 0;
                        }
                    }
                    if (params != NULL) {
                        free_params(params);
                    }
                }
            } else {
                LM_DBG("without P-Charging-Vector header\n");
                result = 1;
            }
        } else {
            LM_ERR("failed to parse message\n");
        }
    } else {
        LM_ERR("bad parameters to parse PCV\n");
    }

    return result;
}

/*
 * Get user part from Request-Line header
 * param msg SIP message
 * param uriuser User part of To header
 * param bufsize Size of touser buffer
 * return 0 success, -1 failure
 */
int ospGetUriUser(
    struct sip_msg* msg,
    char* uriuser,
    int bufsize)
{
    int result = -1;

    if ((uriuser != NULL) && (bufsize > 0)) {
        uriuser[0] = '\0';
        if (parse_sip_msg_uri(msg) >= 0) {
            ospCopyStrToBuffer(&msg->parsed_uri.user, uriuser, bufsize);
            ospSkipUserParam(uriuser);
            result = 0;
        } else {
            LM_ERR("failed to parse Request-Line URI\n");
        }
    } else {
        LM_ERR("bad parameters to parse user part from RURI\n");
    }

    return result;
}

/*
 * Get Identity header
 * param msg SIP message
 * param identity Identity header
 * param bufsize Size of identity header buffer
 * return 0 success, 1 without Identity, -1 failure
 */
int ospGetIdentity(
    struct sip_msg* msg,
    char* identity,
    int bufsize)
{
    struct hdr_field* hf;
    int result = -1;

    if ((identity != NULL) && (bufsize > 0)) {
        identity[0] = '\0';
        if (parse_headers(msg, HDR_EOH_F, 0) == 0) {
            hf = get_header_by_name(msg, IDENTITY, strlen(IDENTITY));
            if (hf) {
                ospCopyStrToBuffer(&hf->body, identity, bufsize);
                result = 0;
            } else {
                LM_DBG("without Identity header\n");
                result = 1;
            }
        } else {
            LM_ERR("failed to parse message\n");
        }
    } else {
        LM_ERR("bad parameters to parse Identity header\n");
    }

    return result;
}

/*
 * Get host part from Contact header
 * param msg SIP message
 * param host Host part of Contact header
 * param bufsize Size of fromuser buffer
 * return 0 success, 1 without Contact, -1 failure
 */
int ospGetContactHost(
    struct sip_msg* msg,
    char* contacthost,
    int bufsize)
{
    contact_t* contacts;
    struct sip_uri uri;
    int result = -1;

    if ((contacthost != NULL) && (bufsize > 0)) {
        contacthost[0] = '\0';
        if (msg->contact != NULL) {
            if (msg->contact->parsed || (parse_contact(msg->contact) >= 0)) {
                contacts = ((contact_body_t*)msg->contact->parsed)->contacts;
                if (parse_uri(contacts->uri.s, contacts->uri.len, &uri) == 0) {
                    ospCopyStrToBuffer(&uri.host, contacthost, bufsize);
                    result = 0;
                } else {
                    LM_ERR("failed to parse Contact uri\n");
                }
            } else {
                LM_ERR("failed to parse Contact uri\n");
            }
        } else {
            LM_DBG("without Contact header\n");
            result = 1;
        }
    } else {
        LM_ERR("bad parameters to parse host part from Contact\n");
    }

    return result;
}

/*
 * Append header to SIP message
 * param msg SIP message
 * param header Header to be appended
 * return 0 success, -1 failure
 */
static int ospAppendHeader(
    struct sip_msg* msg,
    str* header)
{
    char* s;
    struct lump* anchor;

    if((msg == 0) || (header == 0) || (header->s == 0) || (header->len <= 0)) {
        LM_ERR("bad parameters for appending header\n");
        return -1;
    }

    if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
        LM_ERR("failed to parse message\n");
        return -1;
    }

    anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
    if (anchor == 0) {
        LM_ERR("failed to get anchor\n");
        return -1;
    }

    s = (char*)pkg_malloc(header->len);
    if (s == 0) {
        LM_ERR("no pkg memory\n");
        return -1;
    }

    memcpy(s, header->s, header->len);

    if (insert_new_lump_before(anchor, s, header->len, 0) == 0) {
        LM_ERR("failed to insert lump\n");
        pkg_free(s);
        return -1;
    }

    return 0;
}

/*
 * Add OSP token header to SIP message
 * param msg SIP message
 * param token OSP authorization token
 * param tokensize Size of OSP authorization token
 * return 0 success, -1 failure
 */
int ospAddOspToken(
    struct sip_msg* msg,
    unsigned char* token,
    unsigned int tokensize)
{
    str headerval;
    char buffer[OSP_HEADERBUF_SIZE];
    unsigned char encodedtoken[OSP_TOKENBUF_SIZE];
    unsigned int encodedtokensize = sizeof(encodedtoken);
    int errorcode, result = -1;

    if ((token == NULL) || (tokensize == 0)) {
        LM_DBG("destination is not OSP device\n");
        result = 0;
    } else {
        if ((errorcode = OSPPBase64Encode(token, tokensize, encodedtoken, &encodedtokensize)) == OSPC_ERR_NO_ERROR) {
            snprintf(buffer,
                sizeof(buffer),
                "%s: %.*s\r\n",
                OSP_TOKENHEADER_NAME,
                encodedtokensize,
                encodedtoken);

            headerval.s = buffer;
            headerval.len = strlen(buffer);

            LM_DBG("setting osp token header field '%s'\n", buffer);

            if (ospAppendHeader(msg, &headerval) == 0) {
                result = 0;
            } else {
                LM_ERR("failed to append osp header\n");
            }
        } else {
            LM_ERR("failed to base64 encode token (%d)\n", errorcode);
        }
    }

    return result;
}

/*
 * Get OSP token from SIP message
 * param msg SIP message
 * param token OSP authorization token
 * param tokensize Size of OSP authorization token
 * return 0 success, -1 failure
 */
int ospGetOspToken(
    struct sip_msg* msg,
    unsigned char* token,
    unsigned int* tokensize)
{
    struct hdr_field* hf;
    int errorcode;
    int result = -1;

    if (parse_headers(msg, HDR_EOH_F, 0) == 0) {
        hf = get_header_by_name(msg, OSP_TOKENHEADER_NAME, OSP_TOKENHEADER_SIZE);
        if (hf) {
            if ((errorcode = OSPPBase64Decode(hf->body.s, hf->body.len, token, tokensize)) == OSPC_ERR_NO_ERROR) {
                result = 0;
            } else {
                LM_ERR("failed to base64 decode token (%d)\n", errorcode);
                LM_ERR("header '%.*s' length %d\n",
                    hf->body.len, hf->body.s, hf->body.len);
            }
        }
    } else {
        LM_ERR("failed to parse all headers\n");
    }

    return result;
}

/*
 * Get first VIA header and use the IP or host name
 * param msg SIP message
 * param viaaddr Via header IP address
 * param bufsize Size of viaaddr
 * return 0 success, -1 failure
 */
int ospGetViaAddress(
    struct sip_msg* msg,
    char* viaaddr,
    int bufsize)
{
    struct hdr_field* hf;
    struct via_body* via;
    int result = -1;

    if ((viaaddr != NULL) && (bufsize > 0)) {
        /*
         * No need to call parse_headers, called already and VIA is parsed
         * anyway by default
         */
        for (hf = msg->headers; hf; hf = hf->next) {
            if (hf->type == HDR_VIA_T) {
                /* found first VIA */
                via = (struct via_body*)hf->parsed;

                if (via->port != 0) {
                    snprintf(viaaddr, bufsize, "%.*s:%d", via->host.len, via->host.s, via->port);
                } else {
                    ospCopyStrToBuffer(&via->host, viaaddr, bufsize);
                }

                LM_DBG("via address '%s'\n", viaaddr);

                result = 0;
                break;
            }
        }
    } else {
        LM_ERR("bad parameters to parse host from VIA header\n");
    }

    return result;
}

/*
 * Get source device IP address
 * param msg SIP message
 * param srcdev Source device address
 * param bufsize Size of srcdev
 * return 0 success, -1 failure
 */
int ospGetSrcDev(
    struct sip_msg* msg,
    char* srcdev,
    int bufsize)
{
    int result = -1;

    if ((srcdev != NULL) && (bufsize > 0)) {
        switch (_osp_work_mode) {
        case 1:
            if (ospGetAVP(_osp_srcdev_avpid, _osp_srcdev_avptype, srcdev, bufsize) == 0) {
                result = 0;
            } else {
                result = ospGetViaAddress(msg, srcdev, bufsize);
            }
            break;
        case 0:
        default:
            result = ospGetViaAddress(msg, srcdev, bufsize);
            break;
        }
    } else {
        LM_ERR("bad parameters to parse source device\n");
    }

    return result;
}

/*
 * Get source IP address
 * param msg SIP message
 * param source Source IP address
 * param bufsize Size of source
 * return 0 success, -1 failure
 */
int ospGetSource(
    struct sip_msg* msg,
    char* source,
    int bufsize)
{
    int result = -1;

    if ((source != NULL) && (bufsize > 0)) {
        switch (_osp_work_mode) {
        case 1:
            result = ospGetViaAddress(msg, source, bufsize);
            break;
        case 0:
        default:
            strncpy(source, _osp_in_device, bufsize);
            source[bufsize - 1] = '\0';
            result = 0;
            break;
        }
    } else {
        LM_ERR("bad parameters to parse source\n");
    }

    return result;
}

/*
 * Get Call-ID header from SIP message
 * param msg SIP message
 * param callid Call ID
 * return 0 success, -1 failure
 */
int ospGetCallId(
    struct sip_msg* msg,
    OSPT_CALL_ID** callid)
{
    struct hdr_field* hf;
    int result = -1;

    hf = (struct hdr_field*)msg->callid;
    if (hf != NULL) {
        *callid = OSPPCallIdNew(hf->body.len, (unsigned char*)hf->body.s);
        if (*callid) {
            result = 0;
        } else {
            LM_ERR("failed to allocate OSPCALLID object for '%.*s'\n", hf->body.len, hf->body.s);
        }
    } else {
        LM_ERR("failed to find Call-ID header\n");
    }

    return result;
}

/*
 * Get route parameters from the 1st Route or Request-Line
 * param msg SIP message
 * param routeparameters Route parameters
 * param bufsize Size of routeparameters
 * return 0 success, -1 failure
 */
int ospGetRouteParam(
    struct sip_msg* msg,
    char* routeparameters,
    int bufsize)
{
    struct hdr_field* hf;
    rr_t* rt;
    struct sip_uri uri;
    int result = -1;

    if ((routeparameters != NULL) && (bufsize > 0)) {
        LM_DBG("parsed uri host '%.*s' port '%d' vars '%.*s'\n",
            msg->parsed_uri.host.len,
            msg->parsed_uri.host.s,
            msg->parsed_uri.port_no,
            msg->parsed_uri.params.len,
            msg->parsed_uri.params.s);

        if (!(hf = msg->route)) {
            LM_DBG("there is no Route headers\n");
        } else if (!(rt = (rr_t*)hf->parsed)) {
            LM_ERR("route headers are not parsed\n");
        } else if (parse_uri(rt->nameaddr.uri.s, rt->nameaddr.uri.len, &uri) != 0) {
            LM_ERR("failed to parse the Route uri '%.*s'\n", rt->nameaddr.uri.len, rt->nameaddr.uri.s);
        } else if (check_self(&uri.host, uri.port_no ? uri.port_no : SIP_PORT, PROTO_NONE) != 1) {
            LM_DBG("the Route uri is NOT mine\n");
            LM_DBG("host '%.*s' port '%d'\n", uri.host.len, uri.host.s, uri.port_no);
            LM_DBG("params '%.*s'\n", uri.params.len, uri.params.s);
        } else {
            LM_DBG("the Route uri IS mine - '%.*s'\n", uri.params.len, uri.params.s);
            LM_DBG("host '%.*s' port '%d'\n", uri.host.len, uri.host.s, uri.port_no);
            ospCopyStrToBuffer(&uri.params, routeparameters, bufsize);
            result = 0;
        }

        if ((result == -1) && (msg->parsed_uri.params.len > 0)) {
            LM_DBG("using route parameters from Request-Line uri\n");
            ospCopyStrToBuffer(&msg->parsed_uri.params, routeparameters, bufsize);
            routeparameters[msg->parsed_uri.params.len] = '\0';
            result = 0;
        }
    } else {
        LM_ERR("bad parameters to parse parameters from Route header\n");
    }

    return result;
}

/*
 * Rebuild URI
 * param newuri URI to be built, newuri.len includes buffer size
 * param dest Destination data structure
 * return 0 success, -1 failure
 */
int ospRebuildDestUri(
    str* newuri,
    osp_dest* dest)
{
    static const str TRANS = { ";transport=tcp", 14 };
    static const str USERPHONE = { ";user=phone", 11 };
    char* buffer;
    int calledsize;
    int hostsize;
    int uriparamsize;
    int userparamsize;
    int dnidsize;
    int swidsize;
    int paramstrsize;
    int count;

    calledsize = strlen(dest->called);
    hostsize = strlen(dest->host);
    /* ";rn=" + nprn */
    userparamsize = dest->nprn[0] ? 4 + strlen(dest->nprn) : 0;
    /* ";cic=" + npcic */
    userparamsize += dest->npcic[0] ? 5 + strlen(dest->npcic) : 0;
    /* ";npdi" */
    userparamsize += dest->npdi ? 5 : 0;
    /* ";spid=" */
    userparamsize += dest->opname[OSPC_OPNAME_SPID][0] ? 6 + strlen(dest->opname[OSPC_OPNAME_SPID]) : 0;
    /* ";ocn=" */
    userparamsize += dest->opname[OSPC_OPNAME_OCN][0] ? 5 + strlen(dest->opname[OSPC_OPNAME_OCN]) : 0;
    /* ";spn=" */
    userparamsize += dest->opname[OSPC_OPNAME_SPN][0] ? 5 + strlen(dest->opname[OSPC_OPNAME_SPN]) : 0;
    /* ";altspn=" */
    userparamsize += dest->opname[OSPC_OPNAME_ALTSPN][0] ? 8 + strlen(dest->opname[OSPC_OPNAME_ALTSPN]) : 0;
    /* ";mcc=" */
    userparamsize += dest->opname[OSPC_OPNAME_MCC][0] ? 5 + strlen(dest->opname[OSPC_OPNAME_MCC]) : 0;
    /* ";mnc=" */
    userparamsize += dest->opname[OSPC_OPNAME_MNC][0] ? 5 + strlen(dest->opname[OSPC_OPNAME_MNC]) : 0;
    /* ";user=phone" */
    uriparamsize = _osp_append_userphone ? USERPHONE.len : 0;
    /* destination network ID parameter */
    dnidsize = (_osp_dnid_location && dest->dnid[0]) ? 1 + strlen(_osp_dnid_param) + 1 + strlen(dest->dnid) : 0;
    /* destination switch ID parameter */
    swidsize = (_osp_swid_location && dest->swid[0]) ? 1 + strlen(_osp_swid_param) + 1 + strlen(dest->swid) : 0;
    /* parameter string */
    paramstrsize = (_osp_paramstr_location && _osp_paramstr_value[0]) ? 1 + strlen(_osp_paramstr_value) : 0;

    LM_DBG("'%s' (%d) '%s' (%d) '%s' '%s' '%d' '%s' '%s' '%s' '%s' '%s' '%s' (%d) '%s' '%s' (%d)\n",
        dest->called,
        calledsize,
        dest->host,
        hostsize,
        dest->nprn,
        dest->npcic,
        dest->npdi,
        dest->opname[OSPC_OPNAME_SPID],
        dest->opname[OSPC_OPNAME_OCN],
        dest->opname[OSPC_OPNAME_SPN],
        dest->opname[OSPC_OPNAME_ALTSPN],
        dest->opname[OSPC_OPNAME_MCC],
        dest->opname[OSPC_OPNAME_MNC],
        userparamsize,
        dest->dnid,
        dest->swid,
        uriparamsize);

    /* "sip:" + called + NP + "@" + host + ";user=phone" + ";_osp_dnid_param=" + dnid + " + ";_osp_swid_param=" + swid + " SIP/2.0" etc. */
    /* OpenSIPS will add "<>" for the Contact headers of SIP 3xx messages */
    if (newuri->len < (4 + calledsize + userparamsize + 1 + hostsize + uriparamsize + dnidsize + swidsize + paramstrsize + 1 + 7 + TRANS.len)) {
        LM_ERR("new uri buffer is too small\n");
        newuri->len = 0;
        return -1;
    }

    buffer = newuri->s;

    *buffer++ = 's';
    *buffer++ = 'i';
    *buffer++ = 'p';
    *buffer++ = ':';

    memcpy(buffer, dest->called, calledsize);
    buffer += calledsize;

    if (_osp_export_np == 0) {
        if (dest->nprn[0]) {
            count = sprintf(buffer, ";rn=%s", dest->nprn);
            buffer += count;
        }
        if (dest->npcic[0]) {
            count = sprintf(buffer, ";cic=%s", dest->npcic);
            buffer += count;
        }
        if (dest->npdi) {
            sprintf(buffer, ";npdi");
            buffer += 5;
        }
        if (dest->opname[OSPC_OPNAME_SPID][0]) {
            count = sprintf(buffer, ";spid=%s", dest->opname[OSPC_OPNAME_SPID]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_OCN][0]) {
            count = sprintf(buffer, ";ocn=%s", dest->opname[OSPC_OPNAME_OCN]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_SPN][0]) {
            count = sprintf(buffer, ";spn=%s", dest->opname[OSPC_OPNAME_SPN]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_ALTSPN][0]) {
            count = sprintf(buffer, ";altspn=%s", dest->opname[OSPC_OPNAME_ALTSPN]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_MCC][0]) {
            count = sprintf(buffer, ";mcc=%s", dest->opname[OSPC_OPNAME_MCC]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_MNC][0]) {
            count = sprintf(buffer, ";mnc=%s", dest->opname[OSPC_OPNAME_MNC]);
            buffer += count;
        }
    
        if ((_osp_dnid_location == 1) && (dest->dnid[0] != '\0')) {
            count = sprintf(buffer, ";%s=%s", _osp_dnid_param, dest->dnid);
            buffer += count;
        }
    
        if ((_osp_swid_location == 1) && (dest->swid[0] != '\0')) {
            count = sprintf(buffer, ";%s=%s", _osp_swid_param, dest->swid);
            buffer += count;
        }
    
        if ((_osp_paramstr_location == 1) && (_osp_paramstr_value[0] != '\0')) {
            count = sprintf(buffer, ";%s", _osp_paramstr_value);
            buffer += count;
        }
    } else {
        if ((_osp_dnid_location == 1) && (dest->dnid[0] != '\0')) {
            count = sprintf(buffer, ";%s=%s", _osp_dnid_param, dest->dnid);
            buffer += count;
        }
    
        if ((_osp_swid_location == 1) && (dest->swid[0] != '\0')) {
            count = sprintf(buffer, ";%s=%s", _osp_swid_param, dest->swid);
            buffer += count;
        }
    
        if ((_osp_paramstr_location == 1) && (_osp_paramstr_value[0] != '\0')) {
            count = sprintf(buffer, ";%s", _osp_paramstr_value);
            buffer += count;
        }
    
        if (dest->opname[OSPC_OPNAME_SPID][0]) {
            count = sprintf(buffer, ";spid=%s", dest->opname[OSPC_OPNAME_SPID]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_OCN][0]) {
            count = sprintf(buffer, ";ocn=%s", dest->opname[OSPC_OPNAME_OCN]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_SPN][0]) {
            count = sprintf(buffer, ";spn=%s", dest->opname[OSPC_OPNAME_SPN]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_ALTSPN][0]) {
            count = sprintf(buffer, ";altspn=%s", dest->opname[OSPC_OPNAME_ALTSPN]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_MCC][0]) {
            count = sprintf(buffer, ";mcc=%s", dest->opname[OSPC_OPNAME_MCC]);
            buffer += count;
        }
        if (dest->opname[OSPC_OPNAME_MNC][0]) {
            count = sprintf(buffer, ";mnc=%s", dest->opname[OSPC_OPNAME_MNC]);
            buffer += count;
        }
        if (dest->npdi) {
            sprintf(buffer, ";npdi");
            buffer += 5;
        }
        if (dest->npcic[0]) {
            count = sprintf(buffer, ";cic=%s", dest->npcic);
            buffer += count;
        }
        if (dest->nprn[0]) {
            count = sprintf(buffer, ";rn=%s", dest->nprn);
            buffer += count;
        }
    }

    *buffer++ = '@';

    strncpy(buffer, dest->host, newuri->len - (buffer - newuri->s));
    buffer += hostsize;

    if (_osp_append_userphone != 0) {
        memcpy(buffer, USERPHONE.s, USERPHONE.len);
        buffer += USERPHONE.len;
    }

    if ((_osp_dnid_location == 2) && (dest->dnid[0] != '\0')) {
        count = sprintf(buffer, ";%s=%s", _osp_dnid_param, dest->dnid);
        buffer += count;
    }

    if ((_osp_swid_location == 2) && (dest->swid[0] != '\0')) {
        count = sprintf(buffer, ";%s=%s", _osp_swid_param, dest->swid);
        buffer += count;
    }

    if ((_osp_paramstr_location == 2) && (_osp_paramstr_value[0] != '\0')) {
        count = sprintf(buffer, ";%s", _osp_paramstr_value);
        buffer += count;
    }

/*
    *buffer++ = ' ';
    *buffer++ = 'S';
    *buffer++ = 'I';
    *buffer++ = 'P';
    *buffer++ = '/';
    *buffer++ = '2';
    *buffer++ = '.';
    *buffer++ = '0';

    memcpy(buffer, TRANS.s, TRANS.len);
    buffer += TRANS.len;
    *buffer = '\0';
*/

    newuri->len = buffer - newuri->s;

    LM_DBG("new uri '%.*s'\n", newuri->len, newuri->s);

    return 0;
}

/*
 * Get next hop using the first Route not generated by this proxy or URI from the Request-Line
 * param msg SIP message
 * param nexthop Next hop IP
 * param bufsize Size of nexthop
 * return 0 success, -1 failure
 */
int ospGetNextHop(
    struct sip_msg* msg,
    char* nexthop,
    int bufsize)
{
    struct hdr_field* hf;
    struct sip_uri uri;
    rr_t* rt;
    int found = 0;
    int result = -1;

    if ((nexthop != NULL) && (bufsize > 0)) {
        result = 0;

        for (hf = msg->headers; hf; hf = hf->next) {
            if (hf->type == HDR_ROUTE_T) {
                for (rt = (rr_t*)hf->parsed; rt; rt = rt->next) {
                    if (parse_uri(rt->nameaddr.uri.s, rt->nameaddr.uri.len, &uri) == 0) {
                        LM_DBG("host '%.*s' port '%d'\n", uri.host.len, uri.host.s, uri.port_no);

                        if (check_self(&uri.host, uri.port_no ? uri.port_no : SIP_PORT, PROTO_NONE) != 1) {
                            LM_DBG("it is NOT me, FOUND!\n");

                            if (uri.port_no != 0) {
                                snprintf(nexthop, bufsize, "%.*s:%d", uri.host.len, uri.host.s, uri.port_no);
                            } else {
                                ospCopyStrToBuffer(&uri.host, nexthop, bufsize);
                            }
                            found = 1;
                            break;
                        } else {
                            LM_DBG("it IS me, keep looking\n");
                        }
                    } else {
                        LM_ERR("failed to parse route uri '%.*s'\n",
                            rt->nameaddr.uri.len,
                            rt->nameaddr.uri.s);
                    }
                }
                if (found == 1) {
                    break;
                }
            }
        }

        if (!found) {
            LM_DBG("using the Request-Line instead host '%.*s' port '%d'\n",
                 msg->parsed_uri.host.len,
                 msg->parsed_uri.host.s,
                 msg->parsed_uri.port_no);

            if (msg->parsed_uri.port_no != 0) {
                snprintf(nexthop, bufsize, "%.*s:%d", msg->parsed_uri.host.len, msg->parsed_uri.host.s, msg->parsed_uri.port_no);
            } else {
                ospCopyStrToBuffer(&msg->parsed_uri.host, nexthop, bufsize);
            }
            found = 1;
        }
    } else {
        LM_ERR("bad parameters to get next hop\n");
    }

    return result;
}

/*
 * Get number portability parameter from Request-Line
 * param msg SIP message
 * param rn Routing number
 * param rnbufsize Size of rn buffer
 * param cic Carrier identification code
 * param cicbufsize Size of cic buffer
 * param npdi NP database dip indicator
 * return 0 success, 1 not use NP or without NP parameters, -1 failure
 */
int ospGetNpParam(
    struct sip_msg* msg,
    char* rn,
    int rnbufsize,
    char* cic,
    int cicbufsize,
    int* npdi)
{
    str sv;
    param_hooks_t phooks;
    param_t* params = NULL;
    param_t* pit;
    int result = -1;

    if (((rn != NULL) && (rnbufsize > 0)) && ((cic != NULL) && (cicbufsize > 0)) && (npdi != NULL)) {
        rn[0] = '\0';
        cic[0] = '\0';
        *npdi = 0;

        if (_osp_use_np != 0) {
            if (parse_sip_msg_uri(msg) >= 0) {
                switch (msg->parsed_uri.type) {
                case TEL_URI_T:
                case TELS_URI_T:
                    sv = msg->parsed_uri.params;
                    break;
                case ERROR_URI_T:
                case SIP_URI_T:
                case SIPS_URI_T:
                default:
                    sv = msg->parsed_uri.user;
                    break;
                }
                if (parse_params(&sv, CLASS_ANY, &phooks, &params) == 0) {
                    for (pit = params; pit; pit = pit->next) {
                        if ((pit->name.len == OSP_RN_SIZE) &&
                            (strncasecmp(pit->name.s, OSP_RN_NAME, OSP_RN_SIZE) == 0) &&
                            (rn[0] == '\0'))
                        {
                            ospCopyStrToBuffer(&pit->body, rn, rnbufsize);
                        } else if ((pit->name.len == OSP_CIC_SIZE) &&
                            (strncasecmp(pit->name.s, OSP_CIC_NAME, OSP_CIC_SIZE) == 0) &&
                            (cic[0] == '\0'))
                        {
                            ospCopyStrToBuffer(&pit->body, cic, cicbufsize);
                        } else if ((pit->name.len == OSP_NPDI_SIZE) &&
                            (strncasecmp(pit->name.s, OSP_NPDI_NAME, OSP_NPDI_SIZE) == 0))
                        {
                            *npdi = 1;
                        }
                    }
                    if (params != NULL) {
                        free_params(params);
                    }
                }
                if ((rn[0] != '\0') || (cic[0] != '\0') || (*npdi != 0)) {
                    result = 0;
                } else {
                    LM_DBG("without number portability parameters\n");
                    result = 1;
                }
            } else {
                LM_ERR("failed to parse Request-Line URI\n");
            }
        } else {
            LM_DBG("do not use number portability\n");
            result = 1;
        }
    } else {
        LM_ERR("bad parameters to parse number portability parameters\n");
    }

    return result;
}

/*
 * Get operator name from Request-Line
 * param msg SIP message
 * param type Operator name type
 * param name Operator name buffer
 * param namebufsize Size of name buffer
 * return 0 success, 1 not use NP or without operator name, -1 failure
 */
int ospGetOperatorName(
    struct sip_msg* msg,
    OSPE_OPERATOR_NAME type,
    char* name,
    int namebufsize)
{
    str sv;
    param_hooks_t phooks;
    param_t* params = NULL;
    param_t* pit;
    int result = -1;

    if (((name != NULL) && (namebufsize > 0))) {
        name[0] = '\0';

        if (_osp_use_np != 0) {
            if (parse_sip_msg_uri(msg) >= 0) {
                switch (msg->parsed_uri.type) {
                case TEL_URI_T:
                case TELS_URI_T:
                    sv = msg->parsed_uri.params;
                    break;
                case ERROR_URI_T:
                case SIP_URI_T:
                case SIPS_URI_T:
                default:
                    sv = msg->parsed_uri.user;
                    break;
                }
                if (parse_params(&sv, CLASS_ANY, &phooks, &params) == 0) {
                    for (pit = params; pit; pit = pit->next) {
                        switch (type) {
                        case OSPC_OPNAME_SPID:
                            if ((pit->name.len == OSP_SPID_SIZE) &&
                                (strncasecmp(pit->name.s, OSP_SPID_NAME, OSP_SPID_SIZE) == 0) &&
                                (name[0] == '\0'))
                            {
                                ospCopyStrToBuffer(&pit->body, name, namebufsize);
                            }
                            break;
                        case OSPC_OPNAME_OCN:
                            if ((pit->name.len == OSP_OCN_SIZE) &&
                                (strncasecmp(pit->name.s, OSP_OCN_NAME, OSP_OCN_SIZE) == 0) &&
                                (name[0] == '\0'))
                            {
                                ospCopyStrToBuffer(&pit->body, name, namebufsize);
                            }
                            break;
                        case OSPC_OPNAME_SPN:
                            if ((pit->name.len == OSP_SPN_SIZE) &&
                                (strncasecmp(pit->name.s, OSP_SPN_NAME, OSP_SPN_SIZE) == 0) &&
                                (name[0] == '\0'))
                            {
                                ospCopyStrToBuffer(&pit->body, name, namebufsize);
                            }
                            break;
                        case OSPC_OPNAME_ALTSPN:
                            if ((pit->name.len == OSP_ALTSPN_SIZE) &&
                                (strncasecmp(pit->name.s, OSP_ALTSPN_NAME, OSP_ALTSPN_SIZE) == 0) &&
                                (name[0] == '\0'))
                            {
                                ospCopyStrToBuffer(&pit->body, name, namebufsize);
                            }
                            break;
                        case OSPC_OPNAME_MCC:
                            if ((pit->name.len == OSP_MCC_SIZE) &&
                                (strncasecmp(pit->name.s, OSP_MCC_NAME, OSP_MCC_SIZE) == 0) &&
                                (name[0] == '\0'))
                            {
                                ospCopyStrToBuffer(&pit->body, name, namebufsize);
                            }
                            break;
                        case OSPC_OPNAME_MNC:
                            if ((pit->name.len == OSP_MNC_SIZE) &&
                                (strncasecmp(pit->name.s, OSP_MNC_NAME, OSP_MNC_SIZE) == 0) &&
                                (name[0] == '\0'))
                            {
                                ospCopyStrToBuffer(&pit->body, name, namebufsize);
                            }
                            break;
                        default:
                            break;
                        }
                    }
                    if (params != NULL) {
                        free_params(params);
                    }
                }
                if (name[0] != '\0') {
                    result = 0;
                } else {
                    LM_DBG("without operator name\n");
                    result = 1;
                }
            } else {
                LM_ERR("failed to parse Request-Line URI\n");
            }
        } else {
            LM_DBG("do not use number portability\n");
            result = 1;
        }
    } else {
        LM_ERR("bad parameters to parse operator name\n");
    }

    return result;
}

/*
 * Get User-Agent header
 * param msg SIP message
 * param useragent User-Agent buffer
 * param bufsize Size of useragent
 * return 0 success, -1 failure
 */
int ospGetUserAgent(
    struct sip_msg* msg,
    char* useragent,
    int bufsize)
{
    int result = -1;

    if ((useragent != NULL) && (bufsize > 0)) {
        useragent[0] = '\0';
        if (parse_headers(msg, HDR_USERAGENT_F, 0) == 0) {
            if ((msg->user_agent != NULL) && (msg->user_agent->body.s != NULL) && (msg->user_agent->body.len > 0)) {
                ospCopyStrToBuffer(&msg->user_agent->body, useragent, bufsize);
            }
            result = 0;
        } else {
            LM_ERR("failed to parse User-Agent header\n");
        }
    } else {
        LM_ERR("bad paraneters to parse User-Agent header\n");
    }

    return result;
}

/*
 * Set request Date header AVP
 * param ignore1
 * param ignore2
 * return  MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure MODULE_RETURNCODE_ERROR error
 */
int ospSetRequestDate(
    struct sip_msg* msg,
    char* ignore1,
    char* ignore2)
{
    char datebuf[OSP_STRBUF_SIZE];
    str date;
    time_t datetime = time(NULL);
    int result = MODULE_RETURNCODE_TRUE;

    if (ospTimeToStr(datetime, datebuf, sizeof(datebuf)) == 0) {
        date.s = datebuf;
        date.len = strlen(datebuf);
        add_avp(_osp_reqdate_avptype | AVP_VAL_STR, _osp_reqdate_avpid, (int_str)date);
    } else {
        result = MODULE_RETURNCODE_FALSE;
    }

    return result;
}

