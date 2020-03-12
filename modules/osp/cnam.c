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
 *  2016-06-01  CNAM related functions.
 */

#include "../../mod_fix.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_event.h"
#include "../../parser/parse_expires.h"
#include "../../parser/contact/parse_contact.h"
#include "../../data_lump_rpl.h"
#include "../signaling/signaling.h"
#include "../tm/tm_load.h"
#include "../presence/utils_func.h"
#include "osp_mod.h"
#include "cnam.h"
#include "signaling.h"
#include "tm.h"

extern char* _osp_extraheaders_value;

/*
 * Parse SUBSCRIBE
 * param msg SIP message
 * return 0 success, others failure
 */
static int ospParseSubscribe(
    struct sip_msg* msg)
{
    int ret = -1;

    if (msg == NULL) {
        LM_ERR("wrong message\n");
    } else if (parse_headers(msg,HDR_EOH_F, 0) < 0) {
        LM_ERR("failed to parse message\n");
    } else if (parse_sip_msg_uri(msg) < 0) {
        LM_ERR("failed to parse ruri\n");
    } else if (parse_from_uri(msg) == NULL) {
        LM_ERR("failed to parse from\n");
    } else if (parse_to_uri(msg) == NULL) {
        LM_ERR("failed to parse to\n");
    } else if ((msg->contact == NULL) || (msg->contact->body.len <= 0) || (parse_contact(msg->contact) < 0)) {
        LM_ERR("failed to parse contact\n");
    } else if ((msg->event == NULL) || (msg->event->body.len <= 0) || (parse_event(msg->event) < 0)) {
        LM_ERR("failed to parse event\n");
    } else if ((msg->expires != NULL) && (msg->expires->body.len > 0) && (parse_expires(msg->expires) < 0)) {
        LM_ERR("failed to parse expires\n");
    } else {
        ret = 0;
    }

    return ret;
}

/*
 * Send 200 OK reply
 * param msg SIP message
 * param expire Expires value
 * param tag To tag
 * return 0 success, others failure
 */
static int ospReply200(struct sip_msg* msg, int expire, str* contact, str* tag)
{
    int length;
    char buffer[OSP_STRBUF_SIZE];
    char headers[OSP_HEADERBUF_SIZE];
    str ok = { "OK", 2 };
    int ret = -1;

    buffer[0] = '\0';
    if (msg->rcv.proto != PROTO_UDP) {
        memcpy(buffer, ";transport=", 11);
        if (proto2str(msg->rcv.proto, buffer + 11) == 0) {
            buffer[0] = '\0';
        }
    }

    length = snprintf(headers, sizeof(headers), "Expires: %ud\r\nContact: <%.*s%s>\r\n",
        expire,
        contact->len, contact->s, buffer);

    if (add_lump_rpl(msg, headers, length, LUMP_RPL_HDR) == 0) {
        LM_ERR("failed to add lump_rl\n");
    } else if (osp_sigb.reply(msg, 200, &ok, tag)< 0) {
        LM_ERR("failed to send reply\n");
    } else {
        ret = 0;
    }

    return ret;
}

/*
 * Create dialog structure
 * param msg SIP message
 * return dialog
 */
static dlg_t* ospCreateDialog(
    struct sip_msg* msg,
    str* tag)
{
    struct to_body* from;
    struct to_body* to;
    contact_body_t* contact;
    str record_route = { 0, 0 };
    dlg_t* dialog = NULL;

    if ((dialog = (dlg_t*)pkg_malloc(sizeof(dlg_t))) != NULL) {
        /* Retrieve message info */
        from = msg->from->parsed;
        to = msg->to->parsed;
        contact = msg->contact->parsed;

        /* Init dialog structure */
        memset(dialog, 0, sizeof(dlg_t));

        if (uandd_to_uri(from->parsed_uri.user, from->parsed_uri.host, &dialog->rem_uri) < 0) {
            LM_ERR("failed to construct from uri\n");
            pkg_free(dialog);
            dialog = NULL;
        } else if (uandd_to_uri(to->parsed_uri.user, to->parsed_uri.host, &dialog->loc_uri) < 0) {
            LM_ERR("failed to construct to uri\n");
            pkg_free(dialog->rem_uri.s);
            pkg_free(dialog);
            dialog = NULL;
        } else {
            /* Set From */
            dialog->id.rem_tag = from->tag_value;

            /* Set To*/
            if ((to->tag_value.s == NULL) || (to->tag_value.len == 0)) {
                dialog->id.loc_tag = *tag;
            } else {
                dialog->id.loc_tag = to->tag_value;
            }

            /* Set display names */
            if(osp_tmb.dlg_add_extra(dialog, &(from->display), &(to->display)) < 0) {
                LM_WARN("failed to add display names\n");
            }

            /* Set Call-ID */
            dialog->id.call_id = msg->callid->body;

            /* Set Contact */
            if ((contact->contacts->uri.len == 0) || (contact->contacts->uri.s == NULL)) {
                dialog->rem_target = dialog->rem_uri;
            } else {
                dialog->rem_target = contact->contacts->uri;
            }

            /* Set CSeq */
            dialog->loc_seq.value = 0;
            dialog->loc_seq.is_set = 1;

            /* Set Route */
            if (msg->record_route != NULL) {
                if (print_rr_body(msg->record_route, &record_route, 0, 0, NULL) == 0) {
                    if (parse_rr_body(record_route.s, record_route.len, &dialog->route_set) < 0) {
                        LM_ERR("failed to parse record route\n");
                    }
                }
            }

            /* Set dialog status */
            dialog->state= DLG_CONFIRMED ;

            /* Set send address */
            dialog->send_sock = msg->rcv.bind_address;
        }
    } else {
        LM_ERR("failed to allocate memory\n");
    }

    return dialog;
}

/*
 * Free dialog structure
 * param dialog Dialog structure
 */
static void ospFreeDialog(
    dlg_t* dialog)
{
    if (dialog != NULL) {
        if (dialog->loc_uri.s != NULL) {
            pkg_free(dialog->loc_uri.s);
        }
        if (dialog->rem_uri.s != NULL) {
            pkg_free(dialog->rem_uri.s);
        }
        pkg_free(dialog);
    }
}

/*
 * Generate NOTIFY additional headers
 * param msg SIP message
 * param expire Expires value
 * param contact Contact
 * param headers Extra headers
 * return 0 success, others failure
 */
static int ospExtraHeaders(
    struct sip_msg* msg,
    int expire,
    str* contact,
    str* headers)
{
    int length;
    param_t* param;
    event_t* event;
    str eventid = { NULL, 0 };
    char probuf[OSP_STRBUF_SIZE];
    char statebuf[OSP_STRBUF_SIZE];
    int ret = -1;

    event = msg->event->parsed;
    param = event->params;
    while (param) {
        if ((param->name.len == 2) && (strncasecmp(param->name.s, "id", 2) == 0)) {
            eventid = param->body;
            break;
        }
        param= param->next;
    }

    probuf[0] = '\0';
    if (msg->rcv.proto != PROTO_UDP) {
        memcpy(probuf, ";transport=", 11);
        if (proto2str(msg->rcv.proto, probuf+ 11) == 0) {
            probuf[0] = '\0';
        }
    }

    if (expire > 0) {
        snprintf(statebuf, sizeof(statebuf), "active;expires=%ud", expire);
    } else {
        snprintf(statebuf, sizeof(statebuf), "terminated;reason=timeout");
    }

    if ((headers->s != NULL) && (headers->len > 0)) {
        length = snprintf(headers->s, headers->len,
            "Expires: %ud\r\nEvent: %.*s;id=%.*s\r\nContact: <%.*s%s>\r\nSubscription-State: %s\r\n%s\r\nContent-Type: %s\r\n",
            expire,
            event->text.len, event->text.s, eventid.len, eventid.s, 
            contact->len, contact->s, probuf,
            statebuf,
            _osp_extraheaders_value,
            "application/calling-name-info");
        headers->len = length;
        ret = 0;
    } else {
        LM_WARN("wrong parameter\n");
    }

    return ret;
}

/*
 * Callback function for NOTIFY
 * param t
 * param type
 * param ps
 */
static void ospNotifyCallback(
    struct cell* t,
    int type,
    struct tmcb_params *ps)
{
    LM_DBG("NOTIFY finished with code '%d'\n", ps->code);
    return;
}

/*
 * Process SUBSCRIBE
 * param msg SIP message
 * param cnamrecord Cached CNAM record
 * param ignore2
 * return MODULE_RETURNCODE_TRUE success, MODULE_RETURNCODE_FALSE failure
 */
int ospProcessSubscribe(
    struct sip_msg* msg,
    str* cnamrecord)
{
    int expire;
    str contact = { NULL, 0 };
    str tag = { NULL, 0 };
    str notify = { "NOTIFY", 6 };
    dlg_t *dialog;
    char buffer[OSP_HEADERBUF_SIZE];
    str headers = { buffer, sizeof(buffer) };
    int result = MODULE_RETURNCODE_FALSE;

    LM_DBG("cnam record '%.*s'\n", cnamrecord->len, cnamrecord->s);
    /* Parse SUBSCRIBE */
    if (ospParseSubscribe(msg) == 0) {
        expire = 0;
        if (msg->expires != NULL) {
            expire = ((exp_body_t*)msg->expires->parsed)->val;
        }

        if (get_local_contact(msg->rcv.bind_address, NULL, &contact) < 0) {
            LM_WARN("failed to get contact\n");
        }

        /* Send 200 OK reply */
        if (ospReply200(msg, expire, &contact, &tag) == 0) {
            /* Create dialog */
            if ((dialog = ospCreateDialog(msg, &tag)) != NULL) {
                /* Generate extra headers */
                if (ospExtraHeaders(msg, expire, &contact, &headers) == 0) {
                    /* Send NOTIFY */
                    if (osp_tmb.t_request_within(&notify, &headers, cnamrecord, dialog, ospNotifyCallback, NULL, NULL) < 0) {
                        LM_ERR("failed to send notify\n");
                    } else {
                       result = MODULE_RETURNCODE_TRUE;
                    }
                } else {
                    LM_ERR("failed to generate extre headers\n");
                }
            } else {
                LM_ERR("failed to create dialog\n");
            }
            ospFreeDialog(dialog);
        } else {
            LM_ERR("failed to send ok\n");
        }
    } else {
        LM_ERR("failed to parse subscribe\n");
    }

    return result;
}
