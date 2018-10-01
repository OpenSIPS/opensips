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

#ifndef _OSP_MOD_H_
#define _OSP_MOD_H_

#define MODULE_RETURNCODE_TRUE          1
#define MODULE_RETURNCODE_STOPROUTE     0
#define MODULE_RETURNCODE_FALSE         -1
#define MODULE_RETURNCODE_ERROR         -2

#define OSP_DEF_AVP                     -1
#define OSP_DEF_HW                      0
#define OSP_DEF_CALLID                  1   /* Validate call ids, set to 0 to disable */
#define OSP_DEF_SSLLIFE                 300
#define OSP_DEF_PERSISTENCE             60
#define OSP_DEF_DELAY                   0
#define OSP_DEF_RETRY                   2
#define OSP_DEF_TIMEOUT                 (60 * 1000)
#define OSP_DEF_MODE                    0
#define OSP_DEF_SERVICE                 0
#define OSP_DEF_SPS                     16
#define OSP_DEF_WEIGHT                  1000
#define OSP_DEF_USESEC                  0
#define OSP_DEF_TOKEN                   2
#define OSP_DEF_NONSIP                  0
#define OSP_DEF_DESTS                   12
#define OSP_DEF_REPORTNID               3
#define OSP_DEF_USENP                   1
#define OSP_DEF_EXPORTNP                0
#define OSP_DEF_USERPHONE               0
#define OSP_DEF_DNIDLOC                 2
#define OSP_DEF_DNIDPARAM               "networkid"
#define OSP_DEF_SWIDLOC                 2
#define OSP_DEF_SWIDPARAM               "switchid"
#define OSP_DEF_PARAMSTRLOC             0
#define OSP_DEF_PARAMSTRVAL             ""
#define OSP_DEF_SRCIPAVP                "$avp(_osp_source_device_)"
#define OSP_DEF_SNIDAVP                 "$avp(_osp_source_networkid_)"
#define OSP_DEF_SWIDAVP                 "$avp(_osp_source_switchid_)"
#define OSP_DEF_CINFONUM                 8
#define OSP_DEF_CINFOAVP                "$avp(_osp_custom_info_)"
#define OSP_DEF_CNAMAVP                 "$avp(_osp_cnam_)"
#define OSP_DEF_EXTHEADERVAL            ""
#define OSP_DEF_SRCMEDIAAVP             "$avp(_osp_source_media_address_)"
#define OSP_DEF_DESTMEDIAAVP            "$avp(_osp_destination_media_address_)"
#define OSP_DEF_REQDATEAVP              "$avp(_osp_request_date_)"
#define OSP_DEF_SDPFPNUM                4
#define OSP_DEF_SDPFPAVP                "$avp(_osp_sdp_fingerprint_)"
#define OSP_DEF_IDENTITYAVP             "$avp(_osp_identity_)"
#define OSP_DEF_SPAVP                   "$avp(_osp_service_provider_)"
#define OSP_DEF_USERGROUPAVP            "$avp(_osp_user_group_)"
#define OSP_DEF_USERIDAVP               "$avp(_osp_user_id_)"
#define OSP_DEF_DESTAVP                 "$avp(_osp_destination_)"
#define OSP_DEF_REASONTYPEAVP           "$avp(_osp_reason_type_)"
#define OSP_DEF_REASONCAUSEAVP          "$avp(_osp_reason_cause_)"
#define OSP_DEF_REASONTEXTAVP           "$avp(_osp_reason_text_)"

#define OSP_STRBUF_SIZE                 256
#define OSP_KEYBUF_SIZE                 1024
#define OSP_TOKENBUF_SIZE               2048
#define OSP_HEADERBUF_SIZE              4096

#endif /* _OSP_MOD_H_ */

