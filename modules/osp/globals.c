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

#include <stdio.h>
#include <osp/osp.h>
#include "../../usr_avp.h"
#include "osp_mod.h"

int _osp_inbound_avpid = OSP_DEF_AVP;
int _osp_origdest_avpid = OSP_DEF_AVP;
int _osp_termdest_avpid = OSP_DEF_AVP;
int _osp_calling_avpid = OSP_DEF_AVP;
int _osp_crypto_hw = OSP_DEF_HW;
int _osp_validate_callid = OSP_DEF_CALLID;
int _osp_ssl_lifetime = OSP_DEF_SSLLIFE;
int _osp_persistence = OSP_DEF_PERSISTENCE;
int _osp_retry_delay = OSP_DEF_DELAY;
int _osp_retry_limit = OSP_DEF_RETRY;
int _osp_timeout = OSP_DEF_TIMEOUT;
int _osp_work_mode = OSP_DEF_MODE;
int _osp_service_type = OSP_DEF_SERVICE;
unsigned int _osp_sp_number;
char* _osp_sp_uris[OSP_DEF_SPS];
unsigned long _osp_sp_weights[OSP_DEF_SPS] = {
    OSP_DEF_WEIGHT, OSP_DEF_WEIGHT, OSP_DEF_WEIGHT, OSP_DEF_WEIGHT,
    OSP_DEF_WEIGHT, OSP_DEF_WEIGHT, OSP_DEF_WEIGHT, OSP_DEF_WEIGHT,
    OSP_DEF_WEIGHT, OSP_DEF_WEIGHT, OSP_DEF_WEIGHT, OSP_DEF_WEIGHT,
    OSP_DEF_WEIGHT, OSP_DEF_WEIGHT, OSP_DEF_WEIGHT, OSP_DEF_WEIGHT
};
char* _osp_device_ip = NULL;
char _osp_in_device[OSP_STRBUF_SIZE];
char _osp_out_device[OSP_STRBUF_SIZE];
int _osp_use_security = OSP_DEF_USESEC;
int _osp_token_format = OSP_DEF_TOKEN;
char* _osp_private_key = NULL;
char* _osp_local_certificate = NULL;
char* _osp_ca_certificate = NULL;
int _osp_non_sip = OSP_DEF_NONSIP;
int _osp_max_dests = OSP_DEF_DESTS;
int _osp_report_nid = OSP_DEF_REPORTNID;
int _osp_use_np = OSP_DEF_USENP;
int _osp_export_np = OSP_DEF_EXPORTNP;
int _osp_append_userphone = OSP_DEF_USERPHONE;
int _osp_dnid_location = OSP_DEF_DNIDLOC;
char* _osp_dnid_param = OSP_DEF_DNIDPARAM;
int _osp_swid_location = OSP_DEF_SWIDLOC;
char* _osp_swid_param = OSP_DEF_SWIDPARAM;
int _osp_paramstr_location = OSP_DEF_PARAMSTRLOC;
char* _osp_paramstr_value = OSP_DEF_PARAMSTRVAL;
char _osp_PRIVATE_KEY[OSP_STRBUF_SIZE];
char _osp_LOCAL_CERTIFICATE[OSP_STRBUF_SIZE];
char _osp_CA_CERTIFICATE[OSP_STRBUF_SIZE];
char* _osp_srcdev_avp = OSP_DEF_SNIDAVP;
int_str _osp_srcdev_avpid;
unsigned short _osp_srcdev_avptype;
char* _osp_snid_avp = OSP_DEF_SNIDAVP;
int_str _osp_snid_avpid;
unsigned short _osp_snid_avptype;
char* _osp_swid_avp = OSP_DEF_SWIDAVP;
int_str _osp_swid_avpid;
unsigned short _osp_swid_avptype;
char* _osp_cinfo_avp = OSP_DEF_CINFOAVP;
int_str _osp_cinfo_avpid;
unsigned short _osp_cinfo_avptype;
char* _osp_cnam_avp = OSP_DEF_CNAMAVP;
int_str _osp_cnam_avpid;
unsigned short _osp_cnam_avptype;
char* _osp_extraheaders_value = OSP_DEF_EXTHEADERVAL;
char* _osp_srcmedia_avp = OSP_DEF_SRCMEDIAAVP;
int_str _osp_srcmedia_avpid;
unsigned short _osp_srcmedia_avptype;
char* _osp_destmedia_avp = OSP_DEF_DESTMEDIAAVP;
int_str _osp_destmedia_avpid;
unsigned short _osp_destmedia_avptype;
char* _osp_reqdate_avp = OSP_DEF_REQDATEAVP;
int_str _osp_reqdate_avpid;
unsigned short _osp_reqdate_avptype;
char* _osp_sdpfp_avp = OSP_DEF_SDPFPAVP;
int_str _osp_sdpfp_avpid;
unsigned short _osp_sdpfp_avptype;
char* _osp_identity_avp = OSP_DEF_IDENTITYAVP;
int_str _osp_identity_avpid;
unsigned short _osp_identity_avptype;
char* _osp_sp_avp = OSP_DEF_SPAVP;
int_str _osp_sp_avpid;
unsigned short _osp_sp_avptype;
char* _osp_usergroup_avp = OSP_DEF_USERGROUPAVP;
int_str _osp_usergroup_avpid;
unsigned short _osp_usergroup_avptype;
char* _osp_userid_avp = OSP_DEF_USERIDAVP;
int_str _osp_userid_avpid;
unsigned short _osp_userid_avptype;
char* _osp_dest_avp = OSP_DEF_DESTAVP;
int_str _osp_dest_avpid;
unsigned short _osp_dest_avptype;
char* _osp_reasontype_avp = OSP_DEF_REASONTYPEAVP;
int_str _osp_reasontype_avpid;
unsigned short _osp_reasontype_avptype;
char* _osp_reasoncause_avp = OSP_DEF_REASONCAUSEAVP;
int_str _osp_reasoncause_avpid;
unsigned short _osp_reasoncause_avptype;
char* _osp_reasontext_avp = OSP_DEF_REASONTEXTAVP;
int_str _osp_reasontext_avpid;
unsigned short _osp_reasontext_avptype;
OSPTPROVHANDLE _osp_provider = -1;

