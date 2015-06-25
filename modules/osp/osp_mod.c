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
 *
 * History:
 * ---------
 *  2006-03-13  RR functions are loaded via API function (bogdan)
 */

#include <osp/osp.h>
#include "../../sr_module.h"
#include "../rr/api.h"
#include "../auth/api.h"
#include "osp_mod.h"
#include "destination.h"
#include "orig_transaction.h"
#include "term_transaction.h"
#include "usage.h"
#include "tm.h"
#include "provider.h"

extern int _osp_work_mode;
extern int _osp_service_type;
extern unsigned int _osp_sp_number;
extern char* _osp_sp_uris[];
extern unsigned long _osp_sp_weights[];
extern char* _osp_device_ip;
extern char _osp_in_device[OSP_STRBUF_SIZE];
extern char _osp_out_device[OSP_STRBUF_SIZE];
extern int _osp_use_security;
extern char* _osp_private_key;
extern char* _osp_local_certificate;
extern char* _osp_ca_certificate;
extern int _osp_crypto_hw;
extern int _osp_validate_callid;
extern int _osp_token_format;
extern int _osp_ssl_lifetime;
extern int _osp_persistence;
extern int _osp_retry_delay;
extern int _osp_retry_limit;
extern int _osp_timeout;
extern int _osp_non_sip;
extern int _osp_max_dests;
extern int _osp_report_nid;
extern int _osp_use_np;
extern int _osp_append_userphone;
extern int _osp_dnid_location;
extern char* _osp_dnid_param;
extern int _osp_paramstr_location;
extern char* _osp_paramstr_value;
extern char _osp_PRIVATE_KEY[];
extern char _osp_LOCAL_CERTIFICATE[];
extern char _osp_CA_CERTIFICATE[];
extern char* _osp_srcdev_avp;
extern int _osp_srcdev_avpid;
extern unsigned short _osp_srcdev_avptype;
extern char* _osp_snid_avp;
extern int _osp_snid_avpid;
extern unsigned short _osp_snid_avptype;
extern char* _osp_cinfo_avp;
extern int _osp_cinfo_avpid;
extern unsigned short _osp_cinfo_avptype;
extern OSPTPROVHANDLE _osp_provider;

struct rr_binds osp_rr;
auth_api_t osp_auth;
int osp_index[OSP_DEF_SPS];

static int ospInitMod(void);
static void ospDestMod(void);
static int ospInitChild(int);
static int  ospVerifyParameters(void);
static void ospDumpParameters(void);

static cmd_export_t cmds[]={
    { "checkospheader",           (cmd_function)ospCheckHeader,           0, 0, 0, REQUEST_ROUTE|FAILURE_ROUTE },
    { "validateospheader",        (cmd_function)ospValidateHeader,        0, 0, 0, REQUEST_ROUTE|FAILURE_ROUTE },
    { "requestosprouting",        (cmd_function)ospRequestRouting,        0, 0, 0, REQUEST_ROUTE|FAILURE_ROUTE },
    { "checkosproute",            (cmd_function)ospCheckRoute,            0, 0, 0, REQUEST_ROUTE|FAILURE_ROUTE },
    { "prepareosproute",          (cmd_function)ospPrepareRoute,          0, 0, 0, BRANCH_ROUTE },
    { "prepareredirectosproutes", (cmd_function)ospPrepareRedirectRoutes, 0, 0, 0, REQUEST_ROUTE|FAILURE_ROUTE },
    { "prepareallosproutes",      (cmd_function)ospPrepareAllRoutes,      0, 0, 0, REQUEST_ROUTE|FAILURE_ROUTE },
    { "checkcallingtranslation",  (cmd_function)ospCheckCalling,          0, 0, 0, BRANCH_ROUTE },
    { "reportospusage",           (cmd_function)ospReportUsage,           1, 0, 0, REQUEST_ROUTE },
    { 0, 0, 0, 0, 0, 0 }
};

static param_export_t params[]={
    { "work_mode",                        INT_PARAM, &_osp_work_mode },
    { "service_type",                     INT_PARAM, &_osp_service_type },
    { "sp1_uri",                          STR_PARAM, &_osp_sp_uris[0] },
    { "sp2_uri",                          STR_PARAM, &_osp_sp_uris[1] },
    { "sp3_uri",                          STR_PARAM, &_osp_sp_uris[2] },
    { "sp4_uri",                          STR_PARAM, &_osp_sp_uris[3] },
    { "sp5_uri",                          STR_PARAM, &_osp_sp_uris[4] },
    { "sp6_uri",                          STR_PARAM, &_osp_sp_uris[5] },
    { "sp7_uri",                          STR_PARAM, &_osp_sp_uris[6] },
    { "sp8_uri",                          STR_PARAM, &_osp_sp_uris[7] },
    { "sp9_uri",                          STR_PARAM, &_osp_sp_uris[8] },
    { "sp10_uri",                         STR_PARAM, &_osp_sp_uris[9] },
    { "sp11_uri",                         STR_PARAM, &_osp_sp_uris[10] },
    { "sp12_uri",                         STR_PARAM, &_osp_sp_uris[11] },
    { "sp13_uri",                         STR_PARAM, &_osp_sp_uris[12] },
    { "sp14_uri",                         STR_PARAM, &_osp_sp_uris[13] },
    { "sp15_uri",                         STR_PARAM, &_osp_sp_uris[14] },
    { "sp16_uri",                         STR_PARAM, &_osp_sp_uris[15] },
    { "sp1_weight",                       INT_PARAM, &_osp_sp_weights[0] },
    { "sp2_weight",                       INT_PARAM, &_osp_sp_weights[1] },
    { "sp3_weight",                       INT_PARAM, &_osp_sp_weights[2] },
    { "sp4_weight",                       INT_PARAM, &_osp_sp_weights[3] },
    { "sp5_weight",                       INT_PARAM, &_osp_sp_weights[4] },
    { "sp6_weight",                       INT_PARAM, &_osp_sp_weights[5] },
    { "sp7_weight",                       INT_PARAM, &_osp_sp_weights[6] },
    { "sp8_weight",                       INT_PARAM, &_osp_sp_weights[7] },
    { "sp9_weight",                       INT_PARAM, &_osp_sp_weights[8] },
    { "sp10_weight",                      INT_PARAM, &_osp_sp_weights[9] },
    { "sp11_weight",                      INT_PARAM, &_osp_sp_weights[10] },
    { "sp12_weight",                      INT_PARAM, &_osp_sp_weights[11] },
    { "sp13_weight",                      INT_PARAM, &_osp_sp_weights[12] },
    { "sp14_weight",                      INT_PARAM, &_osp_sp_weights[13] },
    { "sp15_weight",                      INT_PARAM, &_osp_sp_weights[14] },
    { "sp16_weight",                      INT_PARAM, &_osp_sp_weights[15] },
    { "device_ip",                        STR_PARAM, &_osp_device_ip },
    { "use_security_features",            INT_PARAM, &_osp_use_security },
    { "private_key",                      STR_PARAM, &_osp_private_key },
    { "local_certificate",                STR_PARAM, &_osp_local_certificate },
    { "ca_certificates",                  STR_PARAM, &_osp_ca_certificate },
    { "enable_crypto_hardware_support",   INT_PARAM, &_osp_crypto_hw },
    { "validate_callid",                  INT_PARAM, &_osp_validate_callid },
    { "token_format",                     INT_PARAM, &_osp_token_format },
    { "ssl_lifetime",                     INT_PARAM, &_osp_ssl_lifetime },
    { "persistence",                      INT_PARAM, &_osp_persistence },
    { "retry_delay",                      INT_PARAM, &_osp_retry_delay },
    { "retry_limit",                      INT_PARAM, &_osp_retry_limit },
    { "timeout",                          INT_PARAM, &_osp_timeout },
    { "support_nonsip_protocol",          INT_PARAM, &_osp_non_sip },
    { "max_destinations",                 INT_PARAM, &_osp_max_dests },
    { "report_networkid",                 INT_PARAM, &_osp_report_nid },
    { "use_number_portability",           INT_PARAM, &_osp_use_np },
    { "append_userphone",                 INT_PARAM, &_osp_append_userphone },
    { "networkid_location",               INT_PARAM, &_osp_dnid_location},
    { "networkid_parameter",              STR_PARAM, &_osp_dnid_param },
    { "parameterstring_location",         INT_PARAM, &_osp_paramstr_location},
    { "parameterstring_value",            STR_PARAM, &_osp_paramstr_value },
    { "source_device_avp",                STR_PARAM, &_osp_srcdev_avp },
    { "source_networkid_avp",             STR_PARAM, &_osp_snid_avp },
    { "custom_info_avp",                  STR_PARAM, &_osp_cinfo_avp },
    { 0,0,0 }
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "rr",   DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "tm",   DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "auth", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
    "osp",
    MOD_TYPE_DEFAULT,   /* class of this module */
    MODULE_VERSION,     /* module version */
    DEFAULT_DLFLAGS,    /* dlopen flags */
    &deps,              /* OpenSIPS module dependencies */
    cmds,               /* exported functions */
    0,                  /* exported async functions */
    params,             /* exported params */
    0,                  /* exported statistics */
    0,                  /* exported MI functions */
    0,                  /* exported pseudo-variables */
    0,                  /* extra processes */
    ospInitMod,         /* module initialization function */
    0,                  /* response function*/
    ospDestMod,         /* destroy function */
    ospInitChild,       /* per-child init function */
};

/*
 * Initialize OSP module
 * return 0 success, -1 failure
 */
static int ospInitMod(void)
{
    bind_auth_t bind_auth;

    LM_INFO("initializing...\n");

    if (ospVerifyParameters() != 0) {
        /* At least one parameter incorrect -> error */
        return -1;
    }

    /* Load the RR API */
    if (load_rr_api(&osp_rr) != 0) {
        LM_WARN("failed to load the RR API. Check if you load the rr module\n");
        LM_WARN("add_rr_param is required for reporting duration for OSP transactions\n");
        memset(&osp_rr, 0, sizeof(osp_rr));
    }

    /* Load the AUTH API */
    bind_auth = (bind_auth_t)find_export("bind_auth", 0, 0);
    if ((bind_auth == NULL) || (bind_auth(&osp_auth) != 0)) {
        LM_WARN("failed to load the AUTH API. Check if you load the auth module.\n");
        LM_WARN("rpid_avp & rpid_avp_type is required for calling number translation\n");
        memset(&osp_auth, 0, sizeof(osp_auth));
    }

    if (ospInitTm() != 0) {
        return -1;
    }

    if(ospParseAvps() != 0) {
        return -1;
    }

    /* everything is fine, initialization done */
    return 0;
}

/*
 * Destrroy OSP module
 */
static void ospDestMod(void)
{
}

/*
 * Initializeild process of OSP module
 * param rank
 * return 0 success, -1 failure
 */
static int ospInitChild(
    int rank)
{
    int code = -1;

    code = ospSetupProvider();

    LM_DBG("provider '%d' (%d)\n", _osp_provider, code);

    return 0;
}

/*
 * Verify parameters for OSP module
 * return 0 success, -1 failure
 */
static int ospVerifyParameters(void)
{
    int i;
    pv_spec_t avp_spec;
    str avp_str;
    char hostname[OSP_STRBUF_SIZE];
    int result = 0;

    if ((_osp_work_mode < 0) || (_osp_work_mode > 1)) {
        _osp_work_mode = OSP_DEF_MODE;
        LM_WARN("work mode is out of range, reset to %d\n", OSP_DEF_MODE);
    }

    if ((_osp_service_type < 0) || (_osp_service_type > 1)) {
        _osp_service_type = OSP_DEF_SERVICE;
        LM_WARN("service type is out of range, reset to %d\n", OSP_DEF_SERVICE);
    }

    /* If use_security_features is 0, ignroe the certificate files */
    if (_osp_use_security != 0) {
        /* Default location for the cert files is in the compile time variable CFG_DIR */
        if (_osp_private_key == NULL) {
            sprintf(_osp_PRIVATE_KEY, "%spkey.pem", CFG_DIR);
            _osp_private_key = _osp_PRIVATE_KEY;
        }

        if (_osp_local_certificate == NULL) {
            sprintf(_osp_LOCAL_CERTIFICATE, "%slocalcert.pem", CFG_DIR);
            _osp_local_certificate = _osp_LOCAL_CERTIFICATE;
        }

        if (_osp_ca_certificate == NULL) {
            sprintf(_osp_CA_CERTIFICATE, "%scacert_0.pem", CFG_DIR);
            _osp_ca_certificate = _osp_CA_CERTIFICATE;
        }
    }

    if (_osp_device_ip == NULL) {
        gethostname(hostname, sizeof(hostname));
        _osp_device_ip = hostname;
    }
    ospConvertToOutAddress(_osp_device_ip, _osp_out_device, sizeof(_osp_out_device));
    ospConvertToInAddress(_osp_device_ip, _osp_in_device, sizeof(_osp_in_device));

    if (_osp_max_dests > OSP_DEF_DESTS || _osp_max_dests < 1) {
        _osp_max_dests = OSP_DEF_DESTS;
        LM_WARN("max_destinations is out of range, reset to %d\n", OSP_DEF_DESTS);
    }

    if (_osp_report_nid < 0 || _osp_report_nid > 3) {
        _osp_report_nid = OSP_DEF_REPORTNID;
        LM_WARN("report_networkid is out of range, reset to %d\n", OSP_DEF_REPORTNID);
    }

    if (_osp_token_format < 0 || _osp_token_format > 2) {
        _osp_token_format = OSP_DEF_TOKEN;
        LM_WARN("token_format is out of range, reset to %d\n", OSP_DEF_TOKEN);
    }

    _osp_sp_number = 0;
    for (i = 0; i < OSP_DEF_SPS; i++) {
        if (_osp_sp_uris[i] != NULL) {
            if (_osp_sp_number != i) {
                _osp_sp_uris[_osp_sp_number] = _osp_sp_uris[i];
                _osp_sp_weights[_osp_sp_number] = _osp_sp_weights[i];
                _osp_sp_uris[i] = NULL;
                _osp_sp_weights[i] = OSP_DEF_WEIGHT;
            }
            osp_index[_osp_sp_number] = i + 1;
            _osp_sp_number++;
        }
    }

    if (_osp_sp_number == 0) {
        LM_ERR("at least one service point uri must be configured\n");
        result = -1;
    }

    if ((_osp_dnid_location < 0) || (_osp_dnid_location > 2)) {
        _osp_dnid_location = OSP_DEF_DNIDLOC;
        LM_WARN("networkid_location is out of range, reset to %d\n", OSP_DEF_DNIDLOC);
    }

    if (!(_osp_dnid_param && *_osp_dnid_param)) {
        _osp_dnid_param = OSP_DEF_DNIDPARAM;
    }

    if ((_osp_paramstr_location < 0) || (_osp_paramstr_location > 2)) {
        _osp_paramstr_location = OSP_DEF_PARAMSTRLOC;
        LM_WARN("parameterstring_location is out of range, reset to %d\n", OSP_DEF_PARAMSTRLOC);
    }

    if (!(_osp_paramstr_value && *_osp_paramstr_value)) {
        _osp_paramstr_value = OSP_DEF_PARAMSTRVAL;
    }

    if ((_osp_work_mode == 1) && _osp_srcdev_avp && *_osp_srcdev_avp) {
        avp_str.s = _osp_srcdev_avp;
        avp_str.len = strlen(_osp_srcdev_avp);
        if ((pv_parse_spec(&avp_str, &avp_spec) == NULL) ||
            avp_spec.type != PVT_AVP ||
            pv_get_avp_name(0, &(avp_spec.pvp), &_osp_srcdev_avpid, &_osp_srcdev_avptype) != 0)
        {
            LM_WARN("'%s' invalid AVP definition\n", _osp_srcdev_avp);
            _osp_srcdev_avpid = OSP_DEF_AVP;
            _osp_srcdev_avptype = 0;
        }
    } else {
        _osp_srcdev_avpid = OSP_DEF_AVP;
        _osp_srcdev_avptype = 0;
    }

    if (_osp_snid_avp && *_osp_snid_avp) {
        avp_str.s = _osp_snid_avp;
        avp_str.len = strlen(_osp_snid_avp);
        if (pv_parse_spec(&avp_str, &avp_spec) == NULL ||
            avp_spec.type != PVT_AVP ||
            pv_get_avp_name(0, &(avp_spec.pvp), &_osp_snid_avpid, &_osp_snid_avptype) != 0)
        {
            LM_WARN("'%s' invalid AVP definition\n", _osp_snid_avp);
            _osp_snid_avpid = OSP_DEF_AVP;
            _osp_snid_avptype = 0;
        }
    } else {
        _osp_snid_avpid = OSP_DEF_AVP;
        _osp_snid_avptype = 0;
    }

    if (_osp_cinfo_avp && *_osp_cinfo_avp) {
        avp_str.s = _osp_cinfo_avp;
        avp_str.len = strlen(_osp_cinfo_avp);
        if (pv_parse_spec(&avp_str, &avp_spec) == NULL ||
            avp_spec.type != PVT_AVP ||
            pv_get_avp_name(0, &(avp_spec.pvp), &_osp_cinfo_avpid, &_osp_cinfo_avptype) != 0)
        {
            LM_WARN("'%s' invalid AVP definition\n", _osp_cinfo_avp);
            _osp_cinfo_avpid = OSP_DEF_AVP;
            _osp_cinfo_avptype = 0;
        }
    } else {
        _osp_cinfo_avpid = OSP_DEF_AVP;
        _osp_cinfo_avptype = 0;
    }

    ospDumpParameters();

    return result;
}

/*
 * Dump OSP module configuration
 */
static void ospDumpParameters(void)
{
    int i;

    LM_INFO("module configuration: ");
    LM_INFO("    work mode '%d'", _osp_work_mode);
    LM_INFO("    service type '%d'", _osp_service_type);
    LM_INFO("    number of service points '%d'", _osp_sp_number);
    for (i = 0; i < _osp_sp_number; i++) {
        LM_INFO("    sp%d_uri '%s' sp%d_weight '%ld' ",
            osp_index[i], _osp_sp_uris[i], osp_index[i], _osp_sp_weights[i]);
    }
    LM_INFO("    device_ip '%s' ", _osp_in_device);
    LM_INFO("    use_security_features '%d' ", _osp_use_security);
    if (_osp_use_security != 0) {
        LM_INFO("    private_key '%s' ", _osp_private_key);
        LM_INFO("    local_certificate '%s' ", _osp_local_certificate);
        LM_INFO("    ca_certificates '%s' ", _osp_ca_certificate);
    }
    LM_INFO("    enable_crypto_hardware_support '%d' ", _osp_crypto_hw);
    LM_INFO("    token_format '%d' ", _osp_token_format);
    LM_INFO("    ssl_lifetime '%d' ", _osp_ssl_lifetime);
    LM_INFO("    persistence '%d' ", _osp_persistence);
    LM_INFO("    retry_delay '%d' ", _osp_retry_delay);
    LM_INFO("    retry_limit '%d' ", _osp_retry_limit);
    LM_INFO("    timeout '%d' ", _osp_timeout);
    LM_INFO("    validate_call_id '%d' ", _osp_validate_callid);
    LM_INFO("    use_number_portability '%d' ", _osp_use_np);
    LM_INFO("    append_userphone '%d' ", _osp_append_userphone);
    LM_INFO("    networkid_location '%d' ", _osp_dnid_location);
    LM_INFO("    networkid_parameter '%s' ", _osp_dnid_param);
    LM_INFO("    parameterstring_location '%d' ", _osp_paramstr_location);
    LM_INFO("    parameterstring_value '%s' ", _osp_paramstr_value);
    LM_INFO("    max_destinations '%d'\n", _osp_max_dests);
    LM_INFO("    report_networkid '%d'\n", _osp_report_nid);
    LM_INFO("    support_nonsip_protocol '%d'\n", _osp_non_sip);
    LM_INFO("    source device IP AVP ID '%d'\n", _osp_srcdev_avpid);
    LM_INFO("    source network ID AVP ID '%d'\n", _osp_snid_avpid);
    LM_INFO("    custom info AVP ID '%d'\n", _osp_cinfo_avpid);
}

