/*
 * Web3 Authentication Extension Module
 *
 * Copyright (C) 2025 Jonathan Kandel
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include "../../core/sr_module.h"
#include "../../core/dprint.h"
#include "../../core/error.h"
#include "../../modules/auth/api.h"
#include "../../core/mod_fix.h"
#include "../../core/kemi.h"
#include "web3_auth_ext_mod.h"
#include "web3_auth.h"
#include "api.h"
#include "keccak256.h"

MODULE_VERSION

/* Default Web3 configuration */
#define DEFAULT_WEB3_RPC_URL "https://testnet.sapphire.oasis.dev"
#define DEFAULT_WEB3_CONTRACT_ADDRESS "0xE773BB79689379d32Ad1Db839868b6756B493aea"
#define DEFAULT_ENS_REGISTRY_ADDRESS "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
#define DEFAULT_ENS_NAME_WRAPPER_ADDRESS "0x0635513f179D50A207757E05759CbD106d7dFcE8"
#define DEFAULT_ENS_RPC_URL "https://ethereum-sepolia-rpc.publicnode.com"  // Sepolia testnet for ENS

/*
 * Module destroy function prototype
 */
static void destroy(void);

/*
 * Module initialization function prototype
 */
static int mod_init(void);

/*
 * Child initialization function prototype
 */
static int child_init(int rank);

/*
 * Configuration initialization from environment variables
 */
static void init_config_from_env(void);

/* Module parameters - can be overridden by environment variables */
char *web3_rpc_url = NULL;
char *web3_contract_address = NULL;
char *ens_registry_address = NULL;
char *ens_name_wrapper_address = NULL;
char *ens_rpc_url = NULL;
int web3_debug_mode = 1;
int web3_timeout = 10;

/* Base auth module API */
auth_api_s_t auth_api;

/* Function prototypes for exported functions */
static int w_web3_www_authenticate(struct sip_msg *msg, char *realm, char *method);
static int w_web3_proxy_authenticate(struct sip_msg *msg, char *realm, char *method);
static int fixup_web3_auth(void **param, int param_no);

/* API binding function */
int bind_web3_auth(web3_auth_api_t *api);

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
    {"web3_www_authenticate", (cmd_function)w_web3_www_authenticate, 2,
        fixup_web3_auth, 0, REQUEST_ROUTE},
    {"web3_proxy_authenticate", (cmd_function)w_web3_proxy_authenticate, 2,
        fixup_web3_auth, 0, REQUEST_ROUTE},
    {"bind_web3_auth", (cmd_function)bind_web3_auth, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
    {"web3_rpc_url", PARAM_STRING, &web3_rpc_url},
    {"web3_contract_address", PARAM_STRING, &web3_contract_address},
    {"ens_registry_address", PARAM_STRING, &ens_registry_address},
    {"ens_name_wrapper_address", PARAM_STRING, &ens_name_wrapper_address},
    {"ens_rpc_url", PARAM_STRING, &ens_rpc_url},
    {"web3_debug_mode", PARAM_INT, &web3_debug_mode},
    {"web3_timeout", PARAM_INT, &web3_timeout},
    {0, 0, 0}
};

/*
 * Module interface
 */
struct module_exports exports = {
    "web3_auth_ext",    /* module name */
    DEFAULT_DLFLAGS,    /* dlopen flags */
    cmds,               /* exported functions */
    params,             /* exported parameters */
    0,                  /* RPC methods */
    0,                  /* pseudo-variables exports */
    0,                  /* response function */
    mod_init,           /* module initialization function */
    child_init,         /* child initialization function */
    destroy             /* destroy function */
};

/*
 * Module initialization function
 */
static int mod_init(void)
{
    LM_INFO("Web3 Authentication Extension module initializing\n");

    /* Load the base auth module API */
    bind_auth_s_t bind_auth;
    bind_auth = (bind_auth_s_t)find_export("bind_auth_s", 0, 0);
    if (bind_auth == 0) {
        LM_ERR("cannot find bind_auth_s\n");
        return -1;
    }
    if (bind_auth(&auth_api) < 0) {
        LM_ERR("cannot bind auth api\n");
        return -1;
    }

    /* Initialize curl globally */
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LM_ERR("failed to initialize curl globally\n");
        return -1;
    }

    /* Initialize configuration from environment variables */
    init_config_from_env();

    if (web3_debug_mode) {
        LM_INFO("Web3Auth Extension initialized:\n");
        LM_INFO("  RPC URL: %s\n", web3_rpc_url ? web3_rpc_url : "(using default)");
        LM_INFO("  Contract: %s\n", web3_contract_address ? web3_contract_address : "(using default)");
        LM_INFO("  ENS Registry: %s\n", ens_registry_address ? ens_registry_address : "(using default)");
        LM_INFO("  ENS Name Wrapper: %s\n", ens_name_wrapper_address ? ens_name_wrapper_address : "(using default)");
        LM_INFO("  ENS RPC URL: %s\n", ens_rpc_url ? ens_rpc_url : "(using default)");
        LM_INFO("  Debug: %s\n", web3_debug_mode ? "enabled" : "disabled");
        LM_INFO("  Timeout: %d seconds\n", web3_timeout);
    }

    return 0;
}

/*
 * Child initialization function
 */
static int child_init(int rank)
{
    if (web3_debug_mode) {
        LM_INFO("Web3Auth Extension child %d initialized\n", rank);
    }
    return 0;
}

/*
 * Module destroy function
 */
static void destroy(void)
{
    LM_INFO("Web3 Authentication Extension module shutting down\n");
    
    /* Cleanup curl */
    curl_global_cleanup();
}

/*
 * Configuration initialization from environment variables
 */
static void init_config_from_env(void)
{
    char *env_web3_rpc_url = getenv("WEB3_RPC_URL");
    if (env_web3_rpc_url) {
        web3_rpc_url = strdup(env_web3_rpc_url);
        if (!web3_rpc_url) {
            LM_ERR("failed to allocate memory for web3_rpc_url\n");
            web3_rpc_url = DEFAULT_WEB3_RPC_URL;
        }
    } else {
        web3_rpc_url = DEFAULT_WEB3_RPC_URL;
    }

    char *env_web3_contract_address = getenv("WEB3_CONTRACT_ADDRESS");
    if (env_web3_contract_address) {
        web3_contract_address = strdup(env_web3_contract_address);
        if (!web3_contract_address) {
            LM_ERR("failed to allocate memory for web3_contract_address\n");
            web3_contract_address = DEFAULT_WEB3_CONTRACT_ADDRESS;
        }
    } else {
        web3_contract_address = DEFAULT_WEB3_CONTRACT_ADDRESS;
    }

    char *env_ens_registry_address = getenv("ENS_REGISTRY_ADDRESS");
    if (env_ens_registry_address) {
        ens_registry_address = strdup(env_ens_registry_address);
        if (!ens_registry_address) {
            LM_ERR("failed to allocate memory for ens_registry_address\n");
            ens_registry_address = DEFAULT_ENS_REGISTRY_ADDRESS;
        }
    } else {
        ens_registry_address = DEFAULT_ENS_REGISTRY_ADDRESS;
    }

    char *env_ens_name_wrapper_address = getenv("ENS_NAME_WRAPPER_ADDRESS");
    if (env_ens_name_wrapper_address) {
        ens_name_wrapper_address = strdup(env_ens_name_wrapper_address);
        if (!ens_name_wrapper_address) {
            LM_ERR("failed to allocate memory for ens_name_wrapper_address\n");
            ens_name_wrapper_address = DEFAULT_ENS_NAME_WRAPPER_ADDRESS;
        }
    } else {
        ens_name_wrapper_address = DEFAULT_ENS_NAME_WRAPPER_ADDRESS;
    }

    char *env_ens_rpc_url = getenv("ENS_RPC_URL");
    if (env_ens_rpc_url) {
        ens_rpc_url = strdup(env_ens_rpc_url);
        if (!ens_rpc_url) {
            LM_ERR("failed to allocate memory for ens_rpc_url\n");
            ens_rpc_url = DEFAULT_ENS_RPC_URL;
        }
    } else {
        ens_rpc_url = DEFAULT_ENS_RPC_URL;
    }

    char *env_web3_debug_mode = getenv("WEB3_DEBUG_MODE");
    if (env_web3_debug_mode) {
        web3_debug_mode = atoi(env_web3_debug_mode);
    }

    char *env_web3_timeout = getenv("WEB3_TIMEOUT");
    if (env_web3_timeout) {
        web3_timeout = atoi(env_web3_timeout);
    }
}

/*
 * WWW authentication wrapper function
 */
static int w_web3_www_authenticate(struct sip_msg *msg, char *realm, char *method)
{
    str srealm = {0, 0};
    str smethod = {0, 0};

    if (get_str_fparam(&srealm, msg, (fparam_t *)realm) < 0) {
        LM_ERR("failed to get realm value\n");
        return AUTH_ERROR;
    }

    if (srealm.len == 0) {
        LM_ERR("invalid realm value - empty content\n");
        return AUTH_ERROR;
    }

    if (method) {
        if (get_str_fparam(&smethod, msg, (fparam_t *)method) < 0) {
            LM_ERR("failed to get method value\n");
            return AUTH_ERROR;
        }
    } else {
        smethod = msg->first_line.u.request.method;
    }

    return web3_digest_authenticate(msg, &srealm, HDR_AUTHORIZATION_T, &smethod);
}

/*
 * Proxy authentication wrapper function
 */
static int w_web3_proxy_authenticate(struct sip_msg *msg, char *realm, char *method)
{
    str srealm = {0, 0};
    str smethod = {0, 0};

    if (get_str_fparam(&srealm, msg, (fparam_t *)realm) < 0) {
        LM_ERR("failed to get realm value\n");
        return AUTH_ERROR;
    }

    if (srealm.len == 0) {
        LM_ERR("invalid realm value - empty content\n");
        return AUTH_ERROR;
    }

    if (method) {
        if (get_str_fparam(&smethod, msg, (fparam_t *)method) < 0) {
            LM_ERR("failed to get method value\n");
            return AUTH_ERROR;
        }
    } else {
        smethod = msg->first_line.u.request.method;
    }

    return web3_digest_authenticate(msg, &srealm, HDR_PROXYAUTH_T, &smethod);
}

/*
 * Fixup function for authentication functions
 */
static int fixup_web3_auth(void **param, int param_no)
{
    if (strlen((char *)*param) <= 0) {
        LM_ERR("empty parameter %d not allowed\n", param_no);
        return -1;
    }

    switch (param_no) {
        case 1:
        case 2:
            return fixup_var_str_12(param, 1);
    }
    return 0;
}

/*
 * Kamailio integration functions for KEMI
 */
static int ki_web3_www_authenticate(sip_msg_t *msg, str *realm, str *method)
{
    return web3_digest_authenticate(msg, realm, HDR_AUTHORIZATION_T, method);
}

static int ki_web3_proxy_authenticate(sip_msg_t *msg, str *realm, str *method)
{
    return web3_digest_authenticate(msg, realm, HDR_PROXYAUTH_T, method);
}

/*
 * KEMI exports
 */
static sr_kemi_t sr_kemi_web3_auth_exports[] = {
    { str_init("web3_auth_ext"), str_init("web3_www_authenticate"),
        SR_KEMIP_INT, ki_web3_www_authenticate,
        { SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_NONE,
            SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
    },
    { str_init("web3_auth_ext"), str_init("web3_proxy_authenticate"),
        SR_KEMIP_INT, ki_web3_proxy_authenticate,
        { SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_NONE,
            SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
    },
    { {0, 0}, {0, 0}, 0, NULL, { 0, 0, 0, 0, 0, 0 } }
};

/*
 * Module register function
 */
int mod_register(char *path, int *dlflags, void *p1, void *p2)
{
    sr_kemi_modules_add(sr_kemi_web3_auth_exports);
    return 0;
} 