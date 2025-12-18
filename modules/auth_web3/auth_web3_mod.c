/*
 * Web3 Authentication Module
 *
 * Copyright (C) 2025 Cellact B.V.
 *
 * This file is part of OpenSIPS, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * OpenSIPS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * OpenSIPS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include "auth_web3_mod.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mod_fix.h"
#include "../../sr_module.h"
#include "../../pvar.h"
#include "api.h"
#include "keccak256.h"
#include "web3_imple.h"
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

/* Default dlopen flags */
#define DEFAULT_DLFLAGS 0

/* Default Web3 configuration */
#define DEFAULT_AUTHENTICATION_RPC_URL                                         \
  "https://testnet.sapphire.oasis.dev" // Oasis Sapphire testnet
#define DEFAULT_ENS_RPC_URL                                                    \
  "https://ethereum-sepolia-rpc.publicnode.com" // Sepolia testnet for ENS
#define DEFAULT_AUTHENTICATION_CONTRACT_ADDRESS                                \
  "0xE773BB79689379d32Ad1Db839868b6756B493aea" // Oasis Sapphire authentication
                                               // contract
#define DEFAULT_ENS_REGISTRY_ADDRESS                                           \
  "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e" /* Sepolia ENS registry */

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
char *web3_authentication_rpc_url = NULL;
char *web3_authentication_contract_address = NULL;
char *web3_ens_registry_address = NULL;
char *web3_ens_rpc_url = NULL;
int web3_contract_debug_mode = 1;
int web3_rpc_timeout = 10;

/* Base auth module API - removed for OpenSIPS compatibility */

/* Function prototypes for exported functions */
static int w_web3_www_authenticate(struct sip_msg *msg, char *realm,
                                   char *method, char *param3, char *param4, char *param5, char *param6);
static int w_web3_proxy_authenticate(struct sip_msg *msg, char *realm,
                                     char *method, char *param3, char *param4, char *param5, char *param6);

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
    {"web3_www_authenticate", (cmd_function)w_web3_www_authenticate, {
        {CMD_PARAM_STR, 0, 0}, /* realm */
        {CMD_PARAM_STR, 0, 0}, /* method */
        {0, 0, 0}}, REQUEST_ROUTE},
    {"web3_proxy_authenticate", (cmd_function)w_web3_proxy_authenticate, {
        {CMD_PARAM_STR, 0, 0}, /* realm */
        {CMD_PARAM_STR, 0, 0}, /* method */
        {0, 0, 0}}, REQUEST_ROUTE},
    {"bind_web3_auth", (cmd_function)bind_web3_auth, {{0, 0, 0}}, 0},
    {0, 0, {{0, 0, 0}}, 0}};

/*
 * Exported parameters
 */
static param_export_t params[] = {
    {"authentication_rpc_url", STR_PARAM, &web3_authentication_rpc_url},
    {"authentication_contract_address", STR_PARAM,
     &web3_authentication_contract_address},
    {"ens_registry_address", STR_PARAM, &web3_ens_registry_address},
    {"ens_rpc_url", STR_PARAM, &web3_ens_rpc_url},
    {"contract_debug_mode", INT_PARAM, &web3_contract_debug_mode},
    {"rpc_timeout", INT_PARAM, &web3_rpc_timeout},
    {0, 0, 0}};

/*
 * Module interface
 */
struct module_exports exports = {
	"auth_web3",           /* module name */
	MOD_TYPE_DEFAULT,       /* class of this module */
	MODULE_VERSION,         /* module version */
	DEFAULT_DLFLAGS,        /* dlopen flags */
	0,                      /* load function */
	NULL,                   /* OpenSIPS module dependencies */
	cmds,                   /* exported functions */
	0,                      /* exported async cmds */
	params,                 /* param exports */
	0,                      /* exported statistics */
	0,                      /* exported MI functions */
	0,                      /* exported pseudo-variables */
	0,                      /* exported transformations */
	0,                      /* extra processes */
	0,                      /* module pre-initialization function */
	mod_init,               /* module initialization function */
	(response_function) 0,  /* response processing function */
	(destroy_function) destroy, /* module exit function */
	child_init,             /* per-child init function */
	0                       /* reload confirm function */
};
/*
 * Module initialization function
 */
static int mod_init(void) {
  LM_INFO("Authentication module initializing");

  /* Initialize curl globally */
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    LM_ERR("failed to initialize curl globally");
    return -1;
  }

  /* Initialize configuration from environment variables */
  init_config_from_env();

  if (web3_contract_debug_mode) {
    LM_INFO("initialized:");
    LM_INFO("Authentication RPC URL: %s", web3_authentication_rpc_url
                                                  ? web3_authentication_rpc_url
                                                  : "(using default)");
    LM_INFO("Authentication Contract: %s",
            web3_authentication_contract_address ? web3_authentication_contract_address
                                            : "(using default)");
    LM_INFO("ENS Registry: %s",
            web3_ens_registry_address ? web3_ens_registry_address : "(using default)");
    LM_INFO("ENS RPC URL: %s",
            web3_ens_rpc_url ? web3_ens_rpc_url : "(using default)");
    LM_INFO("Debug: %s", web3_contract_debug_mode ? "enabled" : "disabled");
    LM_INFO("Timeout: %d seconds", web3_rpc_timeout);
  }

  return 0;
}

/*
 * Child initialization function
 */
static int child_init(int rank) {
  if (web3_contract_debug_mode) {
    LM_INFO("child %d initialized", rank);
  }
  return 0;
}

/*
 * Module destroy function
 */
static void destroy(void) {
  LM_INFO("Authentication module shutting down");

  /* Cleanup curl */
  curl_global_cleanup();
}

/*
 * Configuration initialization from environment variables
 * Environment variables override config file parameters,
 * defaults are only used if neither config file nor env vars are set
 */
static void init_config_from_env(void) {
  char *env_authentication_rpc_url;
  char *env_authentication_contract_address;
  char *env_ens_registry_address;
  char *env_ens_rpc_url;
  char *env_contract_debug_mode;
  char *env_rpc_timeout;
  size_t len;
  
  env_authentication_rpc_url = getenv("AUTHENTICATION_RPC_URL");
  if (env_authentication_rpc_url) {
    len = strlen(env_authentication_rpc_url);
    web3_authentication_rpc_url = (char *)pkg_malloc(len + 1);
    if (!web3_authentication_rpc_url) {
      LM_ERR("failed to allocate PKG memory for authentication_rpc_url");
      web3_authentication_rpc_url = DEFAULT_AUTHENTICATION_RPC_URL;
    } else {
      memcpy(web3_authentication_rpc_url, env_authentication_rpc_url, len + 1);
    }
  } else if (!web3_authentication_rpc_url) {
    /* Only set default if config file didn't set it */
    web3_authentication_rpc_url = DEFAULT_AUTHENTICATION_RPC_URL;
  }

  env_authentication_contract_address = getenv("AUTHENTICATION_CONTRACT_ADDRESS");
  if (env_authentication_contract_address) {
    len = strlen(env_authentication_contract_address);
    web3_authentication_contract_address = (char *)pkg_malloc(len + 1);
    if (!web3_authentication_contract_address) {
      LM_ERR("failed to allocate PKG memory for authentication_contract_address");
      web3_authentication_contract_address = DEFAULT_AUTHENTICATION_CONTRACT_ADDRESS;
    } else {
      memcpy(web3_authentication_contract_address, env_authentication_contract_address, len + 1);
    }
  } else if (!web3_authentication_contract_address) {
    /* Only set default if config file didn't set it */
    web3_authentication_contract_address = DEFAULT_AUTHENTICATION_CONTRACT_ADDRESS;
  }

  env_ens_registry_address = getenv("ENS_REGISTRY_ADDRESS");
  if (env_ens_registry_address) {
    len = strlen(env_ens_registry_address);
    web3_ens_registry_address = (char *)pkg_malloc(len + 1);
    if (!web3_ens_registry_address) {
      LM_ERR("failed to allocate PKG memory for ens_registry_address");
      web3_ens_registry_address = DEFAULT_ENS_REGISTRY_ADDRESS;
    } else {
      memcpy(web3_ens_registry_address, env_ens_registry_address, len + 1);
    }
  } else if (!web3_ens_registry_address) {
    /* Only set default if config file didn't set it */
    web3_ens_registry_address = DEFAULT_ENS_REGISTRY_ADDRESS;
  }

  env_ens_rpc_url = getenv("ENS_RPC_URL");
  if (env_ens_rpc_url) {
    len = strlen(env_ens_rpc_url);
    web3_ens_rpc_url = (char *)pkg_malloc(len + 1);
    if (!web3_ens_rpc_url) {
      LM_ERR("failed to allocate PKG memory for ens_rpc_url");
      web3_ens_rpc_url = DEFAULT_ENS_RPC_URL;
    } else {
      memcpy(web3_ens_rpc_url, env_ens_rpc_url, len + 1);
    }
  } else if (!web3_ens_rpc_url) {
    /* Only set default if config file didn't set it */
    web3_ens_rpc_url = DEFAULT_ENS_RPC_URL;
  }

  env_contract_debug_mode = getenv("CONTRACT_DEBUG_MODE");
  if (env_contract_debug_mode) {
    web3_contract_debug_mode = atoi(env_contract_debug_mode);
  }

  env_rpc_timeout = getenv("RPC_TIMEOUT");
  if (env_rpc_timeout) {
    web3_rpc_timeout = atoi(env_rpc_timeout);
  }
}

/*
 * WWW authentication wrapper function
 */
static int w_web3_www_authenticate(struct sip_msg *msg, char *realm,
                                   char *method, char *param3, char *param4, char *param5, char *param6) {
  str srealm = {0, 0};
  str smethod = {0, 0};

  srealm.s = realm;
  srealm.len = strlen(realm);

  if (srealm.len == 0) {
    LM_ERR("invalid realm value - empty content");
    return -1;
  }

  /* Always use the actual SIP method from the message, not the config parameter */
  smethod = msg->first_line.u.request.method;
  return web3_digest_authenticate(msg, &srealm, HDR_AUTHORIZATION_T, &smethod);
}

/*
 * Proxy authentication wrapper function
 */
static int w_web3_proxy_authenticate(struct sip_msg *msg, char *realm,
                                     char *method, char *param3, char *param4, char *param5, char *param6) {
  str srealm = {0, 0};
  str smethod = {0, 0};

  srealm.s = realm;
  srealm.len = strlen(realm);

  if (srealm.len == 0) {
    LM_ERR("invalid realm value - empty content");
    return -1;
  }


  /* Always use the actual SIP method from the message, not the config parameter */
  smethod = msg->first_line.u.request.method;

  return web3_digest_authenticate(msg, &srealm, HDR_PROXYAUTH_T, &smethod);
}


/*
 * OpenSIPS integration functions for KEMI
 */
