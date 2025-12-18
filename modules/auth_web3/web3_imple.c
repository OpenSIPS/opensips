/*
 * Web3 Authentication - Core Authentication Implementation
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

#include "web3_imple.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../parser/digest/digest.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../modules/auth/api.h"
#include "auth_web3_mod.h"
#include "keccak256.h"
#include <curl/curl.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* OpenSIPS auth constants mapping */
#define NOT_AUTHENTICATED ERROR
#define AUTHENTICATED AUTHORIZED
#define AUTH_OK AUTHORIZED
#define AUTH_ERROR ERROR
#define AUTH_NONCE_REUSED ERROR
#define AUTH_STALE_NONCE STALE_NONCE
#define AUTH_NO_CREDENTIALS NO_CREDENTIALS
#define AUTH_INVALID_PASSWORD INVALID_PASSWORD
#define NONCE_REUSED STALE_NONCE
#define BAD_CREDENTIALS INVALID_PASSWORD
#define CREATE_CHALLENGE DO_AUTHORIZATION
#define DO_RESYNCHRONIZATION DO_AUTHORIZATION
#define DO_AUTHENTICATION DO_AUTHORIZATION

/**
 * Convert hex string to bytes
 */
static int hex_to_bytes(const char *hex_str, unsigned char *bytes, int max_bytes) {
  int len;
  int byte_len;
  int i;
  char *endptr;
  long val;
  
  len = strlen(hex_str);
  if (len % 2 != 0)
    return -1; /* Invalid hex string */

  byte_len = len / 2;
  if (byte_len > max_bytes)
    return -1; /* Too many bytes */

  for (i = 0; i < byte_len; i++) {
    char hex_byte[3] = {hex_str[i * 2], hex_str[i * 2 + 1], '\0'};
    
    /* Check for valid hex characters before calling strtol */
    if (!isxdigit((unsigned char)hex_byte[0]) || !isxdigit((unsigned char)hex_byte[1])) {
      return -1; /* Invalid hex character */
    }
    
    errno = 0;
    val = strtol(hex_byte, &endptr, 16);
    
    /* Check for conversion errors */
    if (errno != 0 || endptr == hex_byte || *endptr != '\0') {
      return -1; /* Conversion failed */
    }
    
    /* Check for out of range values */
    if (val < 0 || val > 255) {
      return -1; /* Value out of byte range */
    }
    
    bytes[i] = (unsigned char)val;
  }

  return byte_len;
}

/**
 * Curl callback function for Web3 RPC responses
 */
size_t web3_curl_callback(void *contents, size_t size, size_t nmemb,
                          struct Web3ResponseData *data) {
  size_t realsize = size * nmemb;
  char *ptr = pkg_realloc(data->memory, data->size + realsize + 1);
  if (!ptr)
    return 0;

  data->memory = ptr;
  memcpy(&(data->memory[data->size]), contents, realsize);
  data->size += realsize;
  data->memory[data->size] = 0;
  return realsize;
}

/**
 * Helper function to make blockchain calls for ENS and Oasis queries
 * Now accepts rpc_url parameter to support different networks
 */
static int web3_blockchain_call(const char *rpc_url, const char *to_address,
                                const char *data, char *result_buffer,
                                size_t buffer_size) {
  CURL *curl;
  CURLcode res;
  struct Web3ResponseData web3_response = {0};
  struct curl_slist *headers = NULL;
  int result = -1;
  char payload[4096];
  int ret;
  char *result_start;
  char *result_end;
  char *error_start;
  char *message_start;
  size_t result_len;

  curl = curl_easy_init();
  if (!curl) {
    LM_ERR("Failed to initialize curl for blockchain call");
    return -1;
  }

  ret = snprintf(payload, sizeof(payload),
           "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":"
           "\"%s\",\"data\":\"%s\"},\"latest\"],\"id\":1}",
           to_address, data);
  if (ret < 0 || ret >= (int)sizeof(payload)) {
    LM_ERR("Failed to create JSON-RPC payload");
    curl_easy_cleanup(curl);
    return -1;
  }

  if (web3_contract_debug_mode) {
    LM_DBG("Blockchain call: %s", to_address);
  }

  curl_easy_setopt(curl, CURLOPT_URL, rpc_url);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, web3_curl_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &web3_response);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)web3_rpc_timeout);

  headers = curl_slist_append(NULL, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    LM_ERR("curl_easy_perform() failed: %s",
           curl_easy_strerror(res));
    goto cleanup;
  }

  if (!web3_response.memory) {
    LM_ERR("No response from blockchain");
    goto cleanup;
  }

  /* Parse JSON response to extract the result */
  result_start = strstr(web3_response.memory, "\"result\":\"");
  if (!result_start) {
    /* Check if it's an error response */
    error_start = strstr(web3_response.memory, "\"error\":");
    if (error_start) {
      /* Check for specific error messages */
      message_start = strstr(web3_response.memory, "\"message\":");
      if (message_start && strstr(message_start, "User not found")) {
        if (web3_contract_debug_mode) {
          LM_INFO("Contract returned 'User not found' - treating as "
                  "zero address");
        }
        strcpy(result_buffer, "0x0000000000000000000000000000000000000000");
        result = 0;
        goto cleanup;
      }
    }
    LM_ERR("Invalid blockchain response format");
    goto cleanup;
  }

  result_start += 10; /* Skip "result":" */
  result_end = strchr(result_start, '"');
  if (!result_end) {
    LM_ERR("Malformed blockchain response");
    goto cleanup;
  }

  /* Copy result to buffer */
  result_len = result_end - result_start;
  if (result_len >= buffer_size) {
    LM_ERR("Result too long for buffer");
    goto cleanup;
  }

  memcpy(result_buffer, result_start, result_len);
  result_buffer[result_len] = '\0';
  result = 0;

cleanup:
  if (headers)
    curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (web3_response.memory)
    pkg_free(web3_response.memory);

  return result;
}

/* Convert bytes to hex string */
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
  size_t i;
  for (i = 0; i < len; i++) {
    sprintf(hex + 2 * i, "%02x", bytes[i]);
  }
  hex[2 * len] = '\0';
}

/* ENS namehash implementation using proper keccak256 */
static void ens_namehash(const char *name, char *hash_hex) {
  unsigned char hash[32] = {0}; /* Start with 32 zero bytes */
  char *labels[64]; /* Max 64 labels should be enough */
  int label_count = 0;
  int i;
  char *token;

  if (web3_contract_debug_mode) {
    LM_DBG("Computing namehash for: %s", name);
  }

  /* Handle empty string (root domain) */
  if (strlen(name) == 0) {
    bytes_to_hex(hash, 32, hash_hex);
    return;
  }

  /* Split domain into labels and process from right to left */
  char *name_copy = pkg_malloc(strlen(name) + 1);
  if (!name_copy) {
    LM_ERR("Failed to allocate memory for name copy");
    memset(hash_hex, '0', 64);
    hash_hex[64] = '\0';
    return;
  }
  strcpy(name_copy, name);

  /* Split by dots */
  token = strtok(name_copy, ".");
  while (token != NULL && label_count < 64) {
    int j;
    size_t token_len = strlen(token);
    labels[label_count] = pkg_malloc(token_len + 1);
    if (!labels[label_count]) {
      LM_ERR("Failed to allocate memory for label %d", label_count);
      /* Cleanup already allocated labels */
      for (j = 0; j < label_count; j++) {
        pkg_free(labels[j]);
      }
      pkg_free(name_copy);
      memset(hash_hex, '0', 64);
      hash_hex[64] = '\0';
      return;
    }
    strcpy(labels[label_count], token);
    label_count++;
    token = strtok(NULL, ".");
  }

  /* Process labels from right to left (reverse order) */
  for (i = label_count - 1; i >= 0; i--) {
    SHA3_CTX ctx;
    unsigned char label_hash[32];
    unsigned char combined[64]; /* hash + label_hash */

    /* Hash the current label */
    keccak_init(&ctx);
    keccak_update(&ctx, (const unsigned char *)labels[i], strlen(labels[i]));
    keccak_final(&ctx, label_hash);

    /* Combine current hash + label hash */
    memcpy(combined, hash, 32);
    memcpy(combined + 32, label_hash, 32);

    /* Hash the combination */
    keccak_init(&ctx);
    keccak_update(&ctx, combined, 64);
    keccak_final(&ctx, hash);
  }

  /* Convert final hash to hex string */
  bytes_to_hex(hash, 32, hash_hex);

  if (web3_contract_debug_mode) {
    LM_DBG("Namehash computed for '%s'", name);
  }

  /* Cleanup */
  for (i = 0; i < label_count; i++) {
    pkg_free(labels[i]);
  }
  pkg_free(name_copy);
}

/**
 * Check if a contract address is a Name Wrapper by calling name() function
 * Returns 1 if it's a Name Wrapper, 0 if not, -1 on error
 */
static int is_name_wrapper_contract(const char *rpc_url, const char *contract_address) {
  char call_data[256];
  char result[1024];
  int ret;
  char *result_start;
  size_t string_length;
  char *string_data;
  size_t i;
  char decoded_name[256];
  size_t decoded_pos;

  /* Call name() function - selector: 0x06fdde03 */
  ret = snprintf(call_data, sizeof(call_data), "0x06fdde03");
  if (ret < 0 || ret >= (int)sizeof(call_data)) {
    LM_ERR("Failed to encode name() call data");
    return -1;
  }

  /* Make the blockchain call */
  if (web3_blockchain_call(rpc_url, contract_address, call_data, result, sizeof(result)) != 0) {
    return 0; /* Not a Name Wrapper - doesn't support name() */
  }

  /* Parse the ABI-encoded string response
   * Format: offset(32 bytes) + length(32 bytes) + data(padded to 32 bytes)
   * Result is hex string WITH 0x prefix */
  
  /* Skip "0x" prefix if present */
  result_start = result;
  if (result_start[0] == '0' && (result_start[1] == 'x' || result_start[1] == 'X')) {
    result_start += 2;
  }
  
  if (strlen(result_start) < 128) {
    LM_ERR("Response too short for valid string");
    return 0;
  }

  /* Skip the first 64 hex chars (32 bytes = offset pointer) */
  /* Next 64 hex chars are the length */
  result_start = result_start + 64;
  
  /* Parse string length from hex */
  string_length = 0;
  for (i = 0; i < 64 && result_start[i] != '\0'; i++) {
    char c = result_start[i];
    string_length *= 16;
    if (c >= '0' && c <= '9') {
      string_length += c - '0';
    } else if (c >= 'a' && c <= 'f') {
      string_length += c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      string_length += c - 'A' + 10;
    }
  }

  if (string_length == 0 || string_length > 255) {
    LM_ERR("Invalid string length: %zu", string_length);
    return 0;
  }

  /* Now decode the actual string data (starts at position 128 after 0x) */
  string_data = result;
  if (string_data[0] == '0' && (string_data[1] == 'x' || string_data[1] == 'X')) {
    string_data += 2;
  }
  string_data += 128;
  decoded_pos = 0;
  
  for (i = 0; i < string_length * 2 && string_data[i] != '\0' && decoded_pos < sizeof(decoded_name) - 1; i += 2) {
    char hex_byte[3] = {string_data[i], string_data[i + 1], '\0'};
    unsigned int byte_val;
    if (sscanf(hex_byte, "%x", &byte_val) == 1) {
      decoded_name[decoded_pos++] = (char)byte_val;
    } else {
      LM_ERR("Failed to decode hex byte");
      return 0;
    }
  }
  decoded_name[decoded_pos] = '\0';

  /* Check if it equals "NameWrapper" */
  if (strcmp(decoded_name, "NameWrapper") == 0) {
    return 1;
  }

  return 0;
}

/**
 * Get ENS owner address using dynamic Name Wrapper detection:
 * 1. Call ENS Registry owner(bytes32) function with namehash
 * 2. If zero address, return ENS not found
 * 3. Check if owner is a Name Wrapper contract by calling name() function
 * 4. If it's a Name Wrapper:
 *    a. Call ENS Registry resolver(bytes32) to get the resolver address
 *    b. Call resolver's addr(bytes32) to get the associated address
 * 5. If not a Name Wrapper, return the registry owner directly
 */
int web3_ens_get_owner_address(const char *ens_name, char *owner_address) {
  char namehash_hex[65];
  char call_data[256];
  char result[256];
  const char *rpc_url;
  char registry_owner[43] = {0};
  char resolver_address[43] = {0};
  int ret;
  int is_wrapper;

  if (web3_contract_debug_mode) {
    LM_INFO("Getting ENS owner address for: %s", ens_name);
  }

  /* Step 1: Get namehash */
  ens_namehash(ens_name, namehash_hex);

  /* Step 2: Call ENS Registry owner(bytes32) function
   * owner(bytes32) function selector: 0x02571be3 */
  ret = snprintf(call_data, sizeof(call_data), "0x02571be3%s", namehash_hex);
  if (ret < 0 || ret >= (int)sizeof(call_data)) {
    LM_ERR("Failed to encode ENS Registry call data");
    return -1;
  }

  rpc_url = web3_ens_rpc_url ? web3_ens_rpc_url : web3_authentication_rpc_url;

  if (web3_blockchain_call(rpc_url, web3_ens_registry_address, call_data, result,
                           sizeof(result)) != 0) {
    LM_ERR("Failed to call ENS Registry owner function");
    return -1;
  }

  /* Extract owner address (last 40 characters) */
  if (strlen(result) >= 40) {
    ret = snprintf(registry_owner, 43, "0x%s", result + strlen(result) - 40);
    if (ret < 0 || ret >= 43) {
      LM_ERR("Failed to format registry owner address");
      return -1;
    }
  } else {
    LM_ERR("Invalid ENS Registry response format");
    return -1;
  }

  /* Step 3: Check if owner is zero address (ENS not found) */
  if (strcmp(registry_owner, "0x0000000000000000000000000000000000000000") ==
      0) {
    LM_ERR("ENS name %s not found (zero owner)", ens_name);
    strcpy(owner_address, "0x0000000000000000000000000000000000000000");
    return 1; /* Special return code for ENS not found */
  }

  /* Step 4: Check if owner is a Name Wrapper contract dynamically */
  is_wrapper = is_name_wrapper_contract(rpc_url, registry_owner);
  
  if (is_wrapper == -1) {
    LM_ERR("Error checking if contract is Name Wrapper");
    return -1;
  }
  
  if (is_wrapper == 0) {
    /* Not a Name Wrapper contract, return registry owner directly */
    strcpy(owner_address, registry_owner);
    return 0;
  }

  /* Step 5: Owner IS a Name Wrapper, use resolver approach */
  if (web3_contract_debug_mode) {
    LM_INFO("ENS name is wrapped, resolving via Name Wrapper");
  }

  /* Step 5a: Call ENS Registry resolver(bytes32) function
   * resolver(bytes32) function selector: 0x0178b8bf */
  ret = snprintf(call_data, sizeof(call_data), "0x0178b8bf%s", namehash_hex);
  if (ret < 0 || ret >= (int)sizeof(call_data)) {
    LM_ERR("Failed to encode ENS Registry resolver() call data");
    return -1;
  }

  if (web3_blockchain_call(rpc_url, web3_ens_registry_address, call_data, result,
                           sizeof(result)) != 0) {
    LM_ERR("Failed to call ENS Registry resolver function");
    return -1;
  }

  /* Extract resolver address (last 40 characters) */
  if (strlen(result) >= 40) {
    ret = snprintf(resolver_address, 43, "0x%s", result + strlen(result) - 40);
    if (ret < 0 || ret >= 43) {
      LM_ERR("Failed to format resolver address");
      return -1;
    }
  } else {
    LM_ERR("Invalid ENS Registry resolver response format");
    return -1;
  }

  /* Check if resolver is zero address */
  if (strcmp(resolver_address, "0x0000000000000000000000000000000000000000") == 0) {
    LM_ERR("No resolver set for %s", ens_name);
    strcpy(owner_address, "0x0000000000000000000000000000000000000000");
    return 1; /* ENS not properly configured */
  }

  /* Step 5b: Call resolver's addr(bytes32) function
   * addr(bytes32) function selector: 0x3b3b57de */
  ret = snprintf(call_data, sizeof(call_data), "0x3b3b57de%s", namehash_hex);
  if (ret < 0 || ret >= (int)sizeof(call_data)) {
    LM_ERR("Failed to encode resolver addr() call data");
    return -1;
  }

  if (web3_blockchain_call(rpc_url, resolver_address, call_data, result,
                           sizeof(result)) != 0) {
    LM_ERR("Failed to call resolver addr function");
    return -1;
  }

  /* Extract address from resolver (last 40 characters) */
  if (strlen(result) >= 40) {
    ret = snprintf(owner_address, 43, "0x%s", result + strlen(result) - 40);
    if (ret < 0 || ret >= 43) {
      LM_ERR("Failed to format resolved address");
      return -1;
    }
  } else {
    LM_ERR("Invalid resolver addr response format");
    return -1;
  }

  /* Check if resolved address is zero address */
  if (strcmp(owner_address, "0x0000000000000000000000000000000000000000") == 0) {
    LM_ERR("Resolver returned zero address for %s", ens_name);
    return 1; /* ENS not properly configured */
  }

  return 0;
}

/**
 * Legacy function name for compatibility - now calls the new owner resolution
 * This maintains compatibility with existing code that calls
 * web3_ens_resolve_address
 */
int web3_ens_resolve_address(const char *ens_name, char *resolved_address) {
  return web3_ens_get_owner_address(ens_name, resolved_address);
}

/**
 * Get wallet address from Oasis contract using getWalletAddress function
 */
int web3_oasis_get_wallet_address(const char *username, char *wallet_address) {
  char call_data[512];
  char result[256];
  int pos = 0;
  int ret;
  size_t username_len;
  size_t padding;
  size_t i;
  char final_call_data[1024];

  /* Function selector for getWalletAddress(string) - found by testing: 08f20630 */
  ret = snprintf(call_data + pos, sizeof(call_data) - pos, "08f20630");
  if (ret < 0 || ret >= (int)(sizeof(call_data) - pos)) {
    LM_ERR("Failed to encode function selector");
    return -1;
  }
  pos += ret;

  /* Offset to data (32 bytes from start) */
  ret = snprintf(
      call_data + pos, sizeof(call_data) - pos,
      "0000000000000000000000000000000000000000000000000000000000000020");
  if (ret < 0 || ret >= (int)(sizeof(call_data) - pos)) {
    LM_ERR("Failed to encode data offset");
    return -1;
  }
  pos += ret;

  /* String length (username length in bytes) */
  username_len = strlen(username);
  ret = snprintf(call_data + pos, sizeof(call_data) - pos, "%064zx",
                  username_len);
  if (ret < 0 || ret >= (int)(sizeof(call_data) - pos)) {
    LM_ERR("Failed to encode username length");
    return -1;
  }
  pos += ret;

  /* String data (username in hex, padded to 32-byte boundary) */
  for (i = 0; i < username_len; i++) {
    ret = snprintf(call_data + pos, sizeof(call_data) - pos, "%02x",
                    (unsigned char)username[i]);
    if (ret < 0 || ret >= (int)(sizeof(call_data) - pos)) {
      LM_ERR("Failed to encode username data");
      return -1;
    }
    pos += ret;
  }

  /* Pad to 32-byte boundary */
  padding = (32 - (username_len % 32)) % 32;
  for (i = 0; i < padding; i++) {
    ret = snprintf(call_data + pos, sizeof(call_data) - pos, "00");
    if (ret < 0 || ret >= (int)(sizeof(call_data) - pos)) {
      LM_ERR("Failed to encode padding");
      return -1;
    }
    pos += ret;
  }

  /* Prepend 0x */
  ret = snprintf(final_call_data, sizeof(final_call_data), "0x%s", call_data);
  if (ret < 0 || ret >= (int)sizeof(final_call_data)) {
    LM_ERR("Failed to create final call data");
    return -1;
  }

  if (web3_blockchain_call(web3_authentication_rpc_url,
                           web3_authentication_contract_address, final_call_data,
                           result, sizeof(result)) != 0) {
    LM_ERR("Failed to call Oasis contract");
    return -1;
  }

  /* Extract address from result (last 40 hex chars of the 64-char response) */
  if (strlen(result) >= 40) {
    snprintf(wallet_address, 43, "0x%s", result + strlen(result) - 40);
  } else {
    LM_ERR("Invalid Oasis response format");
    return -1;
  }

  return 0;
}

/**
 * Check if username is ENS format and validate against Oasis contract
 * Now uses ENS owner resolution instead of address resolution
 */
int web3_ens_validate(const char *username, dig_cred_t *cred, str *rmethod) {
  /* Check if username contains "." (ENS format) */
  if (!strchr(username, '.')) {
    /* Not an ENS name, proceed with normal authentication */
    return auth_web3_check_response(cred, rmethod);
  }

  char ens_owner_address[43] = {0};
  char oasis_wallet_address[43] = {0};

  /* Extract auth username from credentials for Oasis contract */
  char auth_username[256];
  if (cred->username.user.len >= sizeof(auth_username)) {
    LM_ERR("Auth username too long (%d chars)",
           cred->username.user.len);
    return NOT_AUTHENTICATED;
  }
  memcpy(auth_username, cred->username.user.s, cred->username.user.len);
  auth_username[cred->username.user.len] = '\0';

  if (web3_contract_debug_mode) {
    LM_INFO("ENS authentication: %s -> Oasis user: %s", username, auth_username);
  }

  /* Step 1: Get ENS owner address (new approach) */
  int ens_result = web3_ens_get_owner_address(username, ens_owner_address);
  if (ens_result == 1) {
    LM_ERR("ENS name %s not found or has zero owner", username);
    return 402; /* ENS not valid */
  } else if (ens_result != 0) {
    LM_ERR("Failed to get ENS owner address for %s", username);
    return 402; /* ENS not valid */
  }

  /* Step 2: Get wallet address from Oasis contract (use auth username) */
  if (web3_oasis_get_wallet_address(auth_username, oasis_wallet_address) != 0) {
    LM_ERR("Failed to get wallet address from Oasis for %s",
           auth_username);
    return NOT_AUTHENTICATED;
  }

  /* Step 3: Compare owner addresses */

  if (strcasecmp(ens_owner_address, oasis_wallet_address) == 0) {
    if (web3_contract_debug_mode) {
      LM_INFO("ENS '%s' matches Oasis user '%s', verifying password",
              username, auth_username);
    }
    /* ENS ownership verified, now verify the password/digest response */
    return auth_web3_check_response(cred, rmethod);
  } else {
    /* Check if both addresses are non-zero */
    if (strcmp(oasis_wallet_address,
               "0x0000000000000000000000000000000000000000") != 0) {
      LM_ERR("Address mismatch - ENS owner: %s, Oasis wallet: %s",
             ens_owner_address, oasis_wallet_address);
      return NOT_AUTHENTICATED; /* 401 - Invalid */
    } else {
      LM_ERR("No wallet address found in Oasis for %s",
             auth_username);
      return NOT_AUTHENTICATED; /* 401 - Invalid */
    }
  }
}

/**
 * Core blockchain verification function
 * This is the main authentication logic that replaces password-based auth
 */
int auth_web3_check_response(dig_cred_t *cred, str *rmethod) {
  CURL *curl;
  CURLcode res;
  struct Web3ResponseData web3_response = {0};
  struct curl_slist *headers = NULL;
  int result = NOT_AUTHENTICATED;
  char username_str[256];
  char *call_data = NULL;
  char realm_str[256], method_str[16], uri_str[256], nonce_str[256],
      response_str[256];
  uint8_t algo;
  int response_byte_len;
  unsigned char response_bytes[64];
  int actual_byte_len;
  size_t len1, len2, len3, len4, len5;
  size_t padded_len1, padded_len2, padded_len3, padded_len4, padded_len5, padded_len7;
  size_t offset1, offset2, offset3, offset4, offset5, offset7;
  int total_len;
  int pos;
  size_t i;
  char payload[32768];
  int ret;
  char *result_start;
  char *result_end;
  char *hex_start;
  int hex_len;
  char last_char;

  /* Extract username from credentials */
  if (cred->username.user.len >= sizeof(username_str)) {
    LM_ERR("Username too long (%d chars)", cred->username.user.len);
    return NOT_AUTHENTICATED;
  }

  memcpy(username_str, cred->username.user.s, cred->username.user.len);
  username_str[cred->username.user.len] = '\0';

  if (web3_contract_debug_mode) {
    LM_INFO("Authenticating user=%s, realm=%.*s", username_str,
            cred->realm.len, cred->realm.s);
    LM_INFO("User provided response=%.*s", cred->response.len,
            cred->response.s);
  }

  curl = curl_easy_init();
  if (!curl) {
    LM_ERR("Failed to initialize curl");
    return NOT_AUTHENTICATED;
  }

  /* Extract realm */
  if (cred->realm.len >= sizeof(realm_str)) {
    LM_ERR("Realm too long (%d chars)", cred->realm.len);
    goto cleanup;
  }
  memcpy(realm_str, cred->realm.s, cred->realm.len);
  realm_str[cred->realm.len] = '\0';

  /* Extract method (from the rmethod parameter) */
  if (rmethod && rmethod->len < sizeof(method_str)) {
    memcpy(method_str, rmethod->s, rmethod->len);
    method_str[rmethod->len] = '\0';
  } else {
    strcpy(method_str, "REGISTER"); /* Default method */
  }

  /* Extract URI and nonce from digest credentials */
  if (cred->uri.len >= sizeof(uri_str)) {
    LM_ERR("URI too long (%d chars)", cred->uri.len);
    goto cleanup;
  }
  memcpy(uri_str, cred->uri.s, cred->uri.len);
  uri_str[cred->uri.len] = '\0';

  if (cred->nonce.len >= sizeof(nonce_str)) {
    LM_ERR("Nonce too long (%d chars)", cred->nonce.len);
    goto cleanup;
  }
  memcpy(nonce_str, cred->nonce.s, cred->nonce.len);
  nonce_str[cred->nonce.len] = '\0';

  /* Extract user's response */
  if (cred->response.len >= sizeof(response_str)) {
    LM_ERR("Response too long (%d chars)", cred->response.len);
    goto cleanup;
  }
  memcpy(response_str, cred->response.s, cred->response.len);
  response_str[cred->response.len] = '\0';

  /* Determine algorithm: 0 for MD5, 1 for SHA256, 2 for SHA512 */
  algo = 0; /* Default to MD5 */
  /* Note: In the module, we need to get auth_algorithm from the base auth
   * module For now, defaulting to MD5 */

  /* Convert hex string response to bytes */
  response_byte_len = strlen(response_str) / 2;
  actual_byte_len =
      hex_to_bytes(response_str, response_bytes, sizeof(response_bytes));

  if (actual_byte_len != response_byte_len) {
    LM_ERR("Failed to convert hex response to bytes");
    goto cleanup;
  }

  /* Calculate string lengths */
  len1 = strlen(username_str);
  len2 = strlen(realm_str);
  len3 = strlen(method_str);
  len4 = strlen(uri_str);
  len5 = strlen(nonce_str);

  /* Calculate padded lengths (round up to 32-byte boundaries) */
  padded_len1 = ((len1 + 31) / 32) * 32;
  padded_len2 = ((len2 + 31) / 32) * 32;
  padded_len3 = ((len3 + 31) / 32) * 32;
  padded_len4 = ((len4 + 31) / 32) * 32;
  padded_len5 = ((len5 + 31) / 32) * 32;
  padded_len7 = ((actual_byte_len + 31) / 32) * 32; /* For response bytes */

  /* Calculate offsets (selector + 7 offset words = 0xE0 for first string) */
  offset1 = 0xE0;
  offset2 = offset1 + 32 + padded_len1;
  offset3 = offset2 + 32 + padded_len2;
  offset4 = offset3 + 32 + padded_len3;
  offset5 = offset4 + 32 + padded_len4;
  offset7 = offset5 + 32 + padded_len5;

  /* Calculate total length needed for ABI encoding */
  total_len = 10 + (7 * 64) + (32 + padded_len1) + (32 + padded_len2) +
              (32 + padded_len3) + (32 + padded_len4) + (32 + padded_len5) +
              (32 + padded_len7);

  call_data = (char *)pkg_malloc(total_len * 2 +
                                 1); /* *2 for hex encoding + null terminator */
  if (!call_data) {
    LM_ERR("Failed to allocate memory for ABI data");
    goto cleanup;
  }

  pos = 0;

  /* Function selector for authenticateUser */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "dd02fd8e");
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode function selector");
    goto cleanup;
  }
  pos += ret;

  /* Offset words (32 bytes each, as 64 hex chars) */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", offset1);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode offset1");
    goto cleanup;
  }
  pos += ret;

  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", offset2);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode offset2");
    goto cleanup;
  }
  pos += ret;

  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", offset3);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode offset3");
    goto cleanup;
  }
  pos += ret;

  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", offset4);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode offset4");
    goto cleanup;
  }
  pos += ret;

  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", offset5);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode offset5");
    goto cleanup;
  }
  pos += ret;

  /* uint8 algo parameter (padded to 32 bytes) */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064x", algo);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode algo parameter");
    goto cleanup;
  }
  pos += ret;

  /* Offset for response bytes */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", offset7);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode offset7");
    goto cleanup;
  }
  pos += ret;

  /* String 1: username - length + padded data */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", len1);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode username length");
    goto cleanup;
  }
  pos += ret;
  
  for (i = 0; i < len1; i++) {
    ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x",
                    (unsigned char)username_str[i]);
    if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
      LM_ERR("Failed to encode username data");
      goto cleanup;
    }
    pos += ret;
  }
  for (i = len1 * 2; i < padded_len1 * 2; i++) {
    call_data[pos++] = '0';
  }

  /* String 2: realm - length + padded data */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", len2);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode realm length");
    goto cleanup;
  }
  pos += ret;
  
  for (i = 0; i < len2; i++) {
    ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x",
                    (unsigned char)realm_str[i]);
    if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
      LM_ERR("Failed to encode realm data");
      goto cleanup;
    }
    pos += ret;
  }
  for (i = len2 * 2; i < padded_len2 * 2; i++) {
    call_data[pos++] = '0';
  }

  /* String 3: method - length + padded data */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", len3);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode method length");
    goto cleanup;
  }
  pos += ret;
  
  for (i = 0; i < len3; i++) {
    ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x",
                    (unsigned char)method_str[i]);
    if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
      LM_ERR("Failed to encode method data");
      goto cleanup;
    }
    pos += ret;
  }
  for (i = len3 * 2; i < padded_len3 * 2; i++) {
    call_data[pos++] = '0';
  }

  /* String 4: uri - length + padded data */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", len4);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode uri length");
    goto cleanup;
  }
  pos += ret;
  
  for (i = 0; i < len4; i++) {
    ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x",
                    (unsigned char)uri_str[i]);
    if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
      LM_ERR("Failed to encode uri data");
      goto cleanup;
    }
    pos += ret;
  }
  for (i = len4 * 2; i < padded_len4 * 2; i++) {
    call_data[pos++] = '0';
  }

  /* String 5: nonce - length + padded data */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064zx", len5);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode nonce length");
    goto cleanup;
  }
  pos += ret;
  
  for (i = 0; i < len5; i++) {
    ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x",
                    (unsigned char)nonce_str[i]);
    if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
      LM_ERR("Failed to encode nonce data");
      goto cleanup;
    }
    pos += ret;
  }
  for (i = len5 * 2; i < padded_len5 * 2; i++) {
    call_data[pos++] = '0';
  }

  /* Bytes 7: response - length + padded data */
  ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064x",
                  actual_byte_len);
  if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
    LM_ERR("Failed to encode response length");
    goto cleanup;
  }
  pos += ret;
  
  for (i = 0; i < (size_t)actual_byte_len; i++) {
    ret = snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x",
                    response_bytes[i]);
    if (ret < 0 || ret >= (total_len * 2 + 1 - pos)) {
      LM_ERR("Failed to encode response data");
      goto cleanup;
    }
    pos += ret;
  }
  for (i = actual_byte_len * 2; i < padded_len7 * 2; i++) {
    call_data[pos++] = '0';
  }

  call_data[pos] = '\0';

  ret = snprintf(payload, sizeof(payload),
           "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":"
           "\"%s\",\"data\":\"0x%s\"},\"latest\"],\"id\":1}",
           web3_authentication_contract_address, call_data);
  if (ret < 0 || ret >= (int)sizeof(payload)) {
    LM_ERR("Failed to encode JSON-RPC payload");
    goto cleanup;
  }


  curl_easy_setopt(curl, CURLOPT_URL, web3_authentication_rpc_url);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, web3_curl_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &web3_response);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)web3_rpc_timeout);

  headers = curl_slist_append(NULL, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    LM_ERR("curl_easy_perform() failed: %s",
           curl_easy_strerror(res));
    goto cleanup;
  }

  if (!web3_response.memory) {
    LM_ERR("No response from blockchain");
    goto cleanup;
  }

  if (web3_contract_debug_mode) {
    LM_INFO("Blockchain response: %s", web3_response.memory);
  }

  /* Parse JSON response to extract the boolean result */
  result_start = strstr(web3_response.memory, "\"result\":\"");
  if (!result_start) {
    LM_ERR("Invalid blockchain response format");
    goto cleanup;
  }

  result_start += 10; /* Skip "result":" */
  result_end = strchr(result_start, '"');
  if (!result_end) {
    LM_ERR("Malformed blockchain response");
    goto cleanup;
  }

  /* Extract the result (should be 0x followed by 64 hex chars) */
  hex_start = result_start;
  if (strncmp(hex_start, "0x", 2) == 0) {
    hex_start += 2;
  }

  hex_len = result_end - hex_start;
  if (hex_len < 64) {
    LM_ERR("Invalid result length from blockchain: %d (expected 64)", hex_len);
    goto cleanup;
  }

  /* Check if the last character is '1' (true) or '0' (false) */
  last_char = hex_start[hex_len - 1];
  if (last_char == '1') {
    if (web3_contract_debug_mode) {
      LM_INFO("Authentication successful! Contract returned true");
    }
    result = AUTHENTICATED;
  } else if (last_char == '0') {
    if (web3_contract_debug_mode) {
      LM_INFO("Authentication failed! Contract returned false");
    }
    result = NOT_AUTHENTICATED;
  } else {
    LM_ERR("Invalid boolean result from contract: %c", last_char);
    result = NOT_AUTHENTICATED;
  }

cleanup:
  if (headers)
    curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (web3_response.memory)
    pkg_free(web3_response.memory);
  if (call_data)
    pkg_free(call_data);

  return result;
}

/**
 * Main Web3 authentication function that integrates with the base auth module
 */
int web3_digest_authenticate(struct sip_msg *msg, str *realm,
                             hdr_types_t hftype, str *rmethod) {
  struct hdr_field *h;
  auth_result_t ret;
  auth_result_t rauth;
  char from_username[256] = {0};

  if (web3_contract_debug_mode) {
    LM_INFO("Starting digest authentication for realm=%.*s",
            realm->len, realm->s);
  }

  /* Extract username from "From" header field */
  if (msg->from && msg->from->parsed) {
    struct to_body *from_body = (struct to_body *)msg->from->parsed;
    struct sip_uri parsed_uri;

    /* Parse the URI to extract user part */
    if (parse_uri(from_body->uri.s, from_body->uri.len, &parsed_uri) < 0) {
      LM_ERR("Failed to parse From URI");
      return AUTH_ERROR;
    }

    if (parsed_uri.user.len > 0 &&
        parsed_uri.user.len < sizeof(from_username)) {
      memcpy(from_username, parsed_uri.user.s, parsed_uri.user.len);
      from_username[parsed_uri.user.len] = '\0';

    } else {
      LM_ERR("Invalid or missing username in From header");
      return AUTH_ERROR;
    }
  } else {
    LM_ERR("No From header found");
    return AUTH_ERROR;
  }

  /* For OpenSIPS, we'll implement direct authentication without base auth module */
  /* Extract credentials from Authorization header */
  
  /* Declare variables outside the if block so they're accessible throughout the function */
  dig_cred_t cred = {0};
  str method_str = {0};
  
  if (msg->authorization) {
    h = msg->authorization;
    
    /* Get the raw Authorization header content */
    if (!h->body.s || h->body.len <= 0) {
      LM_ERR("Empty Authorization header");
      return AUTH_ERROR;
    }
    
    /* Parse the digest parameters manually */
    char *auth_header = h->body.s;
    int auth_len = h->body.len;
    
    
    /* Extract all digest parameters from the Authorization header */
    char username[256] = {0};
    char realm[256] = {0};
    char nonce[256] = {0};
    char uri[256] = {0};
    char response[256] = {0};
    char algorithm[16] = {0};
    
    /* Parse username */
    char *username_start = strstr(auth_header, "username=\"");
    if (!username_start) {
      LM_ERR("No username found in Authorization header");
      return AUTH_ERROR;
    }
    username_start += 10; /* Skip "username=\"" */
    char *username_end = strchr(username_start, '"');
    if (!username_end) {
      LM_ERR("Malformed username in Authorization header");
      return AUTH_ERROR;
    }
    int username_len = username_end - username_start;
    if (username_len >= sizeof(username)) {
      LM_ERR("Username too long");
      return AUTH_ERROR;
    }
    memcpy(username, username_start, username_len);
    username[username_len] = '\0';
    
    /* Parse realm */
    char *realm_start = strstr(auth_header, "realm=\"");
    if (realm_start) {
      realm_start += 7; /* Skip "realm=\"" */
      char *realm_end = strchr(realm_start, '"');
      if (realm_end) {
        int realm_len = realm_end - realm_start;
        if (realm_len < sizeof(realm)) {
          memcpy(realm, realm_start, realm_len);
          realm[realm_len] = '\0';
        }
      }
    }
    
    /* Parse nonce */
    char *nonce_start = strstr(auth_header, "nonce=\"");
    if (nonce_start) {
      nonce_start += 7; /* Skip "nonce=\"" */
      char *nonce_end = strchr(nonce_start, '"');
      if (nonce_end) {
        int nonce_len = nonce_end - nonce_start;
        if (nonce_len < sizeof(nonce)) {
          memcpy(nonce, nonce_start, nonce_len);
          nonce[nonce_len] = '\0';
        }
      }
    }
    
    /* Parse uri */
    char *uri_start = strstr(auth_header, "uri=\"");
    if (uri_start) {
      uri_start += 5; /* Skip "uri=\"" */
      char *uri_end = strchr(uri_start, '"');
      if (uri_end) {
        int uri_len = uri_end - uri_start;
        if (uri_len < sizeof(uri)) {
          memcpy(uri, uri_start, uri_len);
          uri[uri_len] = '\0';
        }
      }
    }
    
    
    /* Parse response */
    char *response_start = strstr(auth_header, "response=\"");
    if (response_start) {
      response_start += 10; /* Skip "response=\"" */
      char *response_end = strchr(response_start, '"');
      if (response_end) {
        int response_len = response_end - response_start;
        if (response_len < sizeof(response)) {
          memcpy(response, response_start, response_len);
          response[response_len] = '\0';
        }
      }
    }
    
    /* Parse algorithm - search backwards from the end since it's at the end */
	int i;
    char *algorithm_start = NULL;
    for (i = auth_len - 9; i >= 0; i--) {
      if (strncmp(auth_header + i, "algorithm=", 9) == 0) {
        algorithm_start = auth_header + i;
        break;
      }
    }
    
    if (algorithm_start && algorithm_start < auth_header + auth_len) {
      algorithm_start += 9; /* Skip "algorithm=" */
      /* Algorithm is at the end, so no comma to find */
      int algorithm_len = (auth_header + auth_len) - algorithm_start;
      if (algorithm_len < sizeof(algorithm) && algorithm_len > 0) {
        memcpy(algorithm, algorithm_start, algorithm_len);
        algorithm[algorithm_len] = '\0';
      }
    } else {
      /* Default to MD5 if not specified */
      strcpy(algorithm, "MD5");
    }
    
    
    /* Create dig_cred_t structure */
    
    /* Set username */
    cred.username.user.s = username;
    cred.username.user.len = strlen(username);
    
    /* Set realm */
    cred.realm.s = realm;
    cred.realm.len = strlen(realm);
    
    /* Set nonce */
    cred.nonce.s = nonce;
    cred.nonce.len = strlen(nonce);
    
    /* Set uri */
    cred.uri.s = uri;
    cred.uri.len = strlen(uri);
    
    /* Set response */
    cred.response.s = response;
    cred.response.len = strlen(response);
    
  /* Use the method parameter passed to the function */
  
  
  if (rmethod && rmethod->s && rmethod->len > 0) {
    /* Copy rmethod to local buffer to avoid memory issues */
    char method_buffer[32];
    int copy_len = (rmethod->len < sizeof(method_buffer) - 1) ? rmethod->len : sizeof(method_buffer) - 1;
    memcpy(method_buffer, rmethod->s, copy_len);
    method_buffer[copy_len] = '\0';
    
    method_str.s = method_buffer;
    method_str.len = copy_len;
  } else {
    LM_ERR("Invalid method parameter");
    return AUTH_ERROR;
  }
} else {
  LM_ERR("No Authorization header found");
  return AUTH_ERROR;
}

  /* Use ENS validation which includes fallback to normal Web3 authentication */
  rauth = web3_ens_validate(from_username, &cred, &method_str);

  /* Handle different return codes from ENS validation */
  if (rauth == AUTHENTICATED) {
    ret = AUTH_OK;
    /* For OpenSIPS, authentication is complete at this point */
  } else if (rauth == 402) {
    /* ENS validation failed - return specific error */
    ret = AUTH_ERROR; /* or define a specific AUTH_ENS_INVALID if available */
    LM_ERR("ENS validation failed for %s", from_username);
  } else {
    if (rauth == NOT_AUTHENTICATED)
      ret = AUTH_INVALID_PASSWORD;
    else
      ret = AUTH_ERROR;
  }

  if (web3_contract_debug_mode) {
    LM_INFO("Authentication result: %d", ret);
  }

  return ret;
}
