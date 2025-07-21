/*
 * Web3 Authentication Extension - Core Authentication Implementation
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <stdint.h>
#include "../../core/dprint.h"
#include "../../core/mem/mem.h"
#include "../../core/parser/digest/digest.h"
#include "../../modules/auth/api.h"
#include "web3_auth.h"
#include "web3_auth_ext_mod.h"

/**
 * Convert hex string to bytes
 */
int hex_to_bytes(const char *hex_str, unsigned char *bytes, int max_bytes)
{
    int len = strlen(hex_str);
    if (len % 2 != 0)
        return -1; // Invalid hex string

    int byte_len = len / 2;
    if (byte_len > max_bytes)
        return -1; // Too many bytes

    for (int i = 0; i < byte_len; i++) {
        char hex_byte[3] = {hex_str[i * 2], hex_str[i * 2 + 1], '\0'};
        bytes[i] = (unsigned char)strtol(hex_byte, NULL, 16);
    }

    return byte_len;
}

/**
 * Curl callback function for Web3 RPC responses
 */
size_t web3_curl_callback(void *contents, size_t size, size_t nmemb,
                         struct Web3ResponseData *data)
{
    size_t realsize = size * nmemb;
    char *ptr = realloc(data->memory, data->size + realsize + 1);
    if (!ptr)
        return 0;

    data->memory = ptr;
    memcpy(&(data->memory[data->size]), contents, realsize);
    data->size += realsize;
    data->memory[data->size] = 0;
    return realsize;
}

/**
 * Core blockchain verification function
 * This is the main authentication logic that replaces password-based auth
 */
int web3_auth_check_response(dig_cred_t *cred, str *method)
{
    CURL *curl;
    CURLcode res;
    struct Web3ResponseData web3_response = {0};
    struct curl_slist *headers = NULL;
    int result = NOT_AUTHENTICATED;
    char username_str[256];
    char *call_data = NULL;

    // Extract username from credentials
    if (cred->username.user.len >= sizeof(username_str)) {
        LM_ERR("Web3Auth: Username too long (%d chars)\n", cred->username.user.len);
        return NOT_AUTHENTICATED;
    }

    memcpy(username_str, cred->username.user.s, cred->username.user.len);
    username_str[cred->username.user.len] = '\0';

    if (web3_debug_mode) {
        LM_INFO("Web3Auth: Authenticating user=%s, realm=%.*s\n", 
                username_str, cred->realm.len, cred->realm.s);
        LM_INFO("Web3Auth: User provided response=%.*s\n", 
                cred->response.len, cred->response.s);
    }

    curl = curl_easy_init();
    if (!curl) {
        LM_ERR("Web3Auth: Failed to initialize curl\n");
        return NOT_AUTHENTICATED;
    }

    // Extract parameters from SIP message context
    char realm_str[256], method_str[16], uri_str[256], nonce_str[256], response_str[256];

    // Extract realm
    if (cred->realm.len >= sizeof(realm_str)) {
        LM_ERR("Web3Auth: Realm too long (%d chars)\n", cred->realm.len);
        goto cleanup;
    }
    memcpy(realm_str, cred->realm.s, cred->realm.len);
    realm_str[cred->realm.len] = '\0';

    // Extract method (from the method parameter)
    if (method && method->len < sizeof(method_str)) {
        memcpy(method_str, method->s, method->len);
        method_str[method->len] = '\0';
    } else {
        strcpy(method_str, "REGISTER"); // Default method
    }

    // Extract URI and nonce from digest credentials
    if (cred->uri.len >= sizeof(uri_str)) {
        LM_ERR("Web3Auth: URI too long (%d chars)\n", cred->uri.len);
        goto cleanup;
    }
    memcpy(uri_str, cred->uri.s, cred->uri.len);
    uri_str[cred->uri.len] = '\0';

    if (cred->nonce.len >= sizeof(nonce_str)) {
        LM_ERR("Web3Auth: Nonce too long (%d chars)\n", cred->nonce.len);
        goto cleanup;
    }
    memcpy(nonce_str, cred->nonce.s, cred->nonce.len);
    nonce_str[cred->nonce.len] = '\0';

    // Extract user's response
    if (cred->response.len >= sizeof(response_str)) {
        LM_ERR("Web3Auth: Response too long (%d chars)\n", cred->response.len);
        goto cleanup;
    }
    memcpy(response_str, cred->response.s, cred->response.len);
    response_str[cred->response.len] = '\0';

    // Determine algorithm: 0 for MD5, 1 for SHA256, 2 for SHA512
    uint8_t algo = 0; // Default to MD5
    // Note: In the extension module, we need to get auth_algorithm from the base auth module
    // For now, defaulting to MD5

    // Convert hex string response to bytes
    int response_byte_len = strlen(response_str) / 2;
    unsigned char response_bytes[64]; // Max 64 bytes for SHA-512
    int actual_byte_len = hex_to_bytes(response_str, response_bytes, sizeof(response_bytes));

    if (actual_byte_len != response_byte_len) {
        LM_ERR("Web3Auth: Failed to convert hex response to bytes\n");
        goto cleanup;
    }

    // Calculate string lengths
    size_t len1 = strlen(username_str), len2 = strlen(realm_str), len3 = strlen(method_str);
    size_t len4 = strlen(uri_str), len5 = strlen(nonce_str);

    // Calculate padded lengths (round up to 32-byte boundaries)
    size_t padded_len1 = ((len1 + 31) / 32) * 32;
    size_t padded_len2 = ((len2 + 31) / 32) * 32;
    size_t padded_len3 = ((len3 + 31) / 32) * 32;
    size_t padded_len4 = ((len4 + 31) / 32) * 32;
    size_t padded_len5 = ((len5 + 31) / 32) * 32;
    size_t padded_len7 = ((actual_byte_len + 31) / 32) * 32; // For response bytes

    // Calculate offsets (selector + 7 offset words = 0xE0 for first string)
    size_t offset1 = 0xE0;
    size_t offset2 = offset1 + 32 + padded_len1;
    size_t offset3 = offset2 + 32 + padded_len2;
    size_t offset4 = offset3 + 32 + padded_len3;
    size_t offset5 = offset4 + 32 + padded_len4;
    size_t offset7 = offset5 + 32 + padded_len5;

    // Calculate total length needed for ABI encoding
    int total_len = 10 + (7 * 64) + (32 + padded_len1) + (32 + padded_len2) +
                    (32 + padded_len3) + (32 + padded_len4) + (32 + padded_len5) + 
                    (32 + padded_len7);

    call_data = (char *)pkg_malloc(total_len * 2 + 1); // *2 for hex encoding + null terminator
    if (!call_data) {
        LM_ERR("Web3Auth: Failed to allocate memory for ABI data\n");
        goto cleanup;
    }

    int pos = 0;

    // Function selector for authenticateUser
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "dd02fd8e");

    // Offset words (32 bytes each, as 64 hex chars)
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", offset1);
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", offset2);
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", offset3);
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", offset4);
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", offset5);

    // uint8 algo parameter (padded to 32 bytes)
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064x", algo);

    // Offset for response bytes
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", offset7);

    // String 1: username - length + padded data
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", len1);
    for (size_t i = 0; i < len1; i++) {
        pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x", 
                       (unsigned char)username_str[i]);
    }
    for (size_t i = len1 * 2; i < padded_len1 * 2; i++) {
        call_data[pos++] = '0';
    }

    // String 2: realm - length + padded data
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", len2);
    for (size_t i = 0; i < len2; i++) {
        pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x", 
                       (unsigned char)realm_str[i]);
    }
    for (size_t i = len2 * 2; i < padded_len2 * 2; i++) {
        call_data[pos++] = '0';
    }

    // String 3: method - length + padded data
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", len3);
    for (size_t i = 0; i < len3; i++) {
        pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x", 
                       (unsigned char)method_str[i]);
    }
    for (size_t i = len3 * 2; i < padded_len3 * 2; i++) {
        call_data[pos++] = '0';
    }

    // String 4: uri - length + padded data
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", len4);
    for (size_t i = 0; i < len4; i++) {
        pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x", 
                       (unsigned char)uri_str[i]);
    }
    for (size_t i = len4 * 2; i < padded_len4 * 2; i++) {
        call_data[pos++] = '0';
    }

    // String 5: nonce - length + padded data
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064lx", len5);
    for (size_t i = 0; i < len5; i++) {
        pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x", 
                       (unsigned char)nonce_str[i]);
    }
    for (size_t i = len5 * 2; i < padded_len5 * 2; i++) {
        call_data[pos++] = '0';
    }

    // Bytes 7: response - length + padded data
    pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%064x", actual_byte_len);
    for (int i = 0; i < actual_byte_len; i++) {
        pos += snprintf(call_data + pos, total_len * 2 + 1 - pos, "%02x", response_bytes[i]);
    }
    for (size_t i = actual_byte_len * 2; i < padded_len7 * 2; i++) {
        call_data[pos++] = '0';
    }

    call_data[pos] = '\0';

    char payload[32768]; // Increased buffer size for larger call data
    snprintf(payload, sizeof(payload),
             "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"%s\",\"data\":\"0x%s\"},\"latest\"],\"id\":1}",
             web3_contract_address, call_data);

    if (web3_debug_mode) {
        const char *algo_name = (algo == 0) ? "MD5" : (algo == 1) ? "SHA-256" : "SHA-512";
        LM_INFO("Web3Auth: Algorithm: %s (%d)\n", algo_name, algo);
        LM_INFO("Web3Auth: Calling authenticateUser with payload: %s\n", payload);
    }

    curl_easy_setopt(curl, CURLOPT_URL, web3_rpc_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, web3_curl_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &web3_response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)web3_timeout);

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        LM_ERR("Web3Auth: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        goto cleanup;
    }

    if (!web3_response.memory) {
        LM_ERR("Web3Auth: No response from blockchain\n");
        goto cleanup;
    }

    if (web3_debug_mode) {
        LM_INFO("Web3Auth: Blockchain response: %s\n", web3_response.memory);
    }

    // Parse JSON response to extract the boolean result
    char *result_start = strstr(web3_response.memory, "\"result\":\"");
    if (!result_start) {
        LM_ERR("Web3Auth: Invalid blockchain response format\n");
        goto cleanup;
    }

    result_start += 10; // Skip "result":"
    char *result_end = strchr(result_start, '"');
    if (!result_end) {
        LM_ERR("Web3Auth: Malformed blockchain response\n");
        goto cleanup;
    }

    // Extract the result (should be 0x followed by 64 hex chars)
    char *hex_start = result_start;
    if (strncmp(hex_start, "0x", 2) == 0) {
        hex_start += 2;
    }

    int hex_len = result_end - hex_start;
    if (hex_len < 64) {
        LM_ERR("Web3Auth: Invalid result length from blockchain: %d (expected 64)\n", hex_len);
        goto cleanup;
    }

    // Check if the last character is '1' (true) or '0' (false)
    char last_char = hex_start[hex_len - 1];
    if (last_char == '1') {
        if (web3_debug_mode) {
            LM_INFO("Web3Auth: Authentication successful! Contract returned true\n");
        }
        result = AUTHENTICATED;
    } else if (last_char == '0') {
        if (web3_debug_mode) {
            LM_INFO("Web3Auth: Authentication failed! Contract returned false\n");
        }
        result = NOT_AUTHENTICATED;
    } else {
        LM_ERR("Web3Auth: Invalid boolean result from contract: %c\n", last_char);
        result = NOT_AUTHENTICATED;
    }

cleanup:
    if (headers)
        curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (web3_response.memory)
        free(web3_response.memory);
    if (call_data)
        pkg_free(call_data);

    return result;
}

/**
 * Main Web3 authentication function that integrates with the base auth module
 */
int web3_digest_authenticate(struct sip_msg *msg, str *realm, 
                           hdr_types_t hftype, str *method)
{
    struct hdr_field *h;
    auth_body_t *cred;
    auth_cfg_result_t ret;
    auth_result_t rauth;

    if (web3_debug_mode) {
        LM_INFO("Web3Auth: Starting digest authentication for realm=%.*s\n", 
                realm->len, realm->s);
    }

    // Use the base auth module for pre-authentication processing
    switch (auth_api.pre_auth(msg, realm, hftype, &h, NULL)) {
        case NONCE_REUSED:
            LM_DBG("Web3Auth: nonce reused\n");
            ret = AUTH_NONCE_REUSED;
            goto end;
        case STALE_NONCE:
            LM_DBG("Web3Auth: stale nonce\n");
            ret = AUTH_STALE_NONCE;
            goto end;
        case NO_CREDENTIALS:
            LM_DBG("Web3Auth: no credentials\n");
            ret = AUTH_NO_CREDENTIALS;
            goto end;
        case ERROR:
        case BAD_CREDENTIALS:
            LM_DBG("Web3Auth: error or bad credentials\n");
            ret = AUTH_ERROR;
            goto end;
        case CREATE_CHALLENGE:
            LM_ERR("Web3Auth: CREATE_CHALLENGE is not a valid state\n");
            ret = AUTH_ERROR;
            goto end;
        case DO_RESYNCHRONIZATION:
            LM_ERR("Web3Auth: DO_RESYNCHRONIZATION is not a valid state\n");
            ret = AUTH_ERROR;
            goto end;
        case NOT_AUTHENTICATED:
            LM_DBG("Web3Auth: not authenticated\n");
            ret = AUTH_ERROR;
            goto end;
        case DO_AUTHENTICATION:
            break;
        case AUTHENTICATED:
            ret = AUTH_OK;
            goto end;
    }

    cred = (auth_body_t *)h->parsed;

    // Use our Web3 authentication instead of traditional password-based auth
    rauth = web3_auth_check_response(&(cred->digest), method);
    
    if (rauth == AUTHENTICATED) {
        ret = AUTH_OK;
        // Use base auth module for post-authentication processing
        switch (auth_api.post_auth(msg, h, NULL)) {
            case AUTHENTICATED:
                break;
            default:
                ret = AUTH_ERROR;
                break;
        }
    } else {
        if (rauth == NOT_AUTHENTICATED)
            ret = AUTH_INVALID_PASSWORD;
        else
            ret = AUTH_ERROR;
    }

end:
    if (web3_debug_mode) {
        LM_INFO("Web3Auth: Authentication result: %d\n", ret);
    }
    
    return ret;
} 