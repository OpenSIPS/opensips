/*
 * Complete End-to-End Authentication Test in C
 * Tests: SIP Digest + Web3 Oasis + ENS Resolution
 * 
 * Flow:
 * 1. Client sends digest hash (MD5)
 * 2. Server verifies digest hash
 * 3. Server calls Oasis blockchain for auth username
 * 4. Server resolves ENS name from To field  
 * 5. Server compares addresses
 * 6. Returns authentication result (200/401/402)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "keccak256.h"

// Configuration - configurable via environment variables for better modularity
static char *web3_rpc_url = NULL;
static char *web3_contract_address = NULL;
static char *ens_rpc_url = NULL;
static char *ens_registry_address = NULL;
static char *ens_name_wrapper_address __attribute__((unused)) = NULL; // May be used in future features
static int web3_debug_mode = 1;
static int web3_timeout = 10;

// Initialize configuration from environment variables with fallback defaults
static void init_config() {
    // Web3/Oasis configuration
    web3_rpc_url = getenv("WEB3_RPC_URL");
    if (!web3_rpc_url) {
        web3_rpc_url = "https://testnet.sapphire.oasis.dev"; // Default fallback
    }
    
    web3_contract_address = getenv("WEB3_CONTRACT_ADDRESS");
    if (!web3_contract_address) {
        web3_contract_address = "0xE773BB79689379d32Ad1Db839868b6756B493aea"; // Default fallback
    }
    
    // ENS configuration
    ens_rpc_url = getenv("ENS_RPC_URL");
    if (!ens_rpc_url) {
        ens_rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"; // Default fallback
    }
    
    ens_registry_address = getenv("ENS_REGISTRY_ADDRESS");
    if (!ens_registry_address) {
        ens_registry_address = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"; // Default fallback
    }
    
    ens_name_wrapper_address = getenv("ENS_NAME_WRAPPER_ADDRESS");
    if (!ens_name_wrapper_address) {
        ens_name_wrapper_address = "0x0635513f179D50A207757E05759CbD106d7dFcE8"; // Default fallback
    }
    
    // Debug and timeout configuration
    char *debug_env = getenv("WEB3_DEBUG_MODE");
    if (debug_env) {
        web3_debug_mode = (strcmp(debug_env, "1") == 0 || strcmp(debug_env, "true") == 0);
    }
    
    char *timeout_env = getenv("WEB3_TIMEOUT");
    if (timeout_env) {
        web3_timeout = atoi(timeout_env);
        if (web3_timeout <= 0) web3_timeout = 10; // Minimum timeout
    }
    
    if (web3_debug_mode) {
        printf("DEBUG: Configuration loaded:\n");
        printf("  WEB3_RPC_URL: %s\n", web3_rpc_url);
        printf("  WEB3_CONTRACT_ADDRESS: %s\n", web3_contract_address);
        printf("  ENS_RPC_URL: %s\n", ens_rpc_url);
        printf("  ENS_REGISTRY_ADDRESS: %s\n", ens_registry_address);
        printf("  ENS_NAME_WRAPPER_ADDRESS: %s\n", ens_name_wrapper_address);
        printf("  WEB3_DEBUG_MODE: %d\n", web3_debug_mode);
        printf("  WEB3_TIMEOUT: %d\n", web3_timeout);
    }
}

// Authentication result codes
#define AUTHENTICATED 200
#define NOT_AUTHENTICATED 401
#define ENS_NOT_VALID 402

// Response structure for curl
struct web3_response {
    char *memory;
    size_t size;
};

// Callback function for curl to write response data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, struct web3_response *userp)
{
    size_t realsize = size * nmemb;
    char *ptr = realloc(userp->memory, userp->size + realsize + 1);
    
    if (!ptr) {
        printf("ERROR: Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    userp->memory = ptr;
    memcpy(&(userp->memory[userp->size]), contents, realsize);
    userp->size += realsize;
    userp->memory[userp->size] = 0;
    
    return realsize;
}

// Make blockchain call
static int web3_blockchain_call(const char *rpc_url, const char *to_address, const char *data, char *result_buffer, size_t buffer_size)
{
    CURL *curl;
    CURLcode res;
    struct web3_response web3_response = {0};
    int result = -1;
    
    curl = curl_easy_init();
    if (!curl) {
        printf("ERROR: Failed to initialize curl\n");
        return -1;
    }
    
    // Build JSON payload
    char json_data[2048];
    snprintf(json_data, sizeof(json_data),
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"%s\",\"data\":\"%s\"},\"latest\"],\"id\":1}",
        to_address, data);
    
    if (web3_debug_mode) {
        printf("DEBUG: Blockchain call to %s\n", to_address);
        printf("DEBUG: Using RPC: %s\n", rpc_url);
        printf("DEBUG: Call data: %s\n", data);
        printf("DEBUG: Full payload: %s\n", json_data);
    }
    
    // Set curl options
    curl_easy_setopt(curl, CURLOPT_URL, rpc_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &web3_response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, web3_timeout);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("ERROR: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        goto cleanup;
    }
    
    if (web3_debug_mode) {
        printf("DEBUG: Blockchain response: %s\n", web3_response.memory);
    }
    
    // Parse JSON response for result field
    char *result_start = strstr(web3_response.memory, "\"result\":");
    if (!result_start) {
        // Check for error with "User not found" message
        char *error_start = strstr(web3_response.memory, "\"error\":");
        if (error_start) {
            char *message_start = strstr(web3_response.memory, "\"message\":");
            if (message_start && strstr(message_start, "User not found")) {
                if (web3_debug_mode) {
                    printf("INFO: Contract returned 'User not found' - treating as zero address\n");
                }
                strcpy(result_buffer, "0x0000000000000000000000000000000000000000");
                result = 0;
                goto cleanup;
            }
        }
        printf("ERROR: Invalid blockchain response format\n");
        goto cleanup;
    }
    
    // Extract the result value (skip "result":")
    result_start += 9; // Skip "result":
    if (*result_start == '"') result_start++; // Skip opening quote
    
    // Find the end of the result (closing quote or comma)
    char *result_end = result_start;
    while (*result_end && *result_end != '"' && *result_end != ',' && *result_end != '}') {
        result_end++;
    }
    
    // Copy result to buffer
    size_t result_len = result_end - result_start;
    if (result_len >= buffer_size) {
        printf("ERROR: Result buffer too small\n");
        goto cleanup;
    }
    
    strncpy(result_buffer, result_start, result_len);
    result_buffer[result_len] = '\0';
    
    result = 0;
    
cleanup:
    if (headers) curl_slist_free_all(headers);
    if (web3_response.memory) free(web3_response.memory);
    curl_easy_cleanup(curl);
    
    return result;
}

// Convert bytes to hex string
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2*i, "%02x", bytes[i]);
    }
    hex[2*len] = '\0';
}

// ENS namehash implementation using proper keccak256
void ens_namehash(const char *name, char *hash_hex)
{
    unsigned char hash[32] = {0}; // Start with 32 zero bytes
    
    if (web3_debug_mode) {
        printf("DEBUG: Computing namehash for: %s\n", name);
    }
    
    // Handle empty string (root domain)
    if (strlen(name) == 0) {
        bytes_to_hex(hash, 32, hash_hex);
        return;
    }
    
    // Split domain into labels and process from right to left
    char *name_copy = strdup(name);
    char *labels[64]; // Max 64 labels should be enough
    int label_count = 0;
    
    // Split by dots
    char *token = strtok(name_copy, ".");
    while (token != NULL && label_count < 64) {
        labels[label_count++] = strdup(token);
        token = strtok(NULL, ".");
    }
    
    // Process labels from right to left (reverse order)
    for (int i = label_count - 1; i >= 0; i--) {
        SHA3_CTX ctx;
        unsigned char label_hash[32];
        unsigned char combined[64]; // hash + label_hash
        
        // Hash the current label
        keccak_init(&ctx);
        keccak_update(&ctx, (const unsigned char*)labels[i], strlen(labels[i]));
        keccak_final(&ctx, label_hash);
        
        if (web3_debug_mode) {
            char label_hash_hex[65];
            bytes_to_hex(label_hash, 32, label_hash_hex);
            printf("DEBUG: Label '%s' hash: %s\n", labels[i], label_hash_hex);
        }
        
        // Combine current hash + label hash
        memcpy(combined, hash, 32);
        memcpy(combined + 32, label_hash, 32);
        
        // Hash the combination
        keccak_init(&ctx);
        keccak_update(&ctx, combined, 64);
        keccak_final(&ctx, hash);
        
        if (web3_debug_mode) {
            char current_hash_hex[65];
            bytes_to_hex(hash, 32, current_hash_hex);
            printf("DEBUG: After processing '%s': %s\n", labels[i], current_hash_hex);
        }
    }
    
    // Convert final hash to hex string
    bytes_to_hex(hash, 32, hash_hex);
    
    if (web3_debug_mode) {
        printf("DEBUG: Final namehash for '%s': %s\n", name, hash_hex);
    }
    
    // Cleanup
    for (int i = 0; i < label_count; i++) {
        free(labels[i]);
    }
    free(name_copy);
}

// Get wallet address from Oasis contract
int web3_oasis_get_wallet_address(const char *username, char *wallet_address)
{
    char call_data[512];
    char result[256];
    int pos = 0;
    
    if (web3_debug_mode) {
        printf("INFO: Getting Oasis wallet address for username: %s\n", username);
    }
    
    // Function selector for getWalletAddress(string) - found by testing: 08f20630
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "08f20630");
    
    // Offset to data (32 bytes from start)
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "0000000000000000000000000000000000000000000000000000000000000020");
    
    // String length (username length in bytes)
    size_t username_len = strlen(username);
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064lx", username_len);
    
    // String data (username in hex, padded to 32-byte boundary)
    for (size_t i = 0; i < username_len; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%02x", (unsigned char)username[i]);
    }
    
    // Pad to 32-byte boundary
    size_t padding = (32 - (username_len % 32)) % 32;
    for (size_t i = 0; i < padding; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "00");
    }
    
    // Prepend 0x
    char final_call_data[1024];
    snprintf(final_call_data, sizeof(final_call_data), "0x%s", call_data);
    
    if (web3_debug_mode) {
        printf("INFO: Using main RPC for Oasis query: %s\n", web3_rpc_url);
    }
    
    if (web3_blockchain_call(web3_rpc_url, web3_contract_address, final_call_data, result, sizeof(result)) != 0) {
        printf("ERROR: Failed to call Oasis contract\n");
        return -1;
    }
    
    // Extract address from result (last 40 hex chars)
    if (strlen(result) >= 40) {
        snprintf(wallet_address, 43, "0x%s", result + strlen(result) - 40);
    } else {
        printf("ERROR: Invalid Oasis response format\n");
        return -1;
    }
    
    if (web3_debug_mode) {
        printf("INFO: Oasis wallet address for %s: %s\n", username, wallet_address);
    }
    
    return 0;
}

// Get authentication result from Oasis contract using authenticateUser function
int web3_oasis_authenticate_user(const char *username, const char *realm, const char *method, 
                                 const char *uri, const char *nonce, int algo, const char *response, 
                                 char *auth_result)
{
    char call_data[2048];
    char result[256];
    int pos = 0;
    
    if (web3_debug_mode) {
        printf("INFO: Calling Oasis authenticateUser for: %s\n", username);
        printf("DEBUG: realm=%s, method=%s, uri=%s, nonce=%s, algo=%d\n", realm, method, uri, nonce, algo);
        printf("DEBUG: response=%s\n", response);
    }
    
    // Function selector for authenticateUser(string,string,string,string,string,uint8,bytes)
    // Selector: 0xdd02fd8e
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "dd02fd8e");
    
    if (web3_debug_mode) {
        printf("DEBUG: Using function selector: dd02fd8e\n");
    }
    
    // Calculate total offset positions (7 parameters = 7 * 32 bytes offset)
    int base_offset = 0x20 * 7; // 224 bytes (0xe0)
    
    // Parameter offsets (each points to where string data starts)
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064x", base_offset); // username offset
    
    int current_offset = base_offset;
    
    // Calculate each string length and update offsets
    size_t username_len = strlen(username);
    size_t realm_len = strlen(realm);
    size_t method_len = strlen(method);
    size_t uri_len = strlen(uri);
    size_t nonce_len = strlen(nonce);
    
    // Add remaining offsets
    current_offset += 32 + ((username_len + 31) / 32) * 32; // username length + padded data
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064x", current_offset); // realm offset
    
    current_offset += 32 + ((realm_len + 31) / 32) * 32;
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064x", current_offset); // method offset
    
    current_offset += 32 + ((method_len + 31) / 32) * 32;
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064x", current_offset); // uri offset
    
    current_offset += 32 + ((uri_len + 31) / 32) * 32;
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064x", current_offset); // nonce offset
    
    // algo (uint8) - padded to 32 bytes
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064x", algo);
    
    current_offset += 32 + ((nonce_len + 31) / 32) * 32;
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064x", current_offset); // response offset
    
    // Now add the actual string data
    // Username
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064lx", username_len);
    for (size_t i = 0; i < username_len; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%02x", (unsigned char)username[i]);
    }
    // Pad username to 32-byte boundary
    size_t padding = (32 - (username_len % 32)) % 32;
    for (size_t i = 0; i < padding; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "00");
    }
    
    // Realm
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064lx", realm_len);
    for (size_t i = 0; i < realm_len; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%02x", (unsigned char)realm[i]);
    }
    padding = (32 - (realm_len % 32)) % 32;
    for (size_t i = 0; i < padding; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "00");
    }
    
    // Method
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064lx", method_len);
    for (size_t i = 0; i < method_len; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%02x", (unsigned char)method[i]);
    }
    padding = (32 - (method_len % 32)) % 32;
    for (size_t i = 0; i < padding; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "00");
    }
    
    // URI
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064lx", uri_len);
    for (size_t i = 0; i < uri_len; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%02x", (unsigned char)uri[i]);
    }
    padding = (32 - (uri_len % 32)) % 32;
    for (size_t i = 0; i < padding; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "00");
    }
    
    // Nonce
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064lx", nonce_len);
    for (size_t i = 0; i < nonce_len; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%02x", (unsigned char)nonce[i]);
    }
    padding = (32 - (nonce_len % 32)) % 32;
    for (size_t i = 0; i < padding; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "00");
    }
    
    // Response (bytes) - convert hex string to actual bytes
    // The response should be the raw bytes of the digest, not the hex string
    size_t hex_response_len = strlen(response);
    if (hex_response_len % 2 != 0) {
        printf("ERROR: Response hex string must have even length\n");
        return -1;
    }
    
    size_t actual_response_len = hex_response_len / 2;
    pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%064lx", actual_response_len);
    
    // Convert hex string to bytes
    for (size_t i = 0; i < hex_response_len; i += 2) {
        char hex_byte[3] = {response[i], response[i+1], '\0'};
        unsigned int byte_val = (unsigned int)strtol(hex_byte, NULL, 16);
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "%02x", byte_val);
    }
    
    // Pad to 32-byte boundary
    padding = (32 - (actual_response_len % 32)) % 32;
    for (size_t i = 0; i < padding; i++) {
        pos += snprintf(call_data + pos, sizeof(call_data) - pos, "00");
    }
    
    // Prepend 0x
    char final_call_data[4096];
    snprintf(final_call_data, sizeof(final_call_data), "0x%s", call_data);
    
    if (web3_debug_mode) {
        printf("INFO: Using main RPC for Oasis authentication: %s\n", web3_rpc_url);
        printf("DEBUG: Call data length: %zu\n", strlen(final_call_data));
    }
    
    if (web3_blockchain_call(web3_rpc_url, web3_contract_address, final_call_data, result, sizeof(result)) != 0) {
        printf("ERROR: Failed to call Oasis authenticateUser\n");
        return -1;
    }
    
    // Parse result - authenticateUser should return boolean (true/false)
    if (strlen(result) >= 40) {
        // Check if result is true (1) or false (0)
        char *last_char = result + strlen(result) - 1;
        if (*last_char == '1') {
            strcpy(auth_result, "true");
            if (web3_debug_mode) {
                printf("INFO: Oasis authentication SUCCESS for %s\n", username);
            }
            return 0; // Success
        } else {
            strcpy(auth_result, "false");
            if (web3_debug_mode) {
                printf("INFO: Oasis authentication FAILED for %s\n", username);
            }
            return 1; // Auth failed
        }
    } else {
        printf("ERROR: Invalid Oasis authentication response format\n");
        return -1;
    }
}

// Resolve ENS name to address
int web3_ens_resolve_address(const char *ens_name, char *resolved_address)
{
    char namehash_hex[65];
    char resolver_address[43] = {0};
    char call_data[256];
    char result[256];
    
    if (web3_debug_mode) {
        printf("INFO: Resolving ENS name to address: %s\n", ens_name);
    }
    
    // Step 1: Get namehash
    ens_namehash(ens_name, namehash_hex);
    
    // Step 2: Get resolver address from registry
    // resolver(bytes32) function selector: 0x0178b8bf
    snprintf(call_data, sizeof(call_data), "0x0178b8bf%s", namehash_hex);
    
    const char *rpc_url = ens_rpc_url ? ens_rpc_url : web3_rpc_url;
    if (web3_debug_mode) {
        printf("INFO: Using RPC for ENS registry query: %s\n", rpc_url);
    }
    
    if (web3_blockchain_call(rpc_url, ens_registry_address, call_data, result, sizeof(result)) != 0) {
        printf("ERROR: Failed to get resolver from ENS registry\n");
        return -1;
    }
    
    // Extract resolver address (last 40 characters)
    if (strlen(result) >= 40) {
        snprintf(resolver_address, 43, "0x%s", result + strlen(result) - 40);
    } else {
        printf("ERROR: Invalid resolver response format\n");
        return -1;
    }
    
    if (web3_debug_mode) {
        printf("INFO: ENS resolver address: %s\n", resolver_address);
    }
    
    // Check if resolver is zero (ENS not found)
    if (strcmp(resolver_address, "0x0000000000000000000000000000000000000000") == 0) {
        printf("ERROR: ENS name %s has no resolver (not registered)\n", ens_name);
        strcpy(resolved_address, "0x0000000000000000000000000000000000000000");
        return 0; // Not an error, just not found
    }
    
    // Step 3: Call resolver's addr(bytes32) function to get resolved address
    // addr(bytes32) function selector: 0x3b3b57de
    snprintf(call_data, sizeof(call_data), "0x3b3b57de%s", namehash_hex);
    
    if (web3_debug_mode) {
        printf("INFO: Getting resolved address from resolver\n");
    }
    
    if (web3_blockchain_call(rpc_url, resolver_address, call_data, result, sizeof(result)) != 0) {
        printf("ERROR: Failed to resolve address from ENS resolver\n");
        return -1;
    }
    
    // Extract resolved address (last 40 characters)
    if (strlen(result) >= 40) {
        snprintf(resolved_address, 43, "0x%s", result + strlen(result) - 40);
    } else {
        printf("ERROR: Invalid resolution response format\n");
        return -1;
    }
    
    if (web3_debug_mode) {
        printf("INFO: ENS name %s resolves to: %s\n", ens_name, resolved_address);
    }
    
    return 0;
}

// Complete authentication test
int complete_authentication_test(const char *auth_username, const char *client_digest, const char *ens_name_from_to, 
                                 const char *realm, const char *method, const char *uri, const char *nonce, int algo)
{
    printf("🔐 COMPLETE AUTHENTICATION TEST (C Implementation)\n");
    printf("==================================================\n");
    printf("Auth Username: %s\n", auth_username);
    printf("Client Digest: %s\n", client_digest);
    printf("ENS Name (To field): %s\n", ens_name_from_to);
    printf("SIP Parameters:\n");
    printf("  Realm: %s\n", realm);
    printf("  Method: %s\n", method);
    printf("  URI: %s\n", uri);
    printf("  Nonce: %s\n", nonce);
    printf("  Algo: %d (0=MD5, 1=SHA256, 2=SHA512)\n", algo);
    printf("\n");
    
    // Step 1: Authenticate with Oasis contract using authenticateUser
    printf("--- Step 1: Oasis Authentication ---\n");
    char auth_result[16];
    int auth_status = web3_oasis_authenticate_user(auth_username, realm, method, uri, nonce, algo, client_digest, auth_result);
    
    if (auth_status != 0) {
        if (auth_status == 1) {
            printf("❌ Oasis authentication FAILED - invalid credentials\n");
            return NOT_AUTHENTICATED;
        } else {
            printf("ERROR: Failed to call Oasis authentication service\n");
            return NOT_AUTHENTICATED;
        }
    }
    printf("✅ Oasis authentication PASSED\n");
    
    // Step 2: Check if ENS name format
    if (!strchr(ens_name_from_to, '.')) {
        printf("--- Non-ENS Authentication ---\n");
        printf("✅ Standard authentication successful\n");
        return AUTHENTICATED;
    }
    
    printf("--- Step 2: ENS Detection ---\n");
    printf("✅ Detected ENS name: %s\n", ens_name_from_to);
    
    char ens_resolved_address[43] = {0};
    char oasis_wallet_address[43] = {0};
    
    // Step 3: Get Oasis wallet address (using getWalletAddress for address comparison)
    printf("--- Step 3: Oasis Wallet Address Query ---\n");
    if (web3_oasis_get_wallet_address(auth_username, oasis_wallet_address) != 0) {
        printf("ERROR: Failed to get Oasis wallet address\n");
        return NOT_AUTHENTICATED;
    }
    
    if (strcmp(oasis_wallet_address, "0x0000000000000000000000000000000000000000") == 0) {
        printf("ERROR: User '%s' has no wallet address in Oasis contract\n", auth_username);
        return NOT_AUTHENTICATED;
    }
    
    // Step 4: Resolve ENS name
    printf("--- Step 4: ENS Resolution ---\n");
    if (web3_ens_resolve_address(ens_name_from_to, ens_resolved_address) != 0) {
        printf("ERROR: Failed to resolve ENS name\n");
        return ENS_NOT_VALID;
    }
    
    if (strcmp(ens_resolved_address, "0x0000000000000000000000000000000000000000") == 0) {
        printf("ERROR: ENS name '%s' does not resolve to any address\n", ens_name_from_to);
        return ENS_NOT_VALID;
    }
    
    // Step 5: Compare addresses
    printf("--- Step 5: Address Comparison ---\n");
    printf("Oasis Address: %s\n", oasis_wallet_address);
    printf("ENS Address:   %s\n", ens_resolved_address);
    
    if (strcasecmp(ens_resolved_address, oasis_wallet_address) == 0) {
        printf("✅ ADDRESSES MATCH!\n");
        return AUTHENTICATED;
    } else {
        printf("❌ ADDRESS MISMATCH!\n");
        return NOT_AUTHENTICATED;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 8) {
        printf("Usage: %s <auth_username> <client_digest> <ens_name_from_to> <realm> <method> <uri> <nonce>\n", argv[0]);
        printf("Example: %s jonathan f32a55131aa9fe5dc27eeea25f0b9194 jonathan123.eth sipserver.local REGISTER sip:sipserver.local 1234567890\n", argv[0]);
        printf("\nRequired Parameters:\n");
        printf("  auth_username    - Username for authentication\n");
        printf("  client_digest    - MD5 digest from client\n");
        printf("  ens_name_from_to - ENS name from SIP To field\n");
        printf("  realm           - SIP realm\n");
        printf("  method          - SIP method\n");
        printf("  uri             - SIP URI\n");
        printf("  nonce           - SIP nonce\n");
        printf("\nOptional Environment Variables (with defaults):\n");
        printf("  WEB3_RPC_URL           - Oasis RPC endpoint\n");
        printf("  WEB3_CONTRACT_ADDRESS  - Authentication contract address\n");
        printf("  ENS_RPC_URL           - Ethereum RPC for ENS resolution\n");
        printf("  ENS_REGISTRY_ADDRESS  - ENS registry contract address\n");
        printf("  ENS_NAME_WRAPPER_ADDRESS - ENS name wrapper contract\n");
        printf("  WEB3_DEBUG_MODE       - Enable debug output (1/true or 0/false)\n");
        printf("  WEB3_TIMEOUT          - Request timeout in seconds\n");
        printf("\nAll command line parameters are required - no default values.\n");
        printf("Configuration can be customized via environment variables for different networks.\n");
        return 1;
    }
    
    char *auth_username = argv[1];
    char *client_digest = argv[2];
    char *ens_name_from_to = argv[3];
    char *realm = argv[4];
    char *method = argv[5];
    char *uri = argv[6];
    char *nonce = argv[7];
    int algo = 0; // MD5
    
    printf("🧪 Complete SIP + Web3 + ENS Authentication Test (C Implementation)\n");
    printf("====================================================================\n");
    
    // Initialize configuration from environment variables
    init_config();
    
    // Initialize curl globally
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        printf("ERROR: Failed to initialize curl globally\n");
        return 1;
    }
    
    int result = complete_authentication_test(auth_username, client_digest, ens_name_from_to, 
                                             realm, method, uri, nonce, algo);
    
    printf("\n🎯 Final Result\n");
    printf("===============\n");
    switch (result) {
        case AUTHENTICATED:
            printf("✅ AUTHENTICATED (200) - Complete authentication successful!\n");
            break;
        case NOT_AUTHENTICATED:
            printf("❌ NOT_AUTHENTICATED (401) - Authentication failed\n");
            break;
        case ENS_NOT_VALID:
            printf("⚠️  ENS_NOT_VALID (402) - ENS domain not valid\n");
            break;
        default:
            printf("❓ UNKNOWN (%d) - Unexpected result\n", result);
            break;
    }
    
    // Cleanup curl
    curl_global_cleanup();
    
    return result == AUTHENTICATED ? 0 : 1;
} 