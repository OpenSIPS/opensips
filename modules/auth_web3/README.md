---
title: "The Web3 Auth Module"
---

## Overview


The *auth_web3* module provides Web3-based authentication 
            for OpenSIPS, enabling SIP authentication through blockchain technology and 
            ENS (Ethereum Name Service) resolution.


This module integrates with the Oasis Sapphire blockchain network to verify 
            SIP digest authentication responses and resolve ENS names to wallet addresses.


### Dependencies


The following modules must be loaded before this module:


- *none* - No dependencies on other OpenSIPS modules


External libraries or applications:


- *libcurl* - For HTTP RPC calls to blockchain networks
- *OpenSSL* - For cryptographic operations


### ENS Technical Details


The module supports ENS (Ethereum Name Service) authentication with the following features:


- *Namehash Resolution* - Converts ENS names to namehash for contract calls
- *Multi-network Support* - ENS resolution on Ethereum mainnet, authentication on Oasis Sapphire
- *Wrapped Domain Support* - Handles .eth domains and custom TLDs
- *Resolver Path* - Follows standard ENS resolver contract pattern


### Authentication Function Comparison


The following table compares the authentication functions:


| Function | Header Type | Use Case | Challenge Function |
| --- | --- | --- | --- |
| web3_www_authenticate | Authorization | End-user authentication | www_challenge |
| web3_proxy_authenticate | Proxy-Authorization | Proxy authentication | proxy_challenge |


## Multi-Network Configuration


The auth_web3 module supports dual-network authentication, allowing ENS resolution
            and authentication to operate on different blockchain networks. This enables production
            deployments where ENS resolution happens on Ethereum mainnet while authentication
            happens on Oasis Sapphire.


### Network Operation Modes


#### Single Network Mode (Fallback)


When web3_ens_rpc_url is not configured, all blockchain operations use
                    the same RPC endpoint specified in web3_authentication_rpc_url. This mode
                    is suitable when both ENS and authentication contracts are deployed on
                    the same network.


```c
# Single network configuration
modparam("auth_web3", "web3_authentication_rpc_url", "https://ethereum-sepolia-rpc.publicnode.com")
modparam("auth_web3", "web3_authentication_contract_address", "0xYourContract")
# ens_rpc_url not set - will use authentication_rpc_url for ENS
                
```


#### Dual Network Mode


When web3_ens_rpc_url is configured, ENS resolution queries use the
                    specified Ethereum RPC endpoint while authentication queries use the
                    Oasis Sapphire RPC endpoint. This is the recommended production configuration.


```c
# Dual network configuration
# Authentication on Oasis Sapphire
modparam("auth_web3", "web3_authentication_rpc_url", "https://testnet.sapphire.oasis.dev")
modparam("auth_web3", "web3_authentication_contract_address", "0xYourOasisContract")

# ENS resolution on Ethereum
modparam("auth_web3", "web3_ens_rpc_url", "https://eth.drpc.org")
modparam("auth_web3", "web3_ens_registry_address", "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e")
                
```


### Common Network Configurations


#### Production Setup


Production deployments typically use Ethereum mainnet for ENS and
                    Oasis Sapphire mainnet for authentication:


```c
loadmodule "auth_web3.so"

# Oasis Sapphire Mainnet
modparam("auth_web3", "web3_authentication_rpc_url", "https://sapphire.oasis.io")
modparam("auth_web3", "web3_authentication_contract_address", "0xYourProductionContract")

# Ethereum Mainnet for ENS
modparam("auth_web3", "web3_ens_rpc_url", "https://eth.drpc.org")
modparam("auth_web3", "web3_ens_registry_address", "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e")

# Optional: Enable debug logging
modparam("auth_web3", "web3_contract_debug_mode", 0)
                
```


#### Testing Setup


For testing and development, use Sepolia testnet for ENS and
                    Oasis Sapphire testnet for authentication:


```c
loadmodule "auth_web3.so"

# Oasis Sapphire Testnet
modparam("auth_web3", "web3_authentication_rpc_url", "https://testnet.sapphire.oasis.dev")
modparam("auth_web3", "web3_authentication_contract_address", "0xYourTestContract")

# Ethereum Sepolia for ENS
modparam("auth_web3", "web3_ens_rpc_url", "https://ethereum-sepolia-rpc.publicnode.com")
modparam("auth_web3", "web3_ens_registry_address", "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e")

# Enable debug logging for testing
modparam("auth_web3", "web3_contract_debug_mode", 1)
                
```


### ENS Resolution Process


The module implements standard ENS resolution with automatic Name Wrapper detection:


1. *Query ENS Registry* - Call owner(bytes32) to get the domain owner
2. *Check Contract Identity* - Call name() on owner contract to detect Name Wrapper
3. *Get Resolver* - Call resolver(bytes32) on ENS Registry
4. *Resolve Address* - Call addr(bytes32) on resolver contract


This follows the standard ENS resolution pattern (EIP-137) and supports both
                wrapped and unwrapped domains across all Ethereum networks.


### Benefits of Multi-Network Configuration


- *Network Separation* - Keep ENS queries on Ethereum while using Oasis for authentication
- *Cost Optimization* - Use cheaper testnets for ENS during development
- *Performance* - Separate network load between ENS and authentication calls
- *Flexibility* - Easy migration between networks without code changes
- *Backward Compatibility* - Existing single-network setups continue to work


### Troubleshooting Multi-Network Setup


*Common Issues:*


- *Network Connectivity* - Ensure RPC endpoints are accessible from your server
- *Network Mismatch* - Verify contract addresses match the configured network
- *Fallback Behavior* - If ens_rpc_url is empty, ENS uses authentication_rpc_url
- *Rate Limiting* - Public RPC providers may have usage limits


*Debug Information:*


Enable debug mode to see which RPC is used for each call:


```c
modparam("auth_web3", "web3_contract_debug_mode", 1)
            
```


Look for log messages indicating network usage:


- ENS call using RPC: [url] (ENS-specific: yes/no)
- Oasis call using main RPC: [url]


## Functions


### web3_www_authenticate(realm, method)


Performs Web3-based authentication for WWW-Authenticate challenges.
                Verifies SIP digest authentication through blockchain contracts and ENS resolution.


This function extracts digest parameters from the Authorization header,
                resolves ENS names to wallet addresses, and verifies the digest response
                on the blockchain.


*Parameters:*


- *realm* (string, mandatory) - Authentication realm (usually the domain name)
- *method* (string, optional) - SIP method (REGISTER, INVITE, etc.). If not provided, uses the actual SIP method from the request


*Return value:*


- *1 (AUTHORIZED)* - Authentication successful
- *-1 (ERROR)* - Authentication failed or error occurred


*Example:*


```c
# REGISTER authentication
if (is_method("REGISTER")) {
    if (!$hdr(Authorization)) {
        www_challenge("$td", "0");
        exit;
    }
    if (web3_www_authenticate("$td", "REGISTER")) {
        # Authentication successful
        save("location");
        exit;
    } else {
        send_reply(401, "Unauthorized");
        exit;
    }
}
            
```


### web3_proxy_authenticate(realm, method)


Performs Web3-based authentication for Proxy-Authenticate challenges.
                Similar to web3_www_authenticate but for proxy authentication scenarios.


This function works identically to web3_www_authenticate but is designed
                for proxy authentication flows where Proxy-Authorization headers are used.


*Parameters:*


- *realm* (string, mandatory) - Authentication realm (usually the domain name)
- *method* (string, optional) - SIP method (REGISTER, INVITE, etc.). If not provided, uses the actual SIP method from the request


*Return value:*


- *1 (AUTHORIZED)* - Authentication successful
- *-1 (ERROR)* - Authentication failed or error occurred


*Example:*


```c
# INVITE authentication with proxy auth
if (is_method("INVITE")) {
    if (!$hdr(Authorization)) {
        www_challenge("$fd", "0");
        exit;
    }
    if (web3_proxy_authenticate("$fd", "INVITE")) {
        # Authentication successful
    } else {
        send_reply(407, "Proxy Authentication Required");
        exit;
    }
}
            
```


## Parameters


### authentication_rpc_url (string)


RPC URL for the blockchain network (e.g., Oasis Sapphire testnet or mainnet).
                This parameter specifies the endpoint for blockchain communication.


*Default value:* None (must be configured)


*Example:*


```c
modparam("auth_web3", "authentication_rpc_url", "https://testnet.sapphire.oasis.dev")
            
```


### authentication_contract_address (string)


Address of the smart contract that handles authentication verification.
                This contract must implement the authenticateUser function for digest verification.


*Default value:* None (must be configured)


*Example:*


```c
modparam("auth_web3", "authentication_contract_address", "0xE773BB79689379d32Ad1Db839868b6756B493aea")
            
```


### ens_rpc_url (string)


RPC URL for the Ethereum network used for ENS resolution.
                This should point to an Ethereum mainnet RPC endpoint for ENS name resolution.


*Default value:* None (must be configured)


*Example:*


```c
modparam("auth_web3", "ens_rpc_url", "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY")
            
```


### ens_registry_address (string)


Address of the ENS registry contract on Ethereum mainnet.
                This is used for resolving ENS names to wallet addresses.


*Default value:* 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e (ENS Registry)


*Example:*


```c
modparam("auth_web3", "ens_registry_address", "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e")
            
```


### contract_debug_mode (integer)


Enable debug logging for blockchain contract interactions.
                When enabled, detailed logs are generated for debugging purposes.


*Default value:* 0 (disabled)


*Example:*


```c
modparam("auth_web3", "contract_debug_mode", 1)
            
```


### rpc_timeout (integer)


Timeout in seconds for blockchain RPC calls.
                This parameter controls how long to wait for blockchain responses.


*Default value:* 10 seconds


*Example:*


```c
modparam("auth_web3", "rpc_timeout", 15)
            
```


## C API


The module provides a C-level API for other OpenSIPS modules to use Web3 authentication.


### bind_web3_auth(api)


Binds the Web3 authentication API to a module interface structure.
                This allows other modules to use Web3 authentication functions directly.


*Parameters:*


- *api* (web3_auth_api_t*) - Pointer to API structure to bind


*Return value:*


- *0* - Success
- *-1* - Failure


*Example:*


```c
#include "web3_auth_api.h"

web3_auth_api_t web3_api;

if (bind_web3_auth(&web3_api) < 0) {
    LM_ERR("Failed to bind Web3 auth API");
    return -1;
}

// Use web3_api.web3_digest_authenticate(...)
            
```


## FAQ


**Q: What is Web3 authentication and how does it work?**


Web3 authentication uses blockchain technology to verify SIP digest authentication.
                        Instead of storing passwords in a database, the module verifies authentication
                        responses against a smart contract deployed on the Oasis Sapphire blockchain.
                        ENS (Ethereum Name Service) names are resolved to wallet addresses for user identification.


**Q: What blockchain networks are supported?**


Currently, the module supports Oasis Sapphire testnet and mainnet.
                        The module can be extended to support other EVM-compatible networks
                        by modifying the RPC URL configuration.


**Q: How do I set up ENS names for authentication?**


Users need to register ENS names (e.g., alice.eth) and ensure their
                        wallet addresses are properly configured in the Oasis contract.
                        The module will resolve ENS names to wallet addresses and verify
                        that the wallet owner matches the authentication request.


**Q: What smart contract functions are required?**


The smart contract must implement the authenticateUser function with
                        the following signature:
                        authenticateUser(string username, string realm, string method, string uri, string nonce, bytes response)
                        This function should return true if the digest authentication is valid.


**Q: Is this module compatible with standard SIP clients?**


Yes, the module uses standard SIP digest authentication (RFC 3261).
                        SIP clients will work normally - they just need to use ENS names
                        as usernames instead of traditional usernames.


**Q: How do I debug authentication issues?**


Enable debug mode by setting web3_contract_debug_mode to 1.
                        This will provide detailed logs of blockchain interactions,
                        ENS resolution, and digest verification processes.


**Q: What are the performance implications?**


Each authentication requires blockchain RPC calls, which may add
                        latency compared to traditional database authentication.
                        Consider using appropriate RPC timeouts and potentially caching
                        ENS resolution results for better performance.


**Q: Can I use this module alongside traditional authentication?**


Yes, you can configure different realms or routes to use different
                        authentication methods. The module only handles requests that
                        explicitly call the web3_www_authenticate or web3_proxy_authenticate functions.


**Q: How do I handle environment variable overrides?**


The module supports environment variable overrides for container deployments:
                        WEB3_AUTH_RPC_URL, WEB3_AUTH_CONTRACT_ADDRESS, ENS_RPC_URL, ENS_REGISTRY_ADDRESS,
                        CONTRACT_DEBUG_MODE, and RPC_TIMEOUT. These override configuration file settings.


**Q: What happens if ENS resolution fails?**


If ENS resolution fails, the module falls back to direct Web3 authentication
                        using the username as a wallet address. This allows non-ENS users to still
                        authenticate using their wallet addresses directly.


**Q: How do I monitor authentication success rates?**


Enable debug mode and monitor OpenSIPS logs for authentication attempts.
                        The module logs detailed information about ENS resolution, contract calls,
                        and authentication results when debug mode is enabled.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
