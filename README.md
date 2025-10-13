# auth_web3 Module

## Overview
The `auth_web3` module provides Web3-based authentication for OpenSIPS, enabling SIP authentication through blockchain technology and ENS (Ethereum Name Service) resolution.

## Features
- **ENS Authentication**: Authenticate users using Ethereum Name Service (ENS) domains
- **Blockchain Digest Verification**: Verify SIP digest authentication responses on-chain
- **Oasis Sapphire Integration**: Compatible with Oasis Sapphire testnet and mainnet
- **Standard SIP Compliance**: Works with standard SIP digest authentication flow

## Installation
1. Compile the module with OpenSIPS
2. Load the module in your OpenSIPS configuration
3. Configure Web3 parameters (RPC URLs, contract addresses)

## Configuration
```opensips
loadmodule "auth_web3.so"

modparam("auth_web3", "web3_authentication_rpc_url", "https://testnet.sapphire.oasis.dev")
modparam("auth_web3", "web3_authentication_contract_address", "0x...")
modparam("auth_web3", "web3_contract_debug_mode", 1)
```

## Usage
```opensips
# REGISTER authentication
if (is_method("REGISTER")) {
    if (!is_present_hf("Authorization")) {
        www_challenge("yourdomain.com");
        exit;
    }
    if (web3_www_authenticate("yourdomain.com", "REGISTER")) {
        # Authentication successful
    } else {
        send_reply(401, "Unauthorized");
        exit;
    }
}

# INVITE authentication  
if (is_method("INVITE")) {
    if (!is_present_hf("Authorization")) {
        www_challenge("yourdomain.com");
        exit;
    }
    if (web3_www_authenticate("yourdomain.com", "INVITE")) {
        # Authentication successful
    } else {
        send_reply(401, "Unauthorized");
        exit;
    }
}
```

## Requirements
- OpenSIPS 3.2+
- libcurl
- Access to Oasis Sapphire network (testnet or mainnet)
- ENS-enabled smart contract deployed on Oasis Sapphire

## License
GPL v2 (same as OpenSIPS)
