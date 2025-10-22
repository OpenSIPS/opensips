# Multi-Network ENS Configuration Guide

## Overview

The Web3 Authentication now supports **dual-network authentication**, allowing ENS contracts and Oasis authentication contracts to operate on different blockchain networks.

## Configuration Parameters

### Main Network (Oasis)
- `authentication_rpc_url`: RPC endpoint for Oasis authentication contract
- `authentication_contract_address`: Oasis authentication contract address

### ENS Network (Ethereum/Sepolia)
- `ens_rpc_url`: **NEW** - RPC endpoint for ENS queries (optional)
- `ens_registry_address`: ENS Registry contract address
- **Name Wrapper Detection**: Automatically detects Name Wrapper contracts dynamically

## Network Flow

### Scenario 1: Same Network (Fallback Mode)
```
ens_rpc_url = NULL (not configured)
```
- ✅ ENS queries → `authentication_rpc_url`
- ✅ Oasis queries → `authentication_rpc_url`
- Use case: Both contracts on same network

### Scenario 2: Different Networks (Multi-Network Mode)
```
authentication_rpc_url = "https://testnet.sapphire.oasis.dev"
ens_rpc_url = "https://eth.drpc.org"
```
- ✅ ENS queries → `ens_rpc_url` (Mainnet)
- ✅ Oasis queries → `authentication_rpc_url` (Oasis Sapphire)
- Use case: ENS on Ethereum, Oasis on Oasis network

## Common Network Configurations

### Production Setup
```bash
# Oasis Mainnet + Ethereum Mainnet
authentication_rpc_url = "https://sapphire.oasis.io"
ens_rpc_url = "https://eth.drpc.org"
ens_registry_address = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
# Name Wrapper is automatically detected - no configuration needed
```

### Testing Setup
```bash
# Oasis Testnet + Ethereum Sepolia
authentication_rpc_url = "https://testnet.sapphire.oasis.dev"
ens_rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
ens_registry_address = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
# Name Wrapper is automatically detected - no configuration needed
```

### Development Setup
```bash
# Both on same testnet
authentication_rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
# ens_rpc_url not set - will use authentication_rpc_url
```

## OpenSIPS Configuration Example

```opensips
loadmodule "auth_web3.so"

# Oasis authentication network
modparam("auth_web3", "authentication_rpc_url", "https://testnet.sapphire.oasis.dev")
modparam("auth_web3", "authentication_contract_address", "0xYourOasisContract")

# ENS network (Sepolia testnet)
modparam("auth_web3", "ens_rpc_url", "https://ethereum-sepolia-rpc.publicnode.com")
modparam("auth_web3", "ens_registry_address", "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e")
# Name Wrapper is automatically detected - no need to configure

modparam("auth_web3", "contract_debug_mode", 1)
```

## Testing Your Configuration

Use the provided test program to verify network configuration:

```bash
# Compile test program
make -f Makefile.test

# Test with your configuration
./test_ens_validation jonathan 123123 jonathan123.eth

# Check debug output for network usage:
# "ENS call using RPC: https://ethereum-sepolia-rpc.publicnode.com"
# "Oasis call using main RPC: https://testnet.sapphire.oasis.dev"
```

## Dynamic Name Wrapper Detection with Resolver Resolution

The module now **automatically detects** Name Wrapper contracts and resolves addresses through the ENS resolver system. This eliminates the need for the `ens_name_wrapper_address` parameter and provides more reliable address resolution.

### How It Works

1. **Query ENS Registry**: Call `owner(bytes32)` to get the owner address for the ENS domain
2. **Check Contract Identity**: Call `name()` function on the owner contract to verify if it's a Name Wrapper
3. **Verify Identity**: If the contract returns "NameWrapper", it's a wrapped domain
4. **Get Resolver**: Call ENS Registry `resolver(bytes32)` to get the resolver contract address
5. **Resolve Address**: Call resolver's `addr(bytes32)` to get the actual Ethereum address associated with the domain

### Why Resolver-Based Resolution?

- **Standard ENS Resolution**: Uses the official ENS resolver pattern (`resolver()` → `addr()`)
- **Consistent Behavior**: Works the same way as ENS resolution in other applications
- **Proper Delegation**: Respects the resolver set by the domain owner
- **Multi-Coin Support**: Resolvers can support multiple address types (future-proof)

### Benefits of Dynamic Detection

- **Network Agnostic**: Works on mainnet, testnets, and any future networks
- **No Configuration Needed**: One less parameter to configure
- **Future-Proof**: Automatically adapts to Name Wrapper and resolver upgrades
- **Zero Errors**: No risk of configuring wrong Name Wrapper addresses
- **Standard Compliant**: Follows EIP-137 (ENS) and EIP-181 (reverse resolution) standards

### Compatibility

- ✅ Works with both wrapped and unwrapped ENS domains
- ✅ Compatible with all Ethereum networks (mainnet, Sepolia, Holesky, etc.)
- ✅ Handles non-Name Wrapper owners gracefully (returns registry owner directly)
- ✅ Supports custom resolvers set by domain owners
- ✅ Works with Public Resolver and custom resolver implementations

## Benefits

1. **Network Separation**: Keep ENS queries on Ethereum while using Oasis for authentication
2. **Cost Optimization**: Use cheaper testnets for ENS during development
3. **Performance**: Separate network load between ENS and authentication calls
4. **Flexibility**: Easy migration between networks
5. **Backward Compatibility**: Existing single-network setups continue to work
6. **No API Keys Required**: PublicNode provides free, reliable RPC access
7. **Smart Detection**: Automatic Name Wrapper identification across all networks

## Troubleshooting

### Common Issues

1. **Network Connectivity**: Ensure PublicNode RPC is accessible from your server
2. **Network Mismatch**: Verify contract addresses match the configured network
3. **Fallback Behavior**: If `ens_rpc_url` is empty, ENS uses `authentication_rpc_url`
4. **Rate Limiting**: PublicNode has fair usage limits for free tier

### Debug Information

Enable debug mode to see which RPC is used for each call:
```
modparam("auth_web3", "contract_debug_mode", 1)
```

Look for log messages:
- `ENS call using RPC: [url] (ENS-specific: yes/no)`
- `Oasis call using main RPC: [url]`

### Why PublicNode?

- ✅ **Free**: No API keys required
- ✅ **Fast**: Low latency, high availability
- ✅ **Privacy-focused**: No tracking or data collection
- ✅ **Reliable**: Professional infrastructure
- ✅ **Multiple networks**: Supports many blockchain networks