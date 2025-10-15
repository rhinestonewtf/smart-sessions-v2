# SSXLibSet Usage Examples

This document provides examples for using the `SSXLibSet` helper library to construct configuration flags for `ConfigBitMapLib`.

## Architecture

- **ConfigBitMapLib** (SSXLib.sol) - Defines byte position constants and inspection functions (single source of truth)
- **SSXLibSet** (SSXLibSet.sol) - References ConfigBitMapLib constants and provides builder functions for creating configurations

## Overview

The `ConfigBitMapLib` uses a `bytes32` as a bitmap to efficiently store multiple configuration flags. Each byte position in the `bytes32` represents a different configuration setting. The `SSXLibSet` library provides type-safe builder functions to construct these configuration flags.

## Byte Map Reference

| Byte Position | Flag | Values |
|--------------|------|--------|
| 31 | isEnabled | 0x00 (disabled) / 0x01 (enabled) |
| 30 | isAnyTargetChainId | 0x00 (specific) / 0x01 (any) |
| 28 | inspectPreClaimOps | 0x00 (skip) / 0x01 (inspect) |
| 27 | inspectTargetOps | 0x00 (skip) / 0x01 (inspect) |
| 26 | claimExpiryMode | PermissionMode enum (0-3) |
| 25 | fillExpiryMode | PermissionMode enum (0-3) |
| 3 | recipientMode | PermissionMode enum (0-3) |
| 2 | tokenOutMode | PermissionMode enum (0-3) |
| 1 | tokenInMode | PermissionMode enum (0-3) |

## PermissionMode Enum

```solidity
enum PermissionMode {
    IGNORE,           // 0 - Don't check this field
    COMPARE,          // 1 - Compare values directly
    LOCAL_MAPPING,    // 2 - Use local storage mapping
    EXTERNAL_POLICY   // 3 - Use external policy contract
}
```

## Usage Examples

### 1. Building Configuration Step-by-Step

```solidity
import { SSXLibSet } from "src/lib/SSXLibSet.sol";
import { PermissionMode } from "src/lib/SSXLib.sol";

// Start with empty config
bytes32 config = bytes32(0);

// Set individual flags
config = SSXLibSet.setEnabled(config, true);
config = SSXLibSet.setAnyTargetChainId(config, true);
config = SSXLibSet.setPreClaimOps(config, true);
config = SSXLibSet.setTargetOps(config, false);

// Set permission modes
config = SSXLibSet.setRecipientMode(config, PermissionMode.LOCAL_MAPPING);
config = SSXLibSet.setTokenOutMode(config, PermissionMode.IGNORE);
config = SSXLibSet.setTokenInMode(config, PermissionMode.LOCAL_MAPPING);
```

### 2. Create Complete Configuration in One Call

```solidity
bytes32 config = SSXLibSet.createConfig({
    enabled: true,
    anyChainId: true,
    inspectPreClaimOps: true,
    inspectTargetOps: false,
    recipientMode: PermissionMode.LOCAL_MAPPING,
    tokenOutMode: PermissionMode.IGNORE,
    tokenInMode: PermissionMode.LOCAL_MAPPING
});
```

### 3. Create Configuration with Expiry Modes

```solidity
bytes32 config = SSXLibSet.createConfigWithExpiry({
    enabled: true,
    anyChainId: false,
    inspectPreClaimOps: true,
    inspectTargetOps: true,
    claimExpiryMode: PermissionMode.COMPARE,
    fillExpiryMode: PermissionMode.COMPARE,
    recipientMode: PermissionMode.LOCAL_MAPPING,
    tokenOutMode: PermissionMode.LOCAL_MAPPING,
    tokenInMode: PermissionMode.IGNORE
});
```

### 4. Using Convenience Presets

#### Permissive Configuration (Allow Most Operations)
```solidity
// Creates config with:
// - enabled: true
// - anyChainId: true
// - inspectPreClaimOps: false
// - inspectTargetOps: false
// - All permission modes: IGNORE
bytes32 config = SSXLibSet.createPermissiveConfig();
```

#### Restrictive Configuration (Strict Checks)
```solidity
// Creates config with:
// - enabled: true
// - anyChainId: false
// - inspectPreClaimOps: true
// - inspectTargetOps: true
// - All permission modes: LOCAL_MAPPING
bytes32 config = SSXLibSet.createRestrictiveConfig();
```

#### Disabled Configuration
```solidity
// Creates config with all zeros (disabled)
bytes32 config = SSXLibSet.createDisabledConfig();
```

### 5. Modifying Existing Configuration

```solidity
// Start with permissive config
bytes32 config = SSXLibSet.createPermissiveConfig();

// Make it more restrictive
config = SSXLibSet.setAnyTargetChainId(config, false);
config = SSXLibSet.setRecipientMode(config, PermissionMode.COMPARE);
config = SSXLibSet.setTokenOutMode(config, PermissionMode.LOCAL_MAPPING);
```

### 6. Toggling Flags

```solidity
bytes32 config = SSXLibSet.createPermissiveConfig();

// Disable temporarily
config = SSXLibSet.setEnabled(config, false);

// Re-enable when ready
config = SSXLibSet.setEnabled(config, true);
```

## Common Patterns

### Pattern 1: Open Session with Token Restrictions

```solidity
// Allow any chain and recipient, but restrict tokens
bytes32 config = SSXLibSet.createConfig({
    enabled: true,
    anyChainId: true,
    inspectPreClaimOps: false,
    inspectTargetOps: false,
    recipientMode: PermissionMode.IGNORE,
    tokenOutMode: PermissionMode.LOCAL_MAPPING,
    tokenInMode: PermissionMode.LOCAL_MAPPING
});
```

### Pattern 2: Strict Session with All Checks

```solidity
// Require specific chain, check all operations, use mappings
bytes32 config = SSXLibSet.createConfigWithExpiry({
    enabled: true,
    anyChainId: false,
    inspectPreClaimOps: true,
    inspectTargetOps: true,
    claimExpiryMode: PermissionMode.COMPARE,
    fillExpiryMode: PermissionMode.COMPARE,
    recipientMode: PermissionMode.LOCAL_MAPPING,
    tokenOutMode: PermissionMode.LOCAL_MAPPING,
    tokenInMode: PermissionMode.LOCAL_MAPPING
});
```

### Pattern 3: External Policy Delegation

```solidity
// Delegate all checks to external policies
bytes32 config = SSXLibSet.createConfig({
    enabled: true,
    anyChainId: true,
    inspectPreClaimOps: false,
    inspectTargetOps: false,
    recipientMode: PermissionMode.EXTERNAL_POLICY,
    tokenOutMode: PermissionMode.EXTERNAL_POLICY,
    tokenInMode: PermissionMode.EXTERNAL_POLICY
});
```

## Reading Configuration Flags

Once a configuration is created, use `ConfigBitMapLib` to read the flags:

```solidity
import { ConfigBitMapLib } from "src/lib/SSXLib.sol";
using ConfigBitMapLib for bytes32;

// Check if enabled
bool enabled = config.isEnabled();

// Check chain ID flag
bool anyChain = config.isAnyTargetChainId();

// Inspect operations
bool shouldInspectPre = config.inspectPreClaimOps(preClaimOps);
bool shouldInspectTarget = config.inspectTargetOps(targetOps);

// Check expiry (with provided and max values)
bool validClaimExpiry = config.isInspectClaimExpiry(providedExpiry, maxExpiry);
bool validFillExpiry = config.isInspectFillExpiry(providedExpiry, maxExpiry);

// Inspect with storage
bool validRecipient = config.inspectRecipient(recipient, sponsor, $permission);
bool validTokenOut = config.inspectTokenOuts(tokenOutArray, $permission);
bool validTokenIn = config.inspectTokenIns(tokenInArray, $permission);
```

## Integration Example

```solidity
contract MyContract {
    using SSXLibSet for bytes32;
    using ConfigBitMapLib for bytes32;

    mapping(address => bytes32) public userConfigs;

    function setupUserPermissions(address user, bool isRestricted) external {
        bytes32 config;

        if (isRestricted) {
            config = SSXLibSet.createRestrictiveConfig();
        } else {
            config = SSXLibSet.createPermissiveConfig();
        }

        userConfigs[user] = config;
    }

    function updateUserChainRestriction(address user, bool anyChain) external {
        bytes32 config = userConfigs[user];
        config = SSXLibSet.setAnyTargetChainId(config, anyChain);
        userConfigs[user] = config;
    }

    function checkUserEnabled(address user) external view returns (bool) {
        return userConfigs[user].isEnabled();
    }
}
```

## Best Practices

1. **Use Batch Functions**: When setting multiple flags, use `createConfig()` or `createConfigWithExpiry()` for gas efficiency
2. **Use Presets**: Start with `createPermissiveConfig()` or `createRestrictiveConfig()` and modify as needed
3. **Test Thoroughly**: Use the test suite in `test/unit/lib/SSXLibSet/SSXLibSet.t.sol` as reference
4. **Document Configs**: Always document which flags are set for your use case
5. **Validate After Changes**: After modifying a config, verify it still meets your requirements using `ConfigBitMapLib` read functions
