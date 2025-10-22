// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { PermissionMode, ConfigBitMapLib } from "./SSXLib.sol";

/// @title SSXLibSet
/// @notice Helper library for constructing bytes32 configuration flags for ConfigBitMapLib
/// @dev This library provides builder functions to set individual flags in the bytes32 bitmap
///      Each function operates on a specific byte position to enable type-safe flag construction
///      Byte position constants are referenced from ConfigBitMapLib for consistency
library SSXLibSet {
    /* //////////////////////////////////////////////////////////////
                            BYTE POSITIONS
    //////////////////////////////////////////////////////////////*/

    // Reference byte position constants from ConfigBitMapLib (single source of truth)
    uint8 internal constant BYTE_IS_ENABLED = ConfigBitMapLib.BYTE_IS_ENABLED;
    uint8 internal constant BYTE_ANY_TARGET_CHAIN_ID = ConfigBitMapLib.BYTE_ANY_TARGET_CHAIN_ID;
    uint8 internal constant BYTE_PRE_CLAIM_OPS = ConfigBitMapLib.BYTE_PRE_CLAIM_OPS;
    uint8 internal constant BYTE_TARGET_OPS = ConfigBitMapLib.BYTE_TARGET_OPS;
    uint8 internal constant BYTE_CLAIM_EXPIRY = ConfigBitMapLib.BYTE_CLAIM_EXPIRY;
    uint8 internal constant BYTE_FILL_EXPIRY = ConfigBitMapLib.BYTE_FILL_EXPIRY;
    uint8 internal constant BYTE_RECIPIENT = ConfigBitMapLib.BYTE_RECIPIENT;
    uint8 internal constant BYTE_TOKEN_OUT = ConfigBitMapLib.BYTE_TOKEN_OUT;
    uint8 internal constant BYTE_TOKEN_IN = ConfigBitMapLib.BYTE_TOKEN_IN;

    /* //////////////////////////////////////////////////////////////
                          BUILDER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the global enable flag
    /// @param configFlag The current configuration bytes32
    /// @param enabled Whether the configuration is enabled (true) or disabled (false)
    /// @return Updated configuration bytes32
    function setEnabled(bytes32 configFlag, bool enabled) internal pure returns (bytes32) {
        return _setByte(configFlag, BYTE_IS_ENABLED, enabled ? bytes1(0x01) : bytes1(0x00));
    }

    /// @notice Sets the chain ID target flag
    /// @param configFlag The current configuration bytes32
    /// @param anyChainId Whether to allow any chain ID (true) or specific chain ID (false)
    /// @return Updated configuration bytes32
    function setAnyTargetChainId(bytes32 configFlag, bool anyChainId)
        internal
        pure
        returns (bytes32)
    {
        return _setByte(
            configFlag, BYTE_ANY_TARGET_CHAIN_ID, anyChainId ? bytes1(0x01) : bytes1(0x00)
        );
    }

    /// @notice Sets the preClaimOps inspection flag
    /// @param configFlag The current configuration bytes32
    /// @param inspect Whether to inspect preClaimOps (true) or skip inspection (false)
    /// @return Updated configuration bytes32
    function setPreClaimOps(bytes32 configFlag, bool inspect) internal pure returns (bytes32) {
        return _setByte(configFlag, BYTE_PRE_CLAIM_OPS, inspect ? bytes1(0x01) : bytes1(0x00));
    }

    /// @notice Sets the targetOps inspection flag
    /// @param configFlag The current configuration bytes32
    /// @param inspect Whether to inspect targetOps (true) or skip inspection (false)
    /// @return Updated configuration bytes32
    function setTargetOps(bytes32 configFlag, bool inspect) internal pure returns (bytes32) {
        return _setByte(configFlag, BYTE_TARGET_OPS, inspect ? bytes1(0x01) : bytes1(0x00));
    }

    /// @notice Sets the claim expiry inspection mode
    /// @param configFlag The current configuration bytes32
    /// @param mode The PermissionMode to use for claim expiry inspection
    /// @return Updated configuration bytes32
    function setClaimExpiryMode(bytes32 configFlag, PermissionMode mode)
        internal
        pure
        returns (bytes32)
    {
        return _setByte(configFlag, BYTE_CLAIM_EXPIRY, bytes1(uint8(mode)));
    }

    /// @notice Sets the fill expiry inspection mode
    /// @param configFlag The current configuration bytes32
    /// @param mode The PermissionMode to use for fill expiry inspection
    /// @return Updated configuration bytes32
    function setFillExpiryMode(bytes32 configFlag, PermissionMode mode)
        internal
        pure
        returns (bytes32)
    {
        return _setByte(configFlag, BYTE_FILL_EXPIRY, bytes1(uint8(mode)));
    }

    /// @notice Sets the recipient inspection mode
    /// @param configFlag The current configuration bytes32
    /// @param mode The PermissionMode to use for recipient inspection
    /// @return Updated configuration bytes32
    function setRecipientMode(bytes32 configFlag, PermissionMode mode)
        internal
        pure
        returns (bytes32)
    {
        return _setByte(configFlag, BYTE_RECIPIENT, bytes1(uint8(mode)));
    }

    /// @notice Sets the tokenOut inspection mode
    /// @param configFlag The current configuration bytes32
    /// @param mode The PermissionMode to use for tokenOut inspection
    /// @return Updated configuration bytes32
    function setTokenOutMode(bytes32 configFlag, PermissionMode mode)
        internal
        pure
        returns (bytes32)
    {
        return _setByte(configFlag, BYTE_TOKEN_OUT, bytes1(uint8(mode)));
    }

    /// @notice Sets the tokenIn inspection mode
    /// @param configFlag The current configuration bytes32
    /// @param mode The PermissionMode to use for tokenIn inspection
    /// @return Updated configuration bytes32
    function setTokenInMode(bytes32 configFlag, PermissionMode mode)
        internal
        pure
        returns (bytes32)
    {
        return _setByte(configFlag, BYTE_TOKEN_IN, bytes1(uint8(mode)));
    }

    /* //////////////////////////////////////////////////////////////
                          BATCH SETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a complete configuration in one call with all common flags
    /// @param enabled Global enable flag
    /// @param anyChainId Whether to allow any chain ID
    /// @param inspectPreClaimOps Whether to inspect preClaimOps
    /// @param inspectTargetOps Whether to inspect targetOps
    /// @param recipientMode Permission mode for recipient inspection
    /// @param tokenOutMode Permission mode for tokenOut inspection
    /// @param tokenInMode Permission mode for tokenIn inspection
    /// @return Complete configuration bytes32
    function createConfig(
        bool enabled,
        bool anyChainId,
        bool inspectPreClaimOps,
        bool inspectTargetOps,
        PermissionMode recipientMode,
        PermissionMode tokenOutMode,
        PermissionMode tokenInMode
    )
        internal
        pure
        returns (bytes32)
    {
        bytes32 config = bytes32(0);
        config = setEnabled(config, enabled);
        config = setAnyTargetChainId(config, anyChainId);
        config = setPreClaimOps(config, inspectPreClaimOps);
        config = setTargetOps(config, inspectTargetOps);
        config = setRecipientMode(config, recipientMode);
        config = setTokenOutMode(config, tokenOutMode);
        config = setTokenInMode(config, tokenInMode);
        return config;
    }

    /// @notice Creates a complete configuration with expiry modes included
    /// @param enabled Global enable flag
    /// @param anyChainId Whether to allow any chain ID
    /// @param inspectPreClaimOps Whether to inspect preClaimOps
    /// @param inspectTargetOps Whether to inspect targetOps
    /// @param claimExpiryMode Permission mode for claim expiry inspection
    /// @param fillExpiryMode Permission mode for fill expiry inspection
    /// @param recipientMode Permission mode for recipient inspection
    /// @param tokenOutMode Permission mode for tokenOut inspection
    /// @param tokenInMode Permission mode for tokenIn inspection
    /// @return Complete configuration bytes32
    function createConfigWithExpiry(
        bool enabled,
        bool anyChainId,
        bool inspectPreClaimOps,
        bool inspectTargetOps,
        PermissionMode claimExpiryMode,
        PermissionMode fillExpiryMode,
        PermissionMode recipientMode,
        PermissionMode tokenOutMode,
        PermissionMode tokenInMode
    )
        internal
        pure
        returns (bytes32)
    {
        bytes32 config = bytes32(0);
        config = setEnabled(config, enabled);
        config = setAnyTargetChainId(config, anyChainId);
        config = setPreClaimOps(config, inspectPreClaimOps);
        config = setTargetOps(config, inspectTargetOps);
        config = setClaimExpiryMode(config, claimExpiryMode);
        config = setFillExpiryMode(config, fillExpiryMode);
        config = setRecipientMode(config, recipientMode);
        config = setTokenOutMode(config, tokenOutMode);
        config = setTokenInMode(config, tokenInMode);
        return config;
    }

    /* //////////////////////////////////////////////////////////////
                          INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Internal helper to set a specific byte in the bytes32
    /// @param data The original bytes32 data
    /// @param byteIndex The index of the byte to set (0-31, where 31 is rightmost)
    /// @param value The byte value to set
    /// @return Updated bytes32 with the byte set
    function _setByte(bytes32 data, uint8 byteIndex, bytes1 value) private pure returns (bytes32) {
        // Create a mask to clear the target byte (all 1s except target byte)
        bytes32 mask = ~(bytes32(bytes1(0xff)) >> (byteIndex * 8));
        // Clear the target byte and set the new value
        return (data & mask) | (bytes32(value) >> (byteIndex * 8));
    }

    /* //////////////////////////////////////////////////////////////
                          CONVENIENCE PRESETS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a permissive configuration that ignores most checks
    /// @return Configuration bytes32 with enabled=true and all modes set to IGNORE
    function createPermissiveConfig() internal pure returns (bytes32) {
        return createConfig({
            enabled: true,
            anyChainId: true,
            inspectPreClaimOps: false,
            inspectTargetOps: false,
            recipientMode: PermissionMode.IGNORE,
            tokenOutMode: PermissionMode.IGNORE,
            tokenInMode: PermissionMode.IGNORE
        });
    }

    /// @notice Creates a restrictive configuration using local mappings
    /// @return Configuration bytes32 with enabled=true and LOCAL_MAPPING for tokens/recipient
    function createRestrictiveConfig() internal pure returns (bytes32) {
        return createConfig({
            enabled: true,
            anyChainId: false,
            inspectPreClaimOps: true,
            inspectTargetOps: true,
            recipientMode: PermissionMode.LOCAL_MAPPING,
            tokenOutMode: PermissionMode.LOCAL_MAPPING,
            tokenInMode: PermissionMode.LOCAL_MAPPING
        });
    }

    /// @notice Creates a disabled configuration (all checks fail)
    /// @return Configuration bytes32 with enabled=false
    function createDisabledConfig() internal pure returns (bytes32) {
        return bytes32(0); // All zeros means disabled
    }
}
