// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    TokenInConfig,
    TokenOutConfig,
    TargetConfig,
    OpsRequirementConfig,
    QualificationConfig,
    ParamRules,
    ParamRule
} from "@policies/compact/types/DataTypes.sol";

/* //////////////////////////////////////////////////////////////
                            TYPES
//////////////////////////////////////////////////////////////*/

type PolicyConfig is uint16; // Bitmap to determine which conditions to check + catch-all flags

using { neQConfig as != } for PolicyConfig global;
using { eqConfig as == } for PolicyConfig global;

/// @notice Checks if the current config does not match the given config
function neQConfig(PolicyConfig self, PolicyConfig config) pure returns (bool) {
    return PolicyConfig.unwrap(self) != PolicyConfig.unwrap(config);
}

/// @notice Checks if the current config matches the given config
function eqConfig(PolicyConfig self, PolicyConfig config) pure returns (bool) {
    return PolicyConfig.unwrap(self) == PolicyConfig.unwrap(config);
}

/// @title Config Library
/// @notice Library for managing condition configurations in the MultiChainClaimPolicy
library ConfigLib {
    /* //////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialization data structure
    struct InitData {
        // Which conditions to enable
        // Bits 0-7: Condition checks
        // 0 - CHECK_ARBITER
        // 1 - CHECK_CLAIM_EXPIRES
        // 2 - CHECK_TOKEN_IN
        // 3 - CHECK_TARGET
        // 4 - CHECK_TOKEN_OUT
        // 5 - CHECK_HAS_ORIGIN_OPS
        // 6 - CHECK_HAS_DEST_OPS
        // 7 - CHECK_QUALIFICATION
        //
        // Bits 8-12: Catch-all flags (set automatically during setConfig)
        // 8 - HAS_TOKENIN_CATCHALL
        // 9 - HAS_TARGET_CATCHALL
        // 10 - HAS_TOKENOUT_CATCHALL
        // 11 - HAS_OPS_REQUIREMENT_CATCHALL
        // 12 - HAS_QUALIFICATION_CATCHALL
        uint16 conditionsBitmap;
        // CHECK_ARBITER (condition 0)
        address arbiter;
        // CHECK_CLAIM_EXPIRES (condition 1)
        uint128 minClaimExpires;
        uint128 maxClaimExpires;
        // CHECK_TOKEN_IN (condition 2)
        // Can have multiple tokenIn configurations per chain (chainId = 0 for catch-all)
        TokenInConfig[] tokenInConfigs;
        // CHECK_TARGET (condition 3)
        // Can have multiple target configurations per targetChainId (0 for catch-all)
        TargetConfig[] targetConfigs;
        // CHECK_TOKEN_OUT (condition 4)
        // Can have multiple tokenOut configurations per target chain
        TokenOutConfig[] tokenOutConfigs;
        // CHECK_HAS_ORIGIN_OPS / CHECK_HAS_DEST_OPS (conditions 5 & 6)
        // Can have multiple ops requirement configurations per chainId (0 for catch-all)
        OpsRequirementConfig[] opsRequirementConfigs;
        // CHECK_QUALIFICATION (condition 7)
        // Can have multiple qualification configurations per chainId (0 for catch-all)
        QualificationConfig[] qualificationConfigs;
    }

    /* //////////////////////////////////////////////////////////////
                                 BITMAP
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns if the bitmap has the arbiter condition set
    /// @return true if the arbiter condition is set, false otherwise
    function hasCheckArbiter(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 1 != 0;
    }

    /// @notice Returns if the bitmap has the claim expires condition set
    /// @return true if the claim expires condition is set, false otherwise
    function hasCheckClaimExpires(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 2 != 0;
    }

    /// @notice Returns if the bitmap has the tokenIn condition set
    /// @return true if the tokenIn condition is set, false otherwise
    function hasCheckTokenIn(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 4 != 0;
    }

    /// @notice Returns if the bitmap has the target condition set
    /// @return true if the target condition is set, false otherwise
    function hasCheckTarget(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 8 != 0;
    }

    /// @notice Returns if the bitmap has the tokenOut condition set
    /// @return true if the tokenOut condition is set, false otherwise
    function hasCheckTokenOut(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 16 != 0;
    }

    /// @notice Returns if the bitmap has the hasOriginOps condition set
    /// @return true if the hasOriginOps condition is set, false otherwise
    function hasCheckHasOriginOps(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 32 != 0;
    }

    /// @notice Returns if the bitmap has the hasDestOps condition set
    /// @return true if the hasDestOps condition is set, false otherwise
    function hasCheckHasDestOps(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 64 != 0;
    }

    /// @notice Returns if the bitmap has the qualifications condition set
    /// @return true if the qualifications condition is set, false otherwise
    function hasCheckQualification(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 128 != 0;
    }

    /* //////////////////////////////////////////////////////////////
                            CATCH-ALL FLAGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns if tokenIn has a catch-all configuration (chainId = 0)
    /// @return true if catch-all exists, false otherwise
    function hasTokenInCatchAll(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 256 != 0;
    }

    /// @notice Returns if target has a catch-all configuration (targetChainId = 0)
    /// @return true if catch-all exists, false otherwise
    function hasTargetCatchAll(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 512 != 0;
    }

    /// @notice Returns if tokenOut has a catch-all configuration (targetChainId = 0)
    /// @return true if catch-all exists, false otherwise
    function hasTokenOutCatchAll(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 1024 != 0;
    }

    /// @notice Returns if ops requirement has a catch-all configuration (chainId = 0)
    /// @return true if catch-all exists, false otherwise
    function hasOpsRequirementCatchAll(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 2048 != 0;
    }

    /// @notice Returns if qualification has a catch-all configuration (chainId = 0)
    /// @return true if catch-all exists, false otherwise
    function hasQualificationCatchAll(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 4096 != 0;
    }

    /* //////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes the arbiter address from the initialization data
    /// @param initData The initialization data containing the arbiter address
    /// @return arbiter The arbiter address
    /// @return data The remaining initialization data after decoding
    function decodeArbiterConfig(bytes calldata initData)
        internal
        pure
        returns (address arbiter, bytes calldata data)
    {
        arbiter = address(bytes20(initData[0:20]));
        data = initData[20:];
    }

    /// @notice Decodes the claim expires bounds from the initialization data
    /// @param initData The initialization data containing min/max claim expires
    /// @return packedExpires Packed expiration (uint128 min | uint128 max)
    /// @return data The remaining initialization data after decoding
    function decodeClaimExpiresConfig(bytes calldata initData)
        internal
        pure
        returns (uint256 packedExpires, bytes calldata data)
    {
        uint128 minExpires = uint128(bytes16(initData[0:16]));
        uint128 maxExpires = uint128(bytes16(initData[16:32]));
        packedExpires = packUint128(minExpires, maxExpires);
        data = initData[32:];
    }

    /// @notice Decodes the tokenIn configuration from the initialization data
    /// @dev Each TokenInConfig: 32 (chainId) + 20 (token) + 12 (lockTag) = 64 bytes
    /// @param initData The initialization data containing tokenIn configs
    /// @return configs Array of tokenIn configurations
    /// @return chainIds Array of chainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeTokenInConfig(bytes calldata initData)
        internal
        pure
        returns (TokenInConfig[] memory configs, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new TokenInConfig[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 64;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));
            configs[i] = TokenInConfig({
                token: address(bytes20(initData[offset + 32:offset + 52])),
                lockTag: bytes12(initData[offset + 52:offset + 64])
            });
        }

        data = initData[32 + count * 64:];
    }

    /// @notice Decodes the target configuration from the initialization data
    /// @dev Each TargetConfig: 32 (targetChainId) + 20 (recipient) + 16 (minFillExpiry) + 16
    /// (maxFillExpiry) = 84 bytes @param initData The initialization data containing target configs
    /// @return configs Array of target configurations
    /// @return chainIds Array of targetChainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeTargetConfig(bytes calldata initData)
        internal
        pure
        returns (TargetConfig[] memory configs, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new TargetConfig[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 84;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));

            uint128 minFillExpiry = uint128(bytes16(initData[offset + 52:offset + 68]));
            uint128 maxFillExpiry = uint128(bytes16(initData[offset + 68:offset + 84]));

            configs[i] = TargetConfig({
                recipient: address(bytes20(initData[offset + 32:offset + 52])),
                packedFillExpiry: packUint128(minFillExpiry, maxFillExpiry)
            });
        }

        data = initData[32 + count * 84:];
    }

    /// @notice Decodes the tokenOut configuration from the initialization data
    /// @dev Each TokenOutConfig: 32 (targetChainId) + 20 (token) = 52 bytes
    /// @param initData The initialization data containing tokenOut configs
    /// @return configs Array of tokenOut configurations
    /// @return chainIds Array of targetChainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeTokenOutConfig(bytes calldata initData)
        internal
        pure
        returns (TokenOutConfig[] memory configs, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new TokenOutConfig[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 52;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));
            configs[i] =
                TokenOutConfig({ token: address(bytes20(initData[offset + 32:offset + 52])) });
        }

        data = initData[32 + count * 52:];
    }

    /// @notice Decodes the ops requirement configuration from the initialization data
    /// @dev Each OpsRequirementConfig: 32 (chainId) + 1 (requireOriginOps) + 1 (requireDestOps) =
    /// 34 bytes @param initData The initialization data containing ops requirement configs
    /// @return configs Array of ops requirement configurations
    /// @return chainIds Array of chainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeOpsRequirementConfig(bytes calldata initData)
        internal
        pure
        returns (
            OpsRequirementConfig[] memory configs,
            uint256[] memory chainIds,
            bytes calldata data
        )
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new OpsRequirementConfig[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 34;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));
            configs[i] = OpsRequirementConfig({
                requireOriginOps: uint8(initData[offset + 32]) != 0,
                requireDestOps: uint8(initData[offset + 33]) != 0
            });
        }

        data = initData[32 + count * 34:];
    }

    /// @notice Decodes the qualification configuration from the initialization data
    /// @dev Format: count (32) + [chainId (32) + typehash (32) + rootNodeIndex (1) + ruleCount (32)
    /// + rules + packedNodes] * count @param initData The initialization data containing
    /// qualification configs
    /// @return configs Array of qualification configurations
    /// @return chainIds Array of chainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeQualificationConfig(bytes calldata initData)
        internal
        pure
        returns (
            QualificationConfig[] memory configs,
            uint256[] memory chainIds,
            bytes calldata data
        )
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new QualificationConfig[](count);
        chainIds = new uint256[](count);
        uint256 offset = 32;

        for (uint256 j = 0; j < count; j++) {
            // Decode chainId
            chainIds[j] = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode qualification typehash
            bytes32 qualificationTypehash = bytes32(initData[offset:offset + 32]);
            offset += 32;

            // Decode the root node index
            uint8 rootNodeIndex = uint8(initData[offset]);
            offset += 1;

            // Decode the number of rules
            uint256 ruleCount = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            ParamRule[] memory paramRules = new ParamRule[](ruleCount);

            for (uint256 i = 0; i < ruleCount; i++) {
                paramRules[i] = ParamRule({
                    condition: ParamCondition(uint8(initData[offset])),
                    offset: uint64(bytes8(initData[offset + 1:offset + 9])),
                    length: uint8(initData[offset + 9]),
                    ref: bytes32(initData[offset + 10:offset + 42])
                });
                offset += 42; // Move to the next rule
            }

            // Decode packed nodes length
            uint256 packedNodesLength = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            uint256[] memory packedNodes = new uint256[](packedNodesLength);
            for (uint256 i = 0; i < packedNodesLength; i++) {
                packedNodes[i] = uint256(bytes32(initData[offset:offset + 32]));
                offset += 32;
            }

            configs[j] = QualificationConfig({
                chainId: chainIds[j],
                qualificationTypehash: qualificationTypehash,
                rules: ParamRules({
                    rootNodeIndex: rootNodeIndex, rules: paramRules, packedNodes: packedNodes
                })
            });
        }

        data = initData[offset:];
    }

    /* //////////////////////////////////////////////////////////////
                          PACK/UNPACK HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Packs two uint128 values into a single uint256
    /// @param lower Lower 128 bits value (min)
    /// @param upper Upper 128 bits value (max)
    /// @return packed The packed uint256 value
    function packUint128(uint128 lower, uint128 upper) internal pure returns (uint256 packed) {
        packed = uint256(lower) | (uint256(upper) << 128);
    }

    /// @notice Unpacks a uint256 into two uint128 values
    /// @param packed The packed uint256 value
    /// @return lower Lower 128 bits value (min)
    /// @return upper Upper 128 bits value (max)
    function unpackUint128(uint256 packed) internal pure returns (uint128 lower, uint128 upper) {
        lower = uint128(packed);
        upper = uint128(packed >> 128);
    }
}
