// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    TokenInConfig,
    TokenOutConfig,
    ParamRules,
    ParamRule,
    TokenAmountConfig
} from "@policies/claim/types/DataTypes.sol";

/* //////////////////////////////////////////////////////////////
                            TYPES
//////////////////////////////////////////////////////////////*/

type PolicyConfig is uint8; // Bitmap to determine which conditions to check

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
        // Each bit represents a condition:
        // 0 - CHECK_HAS_EXECUTIONS
        // 1 - CHECK_QUALIFICATIONS
        // 2 - CHECK_RECIPIENT_AND_TARGET_CHAIN
        // 3 - CHECK_TOKEN_IN
        // 4 - CHECK_TOKEN_OUT
        uint8 conditionsBitmap;
        // CHECK_HAS_EXECUTIONS (condition 0)
        // No additional data needed for this condition
        // CHECK_PRE_CLAIM_OPS (condition 1)
        // CHECK_RECIPIENT_AND_TARGET_CHAIN (condition 2)
        // Target chain for recipient
        uint256 targetChainId;
        // Expected recipient address
        address recipient;
        // CHECK_TOKEN_IN (condition 3)
        // Can have multiple tokenIn configurations per chain
        TokenInConfig[] tokenInConfigs;
        // CHECK_TOKEN_OUT (condition 4)
        // Can have multiple tokenOut configurations per target chain
        TokenOutConfig[] tokenOutConfigs;
        // CHECK_QUALIFICATIONS (condition 5)
        // Qualification data configuration
        ParamRules qualificationConfig;
    }

    /* //////////////////////////////////////////////////////////////
                                 BITMAP
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns if the bitmap has the hasExecutions condition set
    /// @return true if the hasExecutions condition is set, false otherwise
    function hasCheckHasExecutions(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 1 != 0;
    }

    /// @notice Returns if the bitmap has the qualifications condition set
    /// @return true if the qualifications condition is set, false otherwise
    function hasCheckQualification(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 2 != 0;
    }

    /// @notice Returns if the bitmap has the recipient and targetChain condition set
    /// @return true if the recipient and targetChain condition is set, false otherwise
    function hasCheckRecipientAndTargetChain(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 4 != 0;
    }

    /// @notice Returns if the bitmap has the tokenIn condition set
    /// @return true if the tokenIn condition is set, false otherwise
    function hasCheckTokenIn(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 8 != 0;
    }

    /// @notice Returns if the bitmap has the tokenOut condition set
    /// @return true if the tokenOut condition is set, false otherwise
    function hasCheckTokenOut(PolicyConfig config) internal pure returns (bool) {
        return PolicyConfig.unwrap(config) & 16 != 0;
    }

    /* //////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes the targetChainId and recipient address from the initialization data
    /// @param initData The initialization data containing the targetChainId and recipient address
    function decodeRecipientAndTargetChain(bytes calldata initData)
        internal
        pure
        returns (uint256 targetChainId, address recipient, bytes calldata data)
    {
        targetChainId = uint256(bytes32(initData[0:32]));
        recipient = address(bytes20(initData[32:52]));
        data = initData[52:]; // Skip the first 52 bytes
    }

    /// @notice Decodes the tokenIn configuration from the initialization data
    function decodeTokenInConfig(bytes calldata initData)
        internal
        pure
        returns (TokenInConfig[] memory tokenInConfigs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        tokenInConfigs = new TokenInConfig[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 40; // 32 bytes for count + 40 bytes per TokenInConfig
            tokenInConfigs[i] = TokenInConfig({
                chainId: uint256(bytes32(initData[offset:offset + 32])),
                config: TokenAmountConfig({
                    token: address(bytes20(initData[offset + 32:offset + 52])),
                    minAmount: uint128(bytes16(initData[offset + 52:offset + 68])),
                    maxAmount: uint128(bytes16(initData[offset + 68:offset + 84]))
                })
            });
        }
        data = initData[32 + count * 40:]; // Skip the first 32 bytes and the tokenInConfigs
    }

    /// @notice Decodes the tokenOut configuration from the initialization data
    function decodeTokenOutConfig(bytes calldata initData)
        internal
        pure
        returns (TokenOutConfig[] memory tokenOutConfigs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        tokenOutConfigs = new TokenOutConfig[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 40; // 32 bytes for count + 40 bytes per TokenOutConfig
            tokenOutConfigs[i] = TokenOutConfig({
                targetChainId: uint256(bytes32(initData[offset:offset + 32])),
                config: TokenAmountConfig({
                    token: address(bytes20(initData[offset + 32:offset + 52])),
                    minAmount: uint128(bytes16(initData[offset + 52:offset + 68])),
                    maxAmount: uint128(bytes16(initData[offset + 68:offset + 84]))
                })
            });
        }
        data = initData[32 + count * 40:]; // Skip the first 32 bytes and the tokenOutConfigs
    }

    /// @notice Decodes the qualification configuration from the initialization data
    function decodeQualificationConfig(bytes calldata initData)
        internal
        pure
        returns (ParamRules memory rules, bytes calldata data, bytes32 qualificationTypehash)
    {
        // Decode qualification typehash from the first 32 bytes
        qualificationTypehash = bytes32(initData[0:32]);
        // Decode the root node index
        uint8 rootNodeIndex = uint8(initData[32]);
        // Decode the number of rules
        uint256 ruleCount = uint256(bytes32(initData[33:65]));
        ParamRule[] memory paramRules = new ParamRule[](ruleCount);
        uint256 offset = 65; // Start after rootNodeIndex, ruleCount and qualificationTypehash

        for (uint256 i = 0; i < ruleCount; i++) {
            paramRules[i] = ParamRule({
                condition: ParamCondition(uint8(initData[offset])),
                offset: uint64(bytes8(initData[offset + 1:offset + 9])),
                length: uint8(initData[offset + 9]),
                ref: bytes32(initData[offset + 10:offset + 42])
            });
            offset += 42; // Move to the next rule (1 byte condition + 8 bytes offset
                // + 1 byte length + 32 bytes ref)
        }

        // Decode packed nodes
        uint256 packedNodesLength = (initData.length - offset) / 32;
        uint256[] memory packedNodes = new uint256[](packedNodesLength);
        for (uint256 i = 0; i < packedNodesLength; i++) {
            packedNodes[i] = uint256(bytes32(initData[offset + i * 32:offset + (i + 1) * 32]));
        }

        rules = ParamRules({
            rootNodeIndex: rootNodeIndex, rules: paramRules, packedNodes: packedNodes
        });

        data = initData[offset + packedNodesLength * 32:]; // Remaining data after decoding
    }
}
