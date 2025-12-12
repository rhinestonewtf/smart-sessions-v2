// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

// Types
import { QualificationRulesStorage } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title BaseClaimPolicy.getQualificationRules Unit Tests
/// @notice Unit tests for the getQualificationRules function
contract BaseClaimPolicy_getQualificationRules_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns empty struct when not initialized
    function test_getQualificationRules_notInitialized() external view {
        // Act
        QualificationRulesStorage memory result =
            policy.getQualificationRules(configId, account, chainId1, arbiter1);

        // Assert
        assertFalse(result.useArbiterHash);
        assertEq(result.rules.rootNodeIndex, 0);
        assertEq(result.rules.rules.length, 0);
        assertEq(result.rules.packedNodes.length, 0);
    }

    /// @notice Test returns rules after initialization
    function test_getQualificationRules_afterInitialization() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeQualificationConfig(chainId1, arbiter1, false));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        QualificationRulesStorage memory result =
            policy.getQualificationRules(configId, account, chainId1, arbiter1);

        // Assert
        assertFalse(result.useArbiterHash);
        assertEq(result.rules.rootNodeIndex, 0);
        assertEq(result.rules.rules.length, 1);
        assertEq(result.rules.packedNodes.length, 1);
    }

    /// @notice Test returns useArbiterHash=true when configured
    function test_getQualificationRules_withUseArbiterHash() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeQualificationConfig(chainId1, arbiter1, true));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        QualificationRulesStorage memory result =
            policy.getQualificationRules(configId, account, chainId1, arbiter1);

        // Assert
        assertTrue(result.useArbiterHash);
        assertEq(result.rules.rules.length, 1);
    }

    /// @notice Test returns empty struct for unconfigured chainId
    function test_getQualificationRules_unconfiguredChainId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeQualificationConfig(chainId1, arbiter1, false));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        QualificationRulesStorage memory result =
            policy.getQualificationRules(configId, account, chainId2, arbiter1);

        // Assert
        assertFalse(result.useArbiterHash);
        assertEq(result.rules.rules.length, 0);
    }

    /// @notice Test returns empty struct for unconfigured arbiter
    function test_getQualificationRules_unconfiguredArbiter() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeQualificationConfig(chainId1, arbiter1, false));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        QualificationRulesStorage memory result =
            policy.getQualificationRules(configId, account, chainId1, arbiter2);

        // Assert
        assertFalse(result.useArbiterHash);
        assertEq(result.rules.rules.length, 0);
    }

    /// @notice Test isolation per chainId/arbiter pair
    function test_getQualificationRules_isolatedPerPair() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);

        uint256[] memory chainIds = new uint256[](2);
        address[] memory arbiters = new address[](2);
        bool[] memory useArbiterHashes = new bool[](2);

        chainIds[0] = chainId1;
        chainIds[1] = chainId2;
        arbiters[0] = arbiter1;
        arbiters[1] = arbiter2;
        useArbiterHashes[0] = false;
        useArbiterHashes[1] = true;

        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeQualificationConfigMultiple(chainIds, arbiters, useArbiterHashes)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        QualificationRulesStorage memory result1 =
            policy.getQualificationRules(configId, account, chainId1, arbiter1);
        QualificationRulesStorage memory result2 =
            policy.getQualificationRules(configId, account, chainId2, arbiter2);

        assertFalse(result1.useArbiterHash);
        assertTrue(result2.useArbiterHash);
        assertEq(result1.rules.rules.length, 1);
        assertEq(result2.rules.rules.length, 1);
    }
}
