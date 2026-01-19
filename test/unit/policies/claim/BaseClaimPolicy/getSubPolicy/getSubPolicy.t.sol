// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

/// @title BaseClaimPolicy.getSubPolicy Unit Tests
/// @notice Unit tests for the getSubPolicy function
contract BaseClaimPolicy_getSubPolicy_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns correct subpolicy after initialization
    function test_getSubPolicy_afterInitialization() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory subPolicyInitData = "";
        bytes memory subPolicyConfig = abi.encodePacked(
            uint8(1), // count
            uint8(FIELD_ARBITER),
            address(mockSubPolicy),
            uint256(subPolicyInitData.length),
            subPolicyInitData
        );
        bytes memory initData = abi.encodePacked(modeConfig, subPolicyConfig);

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address result = policy.getSubPolicy(configId, account, FIELD_ARBITER);

        // Assert
        assertEq(result, address(mockSubPolicy));
    }

    /// @notice Test returns address(0) when not initialized
    function test_getSubPolicy_notInitialized() external view {
        // Act
        address result = policy.getSubPolicy(configId, account, FIELD_ARBITER);

        // Assert
        assertEq(result, address(0));
    }

    /// @notice Test returns address(0) for unconfigured fieldId
    function test_getSubPolicy_unconfiguredFieldId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory subPolicyInitData = "";
        bytes memory subPolicyConfig = abi.encodePacked(
            uint8(1),
            uint8(FIELD_ARBITER),
            address(mockSubPolicy),
            uint256(subPolicyInitData.length),
            subPolicyInitData
        );
        bytes memory initData = abi.encodePacked(modeConfig, subPolicyConfig);
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        address result = policy.getSubPolicy(configId, account, FIELD_EXPIRY);

        // Assert
        assertEq(result, address(0));
    }

    /// @notice Test returns correct subpolicy per fieldId
    function test_getSubPolicy_multipleFieldIds() external {
        // Arrange
        MockSubPolicy mockSubPolicy2 = new MockSubPolicy();

        uint8[] memory fieldIds = new uint8[](2);
        uint8[] memory modes = new uint8[](2);
        fieldIds[0] = FIELD_ARBITER;
        fieldIds[1] = FIELD_EXPIRY;
        modes[0] = MODE_CHECK_SUBPOLICY;
        modes[1] = MODE_CHECK_SUBPOLICY;
        uint32 modeConfig = _buildModeConfig(fieldIds, modes);

        bytes memory subPolicyInitData = "";
        bytes memory subPolicyConfig = abi.encodePacked(
            uint8(2), // count
            uint8(FIELD_ARBITER),
            address(mockSubPolicy),
            uint256(subPolicyInitData.length),
            subPolicyInitData,
            uint8(FIELD_EXPIRY),
            address(mockSubPolicy2),
            uint256(subPolicyInitData.length),
            subPolicyInitData
        );
        bytes memory initData = abi.encodePacked(modeConfig, subPolicyConfig);

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getSubPolicy(configId, account, FIELD_ARBITER), address(mockSubPolicy));
        assertEq(policy.getSubPolicy(configId, account, FIELD_EXPIRY), address(mockSubPolicy2));
    }
}
