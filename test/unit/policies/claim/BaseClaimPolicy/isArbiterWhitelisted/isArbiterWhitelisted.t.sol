// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

/// @title BaseClaimPolicy.isArbiterWhitelisted Unit Tests
/// @notice Unit tests for the isArbiterWhitelisted function
contract BaseClaimPolicy_isArbiterWhitelisted_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true for whitelisted arbiter
    function test_isArbiterWhitelisted_whenWhitelisted() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool result = policy.isArbiterWhitelisted(configId, account, arbiter1);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false for non-whitelisted arbiter
    function test_isArbiterWhitelisted_whenNotWhitelisted() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool result = policy.isArbiterWhitelisted(configId, account, arbiter2);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns false when not initialized
    function test_isArbiterWhitelisted_notInitialized() external view {
        // Act
        bool result = policy.isArbiterWhitelisted(configId, account, arbiter1);

        // Assert
        assertFalse(result);
    }

    /// @notice Test with multiple whitelisted arbiters
    function test_isArbiterWhitelisted_multipleArbiters() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](2);
        arbiters[0] = arbiter1;
        arbiters[1] = arbiter2;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act & Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter2));
        assertFalse(policy.isArbiterWhitelisted(configId, account, arbiter3));
    }

    /// @notice Fuzz test for isArbiterWhitelisted
    function testFuzz_isArbiterWhitelisted(address _arbiter, address _checkArbiter) external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = _arbiter;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool result = policy.isArbiterWhitelisted(configId, account, _checkArbiter);

        // Assert
        assertEq(result, _arbiter == _checkArbiter);
    }
}
