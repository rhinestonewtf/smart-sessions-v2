// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

/// @title BaseClaimPolicy.getExpiryBounds Unit Tests
/// @notice Unit tests for the getExpiryBounds function
contract BaseClaimPolicy_getExpiryBounds_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns correct bounds after initialization
    function test_getExpiryBounds_afterInitialization() external {
        // Arrange
        uint128 minExpiry = 1000;
        uint128 maxExpiry = 2000;
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeExpiryConfig(minExpiry, maxExpiry));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);

        // Assert
        assertEq(resultMin, minExpiry);
        assertEq(resultMax, maxExpiry);
    }

    /// @notice Test returns zeros when not initialized
    function test_getExpiryBounds_notInitialized() external view {
        // Act
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);

        // Assert
        assertEq(resultMin, 0);
        assertEq(resultMax, 0);
    }

    /// @notice Test returns zeros when expiry field is SKIP
    function test_getExpiryBounds_withModeSkip() external {
        // Arrange - expiry SKIP, arbiter CHECK_STORAGE
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        (uint128 minExpiry, uint128 maxExpiry) = policy.getExpiryBounds(configId, account);

        // Assert
        assertEq(minExpiry, 0);
        assertEq(maxExpiry, 0);
    }

    /// @notice Test with max uint128 values
    function test_getExpiryBounds_maxValues() external {
        // Arrange
        uint128 minExpiry = type(uint128).max - 1;
        uint128 maxExpiry = type(uint128).max;
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeExpiryConfig(minExpiry, maxExpiry));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);

        // Assert
        assertEq(resultMin, minExpiry);
        assertEq(resultMax, maxExpiry);
    }

    /// @notice Fuzz test for getExpiryBounds
    function testFuzz_getExpiryBounds(uint128 _minExpiry, uint128 _maxExpiry) external {
        vm.assume(_minExpiry <= _maxExpiry);
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeExpiryConfig(_minExpiry, _maxExpiry));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);

        // Assert
        assertEq(resultMin, _minExpiry);
        assertEq(resultMax, _maxExpiry);
    }
}
