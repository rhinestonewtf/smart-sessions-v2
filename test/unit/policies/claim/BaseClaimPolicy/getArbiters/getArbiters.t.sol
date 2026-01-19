// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

/// @title BaseClaimPolicy.getArbiters Unit Tests
/// @notice Unit tests for the getArbiters function
contract BaseClaimPolicy_getArbiters_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns arbiters after initialization
    function test_getArbiters_afterInitialization() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address[] memory result = policy.getArbiters(configId, account);

        // Assert
        assertEq(result.length, 1);
        assertEq(result[0], arbiter1);
    }

    /// @notice Test returns empty array when not initialized
    function test_getArbiters_notInitialized() external view {
        // Act
        address[] memory result = policy.getArbiters(configId, account);

        // Assert
        assertEq(result.length, 0);
    }

    /// @notice Test returns multiple arbiters
    function test_getArbiters_multipleArbiters() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](3);
        arbiters[0] = arbiter1;
        arbiters[1] = arbiter2;
        arbiters[2] = arbiter3;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address[] memory result = policy.getArbiters(configId, account);

        // Assert
        assertEq(result.length, 3);
        // Note: EnumerableSet may not preserve order, so we check contains
        assertTrue(_contains(result, arbiter1));
        assertTrue(_contains(result, arbiter2));
        assertTrue(_contains(result, arbiter3));
    }

    /// @notice Test returns empty when arbiter field is SKIP
    function test_getArbiters_withModeSkip() external {
        // Arrange - arbiter SKIP, expiry CHECK_STORAGE
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeExpiryConfig(100, 200));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address[] memory result = policy.getArbiters(configId, account);

        // Assert
        assertEq(result.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _contains(address[] memory arr, address value) internal pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == value) return true;
        }
        return false;
    }
}
