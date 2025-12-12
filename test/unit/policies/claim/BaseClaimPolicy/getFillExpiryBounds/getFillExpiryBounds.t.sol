// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseClaimPolicy.getFillExpiryBounds Unit Tests
/// @notice Unit tests for the getFillExpiryBounds function
contract BaseClaimPolicy_getFillExpiryBounds_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns zeros when not initialized
    function test_getFillExpiryBounds_notInitialized() external view {
        // Act
        (uint128 minFillExpiry, uint128 maxFillExpiry) =
            policy.getFillExpiryBounds(configId, account, chainId1);

        // Assert
        assertEq(minFillExpiry, 0);
        assertEq(maxFillExpiry, 0);
    }

    /// @notice Test returns correct bounds after initialization
    function test_getFillExpiryBounds_afterInitialization() external {
        // Arrange
        uint128 minFillExpiry = 100;
        uint128 maxFillExpiry = 500;
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory mins = new uint128[](1);
        uint128[] memory maxs = new uint128[](1);
        chainIds[0] = chainId1;
        mins[0] = minFillExpiry;
        maxs[0] = maxFillExpiry;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeFillExpiryConfig(chainIds, mins, maxs));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        (uint128 resultMin, uint128 resultMax) =
            policy.getFillExpiryBounds(configId, account, chainId1);

        // Assert
        assertEq(resultMin, minFillExpiry);
        assertEq(resultMax, maxFillExpiry);
    }

    /// @notice Test returns zeros for unconfigured chainId
    function test_getFillExpiryBounds_unconfiguredChainId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory mins = new uint128[](1);
        uint128[] memory maxs = new uint128[](1);
        chainIds[0] = chainId1;
        mins[0] = 100;
        maxs[0] = 500;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeFillExpiryConfig(chainIds, mins, maxs));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        (uint128 resultMin, uint128 resultMax) =
            policy.getFillExpiryBounds(configId, account, chainId2);

        // Assert
        assertEq(resultMin, 0);
        assertEq(resultMax, 0);
    }

    /// @notice Test returns correct bounds for multiple chainIds
    function test_getFillExpiryBounds_multipleChainIds() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](2);
        uint128[] memory mins = new uint128[](2);
        uint128[] memory maxs = new uint128[](2);
        chainIds[0] = chainId1;
        chainIds[1] = chainId2;
        mins[0] = 100;
        mins[1] = 200;
        maxs[0] = 500;
        maxs[1] = 600;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeFillExpiryConfig(chainIds, mins, maxs));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 min1, uint128 max1) = policy.getFillExpiryBounds(configId, account, chainId1);
        (uint128 min2, uint128 max2) = policy.getFillExpiryBounds(configId, account, chainId2);
        assertEq(min1, 100);
        assertEq(max1, 500);
        assertEq(min2, 200);
        assertEq(max2, 600);
    }

    /// @notice Test with CATCHALL mode (chainId 0)
    function test_getFillExpiryBounds_catchallMode() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_CATCHALL);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory mins = new uint128[](1);
        uint128[] memory maxs = new uint128[](1);
        chainIds[0] = 0; // Catchall
        mins[0] = 100;
        maxs[0] = 500;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeFillExpiryConfig(chainIds, mins, maxs));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        (uint128 resultMin, uint128 resultMax) = policy.getFillExpiryBounds(configId, account, 0);

        // Assert
        assertEq(resultMin, 100);
        assertEq(resultMax, 500);
    }

    /// @notice Fuzz test for getFillExpiryBounds
    function testFuzz_getFillExpiryBounds(
        uint256 _chainId,
        uint128 _minFillExpiry,
        uint128 _maxFillExpiry
    )
        external
    {
        vm.assume(_minFillExpiry <= _maxFillExpiry);
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory mins = new uint128[](1);
        uint128[] memory maxs = new uint128[](1);
        chainIds[0] = _chainId;
        mins[0] = _minFillExpiry;
        maxs[0] = _maxFillExpiry;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeFillExpiryConfig(chainIds, mins, maxs));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        (uint128 resultMin, uint128 resultMax) =
            policy.getFillExpiryBounds(configId, account, _chainId);

        // Assert
        assertEq(resultMin, _minFillExpiry);
        assertEq(resultMax, _maxFillExpiry);
    }
}
