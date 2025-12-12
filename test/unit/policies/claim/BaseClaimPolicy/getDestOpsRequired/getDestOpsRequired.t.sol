// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

/// @title BaseClaimPolicy.getDestOpsRequired Unit Tests
/// @notice Unit tests for the getDestOpsRequired function
contract BaseClaimPolicy_getDestOpsRequired_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when not initialized
    function test_getDestOpsRequired_notInitialized() external view {
        // Act
        bool result = policy.getDestOpsRequired(configId, account, chainId1);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns true when required=true
    function test_getDestOpsRequired_requiredTrue() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = chainId1;
        required[0] = true;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeDestOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        bool result = policy.getDestOpsRequired(configId, account, chainId1);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when required=false
    function test_getDestOpsRequired_requiredFalse() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = chainId1;
        required[0] = false;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeDestOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        bool result = policy.getDestOpsRequired(configId, account, chainId1);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns correct value per chainId
    function test_getDestOpsRequired_multipleChainIds() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](2);
        bool[] memory required = new bool[](2);
        chainIds[0] = chainId1;
        chainIds[1] = chainId2;
        required[0] = true;
        required[1] = false;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeDestOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.getDestOpsRequired(configId, account, chainId1));
        assertFalse(policy.getDestOpsRequired(configId, account, chainId2));
    }

    /// @notice Test returns false for unconfigured chainId
    function test_getDestOpsRequired_unconfiguredChainId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = chainId1;
        required[0] = true;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeDestOpsConfig(chainIds, required));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool result = policy.getDestOpsRequired(configId, account, chainId2);

        // Assert
        assertFalse(result);
    }
}
