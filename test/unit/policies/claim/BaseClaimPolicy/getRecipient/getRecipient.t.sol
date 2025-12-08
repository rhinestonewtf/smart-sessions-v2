// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

/// @title BaseClaimPolicy.getRecipient Unit Tests
/// @notice Unit tests for the getRecipient function
contract BaseClaimPolicy_getRecipient_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns correct recipient after initialization
    function test_getRecipient_afterInitialization() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = chainId1;
        recipients[0] = recipient1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address result = policy.getRecipient(configId, account, chainId1);

        // Assert
        assertEq(result, recipient1);
    }

    /// @notice Test returns address(0) when not initialized
    function test_getRecipient_notInitialized() external view {
        // Act
        address result = policy.getRecipient(configId, account, chainId1);

        // Assert
        assertEq(result, address(0));
    }

    /// @notice Test returns address(0) for unconfigured chainId
    function test_getRecipient_unconfiguredChainId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = chainId1;
        recipients[0] = recipient1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        address result = policy.getRecipient(configId, account, chainId2);

        // Assert
        assertEq(result, address(0));
    }

    /// @notice Test returns correct recipient per chainId
    function test_getRecipient_multipleChainIds() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](2);
        address[] memory recipients = new address[](2);
        chainIds[0] = chainId1;
        chainIds[1] = chainId2;
        recipients[0] = recipient1;
        recipients[1] = recipient2;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getRecipient(configId, account, chainId1), recipient1);
        assertEq(policy.getRecipient(configId, account, chainId2), recipient2);
    }

    /// @notice Test catchall with chainId 0
    function test_getRecipient_catchallChainId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_CATCHALL);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = 0; // Catchall
        recipients[0] = recipient1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address result = policy.getRecipient(configId, account, 0);

        // Assert
        assertEq(result, recipient1);
    }
}
