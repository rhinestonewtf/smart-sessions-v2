// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

// Interfaces
import { IBaseClaimPolicy } from "@policies/claim/base/interfaces/IBaseClaimPolicy.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Mocks
import { MockBaseClaimPolicy } from "@mocks/MockBaseClaimPolicy.sol";
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";
import { InvalidSubPolicy } from "@mocks/InvalidSubPolicy.sol";

// Types
import {
    PolicyConfig,
    QualificationRulesStorage
} from "@policies/claim/base/types/BaseDataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseClaimPolicy.initializeWithMultiplexer Unit Tests
/// @notice Unit tests for the initializeWithMultiplexer function
contract BaseClaimPolicy_initializeWithMultiplexer_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event PolicyInitialized(
        ConfigId indexed configId, address indexed account, PolicyConfig modeConfig
    );

    /*//////////////////////////////////////////////////////////////
                          ALL FIELDS SKIP TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes with all fields SKIP (modeConfig = 0)
    function test_initializeWithMultiplexer_revertsWhen_allFieldsSkip() external {
        // Arrange
        uint32 modeConfig = 0;
        bytes memory initData = abi.encodePacked(modeConfig);

        // Act
        vm.expectRevert(IBaseClaimPolicy.InvalidConfigurationData.selector);
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Test emits PolicyInitialized event
    function test_initializeWithMultiplexer_emitsEvent() external {
        // Arrange
        uint32 modeConfig = PolicyConfig.unwrap(DEFAULT_MINIMAL_CONFIG);
        bytes memory initData = abi.encodePacked(modeConfig);

        // Act & Assert
        vm.expectEmit(true, true, false, true);
        emit PolicyInitialized(configId, account, PolicyConfig.wrap(modeConfig));
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Test reverts when initData is empty
    function test_initializeWithMultiplexer_revertsWhen_emptyData() external {
        // Arrange
        bytes memory initData = "";

        // Act & Assert
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Test reverts when initData has extra bytes
    function test_initializeWithMultiplexer_revertsWhen_extraBytes() external {
        // Arrange
        uint32 modeConfig = 0;
        bytes memory initData = abi.encodePacked(modeConfig, bytes1(0x00));

        // Act & Assert
        vm.expectRevert(IBaseClaimPolicy.InvalidConfigurationData.selector);
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Test reverts when initData is too short for modeConfig
    function test_initializeWithMultiplexer_revertsWhen_shortData() external {
        // Arrange
        bytes memory initData = hex"0000";

        // Act & Assert
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /*//////////////////////////////////////////////////////////////
                          ARBITER FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes single arbiter with STORAGE mode
    function test_initializeWithMultiplexer_arbiterStorage_single() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        assertFalse(policy.isArbiterWhitelisted(configId, account, arbiter2));
    }

    /// @notice Test initializes multiple arbiters with STORAGE mode
    function test_initializeWithMultiplexer_arbiterStorage_multiple() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](3);
        arbiters[0] = arbiter1;
        arbiters[1] = arbiter2;
        arbiters[2] = arbiter3;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter2));
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter3));
        address[] memory result = policy.getArbiters(configId, account);
        assertEq(result.length, 3);
    }

    /// @notice Test initializes zero arbiters with STORAGE mode
    function test_initializeWithMultiplexer_arbiterStorage_zero() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](0);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        address[] memory result = policy.getArbiters(configId, account);
        assertEq(result.length, 0);
    }

    /// @notice Test initializes arbiter with CATCHALL mode
    function test_initializeWithMultiplexer_arbiterCatchall() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_CATCHALL);
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
    }

    /// @notice Test allows address(0) as arbiter
    function test_initializeWithMultiplexer_arbiterStorage_zeroAddress() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = address(0);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, address(0)));
    }

    /// @notice Test deduplicates duplicate arbiters
    function test_initializeWithMultiplexer_arbiterStorage_deduplicates() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](3);
        arbiters[0] = arbiter1;
        arbiters[1] = arbiter1;
        arbiters[2] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        address[] memory result = policy.getArbiters(configId, account);
        assertEq(result.length, 1);
        assertEq(result[0], arbiter1);
    }

    /// @notice Test re-initialization adds to arbiter set
    function test_initializeWithMultiplexer_arbiterStorage_additive() external {
        // Arrange - first init
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters1 = new address[](1);
        arbiters1[0] = arbiter1;
        bytes memory initData1 = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters1));
        policy.initializeWithMultiplexer(account, configId, initData1);

        // Arrange - second init
        address[] memory arbiters2 = new address[](1);
        arbiters2[0] = arbiter2;
        bytes memory initData2 = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters2));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData2);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter2));
    }

    /// @notice Test reverts when arbiter data is incomplete
    function test_initializeWithMultiplexer_revertsWhen_incompleteArbiterData() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1));

        // Act & Assert
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Test reverts when count mismatch in arbiter data
    function test_initializeWithMultiplexer_revertsWhen_arbiterCountMismatch() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(2), arbiter1);

        // Act & Assert
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /*//////////////////////////////////////////////////////////////
                          EXPIRY FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes expiry with STORAGE mode
    function test_initializeWithMultiplexer_expiryStorage() external {
        // Arrange
        uint128 minExpiry = 1000;
        uint128 maxExpiry = 5000;
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeExpiryConfig(minExpiry, maxExpiry));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);
        assertEq(resultMin, minExpiry);
        assertEq(resultMax, maxExpiry);
    }

    /// @notice Test initializes expiry with max uint128 values
    function test_initializeWithMultiplexer_expiryStorage_maxValues() external {
        // Arrange
        uint128 minExpiry = 0;
        uint128 maxExpiry = type(uint128).max;
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeExpiryConfig(minExpiry, maxExpiry));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);
        assertEq(resultMin, minExpiry);
        assertEq(resultMax, maxExpiry);
    }

    /// @notice Test initializes expiry with CATCHALL mode
    function test_initializeWithMultiplexer_expiryCatchall() external {
        // Arrange
        uint128 minExpiry = 100;
        uint128 maxExpiry = 200;
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_CATCHALL);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeExpiryConfig(minExpiry, maxExpiry));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);
        assertEq(resultMin, minExpiry);
        assertEq(resultMax, maxExpiry);
    }

    /// @notice Test allows expiry min == max
    function test_initializeWithMultiplexer_expiryStorage_minEqualsMax() external {
        // Arrange
        uint128 expiry = 1000;
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeExpiryConfig(expiry, expiry));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);
        assertEq(resultMin, expiry);
        assertEq(resultMax, expiry);
    }

    /// @notice Test re-initialization overwrites expiry config
    function test_initializeWithMultiplexer_expiryStorage_overwrites() external {
        // Arrange - first init
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData1 = abi.encodePacked(modeConfig, _encodeExpiryConfig(100, 200));
        policy.initializeWithMultiplexer(account, configId, initData1);

        // Arrange - second init
        bytes memory initData2 = abi.encodePacked(modeConfig, _encodeExpiryConfig(300, 400));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData2);

        // Assert
        (uint128 min, uint128 max) = policy.getExpiryBounds(configId, account);
        assertEq(min, 300);
        assertEq(max, 400);
    }

    /// @notice Test reverts when expiry min > max
    function test_initializeWithMultiplexer_revertsWhen_expiryMinGreaterThanMax() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeExpiryConfig(1000, 100));

        // Act & Assert
        vm.expectRevert(BaseConfigLib.InvalidBounds.selector);
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Test reverts when expiry data is incomplete
    function test_initializeWithMultiplexer_revertsWhen_incompleteExpiryData() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint128(100));

        // Act & Assert
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /*//////////////////////////////////////////////////////////////
                         RECIPIENT FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes single recipient with STORAGE mode
    function test_initializeWithMultiplexer_recipientStorage_single() external {
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

        // Assert
        assertEq(policy.getRecipient(configId, account, chainId1), recipient1);
        assertEq(policy.getRecipient(configId, account, chainId2), address(0));
    }

    /// @notice Test initializes multiple recipients with STORAGE mode
    function test_initializeWithMultiplexer_recipientStorage_multiple() external {
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

    /// @notice Test initializes recipient with CATCHALL mode
    function test_initializeWithMultiplexer_recipientCatchall() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_CATCHALL);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = 0;
        recipients[0] = recipient1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getRecipient(configId, account, 0), recipient1);
    }

    /// @notice Test allows address(0) as recipient
    function test_initializeWithMultiplexer_recipientStorage_zeroAddress() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = chainId1;
        recipients[0] = address(0);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getRecipient(configId, account, chainId1), address(0));
    }

    /// @notice Test allows max uint256 as chainId
    function test_initializeWithMultiplexer_recipientStorage_maxChainId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = type(uint256).max;
        recipients[0] = recipient1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getRecipient(configId, account, type(uint256).max), recipient1);
    }

    /// @notice Test overwrites when same chainId appears twice
    function test_initializeWithMultiplexer_recipientStorage_overwritesSameChainId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](2);
        address[] memory recipients = new address[](2);
        chainIds[0] = chainId1;
        chainIds[1] = chainId1;
        recipients[0] = recipient1;
        recipients[1] = recipient2;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getRecipient(configId, account, chainId1), recipient2);
    }

    /// @notice Test re-initialization overwrites recipient config
    function test_initializeWithMultiplexer_recipientStorage_overwrites() external {
        // Arrange - first init
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = chainId1;
        recipients[0] = recipient1;
        bytes memory initData1 =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));
        policy.initializeWithMultiplexer(account, configId, initData1);

        // Arrange - second init
        recipients[0] = recipient2;
        bytes memory initData2 =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData2);

        // Assert
        assertEq(policy.getRecipient(configId, account, chainId1), recipient2);
    }

    /// @notice Test reverts when recipient data is incomplete
    function test_initializeWithMultiplexer_revertsWhen_incompleteRecipientData() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), chainId1);

        // Act & Assert
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /*//////////////////////////////////////////////////////////////
                        FILL EXPIRY FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes single fill expiry with STORAGE mode
    function test_initializeWithMultiplexer_fillExpiryStorage_single() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory minExpiries = new uint128[](1);
        uint128[] memory maxExpiries = new uint128[](1);
        chainIds[0] = chainId1;
        minExpiries[0] = 100;
        maxExpiries[0] = 500;
        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeFillExpiryConfig(chainIds, minExpiries, maxExpiries)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 resultMin, uint128 resultMax) =
            policy.getFillExpiryBounds(configId, account, chainId1);
        assertEq(resultMin, 100);
        assertEq(resultMax, 500);
    }

    /// @notice Test initializes multiple fill expiries with STORAGE mode
    function test_initializeWithMultiplexer_fillExpiryStorage_multiple() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](2);
        uint128[] memory minExpiries = new uint128[](2);
        uint128[] memory maxExpiries = new uint128[](2);
        chainIds[0] = chainId1;
        chainIds[1] = chainId2;
        minExpiries[0] = 100;
        minExpiries[1] = 200;
        maxExpiries[0] = 500;
        maxExpiries[1] = 600;
        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeFillExpiryConfig(chainIds, minExpiries, maxExpiries)
        );

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

    /// @notice Test initializes fill expiry with CATCHALL mode
    function test_initializeWithMultiplexer_fillExpiryCatchall() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_CATCHALL);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory minExpiries = new uint128[](1);
        uint128[] memory maxExpiries = new uint128[](1);
        chainIds[0] = 0;
        minExpiries[0] = 100;
        maxExpiries[0] = 500;
        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeFillExpiryConfig(chainIds, minExpiries, maxExpiries)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 resultMin, uint128 resultMax) = policy.getFillExpiryBounds(configId, account, 0);
        assertEq(resultMin, 100);
        assertEq(resultMax, 500);
    }

    /// @notice Test allows fill expiry min == max
    function test_initializeWithMultiplexer_fillExpiryStorage_minEqualsMax() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory minExpiries = new uint128[](1);
        uint128[] memory maxExpiries = new uint128[](1);
        chainIds[0] = chainId1;
        minExpiries[0] = 500;
        maxExpiries[0] = 500;
        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeFillExpiryConfig(chainIds, minExpiries, maxExpiries)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 resultMin, uint128 resultMax) =
            policy.getFillExpiryBounds(configId, account, chainId1);
        assertEq(resultMin, 500);
        assertEq(resultMax, 500);
    }

    /// @notice Test re-initialization overwrites fill expiry config
    function test_initializeWithMultiplexer_fillExpiryStorage_overwrites() external {
        // Arrange - first init
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory mins = new uint128[](1);
        uint128[] memory maxs = new uint128[](1);
        chainIds[0] = chainId1;
        mins[0] = 100;
        maxs[0] = 200;
        bytes memory initData1 =
            abi.encodePacked(modeConfig, _encodeFillExpiryConfig(chainIds, mins, maxs));
        policy.initializeWithMultiplexer(account, configId, initData1);

        // Arrange - second init
        mins[0] = 300;
        maxs[0] = 400;
        bytes memory initData2 =
            abi.encodePacked(modeConfig, _encodeFillExpiryConfig(chainIds, mins, maxs));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData2);

        // Assert
        (uint128 min, uint128 max) = policy.getFillExpiryBounds(configId, account, chainId1);
        assertEq(min, 300);
        assertEq(max, 400);
    }

    /// @notice Test reverts when fill expiry min > max
    function test_initializeWithMultiplexer_revertsWhen_fillExpiryMinGreaterThanMax() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        uint128[] memory mins = new uint128[](1);
        uint128[] memory maxs = new uint128[](1);
        chainIds[0] = chainId1;
        mins[0] = 1000;
        maxs[0] = 100;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeFillExpiryConfig(chainIds, mins, maxs));

        // Act & Assert
        vm.expectRevert(BaseConfigLib.InvalidBounds.selector);
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /*//////////////////////////////////////////////////////////////
                        TOKEN OUT FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes single token out with STORAGE mode
    function test_initializeWithMultiplexer_tokenOutStorage_single() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = chainId1;
        tokens[0] = token1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token1));
        assertFalse(policy.isTokenOutWhitelisted(configId, account, chainId1, token2));
    }

    /// @notice Test initializes multiple tokens for same chainId
    function test_initializeWithMultiplexer_tokenOutStorage_multipleTokensSameChain() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](3);
        address[] memory tokens = new address[](3);
        chainIds[0] = chainId1;
        chainIds[1] = chainId1;
        chainIds[2] = chainId1;
        tokens[0] = token1;
        tokens[1] = token2;
        tokens[2] = token3;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token1));
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token2));
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token3));
        address[] memory result = policy.getTokensOut(configId, account, chainId1);
        assertEq(result.length, 3);
    }

    /// @notice Test initializes tokens for multiple chainIds
    function test_initializeWithMultiplexer_tokenOutStorage_multipleChains() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](2);
        address[] memory tokens = new address[](2);
        chainIds[0] = chainId1;
        chainIds[1] = chainId2;
        tokens[0] = token1;
        tokens[1] = token2;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token1));
        assertFalse(policy.isTokenOutWhitelisted(configId, account, chainId1, token2));
        assertFalse(policy.isTokenOutWhitelisted(configId, account, chainId2, token1));
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId2, token2));
    }

    /// @notice Test initializes token out with CATCHALL mode
    function test_initializeWithMultiplexer_tokenOutCatchall() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_CATCHALL);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = 0;
        tokens[0] = token1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isTokenOutWhitelisted(configId, account, 0, token1));
    }

    /// @notice Test deduplicates duplicate tokens
    function test_initializeWithMultiplexer_tokenOutStorage_deduplicates() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](3);
        address[] memory tokens = new address[](3);
        chainIds[0] = chainId1;
        chainIds[1] = chainId1;
        chainIds[2] = chainId1;
        tokens[0] = token1;
        tokens[1] = token1;
        tokens[2] = token1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        address[] memory result = policy.getTokensOut(configId, account, chainId1);
        assertEq(result.length, 1);
    }

    /// @notice Test re-initialization adds to tokenOut set
    function test_initializeWithMultiplexer_tokenOutStorage_additive() external {
        // Arrange - first init
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = chainId1;
        tokens[0] = token1;
        bytes memory initData1 =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));
        policy.initializeWithMultiplexer(account, configId, initData1);

        // Arrange - second init
        tokens[0] = token2;
        bytes memory initData2 =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData2);

        // Assert
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token1));
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token2));
    }

    /*//////////////////////////////////////////////////////////////
                        ORIGIN OPS FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes origin ops required=true
    function test_initializeWithMultiplexer_originOpsStorage_requiredTrue() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = chainId1;
        required[0] = true;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeOriginOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.getOriginOpsRequired(configId, account, chainId1));
    }

    /// @notice Test initializes origin ops required=false
    function test_initializeWithMultiplexer_originOpsStorage_requiredFalse() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = chainId1;
        required[0] = false;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeOriginOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertFalse(policy.getOriginOpsRequired(configId, account, chainId1));
    }

    /// @notice Test initializes origin ops for multiple chainIds
    function test_initializeWithMultiplexer_originOpsStorage_multipleChains() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](2);
        bool[] memory required = new bool[](2);
        chainIds[0] = chainId1;
        chainIds[1] = chainId2;
        required[0] = true;
        required[1] = false;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeOriginOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.getOriginOpsRequired(configId, account, chainId1));
        assertFalse(policy.getOriginOpsRequired(configId, account, chainId2));
    }

    /// @notice Test initializes origin ops with CATCHALL mode
    function test_initializeWithMultiplexer_originOpsCatchall() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_CATCHALL);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = 0;
        required[0] = true;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeOriginOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.getOriginOpsRequired(configId, account, 0));
    }

    /// @notice Test re-initialization overwrites originOps config
    function test_initializeWithMultiplexer_originOpsStorage_overwrites() external {
        // Arrange - first init
        uint32 modeConfig = _buildModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = chainId1;
        required[0] = true;
        bytes memory initData1 =
            abi.encodePacked(modeConfig, _encodeOriginOpsConfig(chainIds, required));
        policy.initializeWithMultiplexer(account, configId, initData1);

        // Arrange - second init
        required[0] = false;
        bytes memory initData2 =
            abi.encodePacked(modeConfig, _encodeOriginOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData2);

        // Assert
        assertFalse(policy.getOriginOpsRequired(configId, account, chainId1));
    }

    /*//////////////////////////////////////////////////////////////
                         DEST OPS FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes dest ops required=true
    function test_initializeWithMultiplexer_destOpsStorage_requiredTrue() external {
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

        // Assert
        assertTrue(policy.getDestOpsRequired(configId, account, chainId1));
    }

    /// @notice Test initializes dest ops required=false
    function test_initializeWithMultiplexer_destOpsStorage_requiredFalse() external {
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

        // Assert
        assertFalse(policy.getDestOpsRequired(configId, account, chainId1));
    }

    /// @notice Test initializes dest ops for multiple chainIds
    function test_initializeWithMultiplexer_destOpsStorage_multipleChains() external {
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

    /// @notice Test initializes dest ops with CATCHALL mode
    function test_initializeWithMultiplexer_destOpsCatchall() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_DEST_OPS, MODE_CHECK_CATCHALL);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = 0;
        required[0] = true;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeDestOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.getDestOpsRequired(configId, account, 0));
    }

    /// @notice Test re-initialization overwrites destOps config
    function test_initializeWithMultiplexer_destOpsStorage_overwrites() external {
        // Arrange - first init
        uint32 modeConfig = _buildModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bool[] memory required = new bool[](1);
        chainIds[0] = chainId1;
        required[0] = true;
        bytes memory initData1 =
            abi.encodePacked(modeConfig, _encodeDestOpsConfig(chainIds, required));
        policy.initializeWithMultiplexer(account, configId, initData1);

        // Arrange - second init
        required[0] = false;
        bytes memory initData2 =
            abi.encodePacked(modeConfig, _encodeDestOpsConfig(chainIds, required));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData2);

        // Assert
        assertFalse(policy.getDestOpsRequired(configId, account, chainId1));
    }

    /*//////////////////////////////////////////////////////////////
                       QUALIFICATION FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes qualification with useArbiterHash=false
    function test_initializeWithMultiplexer_qualificationStorage_useArbiterHashFalse() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeQualificationConfig(chainId1, arbiter1, false));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        QualificationRulesStorage memory result =
            policy.getQualificationRules(configId, account, chainId1, arbiter1);
        assertFalse(result.useArbiterHash);
        assertEq(result.rules.rules.length, 1);
    }

    /// @notice Test initializes qualification with useArbiterHash=true
    function test_initializeWithMultiplexer_qualificationStorage_useArbiterHashTrue() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeQualificationConfig(chainId1, arbiter1, true));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        QualificationRulesStorage memory result =
            policy.getQualificationRules(configId, account, chainId1, arbiter1);
        assertTrue(result.useArbiterHash);
        assertEq(result.rules.rules.length, 1);
    }

    /// @notice Test initializes qualification for multiple chainId/arbiter pairs
    function test_initializeWithMultiplexer_qualificationStorage_multiplePairs() external {
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

    /*//////////////////////////////////////////////////////////////
                         SUBPOLICY FIELD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes single subpolicy
    function test_initializeWithMultiplexer_subPolicyStorage_single() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeSubPolicyConfig(FIELD_ARBITER, address(mockSubPolicy), "")
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getSubPolicy(configId, account, FIELD_ARBITER), address(mockSubPolicy));
    }

    /// @notice Test initializes multiple subpolicies
    function test_initializeWithMultiplexer_subPolicyStorage_multiple() external {
        // Arrange
        MockSubPolicy mockSubPolicy2 = new MockSubPolicy();

        uint8[] memory fieldIds = new uint8[](2);
        uint8[] memory modes = new uint8[](2);
        fieldIds[0] = FIELD_ARBITER;
        fieldIds[1] = FIELD_EXPIRY;
        modes[0] = MODE_CHECK_SUBPOLICY;
        modes[1] = MODE_CHECK_SUBPOLICY;
        uint32 modeConfig = _buildModeConfig(fieldIds, modes);

        uint8[] memory subFieldIds = new uint8[](2);
        address[] memory subAddrs = new address[](2);
        bytes[] memory subInitDatas = new bytes[](2);
        subFieldIds[0] = FIELD_ARBITER;
        subFieldIds[1] = FIELD_EXPIRY;
        subAddrs[0] = address(mockSubPolicy);
        subAddrs[1] = address(mockSubPolicy2);
        subInitDatas[0] = "";
        subInitDatas[1] = "";

        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeSubPolicyConfigMultiple(subFieldIds, subAddrs, subInitDatas)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getSubPolicy(configId, account, FIELD_ARBITER), address(mockSubPolicy));
        assertEq(policy.getSubPolicy(configId, account, FIELD_EXPIRY), address(mockSubPolicy2));
    }

    /// @notice Test re-initialization overwrites subPolicy config
    function test_initializeWithMultiplexer_subPolicyStorage_overwrites() external {
        // Arrange - first init
        MockSubPolicy mockSubPolicy2 = new MockSubPolicy();
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory initData1 = abi.encodePacked(
            modeConfig, _encodeSubPolicyConfig(FIELD_ARBITER, address(mockSubPolicy), "")
        );
        policy.initializeWithMultiplexer(account, configId, initData1);

        // Arrange - second init
        bytes memory initData2 = abi.encodePacked(
            modeConfig, _encodeSubPolicyConfig(FIELD_ARBITER, address(mockSubPolicy2), "")
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData2);

        // Assert
        assertEq(policy.getSubPolicy(configId, account, FIELD_ARBITER), address(mockSubPolicy2));
    }

    /// @notice Test reverts when subpolicy is address(0)
    function test_initializeWithMultiplexer_revertsWhen_subPolicyZeroAddress() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeSubPolicyConfig(FIELD_ARBITER, address(0), ""));

        // Act & Assert
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Test reverts when subpolicy is EOA
    function test_initializeWithMultiplexer_revertsWhen_subPolicyEOA() external {
        // Arrange
        address eoa = makeAddr("eoa");
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeSubPolicyConfig(FIELD_ARBITER, eoa, ""));

        // Act & Assert
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Test reverts when subpolicy doesn't implement I1271Policy
    function test_initializeWithMultiplexer_revertsWhen_subPolicyInvalidInterface() external {
        // Arrange
        InvalidSubPolicy invalidPolicy = new InvalidSubPolicy();
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeSubPolicyConfig(FIELD_ARBITER, address(invalidPolicy), "")
        );

        // Act & Assert
        vm.expectRevert(BaseConfigLib.InvalidSubPolicy.selector);
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /*//////////////////////////////////////////////////////////////
                       MULTIPLE FIELDS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes ARBITER then EXPIRY in order
    function test_initializeWithMultiplexer_multipleFields_arbiterThenExpiry() external {
        // Arrange
        uint8[] memory fieldIds = new uint8[](2);
        uint8[] memory modes = new uint8[](2);
        fieldIds[0] = FIELD_ARBITER;
        fieldIds[1] = FIELD_EXPIRY;
        modes[0] = MODE_CHECK_STORAGE;
        modes[1] = MODE_CHECK_STORAGE;
        uint32 modeConfig = _buildModeConfig(fieldIds, modes);

        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;

        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeArbiterConfig(arbiters), _encodeExpiryConfig(100, 200)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);
        assertEq(resultMin, 100);
        assertEq(resultMax, 200);
    }

    /// @notice Test initializes with skipped middle fields
    function test_initializeWithMultiplexer_multipleFields_skipsMiddle() external {
        // Arrange
        uint8[] memory fieldIds = new uint8[](2);
        uint8[] memory modes = new uint8[](2);
        fieldIds[0] = FIELD_ARBITER;
        fieldIds[1] = FIELD_RECIPIENT;
        modes[0] = MODE_CHECK_STORAGE;
        modes[1] = MODE_CHECK_STORAGE;
        uint32 modeConfig = _buildModeConfig(fieldIds, modes);

        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = chainId1;
        recipients[0] = recipient1;

        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeArbiterConfig(arbiters), _encodeRecipientConfig(chainIds, recipients)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        assertEq(policy.getRecipient(configId, account, chainId1), recipient1);
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);
        assertEq(resultMin, 0);
        assertEq(resultMax, 0);
    }

    /// @notice Test initializes many fields in correct order
    function test_initializeWithMultiplexer_multipleFields_manyFields() external {
        // Arrange
        uint8[] memory fieldIds = new uint8[](5);
        uint8[] memory modes = new uint8[](5);
        fieldIds[0] = FIELD_ARBITER;
        fieldIds[1] = FIELD_EXPIRY;
        fieldIds[2] = FIELD_RECIPIENT;
        fieldIds[3] = FIELD_FILL_EXPIRY;
        fieldIds[4] = FIELD_TOKEN_OUT;
        modes[0] = MODE_CHECK_STORAGE;
        modes[1] = MODE_CHECK_STORAGE;
        modes[2] = MODE_CHECK_STORAGE;
        modes[3] = MODE_CHECK_STORAGE;
        modes[4] = MODE_CHECK_STORAGE;
        uint32 modeConfig = _buildModeConfig(fieldIds, modes);

        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;

        uint256[] memory recipientChainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        recipientChainIds[0] = chainId1;
        recipients[0] = recipient1;

        uint256[] memory fillExpiryChainIds = new uint256[](1);
        uint128[] memory fillMins = new uint128[](1);
        uint128[] memory fillMaxs = new uint128[](1);
        fillExpiryChainIds[0] = chainId1;
        fillMins[0] = 50;
        fillMaxs[0] = 150;

        uint256[] memory tokenOutChainIds = new uint256[](1);
        address[] memory tokenOuts = new address[](1);
        tokenOutChainIds[0] = chainId1;
        tokenOuts[0] = token1;

        bytes memory initData = abi.encodePacked(
            modeConfig,
            _encodeArbiterConfig(arbiters),
            _encodeExpiryConfig(100, 200),
            _encodeRecipientConfig(recipientChainIds, recipients),
            _encodeFillExpiryConfig(fillExpiryChainIds, fillMins, fillMaxs),
            _encodeTokenOutConfig(tokenOutChainIds, tokenOuts)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        (uint128 expMin, uint128 expMax) = policy.getExpiryBounds(configId, account);
        assertEq(expMin, 100);
        assertEq(expMax, 200);
        assertEq(policy.getRecipient(configId, account, chainId1), recipient1);
        (uint128 fillMin, uint128 fillMax) = policy.getFillExpiryBounds(configId, account, chainId1);
        assertEq(fillMin, 50);
        assertEq(fillMax, 150);
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token1));
    }

    /// @notice Test all fields as SUBPOLICY
    function test_initializeWithMultiplexer_multipleFields_allSubPolicy() external {
        // Arrange
        uint32 modeConfig = type(uint32).max;

        uint8[] memory fieldIds = new uint8[](10);
        address[] memory subAddrs = new address[](10);
        bytes[] memory subInitDatas = new bytes[](10);

        for (uint8 i = 0; i < 10; i++) {
            fieldIds[i] = i;
            subAddrs[i] = address(mockSubPolicy);
            subInitDatas[i] = "";
        }

        bytes memory initData = abi.encodePacked(
            modeConfig, _encodeSubPolicyConfigMultiple(fieldIds, subAddrs, subInitDatas)
        );

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        for (uint8 i = 0; i < 10; i++) {
            assertEq(policy.getSubPolicy(configId, account, i), address(mockSubPolicy));
        }
    }

    /*//////////////////////////////////////////////////////////////
                       STORAGE ISOLATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test storage is isolated per configId
    function test_initializeWithMultiplexer_isolation_perConfigId() external {
        // Arrange
        ConfigId configId2 = ConfigId.wrap(bytes32(uint256(2)));

        uint32 modeConfig1 = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        uint32 modeConfig2 = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);

        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;

        bytes memory initData1 = abi.encodePacked(modeConfig1, _encodeArbiterConfig(arbiters));
        bytes memory initData2 = abi.encodePacked(modeConfig2, _encodeExpiryConfig(100, 200));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData1);
        policy.initializeWithMultiplexer(account, configId2, initData2);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        assertFalse(policy.isArbiterWhitelisted(configId2, account, arbiter1));

        (uint128 min1, uint128 max1) = policy.getExpiryBounds(configId, account);
        (uint128 min2, uint128 max2) = policy.getExpiryBounds(configId2, account);
        assertEq(min1, 0);
        assertEq(max1, 0);
        assertEq(min2, 100);
        assertEq(max2, 200);
    }

    /// @notice Test storage is isolated per account
    function test_initializeWithMultiplexer_isolation_perAccount() external {
        // Arrange
        address account2 = makeAddr("account2");

        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);

        address[] memory arbiters1 = new address[](1);
        arbiters1[0] = arbiter1;
        address[] memory arbiters2 = new address[](1);
        arbiters2[0] = arbiter2;

        bytes memory initData1 = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters1));
        bytes memory initData2 = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters2));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData1);
        policy.initializeWithMultiplexer(account2, configId, initData2);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, account, arbiter1));
        assertFalse(policy.isArbiterWhitelisted(configId, account, arbiter2));
        assertFalse(policy.isArbiterWhitelisted(configId, account2, arbiter1));
        assertTrue(policy.isArbiterWhitelisted(configId, account2, arbiter2));
    }

    /// @notice Test works with configId = bytes32(0)
    function test_initializeWithMultiplexer_isolation_zeroConfigId() external {
        // Arrange
        ConfigId zeroConfigId = ConfigId.wrap(bytes32(0));
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(account, zeroConfigId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(zeroConfigId, account, arbiter1));
    }

    /// @notice Test works with account = address(0)
    function test_initializeWithMultiplexer_isolation_zeroAccount() external {
        // Arrange
        address zeroAccount = address(0);
        uint32 modeConfig = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeArbiterConfig(arbiters));

        // Act
        policy.initializeWithMultiplexer(zeroAccount, configId, initData);

        // Assert
        assertTrue(policy.isArbiterWhitelisted(configId, zeroAccount, arbiter1));
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test for expiry initialization with valid bounds
    function testFuzz_initializeWithMultiplexer_expiry(
        uint128 _minExpiry,
        uint128 _maxExpiry
    )
        external
    {
        vm.assume(_minExpiry <= _maxExpiry);

        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeExpiryConfig(_minExpiry, _maxExpiry));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        (uint128 resultMin, uint128 resultMax) = policy.getExpiryBounds(configId, account);
        assertEq(resultMin, _minExpiry);
        assertEq(resultMax, _maxExpiry);
    }

    /// @notice Fuzz test for recipient initialization
    function testFuzz_initializeWithMultiplexer_recipient(
        uint256 _chainId,
        address _recipient
    )
        external
    {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory recipients = new address[](1);
        chainIds[0] = _chainId;
        recipients[0] = _recipient;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeRecipientConfig(chainIds, recipients));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);

        // Assert
        assertEq(policy.getRecipient(configId, account, _chainId), _recipient);
    }
}
