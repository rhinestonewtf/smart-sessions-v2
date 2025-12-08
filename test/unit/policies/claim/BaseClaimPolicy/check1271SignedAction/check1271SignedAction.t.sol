// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

// Types
import { PolicyConfig } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title BaseClaimPolicy.check1271SignedAction Unit Tests
/// @notice Unit tests for the check1271SignedAction function
contract BaseClaimPolicy_check1271SignedAction_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    bytes32 internal testHash;
    bytes internal testData;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
        testHash = keccak256("test");
        testData = hex"1234";
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when _validateClaim returns true
    function test_check1271SignedAction_returnsTrue() external {
        // Arrange
        uint32 modeConfig = PolicyConfig.unwrap(DEFAULT_MINIMAL_CONFIG);
        bytes memory initData = abi.encodePacked(modeConfig);
        policy.initializeWithMultiplexer(account, configId, initData);
        policy.setValidateClaimReturnValue(true);

        // Act
        bool result =
            policy.check1271SignedAction(configId, address(0), account, testHash, testData);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when _validateClaim returns false
    function test_check1271SignedAction_returnsFalse() external {
        // Arrange
        uint32 modeConfig = PolicyConfig.unwrap(DEFAULT_MINIMAL_CONFIG);
        bytes memory initData = abi.encodePacked(modeConfig);
        policy.initializeWithMultiplexer(account, configId, initData);
        policy.setValidateClaimReturnValue(false);

        // Act
        bool result =
            policy.check1271SignedAction(configId, address(0), account, testHash, testData);

        // Assert
        assertFalse(result);
    }

    /// @notice Test works with uninitialized policy (default modeConfig)
    function test_check1271SignedAction_notInitialized() external {
        // Arrange
        policy.setValidateClaimReturnValue(true);

        // Act
        bool result =
            policy.check1271SignedAction(configId, address(0), account, testHash, testData);

        // Assert
        assertTrue(result);
    }

    /// @notice Test uses correct storage per configId/account
    function test_check1271SignedAction_isolatedStorage() external {
        // Arrange
        address account2 = makeAddr("account2");
        uint32 modeConfig1 = _buildModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        uint32 modeConfig2 = PolicyConfig.unwrap(DEFAULT_MINIMAL_CONFIG);

        address[] memory arbiters = new address[](1);
        arbiters[0] = arbiter1;

        bytes memory initData1 = abi.encodePacked(modeConfig1, _encodeArbiterConfig(arbiters));
        bytes memory initData2 = abi.encodePacked(modeConfig2);

        policy.initializeWithMultiplexer(account, configId, initData1);
        policy.initializeWithMultiplexer(account2, configId, initData2);

        policy.setValidateClaimReturnValue(true);

        // Act - both should work as _validateClaim returns true
        bool result1 =
            policy.check1271SignedAction(configId, address(0), account, testHash, testData);
        bool result2 =
            policy.check1271SignedAction(configId, address(0), account2, testHash, testData);

        // Assert
        assertTrue(result1);
        assertTrue(result2);
    }
}
