// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { IntentExecutionPolicy_Unit_Test } from "../IntentExecutionPolicy.t.sol";

/// @title IntentExecutionPolicy.checkAction Unit Tests
/// @notice Unit tests for the checkAction function
contract IntentExecutionPolicy_checkAction_Unit_Test is IntentExecutionPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                    WHITELISTED TARGET - ALWAYS PASSES
    //////////////////////////////////////////////////////////////*/

    /// @notice Test whitelisted target always returns SUCCESS regardless of selector
    function test_checkAction_whitelistedTarget_nonApprove() external view {
        // Arrange
        bytes4 transferSelector = bytes4(keccak256("transfer(address,uint256)"));
        bytes memory callData = abi.encodeWithSelector(transferSelector, address(0xBEEF), 100);

        // Act
        uint256 result = policy.checkAction(configId, address(0), whitelistedTarget1, 0, callData);

        // Assert
        assertEq(result, SUCCESS);
    }

    /// @notice Test whitelisted target passes even with approve and non-whitelisted spender
    function test_checkAction_whitelistedTarget_approve_anySpender() external {
        // Arrange
        address randomSpender = makeAddr("randomSpender");
        bytes memory callData = _encodeApprove(randomSpender, 100);

        // Act
        uint256 result = policy.checkAction(configId, address(0), whitelistedTarget1, 0, callData);

        // Assert - whitelisted target short-circuits to SUCCESS
        assertEq(result, SUCCESS);
    }

    /// @notice Test whitelisted target with value returns SUCCESS
    function test_checkAction_whitelistedTarget_withValue() external view {
        // Arrange
        bytes memory callData = abi.encodeWithSelector(bytes4(keccak256("deposit()")));

        // Act
        uint256 result =
            policy.checkAction(configId, address(0), whitelistedTarget1, 1 ether, callData);

        // Assert
        assertEq(result, SUCCESS);
    }

    /// @notice Test whitelisted target with empty calldata returns SUCCESS
    function test_checkAction_whitelistedTarget_emptyCalldata() external view {
        // Act
        uint256 result = policy.checkAction(configId, address(0), whitelistedTarget1, 0, "");

        // Assert
        assertEq(result, SUCCESS);
    }

    /*//////////////////////////////////////////////////////////////
                  NON-WHITELISTED TARGET - NON-APPROVE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test non-whitelisted target with non-approve selector returns FAILED
    function test_checkAction_nonWhitelistedTarget_nonApprove() external view {
        // Arrange
        bytes4 transferSelector = bytes4(keccak256("transfer(address,uint256)"));
        bytes memory callData = abi.encodeWithSelector(transferSelector, address(0xBEEF), 100);

        // Act
        uint256 result =
            policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, callData);

        // Assert
        assertEq(result, FAILED);
    }

    /// @notice Test non-whitelisted target with empty calldata returns FAILED
    function test_checkAction_nonWhitelistedTarget_emptyCalldata() external view {
        // Act
        uint256 result = policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, "");

        // Assert
        assertEq(result, FAILED);
    }

    /// @notice Test non-whitelisted target with short calldata (< 4 bytes) returns FAILED
    function test_checkAction_nonWhitelistedTarget_shortCalldata() external view {
        // Act
        uint256 result =
            policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, hex"aabbcc");

        // Assert
        assertEq(result, FAILED);
    }

    /*//////////////////////////////////////////////////////////////
              NON-WHITELISTED TARGET - APPROVE WITH PAYMASTER
    //////////////////////////////////////////////////////////////*/

    /// @notice Test approve with paymaster as spender on non-whitelisted target returns SUCCESS
    function test_checkAction_approve_paymasterSpender() external view {
        // Arrange
        bytes memory callData = _encodeApprove(paymasterAddr, 100);

        // Act
        uint256 result =
            policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, callData);

        // Assert
        assertEq(result, SUCCESS);
    }

    /*//////////////////////////////////////////////////////////////
          NON-WHITELISTED TARGET - APPROVE WITH WHITELISTED SPENDER
    //////////////////////////////////////////////////////////////*/

    /// @notice Test approve with whitelisted address as spender on non-whitelisted target
    function test_checkAction_approve_whitelistedSpender() external view {
        // Arrange
        bytes memory callData = _encodeApprove(whitelistedTarget2, 100);

        // Act
        uint256 result =
            policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, callData);

        // Assert
        assertEq(result, SUCCESS);
    }

    /*//////////////////////////////////////////////////////////////
        NON-WHITELISTED TARGET - APPROVE WITH NON-WHITELISTED SPENDER
    //////////////////////////////////////////////////////////////*/

    /// @notice Test approve with non-whitelisted spender on non-whitelisted target returns FAILED
    function test_checkAction_approve_nonWhitelistedSpender() external {
        // Arrange
        address randomSpender = makeAddr("randomSpender");
        bytes memory callData = _encodeApprove(randomSpender, 100);

        // Act
        uint256 result =
            policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, callData);

        // Assert
        assertEq(result, FAILED);
    }

    /*//////////////////////////////////////////////////////////////
              NON-WHITELISTED TARGET - APPROVE SHORT CALLDATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Test approve with calldata too short (only selector, no args) returns FAILED
    function test_checkAction_approve_shortCalldata() external view {
        // Arrange - only the selector, no spender argument
        bytes memory callData = _encodeCall(APPROVE_SELECTOR);

        // Act
        uint256 result =
            policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, callData);

        // Assert
        assertEq(result, FAILED);
    }

    /*//////////////////////////////////////////////////////////////
                       WHITELIST STATE CHANGES
    //////////////////////////////////////////////////////////////*/

    /// @notice Test checkAction reflects dynamic whitelist additions and removals
    function test_checkAction_reflectsWhitelistChanges() external {
        // Arrange
        address newTarget = makeAddr("newTarget");
        bytes memory callData = _encodeCall(bytes4(keccak256("foo()")));

        // Assert - initially denied
        assertEq(policy.checkAction(configId, address(0), newTarget, 0, callData), FAILED);

        // Act - whitelist it
        vm.prank(owner);
        policy.setWhitelistedTarget(newTarget, true);

        // Assert - now allowed
        assertEq(policy.checkAction(configId, address(0), newTarget, 0, callData), SUCCESS);

        // Act - remove it
        vm.prank(owner);
        policy.setWhitelistedTarget(newTarget, false);

        // Assert - denied again
        assertEq(policy.checkAction(configId, address(0), newTarget, 0, callData), FAILED);
    }

    /// @notice Test approve spender validation reflects paymaster changes
    function test_checkAction_approve_reflectsPaymasterChange() external {
        // Arrange - use non-whitelisted target to exercise approve path
        address newPaymaster = makeAddr("newPaymaster");
        bytes memory callData = _encodeApprove(newPaymaster, 100);

        // Assert - initially denied (newPaymaster not yet set)
        assertEq(
            policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, callData), FAILED
        );

        // Act
        vm.prank(owner);
        policy.setPaymaster(newPaymaster);

        // Assert - now allowed
        assertEq(
            policy.checkAction(configId, address(0), nonWhitelistedTarget, 0, callData), SUCCESS
        );
    }
}
