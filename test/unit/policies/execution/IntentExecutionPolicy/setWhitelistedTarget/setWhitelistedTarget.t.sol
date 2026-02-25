// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { IntentExecutionPolicy_Unit_Test } from "../IntentExecutionPolicy.t.sol";

// Contracts
import { IntentExecutionPolicy } from "@policies/execution/IntentExecutionPolicy.sol";

/// @title IntentExecutionPolicy.setWhitelistedTarget Unit Tests
/// @notice Unit tests for the setWhitelistedTarget function
contract IntentExecutionPolicy_setWhitelistedTarget_Unit_Test is IntentExecutionPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test adding a target to the whitelist
    function test_setWhitelistedTarget_addsTarget() external {
        // Arrange
        address newTarget = makeAddr("newTarget");
        assertFalse(policy.whitelistedTargets(newTarget));

        // Act
        vm.prank(owner);
        policy.setWhitelistedTarget(newTarget, true);

        // Assert
        assertTrue(policy.whitelistedTargets(newTarget));
    }

    /// @notice Test removing a target from the whitelist
    function test_setWhitelistedTarget_removesTarget() external {
        // Arrange
        assertTrue(policy.whitelistedTargets(whitelistedTarget1));

        // Act
        vm.prank(owner);
        policy.setWhitelistedTarget(whitelistedTarget1, false);

        // Assert
        assertFalse(policy.whitelistedTargets(whitelistedTarget1));
    }

    /// @notice Test emits TargetWhitelisted event when adding
    function test_setWhitelistedTarget_emitsEvent_whenAdding() external {
        // Arrange
        address newTarget = makeAddr("newTarget");

        // Assert
        vm.expectEmit(true, false, false, true);
        emit IntentExecutionPolicy.TargetWhitelisted(newTarget, true);

        // Act
        vm.prank(owner);
        policy.setWhitelistedTarget(newTarget, true);
    }

    /// @notice Test emits TargetWhitelisted event when removing
    function test_setWhitelistedTarget_emitsEvent_whenRemoving() external {
        // Assert
        vm.expectEmit(true, false, false, true);
        emit IntentExecutionPolicy.TargetWhitelisted(whitelistedTarget1, false);

        // Act
        vm.prank(owner);
        policy.setWhitelistedTarget(whitelistedTarget1, false);
    }

    /// @notice Test reverts when caller is not owner
    function test_setWhitelistedTarget_revertsWhen_notOwner() external {
        // Arrange
        address notOwner = makeAddr("notOwner");

        // Act & Assert
        vm.prank(notOwner);
        vm.expectRevert();
        policy.setWhitelistedTarget(makeAddr("target"), true);
    }
}
