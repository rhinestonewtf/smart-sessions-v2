// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { IntentExecutionPolicy_Unit_Test } from "../IntentExecutionPolicy.t.sol";

// Contracts
import { IntentExecutionPolicy } from "@policies/execution/IntentExecutionPolicy.sol";

/// @title IntentExecutionPolicy.setPaymaster Unit Tests
/// @notice Unit tests for the setPaymaster function
contract IntentExecutionPolicy_setPaymaster_Unit_Test is IntentExecutionPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test updating the paymaster address
    function test_setPaymaster_updatesPaymaster() external {
        // Arrange
        address newPaymaster = makeAddr("newPaymaster");

        // Act
        vm.prank(owner);
        policy.setPaymaster(newPaymaster);

        // Assert
        assertEq(policy.paymaster(), newPaymaster);
    }

    /// @notice Test emits PaymasterSet event
    function test_setPaymaster_emitsEvent() external {
        // Arrange
        address newPaymaster = makeAddr("newPaymaster");

        // Assert
        vm.expectEmit(true, false, false, true);
        emit IntentExecutionPolicy.PaymasterSet(newPaymaster);

        // Act
        vm.prank(owner);
        policy.setPaymaster(newPaymaster);
    }

    /// @notice Test reverts when caller is not owner
    function test_setPaymaster_revertsWhen_notOwner() external {
        // Arrange
        address notOwner = makeAddr("notOwner");

        // Act & Assert
        vm.prank(notOwner);
        vm.expectRevert();
        policy.setPaymaster(makeAddr("newPaymaster"));
    }
}
