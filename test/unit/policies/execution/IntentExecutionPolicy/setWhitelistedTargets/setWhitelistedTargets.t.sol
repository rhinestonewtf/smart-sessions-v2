// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { IntentExecutionPolicy_Unit_Test } from "../IntentExecutionPolicy.t.sol";

// Contracts
import { IntentExecutionPolicy, TargetConfig } from "@policies/execution/IntentExecutionPolicy.sol";

/// @title IntentExecutionPolicy.setWhitelistedTargets Unit Tests
/// @notice Unit tests for the setWhitelistedTargets function
contract IntentExecutionPolicy_setWhitelistedTargets_Unit_Test is IntentExecutionPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test adding a single target to the whitelist
    function test_setWhitelistedTargets_addsTarget() external {
        // Arrange
        address newTarget = makeAddr("newTarget");
        assertFalse(policy.whitelistedTargets(newTarget));

        // Act
        vm.prank(owner);
        policy.setWhitelistedTargets(_targetConfig(newTarget, true));

        // Assert
        assertTrue(policy.whitelistedTargets(newTarget));
    }

    /// @notice Test removing a single target from the whitelist
    function test_setWhitelistedTargets_removesTarget() external {
        // Arrange
        assertTrue(policy.whitelistedTargets(whitelistedTarget1));

        // Act
        vm.prank(owner);
        policy.setWhitelistedTargets(_targetConfig(whitelistedTarget1, false));

        // Assert
        assertFalse(policy.whitelistedTargets(whitelistedTarget1));
    }

    /// @notice Test adding multiple targets in a single call
    function test_setWhitelistedTargets_addsMultipleTargets() external {
        // Arrange
        address targetA = makeAddr("targetA");
        address targetB = makeAddr("targetB");
        address targetC = makeAddr("targetC");
        assertFalse(policy.whitelistedTargets(targetA));
        assertFalse(policy.whitelistedTargets(targetB));
        assertFalse(policy.whitelistedTargets(targetC));

        TargetConfig[] memory entries = new TargetConfig[](3);
        entries[0] = TargetConfig({ target: targetA, allowed: true });
        entries[1] = TargetConfig({ target: targetB, allowed: true });
        entries[2] = TargetConfig({ target: targetC, allowed: true });

        // Act
        vm.prank(owner);
        policy.setWhitelistedTargets(entries);

        // Assert
        assertTrue(policy.whitelistedTargets(targetA));
        assertTrue(policy.whitelistedTargets(targetB));
        assertTrue(policy.whitelistedTargets(targetC));
    }

    /// @notice Test mixed add/remove in a single call
    function test_setWhitelistedTargets_mixedAddAndRemove() external {
        // Arrange
        address newTarget = makeAddr("newTarget");
        assertTrue(policy.whitelistedTargets(whitelistedTarget1));
        assertFalse(policy.whitelistedTargets(newTarget));

        TargetConfig[] memory entries = new TargetConfig[](2);
        entries[0] = TargetConfig({ target: whitelistedTarget1, allowed: false });
        entries[1] = TargetConfig({ target: newTarget, allowed: true });

        // Act
        vm.prank(owner);
        policy.setWhitelistedTargets(entries);

        // Assert
        assertFalse(policy.whitelistedTargets(whitelistedTarget1));
        assertTrue(policy.whitelistedTargets(newTarget));
    }

    /// @notice Test emits TargetWhitelisted event for each entry
    function test_setWhitelistedTargets_emitsEvents() external {
        // Arrange
        address targetA = makeAddr("targetA");
        address targetB = makeAddr("targetB");

        TargetConfig[] memory entries = new TargetConfig[](2);
        entries[0] = TargetConfig({ target: targetA, allowed: true });
        entries[1] = TargetConfig({ target: targetB, allowed: false });

        // Assert
        vm.expectEmit(true, false, false, true);
        emit IntentExecutionPolicy.TargetWhitelisted(targetA, true);
        vm.expectEmit(true, false, false, true);
        emit IntentExecutionPolicy.TargetWhitelisted(targetB, false);

        // Act
        vm.prank(owner);
        policy.setWhitelistedTargets(entries);
    }

    /// @notice Test reverts when caller is not owner
    function test_setWhitelistedTargets_revertsWhen_notOwner() external {
        // Arrange
        address notOwner = makeAddr("notOwner");

        // Act & Assert
        vm.prank(notOwner);
        vm.expectRevert();
        policy.setWhitelistedTargets(_targetConfig(makeAddr("target"), true));
    }
}
