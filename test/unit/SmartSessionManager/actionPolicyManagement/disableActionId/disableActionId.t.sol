// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionManager_Unit_Test } from
    "@test/unit/SmartSessionManager/SmartSessionManager.t.sol";

// Interfaces
import { ISmartSession } from "@smartsessions/ISmartSession.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";

// Types
import {
    Session,
    PolicyData,
    ActionData,
    PermissionId,
    ActionId,
    EMPTY_PERMISSIONID,
    PolicyType,
    FALLBACK_TARGET_FLAG
} from "@smartsessions/DataTypes.sol";

contract SmartSessionManager_disableActionId_Test is SmartSessionManager_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();

        // Initialize test variables
        testAccount = makeAddr("testAccount");
        testTarget = makeAddr("testTarget");
        testSelector = bytes4(keccak256("testFunction()"));
        testActionId = testTarget.toActionId(testSelector);

        // Enable a basic session to get a valid permission ID
        validPermissionId = enableBasicSession(testAccount);

        // Enable some test actions with policies for testing
        enableTestActionWithPolicies();
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    ///-------------------------------///
    /// 1. When permission is not enabled ///
    ///-------------------------------///

    function test_disableActionId_RevertWhen_PermissionNotEnabled() public {
        // Arrange
        PermissionId invalidPermissionId = PermissionId.wrap(keccak256("invalid"));

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert with PermissionIdNotEnabled
        smartSessionManager.disableActionId(invalidPermissionId, testActionId);
    }

    ///-------------------------------///
    /// 2. When permission is enabled ///
    ///-------------------------------///

    function test_disableActionId_Success_ActionIdNotEnabled() public {
        // Arrange
        ActionId nonExistentActionId =
            makeAddr("nonExistent").toActionId(bytes4(keccak256("nonExistent()")));

        // Verify action is not enabled
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, nonExistentActionId
            ),
            "Action should not be enabled initially"
        );

        // Get initial enabled actions count
        bytes32[] memory initialActions =
            smartSessionManager.getEnabledActions(testAccount, validPermissionId);
        uint256 initialCount = initialActions.length;

        // Act
        vm.prank(testAccount);
        smartSessionManager.disableActionId(validPermissionId, nonExistentActionId);

        // Assert - Should complete without changes
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, nonExistentActionId
            ),
            "Action should still not be enabled"
        );

        // Verify no change in enabled actions count
        bytes32[] memory finalActions =
            smartSessionManager.getEnabledActions(testAccount, validPermissionId);
        assertEq(finalActions.length, initialCount, "Enabled actions count should not change");
    }

    function test_disableActionId_Success_ActionIdHasPolicies() public {
        // Arrange - Enable action with policies
        ActionId actionWithPolicies = enableActionWithSinglePolicy();

        // Verify action is enabled and has policies
        assertTrue(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, actionWithPolicies
            ),
            "Action should be enabled initially"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionWithPolicies, address(sudoPolicy)
            ),
            "Policy should be enabled initially"
        );

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.ActionIdDisabled(validPermissionId, actionWithPolicies, testAccount);
        smartSessionManager.disableActionId(validPermissionId, actionWithPolicies);

        // Assert
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, actionWithPolicies
            ),
            "Action should be disabled"
        );
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionWithPolicies, address(sudoPolicy)
            ),
            "Policy should be disabled"
        );

        // Verify no policies remain
        address[] memory remainingPolicies = smartSessionManager.getActionPolicies(
            testAccount, validPermissionId, actionWithPolicies
        );
        assertEq(remainingPolicies.length, 0, "Should have no policies remaining");
    }

    function test_disableActionId_Success_ActionIdNoPolicies() public {
        // Arrange - First disable all policies of an action to have an action with no policies
        ActionId actionWithNoPolicies = enableActionWithSinglePolicy();

        // Remove the policy but not the action ID (simulating a state where action exists without
        // policies)
        vm.prank(testAccount);
        address[] memory policiesToRemove = new address[](1);
        policiesToRemove[0] = address(sudoPolicy);
        smartSessionManager.disableActionPolicies(
            validPermissionId, actionWithNoPolicies, policiesToRemove
        );

        // Verify action is disabled after policy removal
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, actionWithNoPolicies
            ),
            "Action should already be disabled after policy removal"
        );

        // Act - Try to disable the action ID again
        vm.prank(testAccount);
        smartSessionManager.disableActionId(validPermissionId, actionWithNoPolicies);

        // Assert - Should complete without errors (action was already disabled)
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, actionWithNoPolicies
            ),
            "Action should remain disabled"
        );
    }

    function test_disableActionId_Success_ActionIdWithMultiplePolicies() public {
        // Arrange - Enable action with multiple policies
        ActionId actionWithMultiplePolicies = enableActionWithMultiplePolicies();

        // Verify action is enabled and has multiple policies
        assertTrue(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, actionWithMultiplePolicies
            ),
            "Action should be enabled initially"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionWithMultiplePolicies, address(sudoPolicy)
            ),
            "SudoPolicy should be enabled initially"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionWithMultiplePolicies, address(noPolicy)
            ),
            "NoPolicy should be enabled initially"
        );

        // Get initial policy count
        address[] memory initialPolicies = smartSessionManager.getActionPolicies(
            testAccount, validPermissionId, actionWithMultiplePolicies
        );
        assertEq(initialPolicies.length, 2, "Should start with two policies");

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.ActionIdDisabled(
            validPermissionId, actionWithMultiplePolicies, testAccount
        );
        smartSessionManager.disableActionId(validPermissionId, actionWithMultiplePolicies);

        // Assert - All policies should be removed
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, actionWithMultiplePolicies
            ),
            "Action should be disabled"
        );
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionWithMultiplePolicies, address(sudoPolicy)
            ),
            "SudoPolicy should be disabled"
        );
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionWithMultiplePolicies, address(noPolicy)
            ),
            "NoPolicy should be disabled"
        );

        // Verify no policies remain
        address[] memory finalPolicies = smartSessionManager.getActionPolicies(
            testAccount, validPermissionId, actionWithMultiplePolicies
        );
        assertEq(finalPolicies.length, 0, "Should have no policies remaining");
    }

    ///-------------------------------///
    /// 3. Edge cases               ///
    ///-------------------------------///

    function test_disableActionId_Success_DisableSameActionTwice() public {
        // Arrange
        ActionId actionToDisable = enableActionWithSinglePolicy();

        // First disable
        vm.prank(testAccount);
        smartSessionManager.disableActionId(validPermissionId, actionToDisable);

        // Verify action is disabled
        assertFalse(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, actionToDisable),
            "Action should be disabled after first call"
        );

        // Act - Try to disable the same action again
        vm.prank(testAccount);
        smartSessionManager.disableActionId(validPermissionId, actionToDisable);

        // Assert - Should complete without errors
        assertFalse(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, actionToDisable),
            "Action should remain disabled"
        );
    }

    function test_disableActionId_Success_DisableMultipleActions() public {
        // Arrange - Enable multiple actions
        ActionId action1 = enableActionWithSinglePolicy();
        ActionId action2 = enableActionWithMultiplePolicies();

        // Verify both actions are enabled
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, action1),
            "Action1 should be enabled initially"
        );
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, action2),
            "Action2 should be enabled initially"
        );

        // Disable first action
        vm.prank(testAccount);
        smartSessionManager.disableActionId(validPermissionId, action1);

        // Verify first action is disabled, second still enabled
        assertFalse(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, action1),
            "Action1 should be disabled"
        );
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, action2),
            "Action2 should still be enabled"
        );

        // Disable second action
        vm.prank(testAccount);
        smartSessionManager.disableActionId(validPermissionId, action2);

        // Verify both actions are disabled
        assertFalse(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, action1),
            "Action1 should remain disabled"
        );
        assertFalse(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, action2),
            "Action2 should be disabled"
        );
    }

    function test_disableActionId_Success_WithTestAction() public {
        // Use the test action that was set up in setUp()

        // Verify test action is enabled
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, testActionId),
            "Test action should be enabled initially"
        );

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.ActionIdDisabled(validPermissionId, testActionId, testAccount);
        smartSessionManager.disableActionId(validPermissionId, testActionId);

        // Assert
        assertFalse(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, testActionId),
            "Test action should be disabled"
        );
    }

    ///-------------------------------///
    /// 4. Fuzz tests               ///
    ///-------------------------------///

    function test_disableActionId_Fuzz_VariousActionIds(uint8 actionCount) public {
        // Arrange
        actionCount = uint8(bound(actionCount, 1, 5)); // Limit to reasonable range

        ActionId[] memory actionsToDisable = new ActionId[](actionCount);

        // Enable various actions
        for (uint256 i = 0; i < actionCount; i++) {
            if (i % 2 == 0) {
                actionsToDisable[i] = enableActionWithSinglePolicy();
            } else {
                actionsToDisable[i] = enableActionWithMultiplePolicies();
            }
        }

        // Verify all actions are enabled
        for (uint256 i = 0; i < actionCount; i++) {
            assertTrue(
                smartSessionManager.isActionIdEnabled(
                    testAccount, validPermissionId, actionsToDisable[i]
                ),
                string.concat("Action ", vm.toString(i), " should be enabled initially")
            );
        }

        // Act - Disable all actions
        vm.startPrank(testAccount);
        for (uint256 i = 0; i < actionCount; i++) {
            smartSessionManager.disableActionId(validPermissionId, actionsToDisable[i]);
        }
        vm.stopPrank();

        // Assert - All actions should be disabled
        for (uint256 i = 0; i < actionCount; i++) {
            assertFalse(
                smartSessionManager.isActionIdEnabled(
                    testAccount, validPermissionId, actionsToDisable[i]
                ),
                string.concat("Action ", vm.toString(i), " should be disabled")
            );
        }
    }

    ///-------------------------------///
    /// 5. State verification tests ///
    ///-------------------------------///

    function test_disableActionId_StateVerification_EnabledActionsCount() public {
        // Arrange - Get initial enabled actions count
        bytes32[] memory initialActions =
            smartSessionManager.getEnabledActions(testAccount, validPermissionId);
        uint256 initialCount = initialActions.length;

        // Enable a new action
        ActionId newAction = enableActionWithSinglePolicy();

        // Verify count increased
        bytes32[] memory afterEnableActions =
            smartSessionManager.getEnabledActions(testAccount, validPermissionId);
        assertEq(afterEnableActions.length, initialCount + 1, "Should have one more enabled action");

        // Act - Disable the action
        vm.prank(testAccount);
        smartSessionManager.disableActionId(validPermissionId, newAction);

        // Assert - Count should return to initial
        bytes32[] memory finalActions =
            smartSessionManager.getEnabledActions(testAccount, validPermissionId);
        assertEq(finalActions.length, initialCount, "Should return to initial count");
    }

    function test_disableActionId_StateVerification_ActionNotInEnabledList() public {
        // Arrange
        ActionId actionToDisable = enableActionWithSinglePolicy();

        // Verify action is in enabled list
        bytes32[] memory enabledActions =
            smartSessionManager.getEnabledActions(testAccount, validPermissionId);
        bool foundBeforeDisable = false;
        for (uint256 i = 0; i < enabledActions.length; i++) {
            if (enabledActions[i] == ActionId.unwrap(actionToDisable)) {
                foundBeforeDisable = true;
                break;
            }
        }
        assertTrue(foundBeforeDisable, "Action should be in enabled list before disable");

        // Act
        vm.prank(testAccount);
        smartSessionManager.disableActionId(validPermissionId, actionToDisable);

        // Assert - Action should not be in enabled list anymore
        bytes32[] memory finalEnabledActions =
            smartSessionManager.getEnabledActions(testAccount, validPermissionId);
        bool foundAfterDisable = false;
        for (uint256 i = 0; i < finalEnabledActions.length; i++) {
            if (finalEnabledActions[i] == ActionId.unwrap(actionToDisable)) {
                foundAfterDisable = true;
                break;
            }
        }
        assertFalse(foundAfterDisable, "Action should not be in enabled list after disable");
    }
}
