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
    EMPTY_PERMISSIONID
} from "@smartsessions/DataTypes.sol";

contract SmartSessionManager_removeSession_Test is SmartSessionManager_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    PermissionId enabledPermissionId;
    PermissionId multiActionPermissionId;
    PermissionId multiPolicyPermissionId;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();

        // Initialize test variables
        testAccount = makeAddr("testAccount");

        // Enable various types of sessions for testing
        enabledPermissionId = enableBasicSession(testAccount);
        multiActionPermissionId = enableSessionWithMultipleActions(testAccount);
        multiPolicyPermissionId = enableSessionWithMultiplePolicies(testAccount);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    ///-------------------------------///
    /// 1. When permissionId is EMPTY_PERMISSIONID ///
    ///-------------------------------///

    function test_removeSession_RevertWhen_EmptyPermissionId() public {
        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert with InvalidSession
        smartSessionManager.removeSession(EMPTY_PERMISSIONID);
    }

    ///-------------------------------///
    /// 2. When permissionId is not EMPTY_PERMISSIONID ///
    ///-------------------------------///

    function test_removeSession_Success_PermissionNotEnabled() public {
        // Arrange
        PermissionId nonExistentPermissionId = PermissionId.wrap(keccak256("nonExistent"));

        // Verify permission is not enabled
        assertFalse(
            smartSessionManager.isPermissionEnabled(nonExistentPermissionId, testAccount),
            "Permission should not be enabled initially"
        );

        // Get initial session count
        PermissionId[] memory initialPermissions = smartSessionManager.getPermissionIDs(testAccount);
        uint256 initialCount = initialPermissions.length;

        // Act
        vm.prank(testAccount);
        smartSessionManager.removeSession(nonExistentPermissionId);

        // Assert - Should complete without changes
        assertFalse(
            smartSessionManager.isPermissionEnabled(nonExistentPermissionId, testAccount),
            "Permission should still not be enabled"
        );

        // Verify no change in permission count
        PermissionId[] memory finalPermissions = smartSessionManager.getPermissionIDs(testAccount);
        assertEq(finalPermissions.length, initialCount, "Permission count should not change");
    }

    function test_removeSession_Success_SessionNoActionPolicies() public {
        // Arrange - Create a session with no actions (just user op policies)
        Session memory sessionWithNoActions = createBasicSession();
        sessionWithNoActions.actions = new ActionData[](0); // No actions
        sessionWithNoActions.salt = keccak256("noActionsSession");

        Session[] memory sessions = new Session[](1);
        sessions[0] = sessionWithNoActions;

        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);
        PermissionId sessionWithNoActionsId = permissionIds[0];

        // Verify session is enabled
        assertTrue(
            smartSessionManager.isPermissionEnabled(sessionWithNoActionsId, testAccount),
            "Session should be enabled initially"
        );
        assertTrue(
            smartSessionManager.isISessionValidatorSet(sessionWithNoActionsId, testAccount),
            "Session validator should be set initially"
        );

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.SessionRemoved(sessionWithNoActionsId, testAccount);
        smartSessionManager.removeSession(sessionWithNoActionsId);

        // Assert
        assertFalse(
            smartSessionManager.isPermissionEnabled(sessionWithNoActionsId, testAccount),
            "Session should be disabled"
        );
        assertFalse(
            smartSessionManager.isISessionValidatorSet(sessionWithNoActionsId, testAccount),
            "Session validator should be removed"
        );
    }

    function test_removeSession_Success_SessionSingleActionPolicy() public {
        // Arrange - Use the basic session with single action
        assertTrue(
            smartSessionManager.isPermissionEnabled(enabledPermissionId, testAccount),
            "Session should be enabled initially"
        );

        // Get initial action for verification
        Session memory basicSession = createBasicSession();
        ActionId actionId = basicSession.actions[0].actionTarget.toActionId(
            basicSession.actions[0].actionTargetSelector
        );

        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, enabledPermissionId, actionId),
            "Action should be enabled initially"
        );

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.SessionRemoved(enabledPermissionId, testAccount);
        smartSessionManager.removeSession(enabledPermissionId);

        // Assert
        assertFalse(
            smartSessionManager.isPermissionEnabled(enabledPermissionId, testAccount),
            "Session should be disabled"
        );
        assertFalse(
            smartSessionManager.isActionIdEnabled(testAccount, enabledPermissionId, actionId),
            "Action should be disabled"
        );
        assertFalse(
            smartSessionManager.isISessionValidatorSet(enabledPermissionId, testAccount),
            "Session validator should be removed"
        );

        // Verify no actions remain
        bytes32[] memory enabledActions =
            smartSessionManager.getEnabledActions(testAccount, enabledPermissionId);
        assertEq(enabledActions.length, 0, "Should have no enabled actions");
    }

    function test_removeSession_Success_SessionMultipleActionPolicies() public {
        // Arrange - Use the session with multiple actions
        assertTrue(
            smartSessionManager.isPermissionEnabled(multiActionPermissionId, testAccount),
            "Session should be enabled initially"
        );

        // Verify multiple actions are enabled
        bytes32[] memory initialActions =
            smartSessionManager.getEnabledActions(testAccount, multiActionPermissionId);
        assertTrue(initialActions.length > 1, "Should have multiple actions initially");

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.SessionRemoved(multiActionPermissionId, testAccount);
        smartSessionManager.removeSession(multiActionPermissionId);

        // Assert
        assertFalse(
            smartSessionManager.isPermissionEnabled(multiActionPermissionId, testAccount),
            "Session should be disabled"
        );
        assertFalse(
            smartSessionManager.isISessionValidatorSet(multiActionPermissionId, testAccount),
            "Session validator should be removed"
        );

        // Verify all actions are removed
        bytes32[] memory finalActions =
            smartSessionManager.getEnabledActions(testAccount, multiActionPermissionId);
        assertEq(finalActions.length, 0, "Should have no enabled actions after removal");

        // Verify individual actions are disabled
        for (uint256 i = 0; i < initialActions.length; i++) {
            ActionId actionId = ActionId.wrap(initialActions[i]);
            assertFalse(
                smartSessionManager.isActionIdEnabled(
                    testAccount, multiActionPermissionId, actionId
                ),
                string.concat("Action ", vm.toString(i), " should be disabled")
            );
        }
    }

    function test_removeSession_Success_SessionWithSessionValidator() public {
        // Arrange - Use session with multiple policies per action
        assertTrue(
            smartSessionManager.isPermissionEnabled(multiPolicyPermissionId, testAccount),
            "Session should be enabled initially"
        );

        // Verify validator is set
        assertTrue(
            smartSessionManager.isISessionValidatorSet(multiPolicyPermissionId, testAccount),
            "Session validator should be set initially"
        );

        // Get validator details before removal
        (address validatorAddress,) =
            smartSessionManager.getSessionValidatorAndConfig(testAccount, multiPolicyPermissionId);
        assertTrue(validatorAddress != address(0), "Validator address should not be zero");

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.SessionRemoved(multiPolicyPermissionId, testAccount);
        smartSessionManager.removeSession(multiPolicyPermissionId);

        // Assert
        assertFalse(
            smartSessionManager.isPermissionEnabled(multiPolicyPermissionId, testAccount),
            "Session should be disabled"
        );
        assertFalse(
            smartSessionManager.isISessionValidatorSet(multiPolicyPermissionId, testAccount),
            "Session validator should be removed"
        );

        // Verify validator details are cleared
        (address finalValidatorAddress, bytes memory finalValidatorConfig) =
            smartSessionManager.getSessionValidatorAndConfig(testAccount, multiPolicyPermissionId);
        assertEq(
            finalValidatorAddress, address(0), "Validator address should be zero after removal"
        );
        assertEq(finalValidatorConfig.length, 0, "Validator config should be empty after removal");
    }

    function test_removeSession_Success_ValidSessionDoesNotExist() public {
        // Arrange - Create a valid permission ID that doesn't actually exist
        Session memory nonExistentSession = createBasicSession();
        nonExistentSession.salt = keccak256("nonExistentSession");
        PermissionId nonExistentPermissionId =
            smartSessionManager.getPermissionId(nonExistentSession);

        // Verify it's a valid permission ID but not enabled
        assertTrue(
            PermissionId.unwrap(nonExistentPermissionId) != PermissionId.unwrap(EMPTY_PERMISSIONID),
            "Should be a valid permission ID"
        );
        assertFalse(
            smartSessionManager.isPermissionEnabled(nonExistentPermissionId, testAccount),
            "Permission should not be enabled"
        );

        // Get initial session count
        PermissionId[] memory initialPermissions = smartSessionManager.getPermissionIDs(testAccount);
        uint256 initialCount = initialPermissions.length;

        // Act
        vm.prank(testAccount);
        smartSessionManager.removeSession(nonExistentPermissionId);

        // Assert - Should complete without changes
        assertFalse(
            smartSessionManager.isPermissionEnabled(nonExistentPermissionId, testAccount),
            "Permission should still not be enabled"
        );

        // Verify no change in permission count
        PermissionId[] memory finalPermissions = smartSessionManager.getPermissionIDs(testAccount);
        assertEq(finalPermissions.length, initialCount, "Permission count should not change");
    }

    ///-------------------------------///
    /// 3. Edge cases                 ///
    ///-------------------------------///

    function test_removeSession_Success_RemoveSameSessionTwice() public {
        // Arrange
        PermissionId sessionToRemove = enableBasicSession(testAccount);

        // First removal
        vm.prank(testAccount);
        smartSessionManager.removeSession(sessionToRemove);

        // Verify session is removed
        assertFalse(
            smartSessionManager.isPermissionEnabled(sessionToRemove, testAccount),
            "Session should be removed after first call"
        );

        // Act - Try to remove the same session again
        vm.prank(testAccount);
        smartSessionManager.removeSession(sessionToRemove);

        // Assert - Should complete without errors
        assertFalse(
            smartSessionManager.isPermissionEnabled(sessionToRemove, testAccount),
            "Session should remain removed"
        );
    }

    function test_removeSession_Success_RemoveMultipleSessions() public {
        // Arrange - Enable multiple sessions
        PermissionId session1 = enableBasicSession(testAccount);
        PermissionId session2 = enableBasicSession(testAccount);

        // Modify one session to make it different
        Session memory differentSession = createBasicSession();
        differentSession.salt = keccak256("differentSession");
        Session[] memory sessions = new Session[](1);
        sessions[0] = differentSession;
        vm.prank(testAccount);
        PermissionId[] memory newPermissionIds = smartSessionManager.enableSessions(sessions);
        PermissionId session3 = newPermissionIds[0];

        // Verify all sessions are enabled
        assertTrue(
            smartSessionManager.isPermissionEnabled(session1, testAccount),
            "Session1 should be enabled"
        );
        assertTrue(
            smartSessionManager.isPermissionEnabled(session2, testAccount),
            "Session2 should be enabled"
        );
        assertTrue(
            smartSessionManager.isPermissionEnabled(session3, testAccount),
            "Session3 should be enabled"
        );

        // Remove first session
        vm.prank(testAccount);
        smartSessionManager.removeSession(session1);

        // Verify first is removed and second are removed
        assertFalse(
            smartSessionManager.isPermissionEnabled(session1, testAccount),
            "Session1 should be removed"
        );
        assertFalse(
            smartSessionManager.isPermissionEnabled(session2, testAccount),
            "Session2 should be removed"
        );
        assertTrue(
            smartSessionManager.isPermissionEnabled(session3, testAccount), "Session3 should remain"
        );

        // Remove remaining sessions
        vm.prank(testAccount);
        smartSessionManager.removeSession(session3);

        // Verify all are removed
        assertFalse(
            smartSessionManager.isPermissionEnabled(session1, testAccount),
            "Session1 should remain removed"
        );
        assertFalse(
            smartSessionManager.isPermissionEnabled(session2, testAccount),
            "Session2 should be removed"
        );
        assertFalse(
            smartSessionManager.isPermissionEnabled(session3, testAccount),
            "Session3 should be removed"
        );
    }

    function test_removeSession_Success_RemoveWithOtherAccountSessions() public {
        // Arrange - Enable sessions for different accounts
        address otherAccount = makeAddr("otherAccount");
        PermissionId thisAccountSession = enableBasicSession(testAccount);
        PermissionId otherAccountSession = enableBasicSession(otherAccount);

        // Verify both sessions are enabled for their respective accounts
        assertTrue(
            smartSessionManager.isPermissionEnabled(thisAccountSession, testAccount),
            "This account session should be enabled"
        );
        assertTrue(
            smartSessionManager.isPermissionEnabled(otherAccountSession, otherAccount),
            "Other account session should be enabled"
        );

        // Act - Remove this account's session
        vm.prank(testAccount);
        smartSessionManager.removeSession(thisAccountSession);

        // Assert - Only this account's session should be removed
        assertFalse(
            smartSessionManager.isPermissionEnabled(thisAccountSession, testAccount),
            "This account session should be removed"
        );
        assertTrue(
            smartSessionManager.isPermissionEnabled(otherAccountSession, otherAccount),
            "Other account session should remain enabled"
        );

        // Verify account isolation - other account's session not affected for this account
        assertFalse(
            smartSessionManager.isPermissionEnabled(otherAccountSession, testAccount),
            "Other account session should not be enabled for this account"
        );
    }

    ///-------------------------------///
    /// 4. Fuzz tests                 ///
    ///-------------------------------///

    function test_removeSession_Fuzz_RemoveRandomSessions(uint8 sessionCount) public {
        // Arrange
        sessionCount = uint8(bound(sessionCount, 1, 5)); // Limit to reasonable range

        PermissionId[] memory sessionsToRemove = new PermissionId[](sessionCount);

        // Enable various sessions
        for (uint256 i = 0; i < sessionCount; i++) {
            sessionsToRemove[i] = enableBasicSession(testAccount);
            // Make each session unique by modifying the basic session
            Session memory uniqueSession = createBasicSession();
            uniqueSession.salt = keccak256(abi.encodePacked("uniqueSession", i));
            Session[] memory sessions = new Session[](1);
            sessions[0] = uniqueSession;
            vm.prank(testAccount);
            PermissionId[] memory newIds = smartSessionManager.enableSessions(sessions);
            if (i < sessionCount) {
                sessionsToRemove[i] = newIds[0];
            }
        }

        // Verify all sessions are enabled
        for (uint256 i = 0; i < sessionCount; i++) {
            assertTrue(
                smartSessionManager.isPermissionEnabled(sessionsToRemove[i], testAccount),
                string.concat("Session ", vm.toString(i), " should be enabled initially")
            );
        }

        // Act - Remove all sessions
        vm.startPrank(testAccount);
        for (uint256 i = 0; i < sessionCount; i++) {
            smartSessionManager.removeSession(sessionsToRemove[i]);
        }
        vm.stopPrank();

        // Assert - All sessions should be removed
        for (uint256 i = 0; i < sessionCount; i++) {
            assertFalse(
                smartSessionManager.isPermissionEnabled(sessionsToRemove[i], testAccount),
                string.concat("Session ", vm.toString(i), " should be removed")
            );
        }
    }

    ///-------------------------------///
    /// 5. State verification tests   ///
    ///-------------------------------///

    function test_removeSession_StateVerification_SessionNotInPermissionsList() public {
        // Arrange
        PermissionId sessionToRemove = enableBasicSession(testAccount);

        // Verify session is in permissions list
        PermissionId[] memory enabledPermissions = smartSessionManager.getPermissionIDs(testAccount);
        bool foundBeforeRemove = false;
        for (uint256 i = 0; i < enabledPermissions.length; i++) {
            if (PermissionId.unwrap(enabledPermissions[i]) == PermissionId.unwrap(sessionToRemove))
            {
                foundBeforeRemove = true;
                break;
            }
        }
        assertTrue(foundBeforeRemove, "Session should be in permissions list before removal");

        // Act
        vm.prank(testAccount);
        smartSessionManager.removeSession(sessionToRemove);

        // Assert - Session should not be in permissions list anymore
        PermissionId[] memory finalEnabledPermissions =
            smartSessionManager.getPermissionIDs(testAccount);
        bool foundAfterRemove = false;
        for (uint256 i = 0; i < finalEnabledPermissions.length; i++) {
            if (
                PermissionId.unwrap(finalEnabledPermissions[i])
                    == PermissionId.unwrap(sessionToRemove)
            ) {
                foundAfterRemove = true;
                break;
            }
        }
        assertFalse(foundAfterRemove, "Session should not be in permissions list after removal");
    }
}
