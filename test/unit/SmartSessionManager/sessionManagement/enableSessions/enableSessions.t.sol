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
    EMPTY_PERMISSIONID,
    ActionId
} from "@smartsessions/DataTypes.sol";

contract InvalidSessionValidator {
// Doesn't implement ISessionValidator interface properly
}

contract SmartSessionManager_enableSessions_Test is SmartSessionManager_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    InvalidSessionValidator invalidValidator;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();

        // Initialize test variables
        testAccount = makeAddr("testAccount");

        // Deploy mock contracts
        invalidValidator = new InvalidSessionValidator();
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    ///-------------------------------///
    /// 1. When sessions array is empty ///
    ///-------------------------------///

    function test_enableSessions_RevertWhen_SessionsArrayEmpty() public {
        // Arrange
        Session[] memory emptySessions = new Session[](0);

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert with InvalidData
        smartSessionManager.enableSessions(emptySessions);
    }

    ///-------------------------------///
    /// 2. When sessions array is not empty ///
    ///-------------------------------///

    function test_enableSessions_RevertWhen_SessionValidatorIsZero() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();
        sessions[0].sessionValidator = ISessionValidator(address(0)); // Invalid validator

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert when trying to enable with zero validator
        smartSessionManager.enableSessions(sessions);
    }

    function test_enableSessions_RevertWhen_PolicyNotRegistered() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();

        // Use an unregistered policy
        PolicyData[] memory invalidPolicyDatas = new PolicyData[](1);
        invalidPolicyDatas[0] = PolicyData({ policy: makeAddr("unregisteredPolicy"), initData: "" });
        sessions[0].actions[0].actionPolicies = invalidPolicyDatas;

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert due to policy not being registered
        smartSessionManager.enableSessions(sessions);
    }

    function test_enableSessions_RevertWhen_InvalidTarget() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();

        // Set invalid target (address(0))
        sessions[0].actions[0].actionTarget = address(0);

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert with InvalidTarget
        smartSessionManager.enableSessions(sessions);
    }

    function test_enableSessions_Success_SingleSession_NewValidator() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();
        PermissionId expectedPermissionId = smartSessionManager.getPermissionId(sessions[0]);

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.SessionCreated(expectedPermissionId, testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission ID");
        assertEq(
            PermissionId.unwrap(permissionIds[0]),
            PermissionId.unwrap(expectedPermissionId),
            "Should return correct permission ID"
        );

        // Verify session is enabled
        assertTrue(
            smartSessionManager.isPermissionEnabled(expectedPermissionId, testAccount),
            "Permission should be enabled"
        );

        // Verify validator is set
        assertTrue(
            smartSessionManager.isISessionValidatorSet(expectedPermissionId, testAccount),
            "Session validator should be set"
        );

        // Verify actions are enabled
        assertTrue(
            smartSessionManager.areActionsEnabled(
                testAccount, expectedPermissionId, sessions[0].actions
            ),
            "Actions should be enabled"
        );
    }

    function test_enableSessions_Success_SingleSession_ExistingValidator() public {
        // Arrange - First enable a session to set the validator
        Session[] memory initialSessions = new Session[](1);
        initialSessions[0] = createBasicSession();

        vm.prank(testAccount);
        smartSessionManager.enableSessions(initialSessions);

        // Create a new session with the same validator but different action
        Session[] memory newSessions = new Session[](1);
        newSessions[0] = createBasicSession();
        newSessions[0].salt = keccak256("differentSalt"); // Different salt for different permission
            // ID
        newSessions[0].actions[0].actionTarget = makeAddr("differentTarget");

        PermissionId expectedPermissionId = smartSessionManager.getPermissionId(newSessions[0]);

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.SessionCreated(expectedPermissionId, testAccount);
        PermissionId[] memory newPermissionIds = smartSessionManager.enableSessions(newSessions);

        // Assert
        assertEq(newPermissionIds.length, 1, "Should return one permission ID");
        assertTrue(
            smartSessionManager.isPermissionEnabled(newPermissionIds[0], testAccount),
            "New permission should be enabled"
        );
        assertTrue(
            smartSessionManager.isISessionValidatorSet(newPermissionIds[0], testAccount),
            "Session validator should be set for new permission"
        );
    }

    function test_enableSessions_Success_MultipleSessions() public {
        // Arrange
        Session[] memory sessions = new Session[](3);
        for (uint256 i = 0; i < 3; i++) {
            sessions[i] = createBasicSession();
            sessions[i].salt = keccak256(abi.encodePacked("salt", i)); // Different salts
            sessions[i].actions[0].actionTarget = address(uint160(i + 1)); // Different targets
        }

        // Calculate expected permission IDs
        PermissionId[] memory expectedPermissionIds = new PermissionId[](3);
        for (uint256 i = 0; i < 3; i++) {
            expectedPermissionIds[i] = smartSessionManager.getPermissionId(sessions[i]);
        }

        // Act
        vm.prank(testAccount);

        // Expect events for each session
        for (uint256 i = 0; i < 3; i++) {
            vm.expectEmit(true, true, false, true);
            emit ISmartSession.SessionCreated(expectedPermissionIds[i], testAccount);
        }

        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 3, "Should return three permission IDs");

        for (uint256 i = 0; i < 3; i++) {
            assertEq(
                PermissionId.unwrap(permissionIds[i]),
                PermissionId.unwrap(expectedPermissionIds[i]),
                string.concat("Should return correct permission ID for session ", vm.toString(i))
            );

            assertTrue(
                smartSessionManager.isPermissionEnabled(expectedPermissionIds[i], testAccount),
                string.concat("Permission should be enabled for session ", vm.toString(i))
            );

            assertTrue(
                smartSessionManager.isISessionValidatorSet(expectedPermissionIds[i], testAccount),
                string.concat("Session validator should be set for session ", vm.toString(i))
            );
        }
    }

    function test_enableSessions_Success_SessionWithMultipleActions() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();

        // Add multiple actions to the session
        ActionData[] memory multipleActions = createActionDataArray(3);
        sessions[0].actions = multipleActions;

        PermissionId expectedPermissionId = smartSessionManager.getPermissionId(sessions[0]);

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.SessionCreated(expectedPermissionId, testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission ID");
        assertEq(
            PermissionId.unwrap(permissionIds[0]),
            PermissionId.unwrap(expectedPermissionId),
            "Should return correct permission ID"
        );

        // Verify all actions are enabled
        assertTrue(
            smartSessionManager.areActionsEnabled(
                testAccount, expectedPermissionId, multipleActions
            ),
            "All actions should be enabled"
        );

        // Verify each action individually
        for (uint256 i = 0; i < multipleActions.length; i++) {
            ActionId actionId =
                multipleActions[i].actionTarget.toActionId(multipleActions[i].actionTargetSelector);
            assertTrue(
                smartSessionManager.isActionIdEnabled(testAccount, expectedPermissionId, actionId),
                string.concat("Action ", vm.toString(i), " should be enabled")
            );
        }
    }

    function test_enableSessions_Success_WithUserOpPolicies() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();

        // Add user operation policies
        PolicyData[] memory userOpPolicies = new PolicyData[](1);
        userOpPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        sessions[0].userOpPolicies = userOpPolicies;

        PermissionId expectedPermissionId = smartSessionManager.getPermissionId(sessions[0]);

        // Act
        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission ID");
        assertTrue(
            smartSessionManager.isPermissionEnabled(expectedPermissionId, testAccount),
            "Permission should be enabled"
        );
    }

    function test_enableSessions_Success_WithERC7739Policies() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();

        // Add ERC7739 policies
        PolicyData[] memory erc1271Policies = new PolicyData[](1);
        erc1271Policies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        sessions[0].erc7739Policies = _getEmptyERC7739Data("testContent", erc1271Policies);

        PermissionId expectedPermissionId = smartSessionManager.getPermissionId(sessions[0]);

        // Act
        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission ID");
        assertTrue(
            smartSessionManager.isPermissionEnabled(expectedPermissionId, testAccount),
            "Permission should be enabled"
        );
    }

    ///-------------------------------///
    /// 3. Edge cases                 ///
    ///-------------------------------///

    function test_enableSessions_Success_DuplicateSalts() public {
        // Arrange - Create two sessions with the same salt (should result in same permission ID)
        Session[] memory sessions = new Session[](2);
        sessions[0] = createBasicSession();
        sessions[1] = createBasicSession();
        // Same salt means same permission ID, which will cause second session to update the first

        // Act
        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 2, "Should return two permission IDs");
        // Both should be the same permission ID due to same session content
        assertEq(
            PermissionId.unwrap(permissionIds[0]),
            PermissionId.unwrap(permissionIds[1]),
            "Permission IDs should be the same due to identical session content"
        );
    }

    function test_enableSessions_Success_SessionWithEmptyInitData() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();
        sessions[0].sessionValidatorInitData = "";

        // Act
        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission ID");
        assertTrue(
            smartSessionManager.isPermissionEnabled(permissionIds[0], testAccount),
            "Permission should be enabled"
        );
    }

    function test_enableSessions_Success_SessionWithEmptyUserOpPolicies() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();
        sessions[0].userOpPolicies = new PolicyData[](0);

        // Act
        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission ID");
        assertTrue(
            smartSessionManager.isPermissionEnabled(permissionIds[0], testAccount),
            "Permission should be enabled"
        );
    }

    function test_enableSessions_Success_PermitERC4337PaymasterFalse() public {
        // Arrange
        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();
        sessions[0].permitERC4337Paymaster = false;

        // Act
        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission ID");
        assertTrue(
            smartSessionManager.isPermissionEnabled(permissionIds[0], testAccount),
            "Permission should be enabled"
        );
    }

    ///-------------------------------///
    /// 4. Fuzz tests                 ///
    ///-------------------------------///

    function test_enableSessions_Fuzz_VariousSessionCounts(uint8 sessionCount) public {
        // Arrange
        sessionCount = uint8(bound(sessionCount, 1, 10)); // Limit to reasonable range

        Session[] memory sessions = new Session[](sessionCount);
        for (uint256 i = 0; i < sessionCount; i++) {
            sessions[i] = createBasicSession();
            sessions[i].salt = keccak256(abi.encodePacked("salt", i));
            sessions[i].actions[0].actionTarget = address(uint160(i + 1));
        }

        // Act
        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(
            permissionIds.length, sessionCount, "Should return correct number of permission IDs"
        );

        for (uint256 i = 0; i < sessionCount; i++) {
            assertTrue(
                smartSessionManager.isPermissionEnabled(permissionIds[i], testAccount),
                string.concat("Permission should be enabled for session ", vm.toString(i))
            );
        }
    }

    function test_enableSessions_Fuzz_VariousActionCounts(uint8 actionCount) public {
        // Arrange
        actionCount = uint8(bound(actionCount, 1, 5)); // Limit to reasonable range

        Session[] memory sessions = new Session[](1);
        sessions[0] = createBasicSession();
        sessions[0].actions = createActionDataArray(actionCount);

        // Act
        vm.prank(testAccount);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission ID");
        assertTrue(
            smartSessionManager.areActionsEnabled(
                testAccount, permissionIds[0], sessions[0].actions
            ),
            "All actions should be enabled"
        );
    }
}
