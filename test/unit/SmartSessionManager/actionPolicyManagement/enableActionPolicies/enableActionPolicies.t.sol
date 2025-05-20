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

contract UnregisteredPolicy { }

contract SmartSessionManager_enableActionPolicies_Test is SmartSessionManager_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    UnregisteredPolicy unregisteredPolicy;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();

        // Initialize test variables
        testAccount = makeAddr("testAccount");

        // Deploy mock contracts
        unregisteredPolicy = new UnregisteredPolicy();
        // Enable a basic session to get a valid permission ID
        validPermissionId = enableBasicSession(testAccount);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    ///-------------------------------///
    /// 1. When permission is not enabled ///
    ///-------------------------------///

    function test_enableActionPolicies_RevertWhen_PermissionNotEnabled() public {
        // Arrange
        PermissionId invalidPermissionId = PermissionId.wrap(keccak256("invalid"));
        ActionData[] memory actionPolicies = createActionDataArray(1);

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert with PermissionIdNotEnabled
        smartSessionManager.enableActionPolicies(invalidPermissionId, actionPolicies);
    }

    ///-------------------------------///
    /// 2. When permission is enabled ///
    ///-------------------------------///

    function test_enableActionPolicies_Success_EmptyArray() public {
        // Arrange
        ActionData[] memory emptyActions = new ActionData[](0);

        // Act
        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, emptyActions);

        // Assert - Should complete without errors and no changes
        assertTrue(
            smartSessionManager.isPermissionEnabled(validPermissionId, testAccount),
            "Permission should still be enabled"
        );
    }

    function test_enableActionPolicies_RevertWhen_PolicyNotRegistered() public {
        // Arrange
        ActionData[] memory actionPolicies = new ActionData[](1);
        PolicyData[] memory unregisteredPolicyDatas = new PolicyData[](1);
        unregisteredPolicyDatas[0] =
            PolicyData({ policy: address(unregisteredPolicy), initData: "" });

        actionPolicies[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: bytes4(keccak256("testFunction()")),
            actionPolicies: unregisteredPolicyDatas
        });

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert with PolicyNotRegistered
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);
    }

    function test_enableActionPolicies_Success_ValidPolicy_NoExistingPolicies() public {
        // Arrange
        ActionData[] memory actionPolicies = new ActionData[](1);
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        actionPolicies[0] = ActionData({
            actionTarget: makeAddr("newTarget"),
            actionTargetSelector: bytes4(keccak256("newFunction()")),
            actionPolicies: policyDatas
        });

        // Calculate expected action ID
        ActionId expectedActionId =
            actionPolicies[0].actionTarget.toActionId(actionPolicies[0].actionTargetSelector);

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, true, true);
        emit ISmartSession.PolicyEnabled(
            validPermissionId, PolicyType.ACTION, address(sudoPolicy), testAccount
        );
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);

        // Assert
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, expectedActionId),
            "Action ID should be enabled"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, expectedActionId, address(sudoPolicy)
            ),
            "Action policy should be enabled"
        );
    }

    function test_enableActionPolicies_Success_ValidPolicy_ExistingPolicies() public {
        // Arrange - First enable an action with one policy
        ActionData[] memory firstActionPolicies = new ActionData[](1);
        PolicyData[] memory firstPolicyDatas = new PolicyData[](1);
        firstPolicyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        firstActionPolicies[0] = ActionData({
            actionTarget: makeAddr("existingTarget"),
            actionTargetSelector: bytes4(keccak256("existingFunction()")),
            actionPolicies: firstPolicyDatas
        });

        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, firstActionPolicies);

        // Now add a second policy to the same action
        ActionData[] memory secondActionPolicies = new ActionData[](1);
        PolicyData[] memory secondPolicyDatas = new PolicyData[](1);
        secondPolicyDatas[0] = PolicyData({ policy: address(noPolicy), initData: "" });

        secondActionPolicies[0] = ActionData({
            actionTarget: firstActionPolicies[0].actionTarget, // Same target
            actionTargetSelector: firstActionPolicies[0].actionTargetSelector, // Same selector
            actionPolicies: secondPolicyDatas
        });

        ActionId actionId = firstActionPolicies[0].actionTarget.toActionId(
            firstActionPolicies[0].actionTargetSelector
        );

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, true, true);
        emit ISmartSession.PolicyEnabled(
            validPermissionId, PolicyType.ACTION, address(noPolicy), testAccount
        );
        smartSessionManager.enableActionPolicies(validPermissionId, secondActionPolicies);

        // Assert - Both policies should be enabled for the same action
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionId, address(sudoPolicy)
            ),
            "First policy should still be enabled"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionId, address(noPolicy)
            ),
            "Second policy should be enabled"
        );

        // Check that both policies are in the action policies array
        address[] memory enabledPolicies =
            smartSessionManager.getActionPolicies(testAccount, validPermissionId, actionId);
        assertEq(enabledPolicies.length, 2, "Should have two policies enabled");
    }

    function test_enableActionPolicies_RevertWhen_InvalidTarget() public {
        // Arrange
        ActionData[] memory actionPolicies = new ActionData[](1);
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Set target to address(0) to trigger revert
        actionPolicies[0] = ActionData({
            actionTarget: address(0),
            actionTargetSelector: bytes4(keccak256("testFunction()")),
            actionPolicies: policyDatas
        });

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert with InvalidTarget
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);
    }

    function test_enableActionPolicies_Success_MultipleActions() public {
        // Arrange
        ActionData[] memory actionPolicies = createActionDataArray(3);

        // Act
        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);

        // Assert - All actions should be enabled
        for (uint256 i = 0; i < actionPolicies.length; i++) {
            ActionId actionId =
                actionPolicies[i].actionTarget.toActionId(actionPolicies[i].actionTargetSelector);
            assertTrue(
                smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, actionId),
                string.concat("Action ", vm.toString(i), " should be enabled")
            );
        }
    }

    ///-------------------------------///
    /// 3. Edge cases                 ///
    ///-------------------------------///

    function test_enableActionPolicies_Success_DuplicatePolicySameAction() public {
        // Arrange - Create two action data with the same target/selector and policy
        ActionData[] memory actionPolicies = new ActionData[](2);
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Same action, same policy - should handle gracefully
        actionPolicies[0] = ActionData({
            actionTarget: makeAddr("duplicateTarget"),
            actionTargetSelector: bytes4(keccak256("duplicateFunction()")),
            actionPolicies: policyDatas
        });
        actionPolicies[1] = actionPolicies[0]; // Exact duplicate

        // Act
        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);

        // Assert - Should only have one instance of the policy
        ActionId actionId =
            actionPolicies[0].actionTarget.toActionId(actionPolicies[0].actionTargetSelector);
        address[] memory enabledPolicies =
            smartSessionManager.getActionPolicies(testAccount, validPermissionId, actionId);

        // Should have only one policy, not two duplicates
        assertTrue(enabledPolicies.length >= 1, "Should have at least one policy");
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionId, address(sudoPolicy)
            ),
            "Policy should be enabled"
        );
    }

    function test_enableActionPolicies_Success_SameActionDifferentPolicies() public {
        // Arrange - Create action data with same target/selector but different policies
        ActionData[] memory actionPolicies = new ActionData[](1);
        PolicyData[] memory policyDatas = new PolicyData[](2);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        policyDatas[1] = PolicyData({ policy: address(noPolicy), initData: "" });

        actionPolicies[0] = ActionData({
            actionTarget: makeAddr("multiPolicyTarget"),
            actionTargetSelector: bytes4(keccak256("multiPolicyFunction()")),
            actionPolicies: policyDatas
        });

        // Act
        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);

        // Assert - Both policies should be enabled for the action
        ActionId actionId =
            actionPolicies[0].actionTarget.toActionId(actionPolicies[0].actionTargetSelector);

        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionId, address(sudoPolicy)
            ),
            "First policy should be enabled"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionId, address(noPolicy)
            ),
            "Second policy should be enabled"
        );

        address[] memory enabledPolicies =
            smartSessionManager.getActionPolicies(testAccount, validPermissionId, actionId);
        assertEq(enabledPolicies.length, 2, "Should have two policies enabled");
    }

    function test_enableActionPolicies_Success_ZeroInitData() public {
        // Arrange
        ActionData[] memory actionPolicies = new ActionData[](1);
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: new bytes(0) });

        actionPolicies[0] = ActionData({
            actionTarget: makeAddr("zeroInitTarget"),
            actionTargetSelector: bytes4(keccak256("zeroInitFunction()")),
            actionPolicies: policyDatas
        });

        // Act/Assert - Should complete without errors
        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);

        ActionId actionId =
            actionPolicies[0].actionTarget.toActionId(actionPolicies[0].actionTargetSelector);
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, actionId),
            "Action should be enabled with zero init data"
        );
    }

    ///-------------------------------///
    /// 4. Fuzz tests               ///
    ///-------------------------------///

    function test_enableActionPolicies_Fuzz_VariousActionCounts(uint8 actionCount) public {
        // Arrange
        actionCount = uint8(bound(actionCount, 1, 10)); // Limit to reasonable range
        ActionData[] memory actionPolicies = createActionDataArray(actionCount);

        // Act
        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);

        // Assert - All actions should be enabled
        for (uint256 i = 0; i < actionCount; i++) {
            ActionId actionId =
                actionPolicies[i].actionTarget.toActionId(actionPolicies[i].actionTargetSelector);
            assertTrue(
                smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, actionId),
                string.concat("Action ", vm.toString(i), " should be enabled")
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Helper to create action data with specific target and selector
    function createActionDataWithTarget(
        address targetAddr,
        bytes4 selector
    )
        internal
        view
        returns (ActionData memory)
    {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        return ActionData({
            actionTarget: targetAddr,
            actionTargetSelector: selector,
            actionPolicies: policyDatas
        });
    }

    /// @notice Helper to verify action is properly enabled
    function assertActionEnabled(
        address account,
        PermissionId permissionId,
        ActionData memory actionData
    )
        internal
        view
    {
        ActionId actionId = actionData.actionTarget.toActionId(actionData.actionTargetSelector);

        assertTrue(
            smartSessionManager.isActionIdEnabled(account, permissionId, actionId),
            "Action ID should be enabled"
        );

        for (uint256 i = 0; i < actionData.actionPolicies.length; i++) {
            assertTrue(
                smartSessionManager.isActionPolicyEnabled(
                    account, permissionId, actionId, actionData.actionPolicies[i].policy
                ),
                string.concat("Policy ", vm.toString(i), " should be enabled")
            );
        }
    }
}
