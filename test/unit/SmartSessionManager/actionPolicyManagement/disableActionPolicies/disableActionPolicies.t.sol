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

contract SmartSessionManager_disableActionPolicies_Test is SmartSessionManager_Unit_Test {
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

    function test_disableActionPolicies_RevertWhen_PermissionNotEnabled() public {
        // Arrange
        PermissionId invalidPermissionId = PermissionId.wrap(keccak256("invalid"));
        address[] memory policies = new address[](1);
        policies[0] = address(sudoPolicy);

        // Act/Assert
        vm.prank(testAccount);
        vm.expectRevert(); // Should revert with PermissionIdNotEnabled
        smartSessionManager.disableActionPolicies(invalidPermissionId, testActionId, policies);
    }

    ///-------------------------------///
    /// 2. When permission is enabled ///
    ///-------------------------------///

    function test_disableActionPolicies_Success_ActionIdNotEnabled() public {
        // Arrange
        ActionId nonExistentActionId =
            makeAddr("nonExistent").toActionId(bytes4(keccak256("nonExistent()")));
        address[] memory policies = new address[](1);
        policies[0] = address(sudoPolicy);

        // Verify action is not enabled
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, nonExistentActionId
            ),
            "Action should not be enabled initially"
        );

        // Act
        vm.prank(testAccount);
        smartSessionManager.disableActionPolicies(validPermissionId, nonExistentActionId, policies);

        // Assert - Should complete without changes
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, nonExistentActionId
            ),
            "Action should still not be enabled"
        );
    }

    function test_disableActionPolicies_Success_EmptyPoliciesArray() public {
        // Arrange
        address[] memory emptyPolicies = new address[](0);

        // Verify action is enabled before test
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, testActionId),
            "Action should be enabled initially"
        );

        // Act
        vm.prank(testAccount);
        smartSessionManager.disableActionPolicies(validPermissionId, testActionId, emptyPolicies);

        // Assert - Should complete without changes
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, testActionId),
            "Action should still be enabled"
        );
    }

    function test_disableActionPolicies_Success_InvalidPolicies() public {
        // Arrange
        address[] memory invalidPolicies = new address[](2);
        invalidPolicies[0] = makeAddr("nonExistentPolicy1");
        invalidPolicies[1] = makeAddr("nonExistentPolicy2");

        // Verify action is enabled before test
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, testActionId),
            "Action should be enabled initially"
        );

        // Act
        vm.prank(testAccount);
        smartSessionManager.disableActionPolicies(validPermissionId, testActionId, invalidPolicies);

        // Assert - Should complete without changes since policies didn't exist
        assertTrue(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, testActionId),
            "Action should still be enabled"
        );
    }

    function test_disableActionPolicies_Success_ValidPolicies_SomePoliciesRemaining() public {
        // Arrange - Enable action with multiple policies and get the actionId
        ActionId multiPolicyActionId = enableActionWithMultiplePolicies();

        // Verify both policies are enabled
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, multiPolicyActionId, address(sudoPolicy)
            ),
            "SudoPolicy should be enabled initially"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, multiPolicyActionId, address(noPolicy)
            ),
            "NoPolicy should be enabled initially"
        );

        // Remove only one policy
        address[] memory policiesToRemove = new address[](1);
        policiesToRemove[0] = address(sudoPolicy);

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, true, true);
        emit ISmartSession.PolicyDisabled(
            validPermissionId, PolicyType.ACTION, address(sudoPolicy), testAccount
        );
        smartSessionManager.disableActionPolicies(
            validPermissionId, multiPolicyActionId, policiesToRemove
        );

        // Assert
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, multiPolicyActionId, address(sudoPolicy)
            ),
            "SudoPolicy should be disabled"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, multiPolicyActionId, address(noPolicy)
            ),
            "NoPolicy should still be enabled"
        );
        assertTrue(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, multiPolicyActionId
            ),
            "Action should still be enabled since policies remain"
        );

        // Verify policy count
        address[] memory remainingPolicies = smartSessionManager.getActionPolicies(
            testAccount, validPermissionId, multiPolicyActionId
        );
        assertEq(remainingPolicies.length, 1, "Should have one policy remaining");
    }

    function test_disableActionPolicies_Success_ValidPolicies_NoPoliciesRemaining() public {
        // Arrange - Enable action with single policy and get the actionId
        ActionId singlePolicyActionId = enableActionWithSinglePolicy();

        // Verify policy is enabled
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, singlePolicyActionId, address(sudoPolicy)
            ),
            "SudoPolicy should be enabled initially"
        );

        // Remove the only policy
        address[] memory policiesToRemove = new address[](1);
        policiesToRemove[0] = address(sudoPolicy);

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, true, true);
        emit ISmartSession.PolicyDisabled(
            validPermissionId, PolicyType.ACTION, address(sudoPolicy), testAccount
        );
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.ActionIdDisabled(validPermissionId, singlePolicyActionId, testAccount);
        smartSessionManager.disableActionPolicies(
            validPermissionId, singlePolicyActionId, policiesToRemove
        );

        // Assert
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, singlePolicyActionId, address(sudoPolicy)
            ),
            "SudoPolicy should be disabled"
        );
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, singlePolicyActionId
            ),
            "Action should be disabled since no policies remain"
        );

        // Verify policy count
        address[] memory remainingPolicies = smartSessionManager.getActionPolicies(
            testAccount, validPermissionId, singlePolicyActionId
        );
        assertEq(remainingPolicies.length, 0, "Should have no policies remaining");
    }

    function test_disableActionPolicies_Success_PoliciesNotEnabledForAction() public {
        // Arrange - Enable action with specific policy and get the actionId
        ActionId actionWithDifferentPolicy = enableActionWithSinglePolicy();

        // Try to remove a policy that's not enabled for this action
        address[] memory policiesToRemove = new address[](1);
        policiesToRemove[0] = address(noPolicy); // This policy is not enabled for this action

        // Verify initial state
        assertTrue(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, actionWithDifferentPolicy
            ),
            "Action should be enabled initially"
        );
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionWithDifferentPolicy, address(noPolicy)
            ),
            "NoPolicy should not be enabled for this action"
        );

        // Act
        vm.prank(testAccount);
        smartSessionManager.disableActionPolicies(
            validPermissionId, actionWithDifferentPolicy, policiesToRemove
        );

        // Assert - Should complete without changes
        assertTrue(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, actionWithDifferentPolicy
            ),
            "Action should still be enabled"
        );
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, actionWithDifferentPolicy, address(sudoPolicy)
            ),
            "SudoPolicy should still be enabled"
        );
    }

    ///-------------------------------///
    /// 3. Edge cases               ///
    ///-------------------------------///

    function test_disableActionPolicies_Success_DisableSamePolicyTwice() public {
        // Arrange
        address[] memory policies = new address[](1);
        policies[0] = address(sudoPolicy);

        // First disable
        vm.prank(testAccount);
        smartSessionManager.disableActionPolicies(validPermissionId, testActionId, policies);

        // Verify policy is disabled
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, testActionId, address(sudoPolicy)
            ),
            "Policy should be disabled after first call"
        );

        // Act - Try to disable the same policy again
        vm.prank(testAccount);
        smartSessionManager.disableActionPolicies(validPermissionId, testActionId, policies);

        // Assert - Should complete without errors
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, testActionId, address(sudoPolicy)
            ),
            "Policy should still be disabled"
        );
    }

    function test_disableActionPolicies_Success_DisableMultiplePolicies() public {
        // Arrange - Enable action with multiple policies and get the actionId
        ActionId multiPolicyActionId = enableActionWithMultiplePolicies();

        // Check initial state
        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, multiPolicyActionId, address(sudoPolicy)
            ),
            "SudoPolicy should be enabled initially"
        );

        assertTrue(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, multiPolicyActionId, address(noPolicy)
            ),
            "NoPolicy should be enabled initially"
        );

        // Disable all policies at once
        address[] memory policiesToRemove = new address[](2);
        policiesToRemove[0] = address(sudoPolicy);
        policiesToRemove[1] = address(noPolicy);

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, true, true);
        emit ISmartSession.PolicyDisabled(
            validPermissionId, PolicyType.ACTION, address(sudoPolicy), testAccount
        );
        vm.expectEmit(true, true, true, true);
        emit ISmartSession.PolicyDisabled(
            validPermissionId, PolicyType.ACTION, address(noPolicy), testAccount
        );
        vm.expectEmit(true, true, false, true);
        emit ISmartSession.ActionIdDisabled(validPermissionId, multiPolicyActionId, testAccount);
        smartSessionManager.disableActionPolicies(
            validPermissionId, multiPolicyActionId, policiesToRemove
        );

        // Assert
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, multiPolicyActionId, address(sudoPolicy)
            ),
            "SudoPolicy should be disabled"
        );
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, multiPolicyActionId, address(noPolicy)
            ),
            "NoPolicy should be disabled"
        );
        assertFalse(
            smartSessionManager.isActionIdEnabled(
                testAccount, validPermissionId, multiPolicyActionId
            ),
            "Action should be disabled since no policies remain"
        );
    }

    function test_disableActionPolicies_Success_MixedValidInvalidPolicies() public {
        // Arrange - Enable action with single policy
        address[] memory policiesToRemove = new address[](3);
        policiesToRemove[0] = address(sudoPolicy); // Valid and enabled
        policiesToRemove[1] = makeAddr("invalidPolicy1"); // Invalid
        policiesToRemove[2] = address(noPolicy); // Valid but not enabled

        // Act
        vm.prank(testAccount);
        vm.expectEmit(true, true, true, true);
        emit ISmartSession.PolicyDisabled(
            validPermissionId, PolicyType.ACTION, address(sudoPolicy), testAccount
        );
        // Should not emit events for invalid policies
        smartSessionManager.disableActionPolicies(validPermissionId, testActionId, policiesToRemove);

        // Assert - Only the valid enabled policy should be removed
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, testActionId, address(sudoPolicy)
            ),
            "SudoPolicy should be disabled"
        );
    }

    function test_disableActionPolicies_Success_ZeroAddressInPolicies() public {
        // Arrange
        address[] memory policiesToRemove = new address[](2);
        policiesToRemove[0] = address(sudoPolicy);
        policiesToRemove[1] = address(0); // Zero address

        // Act - Should handle gracefully
        vm.prank(testAccount);
        smartSessionManager.disableActionPolicies(validPermissionId, testActionId, policiesToRemove);

        // Assert
        assertFalse(
            smartSessionManager.isActionPolicyEnabled(
                testAccount, validPermissionId, testActionId, address(sudoPolicy)
            ),
            "SudoPolicy should be disabled"
        );
    }

    ///-------------------------------///
    /// 4. Fuzz tests               ///
    ///-------------------------------///

    function test_disableActionPolicies_Fuzz_VariousPolicyArraySizes(uint8 policyCount) public {
        // Arrange
        policyCount = uint8(bound(policyCount, 1, 5)); // Limit to reasonable range

        // Enable multiple policies first and get the actionId
        ActionId fuzzActionId = enableActionWithMultiplePolicies();

        // Create array with mix of valid and invalid policies
        address[] memory policiesToRemove = new address[](policyCount);
        for (uint256 i = 0; i < policyCount; i++) {
            if (i == 0) {
                policiesToRemove[i] = address(sudoPolicy); // Valid
            } else if (i == 1 && policyCount > 1) {
                policiesToRemove[i] = address(noPolicy); // Valid
            } else {
                policiesToRemove[i] = makeAddr(string.concat("fuzzPolicy", vm.toString(i))); // Invalid
            }
        }

        // Act
        vm.prank(testAccount);
        smartSessionManager.disableActionPolicies(validPermissionId, fuzzActionId, policiesToRemove);

        // Assert - Valid policies should be removed
        if (policyCount >= 1) {
            assertFalse(
                smartSessionManager.isActionPolicyEnabled(
                    testAccount, validPermissionId, fuzzActionId, address(sudoPolicy)
                ),
                "SudoPolicy should be disabled"
            );
        }
        if (policyCount >= 2) {
            assertFalse(
                smartSessionManager.isActionPolicyEnabled(
                    testAccount, validPermissionId, fuzzActionId, address(noPolicy)
                ),
                "NoPolicy should be disabled"
            );
        }
    }
}
