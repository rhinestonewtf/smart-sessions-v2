// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { SmartSessionExecutionVerifier } from "@contracts/SmartSessionExecutionVerifier.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";

// Types
import {
    Session, ActionData, PolicyData, PermissionId, ActionId
} from "@smartsessions/DataTypes.sol";

contract SmartSessionManager_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The SmartSessionExecutionVerifier contract instance.
    SmartSessionExecutionVerifier internal smartSessionManager;
    /// @notice Test account address.
    address testAccount;
    /// @notice Valid permission ID.
    PermissionId validPermissionId;
    /// @notice Test action ID.
    ActionId testActionId;
    /// @notice Test target address.
    address testTarget;
    /// @notice Test selector.
    bytes4 testSelector;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Deploy the SmartSessionExecutionVerifier contract.
        smartSessionManager = new SmartSessionExecutionVerifier(admin.addr);
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Helper to create a basic session for testing
    function createBasicSession() internal view returns (Session memory) {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: bytes4(keccak256("testFunction()")),
            actionPolicies: policyDatas
        });

        return Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("testSalt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actions,
            permitERC4337Paymaster: true
        });
    }

    /// @notice Helper to enable a session and return its permission ID
    function enableBasicSession(address account) internal returns (PermissionId permissionId) {
        Session memory session = createBasicSession();
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        vm.prank(account);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);
        return permissionIds[0];
    }

    /// @notice Helper to create action data array
    function createActionDataArray(uint256 count) internal view returns (ActionData[] memory) {
        ActionData[] memory actions = new ActionData[](count);
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        for (uint256 i = 0; i < count; i++) {
            actions[i] = ActionData({
                actionTarget: address(uint160(i + 1)), // Different target for each action
                actionTargetSelector: bytes4(keccak256(abi.encodePacked("function", i, "()"))),
                actionPolicies: policyDatas
            });
        }

        return actions;
    }

    /// @notice Helper to enable a test action with a single policy
    function enableTestActionWithPolicies() internal {
        ActionData[] memory actionPolicies = new ActionData[](1);
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        actionPolicies[0] = ActionData({
            actionTarget: testTarget,
            actionTargetSelector: testSelector,
            actionPolicies: policyDatas
        });

        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);
    }

    /// @notice Helper to enable an action with single policy
    function enableActionWithSinglePolicy() internal returns (ActionId) {
        // Create specific target and selector for single policy action
        address actionTarget =
            makeAddr(string.concat("singlePolicyTarget", vm.toString(block.timestamp)));
        bytes4 actionSelector =
            bytes4(keccak256(abi.encodePacked("singlePolicyFunction", block.timestamp)));

        ActionData[] memory actionPolicies = new ActionData[](1);
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        actionPolicies[0] = ActionData({
            actionTarget: actionTarget,
            actionTargetSelector: actionSelector,
            actionPolicies: policyDatas
        });

        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);

        // Return the calculated ActionId
        return actionTarget.toActionId(actionSelector);
    }

    /// @notice Helper to enable an action with multiple policies
    function enableActionWithMultiplePolicies() internal returns (ActionId) {
        // Create specific target and selector for multiple policy action
        address actionTarget =
            makeAddr(string.concat("multiPolicyTarget", vm.toString(block.timestamp)));
        bytes4 actionSelector =
            bytes4(keccak256(abi.encodePacked("multiPolicyFunction", block.timestamp)));

        ActionData[] memory actionPolicies = new ActionData[](1);
        PolicyData[] memory policyDatas = new PolicyData[](2);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        policyDatas[1] = PolicyData({ policy: address(noPolicy), initData: "" });

        actionPolicies[0] = ActionData({
            actionTarget: actionTarget,
            actionTargetSelector: actionSelector,
            actionPolicies: policyDatas
        });

        vm.prank(testAccount);
        smartSessionManager.enableActionPolicies(validPermissionId, actionPolicies);

        // Return the calculated ActionId
        return actionTarget.toActionId(actionSelector);
    }

    /// @notice Helper to verify action policies state
    function assertActionPoliciesState(
        ActionId actionId,
        address[] memory expectedPolicies,
        bool shouldBeEnabled
    )
        internal
        view
    {
        if (shouldBeEnabled) {
            assertTrue(
                smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, actionId),
                "Action should be enabled"
            );
        } else {
            assertFalse(
                smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, actionId),
                "Action should be disabled"
            );
        }

        for (uint256 i = 0; i < expectedPolicies.length; i++) {
            assertTrue(
                smartSessionManager.isActionPolicyEnabled(
                    testAccount, validPermissionId, actionId, expectedPolicies[i]
                ),
                string.concat("Policy ", vm.toString(i), " should be enabled")
            );
        }
    }

    /// @notice Helper to enable a session with multiple actions
    function enableSessionWithMultipleActions(address account) internal returns (PermissionId) {
        Session memory session = createBasicSession();
        session.salt = keccak256("multiActionSession");
        session.actions = createActionDataArray(3);

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        vm.prank(account);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);
        return permissionIds[0];
    }

    /// @notice Helper to enable a session with multiple policies per action
    function enableSessionWithMultiplePolicies(address account) internal returns (PermissionId) {
        Session memory session = createBasicSession();
        session.salt = keccak256("multiPolicySession");

        // Create action with multiple policies
        PolicyData[] memory policyDatas = new PolicyData[](2);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        policyDatas[1] = PolicyData({ policy: address(noPolicy), initData: "" });

        session.actions[0].actionPolicies = policyDatas;

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        vm.prank(account);
        PermissionId[] memory permissionIds = smartSessionManager.enableSessions(sessions);
        return permissionIds[0];
    }

    /// @notice Helper to create session with specific properties
    function createSessionWithProperties(
        bytes32 salt,
        address actionTarget,
        ISessionValidator validator
    )
        internal
        view
        returns (Session memory)
    {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: actionTarget,
            actionTargetSelector: bytes4(keccak256("testFunction()")),
            actionPolicies: policyDatas
        });

        return Session({
            sessionValidator: validator,
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actions,
            permitERC4337Paymaster: true
        });
    }

    /// @notice Helper to verify session state
    function assertSessionEnabled(PermissionId permissionId, address account) internal view {
        assertTrue(
            smartSessionManager.isPermissionEnabled(permissionId, account),
            "Permission should be enabled"
        );
        assertTrue(
            smartSessionManager.isISessionValidatorSet(permissionId, account),
            "Session validator should be set"
        );
    }

    /// @notice Helper to verify session removal state
    function assertSessionRemovedState(PermissionId permissionId, address account) internal view {
        assertFalse(
            smartSessionManager.isPermissionEnabled(permissionId, account),
            "Permission should be disabled"
        );
        assertFalse(
            smartSessionManager.isISessionValidatorSet(permissionId, account),
            "Session validator should be removed"
        );

        bytes32[] memory enabledActions =
            smartSessionManager.getEnabledActions(account, permissionId);
        assertEq(enabledActions.length, 0, "Should have no enabled actions");
    }

    /// @notice Helper to verify action state after disable
    function assertActionDisabledState(ActionId actionId) internal view {
        assertFalse(
            smartSessionManager.isActionIdEnabled(testAccount, validPermissionId, actionId),
            "Action should be disabled"
        );

        address[] memory policies =
            smartSessionManager.getActionPolicies(testAccount, validPermissionId, actionId);
        assertEq(policies.length, 0, "Should have no policies after disable");
    }
}
