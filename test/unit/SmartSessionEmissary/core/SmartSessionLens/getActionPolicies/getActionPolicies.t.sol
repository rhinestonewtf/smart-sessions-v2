// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Contracts
import { SudoPolicy } from "@smartsessions/external/policies/SudoPolicy.sol";

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId, ActionId, ActionData, PolicyData } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getActionPolicies_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    bytes4 testSelector;
    ActionId testActionId;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
        testSelector = bytes4(keccak256("transfer()"));
        testActionId = _toActionId(target, testSelector);
    }

    /*//////////////////////////////////////////////////////////////
                             EMPTY STATE
    //////////////////////////////////////////////////////////////*/

    function test_getActionPolicies_ReturnsEmpty_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        address[] memory policies =
            _lens().getActionPolicies(instance.account, fakePermissionId, testActionId);

        // Assert
        assertEq(policies.length, 0, "Should return empty array");
    }

    function test_getActionPolicies_ReturnsEmpty_ForDifferentActionId() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            testSelector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        ActionId differentActionId = _toActionId(target, bytes4(keccak256("approve()")));

        // Act
        address[] memory policies =
            _lens().getActionPolicies(instance.account, permissionId, differentActionId);

        // Assert
        assertEq(policies.length, 0, "Should return empty for different action");
    }

    /*//////////////////////////////////////////////////////////////
                            WITH POLICIES
    //////////////////////////////////////////////////////////////*/

    function test_getActionPolicies_ReturnsSingle_WhenOnePolicy() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            testSelector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        address[] memory policies =
            _lens().getActionPolicies(instance.account, permissionId, testActionId);

        // Assert
        assertEq(policies.length, 1, "Should return one policy");
        assertEq(policies[0], address(sudoPolicy), "Should be sudo policy");
    }

    function test_getActionPolicies_ReturnsMultiple_WhenManyPolicies() public {
        // Arrange
        address policy1 = address(sudoPolicy);
        address policy2 = address(new SudoPolicy());
        address policy3 = address(new SudoPolicy());

        PolicyData[] memory policyDatas = new PolicyData[](3);
        policyDatas[0] = PolicyData({ policy: policy1, initData: "" });
        policyDatas[1] = PolicyData({ policy: policy2, initData: "" });
        policyDatas[2] = PolicyData({ policy: policy3, initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target, actionTargetSelector: testSelector, actionPolicies: policyDatas
        });

        Session memory session = _createMultiActionSession(
            ISessionValidator(address(yesSessionValidator)), keccak256("testSalt"), actions
        );

        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        address[] memory policies =
            _lens().getActionPolicies(instance.account, permissionId, testActionId);

        // Assert
        assertEq(policies.length, 3, "Should return three policies");
    }
}

