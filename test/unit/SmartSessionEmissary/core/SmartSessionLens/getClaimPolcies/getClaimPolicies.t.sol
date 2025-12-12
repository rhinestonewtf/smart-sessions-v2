// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Contracts
import { SudoPolicy } from "@smartsessions/external/policies/SudoPolicy.sol";

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId, PolicyData, ActionData } from "@smartsessions/DataTypes.sol";
import { Session, ERC7739Data } from "@types/DataTypes.sol";

contract SmartSessionLens_getClaimPolicies_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             EMPTY STATE
    //////////////////////////////////////////////////////////////*/

    function test_getClaimPolicies_ReturnsEmpty_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        address[] memory policies =
            _lens().getClaimPolicies(instance.account, fakePermissionId, TEST_LOCK_TAG);

        // Assert
        assertEq(policies.length, 0, "Should return empty array");
    }

    function test_getClaimPolicies_ReturnsEmpty_ForDifferentLockTag() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        address[] memory policies =
            _lens().getClaimPolicies(instance.account, permissionId, TEST_LOCK_TAG_2);

        // Assert
        assertEq(policies.length, 0, "Should return empty for different lock tag");
    }

    function test_getClaimPolicies_ReturnsEmpty_ForActionOnlySession() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        address[] memory policies =
            _lens().getClaimPolicies(instance.account, permissionId, TEST_LOCK_TAG);

        // Assert
        assertEq(policies.length, 0, "Should return empty for action-only session");
    }

    /*//////////////////////////////////////////////////////////////
                            WITH POLICIES
    //////////////////////////////////////////////////////////////*/

    function test_getClaimPolicies_ReturnsSingle_WhenOnePolicy() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        address[] memory policies =
            _lens().getClaimPolicies(instance.account, permissionId, TEST_LOCK_TAG);

        // Assert
        assertEq(policies.length, 1, "Should return one policy");
        assertEq(policies[0], address(sudoPolicy), "Should be sudo policy");
    }

    function test_getClaimPolicies_ReturnsMultiple_WhenManyPolicies() public {
        // Arrange
        address policy1 = address(sudoPolicy);
        address policy2 = address(new SudoPolicy());
        address policy3 = address(new SudoPolicy());

        PolicyData[] memory claimPolicies = new PolicyData[](3);
        claimPolicies[0] = PolicyData({ policy: policy1, initData: "" });
        claimPolicies[1] = PolicyData({ policy: policy2, initData: "" });
        claimPolicies[2] = PolicyData({ policy: policy3, initData: "" });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("testSalt"),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: claimPolicies
        });

        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        address[] memory policies =
            _lens().getClaimPolicies(instance.account, permissionId, TEST_LOCK_TAG);

        // Assert
        assertEq(policies.length, 3, "Should return three policies");
    }
}
