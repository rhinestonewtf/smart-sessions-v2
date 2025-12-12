// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getERC1271Policies_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 constant TEST_DOMAIN_SEPARATOR = keccak256("testDomain");
    string constant TEST_CONTENT_NAME = "TestContent(string data)TestContent";

    /*//////////////////////////////////////////////////////////////
                             EMPTY STATE
    //////////////////////////////////////////////////////////////*/

    function test_getERC1271Policies_ReturnsEmpty_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        address[] memory policies = _lens().getERC1271Policies(instance.account, fakePermissionId);

        // Assert
        assertEq(policies.length, 0, "Should return empty array");
    }

    function test_getERC1271Policies_ReturnsEmpty_ForActionOnlySession() public {
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
        address[] memory policies = _lens().getERC1271Policies(instance.account, permissionId);

        // Assert
        assertEq(policies.length, 0, "Should return empty for action-only session");
    }

    /*//////////////////////////////////////////////////////////////
                            WITH POLICIES
    //////////////////////////////////////////////////////////////*/

    function test_getERC1271Policies_ReturnsSingle_WhenOnePolicy() public {
        // Arrange
        Session memory session = _createERC7739Session(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy),
            TEST_DOMAIN_SEPARATOR,
            TEST_CONTENT_NAME
        );
        PermissionId permissionId = _enableSession(session, NO_LOCK_TAG);

        // Act
        address[] memory policies = _lens().getERC1271Policies(instance.account, permissionId);

        // Assert
        assertEq(policies.length, 1, "Should return one policy");
        assertEq(policies[0], address(sudoPolicy), "Should be sudo policy");
    }
}
