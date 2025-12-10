// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId, ActionData } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getEnabledActions_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             EMPTY STATE
    //////////////////////////////////////////////////////////////*/

    function test_getEnabledActions_ReturnsEmpty_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        bytes32[] memory actionIds = _lens().getEnabledActions(instance.account, fakePermissionId);

        // Assert
        assertEq(actionIds.length, 0, "Should return empty array");
    }

    /*//////////////////////////////////////////////////////////////
                            WITH ACTIONS
    //////////////////////////////////////////////////////////////*/

    function test_getEnabledActions_ReturnsSingle_WhenOneAction() public {
        // Arrange
        bytes4 selector = bytes4(keccak256("transfer()"));
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            selector,
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        bytes32[] memory actionIds = _lens().getEnabledActions(instance.account, permissionId);

        // Assert
        assertEq(actionIds.length, 1, "Should return one action");
    }

    function test_getEnabledActions_ReturnsMultiple_WhenManyActions() public {
        // Arrange
        ActionData[] memory actions = new ActionData[](3);
        actions[0] = _createActionData(target, bytes4(keccak256("transfer()")), address(sudoPolicy));
        actions[1] = _createActionData(target, bytes4(keccak256("approve()")), address(sudoPolicy));
        actions[2] = _createActionData(
            makeAddr("otherTarget"), bytes4(keccak256("mint()")), address(sudoPolicy)
        );

        Session memory session = _createMultiActionSession(
            ISessionValidator(address(yesSessionValidator)), keccak256("testSalt"), actions
        );

        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        bytes32[] memory actionIds = _lens().getEnabledActions(instance.account, permissionId);

        // Assert
        assertEq(actionIds.length, 3, "Should return three actions");
    }

    function test_getEnabledActions_ReturnsEmpty_ForClaimOnlySession() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        bytes32[] memory actionIds = _lens().getEnabledActions(instance.account, permissionId);

        // Assert
        assertEq(actionIds.length, 0, "Should return empty for claim-only session");
    }
}
