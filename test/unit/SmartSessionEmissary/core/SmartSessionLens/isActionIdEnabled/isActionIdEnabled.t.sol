// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId, ActionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isActionIdEnabled_Test is SmartSessionLens_Unit_Test {
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
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isActionIdEnabled_ReturnsFalse_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        bool isEnabled = _lens().isActionIdEnabled(instance.account, fakePermissionId, testActionId);

        // Assert
        assertFalse(isEnabled, "Should return false for non-existent session");
    }

    function test_isActionIdEnabled_ReturnsFalse_ForDifferentActionId() public {
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
        bool isEnabled =
            _lens().isActionIdEnabled(instance.account, permissionId, differentActionId);

        // Assert
        assertFalse(isEnabled, "Should return false for different action id");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isActionIdEnabled_ReturnsTrue_WhenEnabled() public {
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
        bool isEnabled = _lens().isActionIdEnabled(instance.account, permissionId, testActionId);

        // Assert
        assertTrue(isEnabled, "Should return true for enabled action id");
    }
}
