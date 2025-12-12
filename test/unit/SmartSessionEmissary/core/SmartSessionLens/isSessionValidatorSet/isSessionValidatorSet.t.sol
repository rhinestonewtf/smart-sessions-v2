// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isSessionValidatorSet_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isSessionValidatorSet_ReturnsFalse_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        bool isSet = _lens().isSessionValidatorSet(instance.account, fakePermissionId);

        // Assert
        assertFalse(isSet, "Should return false for non-existent session");
    }

    function test_isSessionValidatorSet_ReturnsFalse_ForDifferentAccount() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        address differentAccount = makeAddr("differentAccount");

        // Act
        bool isSet = _lens().isSessionValidatorSet(differentAccount, permissionId);

        // Assert
        assertFalse(isSet, "Should return false for different account");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isSessionValidatorSet_ReturnsTrue_WhenSessionEnabled() public {
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
        bool isSet = _lens().isSessionValidatorSet(instance.account, permissionId);

        // Assert
        assertTrue(isSet, "Should return true for enabled session");
    }
}

