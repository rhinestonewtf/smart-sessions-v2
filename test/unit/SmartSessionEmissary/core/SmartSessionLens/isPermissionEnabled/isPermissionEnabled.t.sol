// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isPermissionEnabled_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isPermissionEnabled_ReturnsFalse_WhenNotEnabled() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fakePermission"));

        // Act
        bool isEnabled = _lens().isPermissionEnabled(instance.account, fakePermissionId);

        // Assert
        assertFalse(isEnabled, "Should return false for non-enabled permission");
    }

    function test_isPermissionEnabled_ReturnsFalse_WhenDifferentAccount() public {
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
        bool isEnabled = _lens().isPermissionEnabled(differentAccount, permissionId);

        // Assert
        assertFalse(isEnabled, "Should return false for different account");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isPermissionEnabled_ReturnsTrue_WhenEnabled() public {
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
        bool isEnabled = _lens().isPermissionEnabled(instance.account, permissionId);

        // Assert
        assertTrue(isEnabled, "Should return true for enabled permission");
    }

    function test_isPermissionEnabled_ReturnsTrue_ForMultiplePermissions() public {
        // Arrange
        Session memory session1 = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("salt1"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        Session memory session2 = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("salt2"),
            target,
            bytes4(keccak256("approve()")),
            address(sudoPolicy)
        );

        PermissionId permissionId1 = _enableSession(session1, TEST_LOCK_TAG);
        PermissionId permissionId2 = _enableSession(session2, TEST_LOCK_TAG);

        // Act
        bool isEnabled1 = _lens().isPermissionEnabled(instance.account, permissionId1);
        bool isEnabled2 = _lens().isPermissionEnabled(instance.account, permissionId2);

        // Assert
        assertTrue(isEnabled1, "First permission should be enabled");
        assertTrue(isEnabled2, "Second permission should be enabled");
    }

    /// @notice Test permissions are isolated per account
    function test_isPermissionEnabled_IsolatedPerAccount() public {
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
        bool isEnabledForOriginal = _lens().isPermissionEnabled(instance.account, permissionId);
        bool isEnabledForDifferent = _lens().isPermissionEnabled(differentAccount, permissionId);

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original account");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different account");
    }

    /// @notice Test different permissionIds are isolated
    function test_isPermissionEnabled_IsolatedPerPermissionId() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        PermissionId differentPermissionId = PermissionId.wrap(keccak256("different"));

        // Act
        bool isEnabledForOriginal = _lens().isPermissionEnabled(instance.account, permissionId);
        bool isEnabledForDifferent =
            _lens().isPermissionEnabled(instance.account, differentPermissionId);

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original permissionId");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different permissionId");
    }
}
