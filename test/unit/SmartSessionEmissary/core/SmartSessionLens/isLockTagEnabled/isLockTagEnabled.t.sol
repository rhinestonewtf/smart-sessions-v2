// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isLockTagEnabled_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isLockTagEnabled_ReturnsFalse_WhenNotEnabled() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        bool isEnabled = _lens().isLockTagEnabled(instance.account, fakePermissionId, TEST_LOCK_TAG);

        // Assert
        assertFalse(isEnabled, "Should return false for non-enabled lock tag");
    }

    function test_isLockTagEnabled_ReturnsFalse_ForDifferentAccount() public {
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
        bool isEnabled = _lens().isLockTagEnabled(differentAccount, permissionId, TEST_LOCK_TAG);

        // Assert
        assertFalse(isEnabled, "Should return false for different account");
    }

    function test_isLockTagEnabled_ReturnsFalse_ForDifferentLockTag() public {
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
        bool isEnabled = _lens().isLockTagEnabled(instance.account, permissionId, TEST_LOCK_TAG_2);

        // Assert
        assertFalse(isEnabled, "Should return false for different lock tag");
    }

    function test_isLockTagEnabled_ReturnsFalse_ForDifferentPermissionId() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        _enableSession(session, TEST_LOCK_TAG);

        PermissionId differentPermissionId = PermissionId.wrap(keccak256("different"));

        // Act
        bool isEnabled =
            _lens().isLockTagEnabled(instance.account, differentPermissionId, TEST_LOCK_TAG);

        // Assert
        assertFalse(isEnabled, "Should return false for different permission id");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isLockTagEnabled_ReturnsTrue_WhenEnabled() public {
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
        bool isEnabled = _lens().isLockTagEnabled(instance.account, permissionId, TEST_LOCK_TAG);

        // Assert
        assertTrue(isEnabled, "Should return true for enabled lock tag");
    }

    function test_isLockTagEnabled_ReturnsTrue_ForMultipleLockTags() public {
        // Arrange - different sessions, different lockTags
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
        PermissionId permissionId2 = _enableSession(session2, TEST_LOCK_TAG_2);

        // Act
        bool isEnabled1 = _lens().isLockTagEnabled(instance.account, permissionId1, TEST_LOCK_TAG);
        bool isEnabled2 = _lens().isLockTagEnabled(instance.account, permissionId2, TEST_LOCK_TAG_2);

        // Assert
        assertTrue(isEnabled1, "Lock tag 1 should be enabled");
        assertTrue(isEnabled2, "Lock tag 2 should be enabled");
    }

    function test_isLockTagEnabled_ReturnsTrue_SamePermission_MultipleLockTags() public {
        // Arrange - same session, different lockTags
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Enable again with different lockTag (same permissionId)
        vm.prank(instance.account);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, TEST_LOCK_TAG_2);

        // Act
        bool isEnabled1 = _lens().isLockTagEnabled(instance.account, permissionId, TEST_LOCK_TAG);
        bool isEnabled2 = _lens().isLockTagEnabled(instance.account, permissionId, TEST_LOCK_TAG_2);

        // Assert
        assertTrue(isEnabled1, "Lock tag 1 should be enabled");
        assertTrue(isEnabled2, "Lock tag 2 should be enabled");
    }

    function test_isLockTagEnabled_ReturnsTrue_ForNoLockTag() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, NO_LOCK_TAG);

        // Act
        bool isEnabled = _lens().isLockTagEnabled(instance.account, permissionId, NO_LOCK_TAG);

        // Assert
        assertTrue(isEnabled, "No lock tag should be enabled");
    }

    /// @notice Test lockTag isolation - same lockTag, different permissionId
    function test_isLockTagEnabled_ReturnsFalse_ForDifferentPermissionId_SameLockTag() public {
        // Arrange - enable session with testLockTag
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Create different permissionId (never enabled)
        PermissionId differentPermissionId = PermissionId.wrap(keccak256("different"));

        // Act
        bool isEnabledForOriginal =
            _lens().isLockTagEnabled(instance.account, permissionId, TEST_LOCK_TAG);
        bool isEnabledForDifferent =
            _lens().isLockTagEnabled(instance.account, differentPermissionId, TEST_LOCK_TAG);

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original permissionId");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different permissionId");
    }

    /// @notice Test same permissionId can have multiple lockTags
    function test_isLockTagEnabled_ReturnsTrue_SamePermissionId_MultipleLockTags() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        // Enable same session with two different lockTags
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Enable again with different lockTag (same permissionId)
        vm.prank(instance.account);
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, TEST_LOCK_TAG_2);

        // Act
        bool isEnabled1 = _lens().isLockTagEnabled(instance.account, permissionId, TEST_LOCK_TAG);
        bool isEnabled2 = _lens().isLockTagEnabled(instance.account, permissionId, TEST_LOCK_TAG_2);

        // Assert
        assertTrue(isEnabled1, "Lock tag 1 should be enabled");
        assertTrue(isEnabled2, "Lock tag 2 should be enabled");
    }
}
