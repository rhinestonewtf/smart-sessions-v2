// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isClaimPolicyEnabled_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isClaimPolicyEnabled_ReturnsFalse_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        bool isEnabled = _lens()
            .isClaimPolicyEnabled(
                instance.account, fakePermissionId, TEST_LOCK_TAG, address(sudoPolicy)
            );

        // Assert
        assertFalse(isEnabled, "Should return false for non-existent session");
    }

    function test_isClaimPolicyEnabled_ReturnsFalse_ForDifferentPolicy() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        address differentPolicy = makeAddr("differentPolicy");

        // Act
        bool isEnabled = _lens()
            .isClaimPolicyEnabled(instance.account, permissionId, TEST_LOCK_TAG, differentPolicy);

        // Assert
        assertFalse(isEnabled, "Should return false for different policy");
    }

    function test_isClaimPolicyEnabled_ReturnsFalse_ForDifferentLockTag() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        bool isEnabled = _lens()
            .isClaimPolicyEnabled(
                instance.account, permissionId, TEST_LOCK_TAG_2, address(sudoPolicy)
            );

        // Assert
        assertFalse(isEnabled, "Should return false for different lock tag");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isClaimPolicyEnabled_ReturnsTrue_WhenEnabled() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        bool isEnabled = _lens()
            .isClaimPolicyEnabled(
                instance.account, permissionId, TEST_LOCK_TAG, address(sudoPolicy)
            );

        // Assert
        assertTrue(isEnabled, "Should return true for enabled policy");
    }

    /*//////////////////////////////////////////////////////////////
                               ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test claim policies are isolated per permissionId
    function test_isClaimPolicyEnabled_IsolatedPerPermissionId() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        PermissionId differentPermissionId = PermissionId.wrap(keccak256("different"));

        // Act
        bool isEnabledForOriginal = _lens()
            .isClaimPolicyEnabled(
                instance.account, permissionId, TEST_LOCK_TAG, address(sudoPolicy)
            );
        bool isEnabledForDifferent = _lens()
            .isClaimPolicyEnabled(
                instance.account, differentPermissionId, TEST_LOCK_TAG, address(sudoPolicy)
            );

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original permissionId");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different permissionId");
    }

    /// @notice Test claim policies are isolated per lockTag
    function test_isClaimPolicyEnabled_IsolatedPerLockTag() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        bool isEnabledForOriginal = _lens()
            .isClaimPolicyEnabled(
                instance.account, permissionId, TEST_LOCK_TAG, address(sudoPolicy)
            );
        bool isEnabledForDifferent = _lens()
            .isClaimPolicyEnabled(
                instance.account, permissionId, TEST_LOCK_TAG_2, address(sudoPolicy)
            );

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original lockTag");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different lockTag");
    }

    /// @notice Test claim policies are isolated per policy address
    function test_isClaimPolicyEnabled_IsolatedPerPolicy() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        address differentPolicy = makeAddr("differentPolicy");

        // Act
        bool isEnabledForOriginal = _lens()
            .isClaimPolicyEnabled(
                instance.account, permissionId, TEST_LOCK_TAG, address(sudoPolicy)
            );
        bool isEnabledForDifferent = _lens()
            .isClaimPolicyEnabled(instance.account, permissionId, TEST_LOCK_TAG, differentPolicy);

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original policy");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different policy");
    }

    /// @notice Test claim policies are isolated per account
    function test_isClaimPolicyEnabled_IsolatedPerAccount() public {
        // Arrange
        Session memory session = _createClaimSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy)
        );
        PermissionId permissionId = _enableSession(session, TEST_LOCK_TAG);

        address differentAccount = makeAddr("differentAccount");

        // Act
        bool isEnabledForOriginal = _lens()
            .isClaimPolicyEnabled(
                instance.account, permissionId, TEST_LOCK_TAG, address(sudoPolicy)
            );
        bool isEnabledForDifferent = _lens()
            .isClaimPolicyEnabled(
                differentAccount, permissionId, TEST_LOCK_TAG, address(sudoPolicy)
            );

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original account");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different account");
    }
}
