// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isERC1271PolicyEnabled_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 constant TEST_DOMAIN_SEPARATOR = keccak256("testDomain");
    string constant TEST_CONTENT_NAME = "TestContent(string data)TestContent";

    /*//////////////////////////////////////////////////////////////
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isERC1271PolicyEnabled_ReturnsFalse_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        bool isEnabled =
            _lens().isERC1271PolicyEnabled(instance.account, fakePermissionId, address(sudoPolicy));

        // Assert
        assertFalse(isEnabled, "Should return false for non-existent session");
    }

    function test_isERC1271PolicyEnabled_ReturnsFalse_ForDifferentPolicy() public {
        // Arrange
        Session memory session = _createERC7739Session(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy),
            TEST_DOMAIN_SEPARATOR,
            TEST_CONTENT_NAME
        );
        PermissionId permissionId = _enableSession(session, NO_LOCK_TAG);

        address differentPolicy = makeAddr("differentPolicy");

        // Act
        bool isEnabled =
            _lens().isERC1271PolicyEnabled(instance.account, permissionId, differentPolicy);

        // Assert
        assertFalse(isEnabled, "Should return false for different policy");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isERC1271PolicyEnabled_ReturnsTrue_WhenEnabled() public {
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
        bool isEnabled =
            _lens().isERC1271PolicyEnabled(instance.account, permissionId, address(sudoPolicy));

        // Assert
        assertTrue(isEnabled, "Should return true for enabled policy");
    }

    /*//////////////////////////////////////////////////////////////
                               ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test ERC1271 policies are isolated per permissionId
    function test_isERC1271PolicyEnabled_IsolatedPerPermissionId() public {
        // Arrange
        Session memory session = _createERC7739Session(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy),
            keccak256("testDomain"),
            "TestContent"
        );
        PermissionId permissionId = _enableSession(session, NO_LOCK_TAG);

        PermissionId differentPermissionId = PermissionId.wrap(keccak256("different"));

        // Act
        bool isEnabledForOriginal =
            _lens().isERC1271PolicyEnabled(instance.account, permissionId, address(sudoPolicy));
        bool isEnabledForDifferent = _lens()
            .isERC1271PolicyEnabled(instance.account, differentPermissionId, address(sudoPolicy));

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original permissionId");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different permissionId");
    }

    /// @notice Test ERC1271 policies are isolated per policy address
    function test_isERC1271PolicyEnabled_IsolatedPerPolicy() public {
        // Arrange
        Session memory session = _createERC7739Session(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy),
            keccak256("testDomain"),
            "TestContent"
        );
        PermissionId permissionId = _enableSession(session, NO_LOCK_TAG);

        address differentPolicy = makeAddr("differentPolicy");

        // Act
        bool isEnabledForOriginal =
            _lens().isERC1271PolicyEnabled(instance.account, permissionId, address(sudoPolicy));
        bool isEnabledForDifferent =
            _lens().isERC1271PolicyEnabled(instance.account, permissionId, differentPolicy);

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original policy");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different policy");
    }

    /// @notice Test ERC1271 policies are isolated per account
    function test_isERC1271PolicyEnabled_IsolatedPerAccount() public {
        // Arrange
        Session memory session = _createERC7739Session(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy),
            keccak256("testDomain"),
            "TestContent"
        );
        PermissionId permissionId = _enableSession(session, NO_LOCK_TAG);

        address differentAccount = makeAddr("differentAccount");

        // Act
        bool isEnabledForOriginal =
            _lens().isERC1271PolicyEnabled(instance.account, permissionId, address(sudoPolicy));
        bool isEnabledForDifferent =
            _lens().isERC1271PolicyEnabled(differentAccount, permissionId, address(sudoPolicy));

        // Assert
        assertTrue(isEnabledForOriginal, "Should be enabled for original account");
        assertFalse(isEnabledForDifferent, "Should NOT be enabled for different account");
    }
}
