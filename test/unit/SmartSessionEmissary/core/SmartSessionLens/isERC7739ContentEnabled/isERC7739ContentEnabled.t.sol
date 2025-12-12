// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_isERC7739ContentEnabled_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 constant TEST_DOMAIN_SEPARATOR = keccak256("testDomain");
    string constant TEST_CONTENT_NAME = "TestContent(string data)TestContent";

    /*//////////////////////////////////////////////////////////////
                             RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isERC7739ContentEnabled_ReturnsFalse_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        bool isEnabled = _lens()
            .isERC7739ContentEnabled(
                instance.account, fakePermissionId, TEST_DOMAIN_SEPARATOR, TEST_CONTENT_NAME
            );

        // Assert
        assertFalse(isEnabled, "Should return false for non-existent session");
    }

    function test_isERC7739ContentEnabled_ReturnsFalse_ForDifferentDomain() public {
        // Arrange
        Session memory session = _createERC7739Session(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy),
            TEST_DOMAIN_SEPARATOR,
            TEST_CONTENT_NAME
        );
        PermissionId permissionId = _enableSession(session, NO_LOCK_TAG);

        bytes32 differentDomain = keccak256("differentDomain");

        // Act
        bool isEnabled = _lens()
            .isERC7739ContentEnabled(
                instance.account, permissionId, differentDomain, TEST_CONTENT_NAME
            );

        // Assert
        assertFalse(isEnabled, "Should return false for different domain");
    }

    function test_isERC7739ContentEnabled_ReturnsFalse_ForDifferentContent() public {
        // Arrange
        Session memory session = _createERC7739Session(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy),
            TEST_DOMAIN_SEPARATOR,
            TEST_CONTENT_NAME
        );
        PermissionId permissionId = _enableSession(session, NO_LOCK_TAG);

        string memory differentContent = "DifferentContent(uint256 value)DifferentContent";

        // Act
        bool isEnabled = _lens()
            .isERC7739ContentEnabled(
                instance.account, permissionId, TEST_DOMAIN_SEPARATOR, differentContent
            );

        // Assert
        assertFalse(isEnabled, "Should return false for different content");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isERC7739ContentEnabled_ReturnsTrue_WhenEnabled() public {
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
        bool isEnabled = _lens()
            .isERC7739ContentEnabled(
                instance.account, permissionId, TEST_DOMAIN_SEPARATOR, TEST_CONTENT_NAME
            );

        // Assert
        assertTrue(isEnabled, "Should return true for enabled content");
    }
}
