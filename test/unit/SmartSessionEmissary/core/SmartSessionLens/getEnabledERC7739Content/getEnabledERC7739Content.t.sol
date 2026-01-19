// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId, ERC7739ContextHashes } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getEnabledERC7739Content_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 constant TEST_DOMAIN_SEPARATOR = keccak256("testDomain");
    string constant TEST_CONTENT_NAME = "TestContent(string data)TestContent";

    /*//////////////////////////////////////////////////////////////
                             EMPTY STATE
    //////////////////////////////////////////////////////////////*/

    function test_getEnabledERC7739Content_ReturnsEmpty_WhenNoSession() public view {
        // Arrange
        PermissionId fakePermissionId = PermissionId.wrap(keccak256("fake"));

        // Act
        ERC7739ContextHashes[] memory content =
            _lens().getEnabledERC7739Content(instance.account, fakePermissionId);

        // Assert
        assertEq(content.length, 0);
    }

    function test_getEnabledERC7739Content_ReturnsEmpty_ForActionOnlySession() public {
        // Arrange
        PermissionId permissionId = _enableActionSession();

        // Act
        ERC7739ContextHashes[] memory content =
            _lens().getEnabledERC7739Content(instance.account, permissionId);

        // Assert
        assertEq(content.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                            WITH CONTENT
    //////////////////////////////////////////////////////////////*/

    function test_getEnabledERC7739Content_ReturnsContent_WhenEnabled() public {
        // Arrange
        PermissionId permissionId = _enableERC7739Session();

        // Act
        ERC7739ContextHashes[] memory content =
            _lens().getEnabledERC7739Content(instance.account, permissionId);

        // Assert
        assertEq(content.length, 1);
        assertEq(content[0].appDomainSeparator, TEST_DOMAIN_SEPARATOR);
        assertEq(content[0].contentNameHashes.length, 1);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    function _enableActionSession() internal returns (PermissionId) {
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        return _enableSession(session, TEST_LOCK_TAG);
    }

    function _enableERC7739Session() internal returns (PermissionId) {
        Session memory session = _createERC7739Session(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            address(sudoPolicy),
            TEST_DOMAIN_SEPARATOR,
            TEST_CONTENT_NAME
        );
        return _enableSession(session, NO_LOCK_TAG);
    }
}
