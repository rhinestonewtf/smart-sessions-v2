// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getPermissionIds_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                             EMPTY STATE
    //////////////////////////////////////////////////////////////*/

    function test_getPermissionIds_ReturnsEmpty_WhenNoSessions() public view {
        // Act
        PermissionId[] memory permissionIds = _lens().getPermissionIds(instance.account);

        // Assert
        assertEq(permissionIds.length, 0, "Should return empty array");
    }

    function test_getPermissionIds_ReturnsEmpty_ForDifferentAccount() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        _enableSession(session, TEST_LOCK_TAG);

        address differentAccount = makeAddr("differentAccount");

        // Act
        PermissionId[] memory permissionIds = _lens().getPermissionIds(differentAccount);

        // Assert
        assertEq(permissionIds.length, 0, "Should return empty for different account");
    }

    /*//////////////////////////////////////////////////////////////
                            WITH SESSIONS
    //////////////////////////////////////////////////////////////*/

    function test_getPermissionIds_ReturnsSingle_WhenOneSession() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        PermissionId expectedId = _enableSession(session, TEST_LOCK_TAG);

        // Act
        PermissionId[] memory permissionIds = _lens().getPermissionIds(instance.account);

        // Assert
        assertEq(permissionIds.length, 1, "Should return one permission");
        assertEq(
            PermissionId.unwrap(permissionIds[0]),
            PermissionId.unwrap(expectedId),
            "Should match enabled permission"
        );
    }

    function test_getPermissionIds_ReturnsMultiple_WhenManySessions() public {
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
        Session memory session3 = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("salt3"),
            target,
            bytes4(keccak256("mint()")),
            address(sudoPolicy)
        );

        PermissionId id1 = _enableSession(session1, TEST_LOCK_TAG);
        PermissionId id2 = _enableSession(session2, TEST_LOCK_TAG);
        PermissionId id3 = _enableSession(session3, TEST_LOCK_TAG);

        // Act
        PermissionId[] memory permissionIds = _lens().getPermissionIds(instance.account);

        // Assert
        assertEq(permissionIds.length, 3, "Should return three permissions");

        // Check all IDs are present (order may vary)
        bool found1;
        bool found2;
        bool found3;
        for (uint256 i = 0; i < permissionIds.length; i++) {
            if (PermissionId.unwrap(permissionIds[i]) == PermissionId.unwrap(id1)) found1 = true;
            if (PermissionId.unwrap(permissionIds[i]) == PermissionId.unwrap(id2)) found2 = true;
            if (PermissionId.unwrap(permissionIds[i]) == PermissionId.unwrap(id3)) found3 = true;
        }
        assertTrue(found1, "Should contain permission 1");
        assertTrue(found2, "Should contain permission 2");
        assertTrue(found3, "Should contain permission 3");
    }
}
