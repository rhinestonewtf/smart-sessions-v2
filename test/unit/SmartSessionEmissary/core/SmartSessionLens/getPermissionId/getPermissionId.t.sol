// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getPermissionId_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                SUCCESS
    //////////////////////////////////////////////////////////////*/

    function test_getPermissionId_ReturnsCorrectId() public view {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        // Act
        PermissionId permissionId = _lens().getPermissionId(session);

        // Assert
        assertTrue(PermissionId.unwrap(permissionId) != bytes32(0), "Should return non-zero id");
    }

    function test_getPermissionId_DifferentSalts_ReturnDifferentIds() public view {
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
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        // Act
        PermissionId id1 = _lens().getPermissionId(session1);
        PermissionId id2 = _lens().getPermissionId(session2);

        // Assert
        assertTrue(
            PermissionId.unwrap(id1) != PermissionId.unwrap(id2),
            "Different salts should produce different ids"
        );
    }

    function test_getPermissionId_DifferentValidators_ReturnDifferentIds() public view {
        // Arrange
        Session memory session1 = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("sameSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        Session memory session2 = _createActionSession(
            ISessionValidator(address(noSessionValidator)),
            keccak256("sameSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        // Act
        PermissionId id1 = _lens().getPermissionId(session1);
        PermissionId id2 = _lens().getPermissionId(session2);

        // Assert
        assertTrue(
            PermissionId.unwrap(id1) != PermissionId.unwrap(id2),
            "Different validators should produce different ids"
        );
    }

    function test_getPermissionId_SameSession_ReturnsSameId() public view {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        // Act
        PermissionId id1 = _lens().getPermissionId(session);
        PermissionId id2 = _lens().getPermissionId(session);

        // Assert
        assertEq(
            PermissionId.unwrap(id1), PermissionId.unwrap(id2), "Same session should return same id"
        );
    }

    function test_getPermissionId_IsPure() public view {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        // Act - Call multiple times to verify it's deterministic
        PermissionId id1 = _lens().getPermissionId(session);
        PermissionId id2 = _lens().getPermissionId(session);
        PermissionId id3 = _lens().getPermissionId(session);

        // Assert
        assertEq(PermissionId.unwrap(id1), PermissionId.unwrap(id2));
        assertEq(PermissionId.unwrap(id2), PermissionId.unwrap(id3));
    }
}
