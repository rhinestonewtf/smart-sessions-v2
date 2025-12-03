// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { DigestCacheLib_Unit_Test } from "../DigestCacheLib.t.sol";

// Libraries
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

contract DigestCacheLib_markAsVerified_Test is DigestCacheLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes12 lockTag1 = bytes12(keccak256("lockTag1"));
    bytes12 lockTag2 = bytes12(keccak256("lockTag2"));
    PermissionId permissionId1;
    PermissionId permissionId2;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
        permissionId1 = PermissionId.wrap(keccak256("permission1"));
        permissionId2 = PermissionId.wrap(keccak256("permission2"));
    }

    /*//////////////////////////////////////////////////////////////
                                SUCCESS
    //////////////////////////////////////////////////////////////*/

    function test_markAsVerified_Success() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Assert
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);
        assertTrue(isVerified, "Should be marked as verified");
    }

    function test_markAsVerified_MultipleDigests() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);
        DigestCacheLib.markAsVerified(digest2, account1, permissionId1, lockTag1);
        DigestCacheLib.markAsVerified(digest3, account1, permissionId1, lockTag1);

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1),
            "Digest1 should be verified"
        );
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest2, account1, permissionId1, lockTag1),
            "Digest2 should be verified"
        );
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest3, account1, permissionId1, lockTag1),
            "Digest3 should be verified"
        );
    }

    function test_markAsVerified_MultipleLockTags() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag2);

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1),
            "Should be verified with lockTag1"
        );
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag2),
            "Should be verified with lockTag2"
        );
    }

    function test_markAsVerified_MultiplePermissions() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);
        DigestCacheLib.markAsVerified(digest1, account1, permissionId2, lockTag1);

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1),
            "Should be verified with permissionId1"
        );
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId2, lockTag1),
            "Should be verified with permissionId2"
        );
    }

    function test_markAsVerified_IdempotentOperation() public {
        // Act - mark multiple times
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Assert - should still be verified
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);
        assertTrue(isVerified, "Should remain verified after multiple marks");
    }

    /*//////////////////////////////////////////////////////////////
                             EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_markAsVerified_WithZeroAddress() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, address(0), permissionId1, lockTag1);

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, address(0), permissionId1, lockTag1),
            "Should work with zero address"
        );
    }

    function test_markAsVerified_WithZeroDigest() public {
        // Act
        DigestCacheLib.markAsVerified(bytes32(0), account1, permissionId1, lockTag1);

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(bytes32(0), account1, permissionId1, lockTag1),
            "Should work with zero digest"
        );
    }

    function test_markAsVerified_WithZeroPermissionId() public {
        // Act
        PermissionId zeroPermission = PermissionId.wrap(bytes32(0));
        DigestCacheLib.markAsVerified(digest1, account1, zeroPermission, lockTag1);

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, zeroPermission, lockTag1),
            "Should work with zero permissionId"
        );
    }

    function test_markAsVerified_WithZeroLockTag() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, bytes12(0));

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, bytes12(0)),
            "Should work with zero lockTag"
        );
    }
}
