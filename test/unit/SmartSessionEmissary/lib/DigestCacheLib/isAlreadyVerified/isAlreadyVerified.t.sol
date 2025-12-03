// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { DigestCacheLib_Unit_Test } from "../DigestCacheLib.t.sol";

// Libraries
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

contract DigestCacheLib_isAlreadyVerified_Test is DigestCacheLib_Unit_Test {
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
                            RETURNS FALSE
    //////////////////////////////////////////////////////////////*/

    function test_isAlreadyVerified_ReturnsFalse_WhenNotCached() public view {
        // Act
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);

        // Assert
        assertFalse(isVerified, "Should return false for uncached digest");
    }

    /*//////////////////////////////////////////////////////////////
                             RETURNS TRUE
    //////////////////////////////////////////////////////////////*/

    function test_isAlreadyVerified_ReturnsTrue_AfterMarking() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Act
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);

        // Assert
        assertTrue(isVerified, "Should return true after marking as verified");
    }

    /*//////////////////////////////////////////////////////////////
                              ISOLATION
    //////////////////////////////////////////////////////////////*/

    function test_isAlreadyVerified_DifferentAccounts_Isolated() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Act
        bool account1Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);
        bool account2Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account2, permissionId1, lockTag1);

        // Assert
        assertTrue(account1Verified, "Account1 should be verified");
        assertFalse(account2Verified, "Account2 should not be verified");
    }

    function test_isAlreadyVerified_DifferentPermissions_Isolated() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Act
        bool permission1Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);
        bool permission2Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId2, lockTag1);

        // Assert
        assertTrue(permission1Verified, "Permission1 should be verified");
        assertFalse(permission2Verified, "Permission2 should not be verified");
    }

    function test_isAlreadyVerified_DifferentLockTags_Isolated() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Act
        bool lockTag1Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);
        bool lockTag2Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag2);

        // Assert
        assertTrue(lockTag1Verified, "LockTag1 should be verified");
        assertFalse(lockTag2Verified, "LockTag2 should not be verified");
    }

    function test_isAlreadyVerified_DifferentDigests_Isolated() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Act
        bool digest1Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);
        bool digest2Verified =
            DigestCacheLib.isAlreadyVerified(digest2, account1, permissionId1, lockTag1);

        // Assert
        assertTrue(digest1Verified, "Digest1 should be verified");
        assertFalse(digest2Verified, "Digest2 should not be verified");
    }
}
