// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { DigestCacheLib_Unit_Test } from "../DigestCacheLib.t.sol";

// Libraries
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

contract DigestCacheLib_isAlreadyVerified_Test is DigestCacheLib_Unit_Test {
    /* //////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    uint8 configId1 = 1;
    uint8 configId2 = 2;
    bytes12 lockTag1 = bytes12(keccak256("lockTag1"));
    bytes12 lockTag2 = bytes12(keccak256("lockTag2"));
    IStatelessValidator validator1;
    IStatelessValidator validator2;
    PermissionId permissionId1;
    PermissionId permissionId2;

    /* //////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
        validator1 = IStatelessValidator(makeAddr("validator1"));
        validator2 = IStatelessValidator(makeAddr("validator2"));
        permissionId1 = PermissionId.wrap(keccak256("permission1"));
        permissionId2 = PermissionId.wrap(keccak256("permission2"));
    }

    /* //////////////////////////////////////////////////////////////
                             ECDSA/PASSKEY
    //////////////////////////////////////////////////////////////*/

    function test_isAlreadyVerified_ECDSA_ReturnsFalse_WhenNotCached() public view {
        // Act
        bool isVerified = DigestCacheLib.isAlreadyVerified(digest1, account1, configId1, lockTag1);

        // Assert
        assertFalse(isVerified, "Should return false for uncached digest");
    }

    function test_isAlreadyVerified_ECDSA_ReturnsTrue_AfterMarking() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, configId1, lockTag1);

        // Act
        bool isVerified = DigestCacheLib.isAlreadyVerified(digest1, account1, configId1, lockTag1);

        // Assert
        assertTrue(isVerified, "Should return true after marking as verified");
    }

    function test_isAlreadyVerified_ECDSA_DifferentAccounts_Isolated() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, configId1, lockTag1);

        // Act
        bool account1Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, configId1, lockTag1);
        bool account2Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account2, configId1, lockTag1);

        // Assert
        assertTrue(account1Verified, "Account1 should be verified");
        assertFalse(account2Verified, "Account2 should not be verified");
    }

    /* //////////////////////////////////////////////////////////////
                               STATELESS
    //////////////////////////////////////////////////////////////*/

    function test_isAlreadyVerified_Stateless_ReturnsFalse_WhenNotCached() public view {
        // Act
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, validator1, configId1, lockTag1);

        // Assert
        assertFalse(isVerified, "Should return false for uncached digest");
    }

    function test_isAlreadyVerified_Stateless_ReturnsTrue_AfterMarking() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, validator1, configId1, lockTag1);

        // Act
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, validator1, configId1, lockTag1);

        // Assert
        assertTrue(isVerified, "Should return true after marking as verified");
    }

    function test_isAlreadyVerified_Stateless_DifferentValidators_Isolated() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, validator1, configId1, lockTag1);

        // Act
        bool validator1Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, validator1, configId1, lockTag1);
        bool validator2Verified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, validator2, configId1, lockTag1);

        // Assert
        assertTrue(validator1Verified, "Validator1 should be verified");
        assertFalse(validator2Verified, "Validator2 should not be verified");
    }

    /* //////////////////////////////////////////////////////////////
                             SMART SESSION
    //////////////////////////////////////////////////////////////*/

    function test_isAlreadyVerified_SmartSession_ReturnsFalse_WhenNotCached() public view {
        // Act
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);

        // Assert
        assertFalse(isVerified, "Should return false for uncached digest");
    }

    function test_isAlreadyVerified_SmartSession_ReturnsTrue_AfterMarking() public {
        // Arrange
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Act
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);

        // Assert
        assertTrue(isVerified, "Should return true after marking as verified");
    }

    function test_isAlreadyVerified_SmartSession_DifferentPermissions_Isolated() public {
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
}
