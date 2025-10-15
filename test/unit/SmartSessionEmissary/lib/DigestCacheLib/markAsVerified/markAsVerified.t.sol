// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { DigestCacheLib_Unit_Test } from "../DigestCacheLib.t.sol";

// Libraries
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

contract DigestCacheLib_markAsVerified_Test is DigestCacheLib_Unit_Test {
    /* //////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    uint8 configId1 = 1;
    bytes12 lockTag1 = bytes12(keccak256("lockTag1"));
    bytes12 lockTag2 = bytes12(keccak256("lockTag2"));
    IStatelessValidator validator1;
    PermissionId permissionId1;

    /* //////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
        validator1 = IStatelessValidator(makeAddr("validator1"));
        permissionId1 = PermissionId.wrap(keccak256("permission1"));
    }

    /* //////////////////////////////////////////////////////////////
                             ECDSA/PASSKEY
    //////////////////////////////////////////////////////////////*/

    function test_markAsVerified_ECDSA_Success() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, configId1, lockTag1);

        // Assert
        bool isVerified = DigestCacheLib.isAlreadyVerified(digest1, account1, configId1, lockTag1);
        assertTrue(isVerified, "Should be marked as verified");
    }

    function test_markAsVerified_ECDSA_MultipleDigests() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, configId1, lockTag1);
        DigestCacheLib.markAsVerified(digest2, account1, configId1, lockTag1);
        DigestCacheLib.markAsVerified(digest3, account1, configId1, lockTag1);

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, configId1, lockTag1),
            "Digest1 should be verified"
        );
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest2, account1, configId1, lockTag1),
            "Digest2 should be verified"
        );
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest3, account1, configId1, lockTag1),
            "Digest3 should be verified"
        );
    }

    function test_markAsVerified_ECDSA_IdempotentOperation() public {
        // Act - mark multiple times
        DigestCacheLib.markAsVerified(digest1, account1, configId1, lockTag1);
        DigestCacheLib.markAsVerified(digest1, account1, configId1, lockTag1);
        DigestCacheLib.markAsVerified(digest1, account1, configId1, lockTag1);

        // Assert - should still be verified
        bool isVerified = DigestCacheLib.isAlreadyVerified(digest1, account1, configId1, lockTag1);
        assertTrue(isVerified, "Should remain verified after multiple marks");
    }

    /* //////////////////////////////////////////////////////////////
                               STATELESS
    //////////////////////////////////////////////////////////////*/

    function test_markAsVerified_Stateless_Success() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, validator1, configId1, lockTag1);

        // Assert
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, validator1, configId1, lockTag1);
        assertTrue(isVerified, "Should be marked as verified");
    }

    function test_markAsVerified_Stateless_MultipleDigests() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, validator1, configId1, lockTag1);
        DigestCacheLib.markAsVerified(digest2, account1, validator1, configId1, lockTag1);

        // Assert
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, validator1, configId1, lockTag1),
            "Digest1 should be verified"
        );
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest2, account1, validator1, configId1, lockTag1),
            "Digest2 should be verified"
        );
    }

    /* //////////////////////////////////////////////////////////////
                              SMART SESSION
    //////////////////////////////////////////////////////////////*/

    function test_markAsVerified_SmartSession_Success() public {
        // Act
        DigestCacheLib.markAsVerified(digest1, account1, permissionId1, lockTag1);

        // Assert
        bool isVerified =
            DigestCacheLib.isAlreadyVerified(digest1, account1, permissionId1, lockTag1);
        assertTrue(isVerified, "Should be marked as verified");
    }

    function test_markAsVerified_SmartSession_MultipleLockTags() public {
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

    /* //////////////////////////////////////////////////////////////
                             EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_markAsVerified_WithZeroValues() public {
        // Test with zero address
        DigestCacheLib.markAsVerified(digest1, address(0), configId1, lockTag1);
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, address(0), configId1, lockTag1),
            "Should work with zero address"
        );

        // Test with zero digest
        DigestCacheLib.markAsVerified(bytes32(0), account1, configId1, lockTag1);
        assertTrue(
            DigestCacheLib.isAlreadyVerified(bytes32(0), account1, configId1, lockTag1),
            "Should work with zero digest"
        );

        // Test with zero config
        DigestCacheLib.markAsVerified(digest1, account1, 0, lockTag1);
        assertTrue(
            DigestCacheLib.isAlreadyVerified(digest1, account1, 0, lockTag1),
            "Should work with zero configId"
        );
    }
}
