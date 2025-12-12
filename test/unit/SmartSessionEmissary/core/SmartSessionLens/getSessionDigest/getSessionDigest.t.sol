// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getSessionDigest_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                SUCCESS
    //////////////////////////////////////////////////////////////*/

    function test_getSessionDigest_ReturnsNonZero() public view {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        uint256 expires = block.timestamp + 1 hours;

        // Act
        bytes32 digest = _lens().getSessionDigest(instance.account, session, TEST_LOCK_TAG, expires);

        // Assert
        assertTrue(digest != bytes32(0), "Digest should be non-zero");
    }

    function test_getSessionDigest_DifferentExpires_ReturnsDifferentDigest() public view {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );

        // Act
        bytes32 digest1 = _lens()
            .getSessionDigest(instance.account, session, TEST_LOCK_TAG, block.timestamp + 1 hours);
        bytes32 digest2 = _lens()
            .getSessionDigest(instance.account, session, TEST_LOCK_TAG, block.timestamp + 2 hours);

        // Assert
        assertTrue(digest1 != digest2, "Different expires should produce different digests");
    }

    function test_getSessionDigest_DifferentLockTags_ReturnsDifferentDigest() public view {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        uint256 expires = block.timestamp + 1 hours;

        // Act
        bytes32 digest1 =
            _lens().getSessionDigest(instance.account, session, TEST_LOCK_TAG, expires);
        bytes32 digest2 =
            _lens().getSessionDigest(instance.account, session, TEST_LOCK_TAG_2, expires);

        // Assert
        assertTrue(digest1 != digest2, "Different lock tags should produce different digests");
    }

    function test_getSessionDigest_DifferentAccounts_ReturnsDifferentDigest() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        uint256 expires = block.timestamp + 1 hours;
        address otherAccount = makeAddr("otherAccount");

        // Act
        bytes32 digest1 =
            _lens().getSessionDigest(instance.account, session, TEST_LOCK_TAG, expires);
        bytes32 digest2 = _lens().getSessionDigest(otherAccount, session, TEST_LOCK_TAG, expires);

        // Assert
        assertTrue(digest1 != digest2, "Different accounts should produce different digests");
    }

    function test_getSessionDigest_SameInputs_ReturnsSameDigest() public view {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        uint256 expires = block.timestamp + 1 hours;

        // Act
        bytes32 digest1 =
            _lens().getSessionDigest(instance.account, session, TEST_LOCK_TAG, expires);
        bytes32 digest2 =
            _lens().getSessionDigest(instance.account, session, TEST_LOCK_TAG, expires);

        // Assert
        assertEq(digest1, digest2, "Same inputs should produce same digest");
    }

    function test_getSessionDigest_ChangesAfterNonceRevoke() public {
        // Arrange
        Session memory session = _createActionSession(
            ISessionValidator(address(yesSessionValidator)),
            keccak256("testSalt"),
            target,
            bytes4(keccak256("transfer()")),
            address(sudoPolicy)
        );
        uint256 expires = block.timestamp + 1 hours;

        bytes32 digestBefore =
            _lens().getSessionDigest(instance.account, session, TEST_LOCK_TAG, expires);

        // Act - revoke nonce
        vm.prank(instance.account);
        _lens().revokeNonce(TEST_LOCK_TAG);

        bytes32 digestAfter =
            _lens().getSessionDigest(instance.account, session, TEST_LOCK_TAG, expires);

        // Assert
        assertTrue(digestBefore != digestAfter, "Digest should change after nonce revoke");
    }
}

