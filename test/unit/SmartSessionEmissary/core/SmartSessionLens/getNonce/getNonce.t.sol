// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { Session } from "@types/DataTypes.sol";

contract SmartSessionLens_getNonce_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                            INITIAL STATE
    //////////////////////////////////////////////////////////////*/

    function test_getNonce_ReturnsZero_Initially() public view {
        // Act
        uint256 nonce = _lens().getNonce(instance.account, TEST_LOCK_TAG);

        // Assert
        assertEq(nonce, 0, "Initial nonce should be zero");
    }

    function test_getNonce_ReturnsZero_ForDifferentLockTags() public view {
        // Act
        uint256 nonce1 = _lens().getNonce(instance.account, TEST_LOCK_TAG);
        uint256 nonce2 = _lens().getNonce(instance.account, TEST_LOCK_TAG_2);
        uint256 nonce3 = _lens().getNonce(instance.account, NO_LOCK_TAG);

        // Assert
        assertEq(nonce1, 0, "Nonce for lock tag 1 should be zero");
        assertEq(nonce2, 0, "Nonce for lock tag 2 should be zero");
        assertEq(nonce3, 0, "Nonce for no lock tag should be zero");
    }

    /*//////////////////////////////////////////////////////////////
                            AFTER REVOKE
    //////////////////////////////////////////////////////////////*/

    function test_getNonce_ReturnsIncremented_AfterRevoke() public {
        // Arrange
        vm.prank(instance.account);
        _lens().revokeNonce(TEST_LOCK_TAG);

        // Act
        uint256 nonce = _lens().getNonce(instance.account, TEST_LOCK_TAG);

        // Assert
        assertEq(nonce, 1, "Nonce should be 1 after revoke");
    }

    function test_getNonce_ReturnsCorrectValue_AfterMultipleRevokes() public {
        // Arrange
        vm.startPrank(instance.account);
        _lens().revokeNonce(TEST_LOCK_TAG);
        _lens().revokeNonce(TEST_LOCK_TAG);
        _lens().revokeNonce(TEST_LOCK_TAG);
        vm.stopPrank();

        // Act
        uint256 nonce = _lens().getNonce(instance.account, TEST_LOCK_TAG);

        // Assert
        assertEq(nonce, 3, "Nonce should be 3 after three revokes");
    }

    /*//////////////////////////////////////////////////////////////
                              ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test nonces are isolated per account
    function test_getNonce_IsolatedPerAccount() public {
        // Arrange - increment nonce for account1 directly
        smartSessionEmissary.incrementNonce(instance.account, TEST_LOCK_TAG);

        address account2 = makeAddr("account2");

        // Act
        uint256 nonce1 = _lens().getNonce(instance.account, TEST_LOCK_TAG);
        uint256 nonce2 = _lens().getNonce(account2, TEST_LOCK_TAG);

        // Assert
        assertEq(nonce1, 1, "Account1 nonce should be 1");
        assertEq(nonce2, 0, "Account2 nonce should be 0 (never used)");
    }

    /// @notice Test nonces are isolated per lockTag
    function test_getNonce_IsolatedPerLockTag() public {
        // Arrange - increment nonce for TEST_LOCK_TAG
        smartSessionEmissary.incrementNonce(instance.account, TEST_LOCK_TAG);

        // Act
        uint256 nonce1 = _lens().getNonce(instance.account, TEST_LOCK_TAG);
        uint256 nonce2 = _lens().getNonce(instance.account, TEST_LOCK_TAG_2);

        // Assert
        assertEq(nonce1, 1, "TEST_LOCK_TAG nonce should be 1");
        assertEq(nonce2, 0, "TEST_LOCK_TAG_2 nonce should be 0 (never used)");
    }
}
