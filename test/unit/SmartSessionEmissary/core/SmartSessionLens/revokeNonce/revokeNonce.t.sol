// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionLens_Unit_Test } from "../SmartSessionLens.t.sol";

// Interfaces
import { ISmartSessionLens } from "@interfaces/ISmartSessionLens.sol";

contract SmartSessionLens_revokeNonce_Test is SmartSessionLens_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                SUCCESS
    //////////////////////////////////////////////////////////////*/

    function test_revokeNonce_IncrementsNonce() public {
        // Arrange
        uint256 nonceBefore = _lens().getNonce(instance.account, TEST_LOCK_TAG);

        // Act
        vm.prank(instance.account);
        _lens().revokeNonce(TEST_LOCK_TAG);

        // Assert
        uint256 nonceAfter = _lens().getNonce(instance.account, TEST_LOCK_TAG);
        assertEq(nonceAfter, nonceBefore + 1, "Nonce should be incremented");
    }

    function test_revokeNonce_EmitsEvent() public {
        // Arrange
        uint256 expectedNonce = 1;

        // Act & Assert
        vm.expectEmit(true, true, true, true);
        emit ISmartSessionLens.NonceIterated(TEST_LOCK_TAG, instance.account, expectedNonce);

        vm.prank(instance.account);
        _lens().revokeNonce(TEST_LOCK_TAG);
    }

    function test_revokeNonce_WorksForAnyAccount() public {
        // Arrange
        address randomAccount = makeAddr("randomAccount");

        // Act
        vm.prank(randomAccount);
        _lens().revokeNonce(TEST_LOCK_TAG);

        // Assert
        uint256 nonce = _lens().getNonce(randomAccount, TEST_LOCK_TAG);
        assertEq(nonce, 1, "Nonce should be 1 for random account");
    }

    function test_revokeNonce_WorksWithNoLockTag() public {
        // Arrange & Act
        vm.prank(instance.account);
        _lens().revokeNonce(NO_LOCK_TAG);

        // Assert
        uint256 nonce = _lens().getNonce(instance.account, NO_LOCK_TAG);
        assertEq(nonce, 1, "Nonce should be 1 for no lock tag");
    }

    /*//////////////////////////////////////////////////////////////
                              MULTIPLE
    //////////////////////////////////////////////////////////////*/

    function test_revokeNonce_CanBeCalledMultipleTimes() public {
        // Act
        vm.startPrank(instance.account);
        _lens().revokeNonce(TEST_LOCK_TAG);
        _lens().revokeNonce(TEST_LOCK_TAG);
        _lens().revokeNonce(TEST_LOCK_TAG);
        vm.stopPrank();

        // Assert
        uint256 nonce = _lens().getNonce(instance.account, TEST_LOCK_TAG);
        assertEq(nonce, 3, "Nonce should be 3 after three revokes");
    }

    function test_revokeNonce_IndependentPerLockTag() public {
        // Act
        vm.startPrank(instance.account);
        _lens().revokeNonce(TEST_LOCK_TAG);
        _lens().revokeNonce(TEST_LOCK_TAG);
        _lens().revokeNonce(TEST_LOCK_TAG_2);
        vm.stopPrank();

        // Assert
        uint256 nonce1 = _lens().getNonce(instance.account, TEST_LOCK_TAG);
        uint256 nonce2 = _lens().getNonce(instance.account, TEST_LOCK_TAG_2);
        assertEq(nonce1, 2, "Lock tag 1 nonce should be 2");
        assertEq(nonce2, 1, "Lock tag 2 nonce should be 1");
    }
}
