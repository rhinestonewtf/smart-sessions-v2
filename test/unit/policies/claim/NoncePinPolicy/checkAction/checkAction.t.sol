// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    NoncePinPolicy_Unit_Test
} from "@test/unit/policies/claim/NoncePinPolicy/NoncePinPolicy.t.sol";

// Libraries
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title NoncePinPolicy.checkAction Unit Tests
/// @notice Unit tests for the executor-side gate
contract NoncePinPolicy_checkAction_Test is NoncePinPolicy_Unit_Test {
    /// @dev The same call, used by every case; this policy ignores target, value and calldata
    function _check(address who) internal returns (uint256) {
        return noncePinPolicy.checkAction(configId, who, makeAddr("target"), 0, "");
    }

    /*//////////////////////////////////////////////////////////////
                              FAIL CLOSED
    //////////////////////////////////////////////////////////////*/

    /// @dev An unpinned session would otherwise be unguarded on this surface
    function test_checkAction_uninitialized_shouldFail() public {
        assertEq(_check(account), VALIDATION_FAILED, "unconfigured must fail closed");
    }

    /// @dev The `configured` flag matters here too: an unset entry reads nonce zero, so without
    ///      it a session pinned to zero and one never configured would be indistinguishable.
    function test_checkAction_uninitializedWithZeroPin_shouldFail() public {
        assertEq(_check(account), VALIDATION_FAILED, "unset entry must not pass as a zero pin");
    }

    /*//////////////////////////////////////////////////////////////
                            NOT YET SETTLED
    //////////////////////////////////////////////////////////////*/

    /// @dev The ordinary case: nothing has settled, so the executor route may proceed
    function test_checkAction_permit2Untouched_shouldSucceed() public {
        _pin(address(this), PINNED_NONCE);

        assertEq(_check(account), VALIDATION_SUCCESS, "an unspent nonce must permit the action");
    }

    /// @dev A pin of zero is a real pin and must behave like any other
    function test_checkAction_pinnedZero_shouldSucceed() public {
        _pin(address(this), 0);

        assertEq(_check(account), VALIDATION_SUCCESS, "a pinned zero must permit the action");
    }

    /*//////////////////////////////////////////////////////////////
                         ALREADY SETTLED ON PERMIT2
    //////////////////////////////////////////////////////////////*/

    /// @dev The property this surface exists for: a vendor already spent the session.
    function test_checkAction_permit2Settled_shouldFail() public {
        _pin(address(this), PINNED_NONCE);
        permit2.burn(account, PINNED_NONCE);

        assertEq(_check(account), VALIDATION_FAILED, "must refuse after a Permit2 settlement");
    }

    /// @dev Zero is the nonce most likely to collide with an unrelated burn, so pin it explicitly
    function test_checkAction_permit2SettledOnPinnedZero_shouldFail() public {
        _pin(address(this), 0);
        permit2.burn(account, 0);

        assertEq(_check(account), VALIDATION_FAILED, "must refuse when the pinned zero is spent");
    }

    /// @dev The bitmap is read per account
    function test_checkAction_settledForAnotherAccount_shouldSucceed() public {
        _pin(address(this), PINNED_NONCE);
        permit2.burn(makeAddr("otherAccount"), PINNED_NONCE);

        assertEq(_check(account), VALIDATION_SUCCESS, "another account must not block this one");
    }

    /// @dev And for the pinned nonce, not a neighbouring one in the same word
    function test_checkAction_settledOnAdjacentNonce_shouldSucceed() public {
        _pin(address(this), PINNED_NONCE);
        permit2.burn(account, PINNED_NONCE + 1);

        assertEq(_check(account), VALIDATION_SUCCESS, "a neighbouring bit must not block");
    }

    /// @dev Fuzz across the word/bit split, which is where an off-by-one would hide
    function testFuzz_checkAction_onlyThePinnedBitBlocks(uint256 pinned, uint256 burned) public {
        _pin(address(this), pinned);
        permit2.burn(account, burned);

        uint256 expected = pinned == burned ? VALIDATION_FAILED : VALIDATION_SUCCESS;
        assertEq(_check(account), expected, "exactly the pinned bit must block");
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @dev Pins are per multiplexer, so another installer's pin must not answer here
    function test_checkAction_isolatedPerMultiplexer() public {
        _pin(makeAddr("otherMultiplexer"), PINNED_NONCE);

        assertEq(_check(account), VALIDATION_FAILED, "another multiplexer's pin must not apply");
    }

    /// @dev And per config
    function test_checkAction_isolatedPerConfig() public {
        _pin(address(this), PINNED_NONCE);

        ConfigId otherConfig = ConfigId.wrap(keccak256("other.config"));
        assertEq(
            noncePinPolicy.checkAction(otherConfig, account, makeAddr("target"), 0, ""),
            VALIDATION_FAILED,
            "another config's pin must not apply"
        );
    }
}
