// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    NoncePinPolicy_Unit_Test
} from "@test/unit/policies/nonce/NoncePinPolicy/NoncePinPolicy.t.sol";

// Libraries
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title NoncePinPolicy.checkAction Unit Tests
/// @notice Unit tests for the executor-side gate
contract NoncePinPolicy_checkAction_Test is NoncePinPolicy_Unit_Test {
    /// @dev Stand-in for the action target; this policy does not inspect it
    address internal constant TARGET = address(0xA26E7);

    /// @dev The same call, used by every case; this policy ignores target, value and calldata
    function _check(address who) internal view returns (uint256) {
        return noncePinPolicy.checkAction(configId, who, TARGET, 0, "");
    }

    /// @dev Puts a settlement on `nonce` in flight, as the executor does while it validates
    function _inFlight(uint256 nonce) internal {
        intentExecutor.setInFlight(true, nonce);
    }

    /*//////////////////////////////////////////////////////////////
                              FAIL CLOSED
    //////////////////////////////////////////////////////////////*/

    /// @dev An unpinned session would otherwise be unguarded on this surface
    function test_checkAction_uninitialized_shouldFail() public {
        _inFlight(PINNED_NONCE);

        assertEq(_check(account), VALIDATION_FAILED, "unconfigured must fail closed");
    }

    /// @dev The `configured` flag matters here too: an unset entry reads nonce zero, so without
    ///      it a session pinned to zero and one never configured would be indistinguishable.
    function test_checkAction_uninitializedWithZeroPin_shouldFail() public {
        _inFlight(0);

        assertEq(_check(account), VALIDATION_FAILED, "unset entry must not pass as a zero pin");
    }

    /*//////////////////////////////////////////////////////////////
                          NO SETTLEMENT IN FLIGHT
    //////////////////////////////////////////////////////////////*/

    /// @dev Reached outside a settlement — a plain userOp under the same permission — the
    /// policy
    ///      has nothing to bind to and must refuse rather than wave the action through.
    function test_checkAction_nothingInFlight_shouldFail() public {
        _pin(address(this), PINNED_NONCE);

        assertEq(_check(account), VALIDATION_FAILED, "no settlement in flight must fail closed");
    }

    /// @dev Zero is what an uninstrumented executor would report, so a pin of zero must not be
    ///      satisfied by the absence of a settlement.
    function test_checkAction_nothingInFlightWithZeroPin_shouldFail() public {
        _pin(address(this), 0);

        assertEq(_check(account), VALIDATION_FAILED, "inactive must not read as a zero settlement");
    }

    /*//////////////////////////////////////////////////////////////
                           BINDING TO THE PIN
    //////////////////////////////////////////////////////////////*/

    /// @dev The property this surface exists for. Without it the signer picks any nonce, mints a
    ///      fresh digest per nonce and settles repeatedly — each spend individually replay
    ///      protected, the session unbounded.
    function test_checkAction_otherNonceInFlight_shouldFail() public {
        _pin(address(this), PINNED_NONCE);
        _inFlight(PINNED_NONCE + 1);

        assertEq(_check(account), VALIDATION_FAILED, "an unpinned settlement must be refused");
    }

    /// @dev A consumed-nonce read cannot substitute for binding: consumption is permanent, so
    ///      after the pinned settlement it reads identically for every later one. Any check that
    ///      only asked "was the pin ever burned" would pass this case.
    function test_checkAction_otherNonceInFlightAfterPinSettled_shouldFail() public {
        _pin(address(this), PINNED_NONCE);
        intentExecutor.setSettledElsewhere(PINNED_NONCE, account, true);
        _inFlight(PINNED_NONCE + 1);

        assertEq(_check(account), VALIDATION_FAILED, "a settled pin must not license later ones");
    }

    /// @dev Only the pinned nonce passes, across the whole word/bit domain
    function testFuzz_checkAction_onlyThePinnedSettlementPasses(
        uint256 pinned,
        uint256 inFlight
    )
        public
    {
        _pin(address(this), pinned);
        _inFlight(inFlight);

        uint256 expected = pinned == inFlight ? VALIDATION_SUCCESS : VALIDATION_FAILED;
        assertEq(_check(account), expected, "exactly the pinned settlement must pass");
    }

    /*//////////////////////////////////////////////////////////////
                            THE PINNED SETTLEMENT
    //////////////////////////////////////////////////////////////*/

    /// @dev The ordinary case: the pinned settlement, nothing else has settled
    function test_checkAction_pinnedInFlight_shouldSucceed() public {
        _pin(address(this), PINNED_NONCE);
        _inFlight(PINNED_NONCE);

        assertEq(_check(account), VALIDATION_SUCCESS, "the pinned settlement must proceed");
    }

    /// @dev A pin of zero is a real pin and must behave like any other
    function test_checkAction_pinnedZero_shouldSucceed() public {
        _pin(address(this), 0);
        _inFlight(0);

        assertEq(_check(account), VALIDATION_SUCCESS, "a pinned zero must permit the action");
    }

    /*//////////////////////////////////////////////////////////////
                        ALREADY SETTLED ELSEWHERE
    //////////////////////////////////////////////////////////////*/

    /// @dev The executor settles through three families that keep independent replay slots for
    ///      one nonce value, so the pinned settlement is refused if another family took it first.
    function test_checkAction_settledByAnotherFamily_shouldFail() public {
        _pin(address(this), PINNED_NONCE);
        _inFlight(PINNED_NONCE);
        intentExecutor.setSettledElsewhere(PINNED_NONCE, account, true);

        assertEq(_check(account), VALIDATION_FAILED, "another family's settlement must block");
    }

    /*//////////////////////////////////////////////////////////////
                         ALREADY SETTLED ON PERMIT2
    //////////////////////////////////////////////////////////////*/

    /// @dev The cross-family exclusion: an arbiter already spent the session.
    function test_checkAction_permit2Settled_shouldFail() public {
        _pin(address(this), PINNED_NONCE);
        _inFlight(PINNED_NONCE);
        permit2.burn(account, PINNED_NONCE);

        assertEq(_check(account), VALIDATION_FAILED, "must refuse after a Permit2 settlement");
    }

    /// @dev Zero is the nonce most likely to collide with an unrelated burn, so pin it explicitly
    function test_checkAction_permit2SettledOnPinnedZero_shouldFail() public {
        _pin(address(this), 0);
        _inFlight(0);
        permit2.burn(account, 0);

        assertEq(_check(account), VALIDATION_FAILED, "must refuse when the pinned zero is spent");
    }

    /// @dev The bitmap is read per account
    function test_checkAction_settledForAnotherAccount_shouldSucceed() public {
        _pin(address(this), PINNED_NONCE);
        _inFlight(PINNED_NONCE);
        permit2.burn(makeAddr("otherAccount"), PINNED_NONCE);

        assertEq(_check(account), VALIDATION_SUCCESS, "another account must not block this one");
    }

    /// @dev And for the pinned nonce, not a neighbouring one in the same word
    function test_checkAction_settledOnAdjacentNonce_shouldSucceed() public {
        _pin(address(this), PINNED_NONCE);
        _inFlight(PINNED_NONCE);
        permit2.burn(account, PINNED_NONCE + 1);

        assertEq(_check(account), VALIDATION_SUCCESS, "a neighbouring bit must not block");
    }

    /// @dev Fuzz across the word/bit split, which is where an off-by-one would hide
    function testFuzz_checkAction_onlyThePinnedBitBlocks(uint256 pinned, uint256 burned) public {
        _pin(address(this), pinned);
        _inFlight(pinned);
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
        _inFlight(PINNED_NONCE);

        assertEq(_check(account), VALIDATION_FAILED, "another multiplexer's pin must not apply");
    }

    /// @dev And per config
    function test_checkAction_isolatedPerConfig() public {
        _pin(address(this), PINNED_NONCE);
        _inFlight(PINNED_NONCE);

        ConfigId otherConfig = ConfigId.wrap(keccak256("other.config"));
        assertEq(
            noncePinPolicy.checkAction(otherConfig, account, TARGET, 0, ""),
            VALIDATION_FAILED,
            "another config's pin must not apply"
        );
    }
}
