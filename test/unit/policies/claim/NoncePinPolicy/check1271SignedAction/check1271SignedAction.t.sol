// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    NoncePinPolicy_Unit_Test
} from "@test/unit/policies/claim/NoncePinPolicy/NoncePinPolicy.t.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title NoncePinPolicy.check1271SignedAction Unit Tests
/// @notice Unit tests for the check1271SignedAction function
contract NoncePinPolicy_check1271SignedAction_Test is NoncePinPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                              FAIL CLOSED
    //////////////////////////////////////////////////////////////*/

    /// @dev The claim list is a supported install site with the same config id, and there the
    ///      payload is Compact-shaped — so this is misconfiguration, not an obvious mistake.
    function test_check1271SignedAction_foreignCaller_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        address theCompact = makeAddr("theCompact");
        bool result = noncePinPolicy.check1271SignedAction(
            configId, theCompact, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "a caller outside the Permit2 flow must be refused");
    }

    /// @dev Assumes Permit2 away rather than asserting an equality that a fuzzed address
    ///      satisfies essentially never — that form only ever tests the reject path.
    function testFuzz_check1271SignedAction_foreignCallerAlwaysRejected(address requestSender)
        public
    {
        vm.assume(requestSender != PERMIT2_ADDRESS);
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, requestSender, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "no caller outside the Permit2 flow may be answered");
    }

    /// @dev Compact puts the nonce at [32:64], so [20:52] splices a domain-separator tail onto
    ///      a nonce head. Built so the misparse WOULD match if the caller check were removed.
    function test_check1271SignedAction_compactShapedPayload_shouldReturnFalse() public {
        bytes32 domainSeparator = keccak256("compact.domain");
        uint256 compactNonce = 7;

        // Compact layout: [0:32] domainSeparator, [32:64] nonce, [64:96] expires
        bytes memory compactPayload =
            abi.encodePacked(domainSeparator, compactNonce, uint256(DEADLINE));

        // What this policy's Permit2 offsets would read out of that payload
        uint256 misparsed;
        assembly {
            misparsed := mload(add(add(compactPayload, 0x20), 20))
        }

        // Pin exactly that value, so only the caller check can save us
        _pin(address(this), misparsed);

        address theCompact = makeAddr("theCompact");
        bool result = noncePinPolicy.check1271SignedAction(
            configId, theCompact, account, bytes32(0), compactPayload
        );

        assertFalse(result, "a Compact-shaped payload must be refused, not mis-parsed");
    }

    /// @dev The claim policy family fails OPEN when unconfigured; this must not inherit that.
    function test_check1271SignedAction_uninitialized_shouldReturnFalse() public view {
        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "uninitialized config must fail closed");
    }

    /// @dev The only test that catches removal of the `configured` flag: an unset entry reads
    ///      nonce zero, so a zero-nonce payload would compare equal and fail open.
    function test_check1271SignedAction_uninitializedWithZeroNonce_shouldReturnFalse() public view {
        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(0)
        );

        assertFalse(result, "an unconfigured entry must reject nonce zero, not match it");
    }

    /// @notice A payload too short to contain a nonce must reject rather than revert.
    function test_check1271SignedAction_payloadTooShort_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        // 51 bytes: one short of the [20:52] nonce window
        bytes memory truncated = new bytes(51);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), truncated
        );

        assertFalse(result, "short payload must fail closed");
    }

    /// @notice An empty payload must reject rather than revert.
    function test_check1271SignedAction_emptyPayload_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), ""
        );

        assertFalse(result, "empty payload must fail closed");
    }

    /// @notice Fuzz: every payload shorter than the nonce window is rejected.
    /// @dev Bounded fuzz rather than one instance, so an over-strict guard cannot hide behind
    ///      a single hand-picked length.
    function testFuzz_check1271SignedAction_shortPayloadAlwaysRejected(uint8 length) public {
        length = uint8(_bound(length, 0, 51));
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), new bytes(length)
        );

        assertFalse(result, "any payload shorter than the nonce window must fail closed");
    }

    /*//////////////////////////////////////////////////////////////
                             MATCHING NONCE
    //////////////////////////////////////////////////////////////*/

    /// @notice The pinned nonce is accepted.
    function test_check1271SignedAction_matchingNonce_shouldReturnTrue() public {
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertTrue(result, "pinned nonce must be accepted");
    }

    /// @dev The guard's lower boundary. Without it every accepted payload is the full 84-byte
    ///      header, so a guard widened by a whole word still passes.
    function test_check1271SignedAction_minimumLengthPayload_shouldReturnTrue() public {
        _pin(address(this), PINNED_NONCE);

        // 52 bytes: arbiter (20) + nonce (32), with no deadline or mandate following
        bytes memory exact = abi.encodePacked(address(0xA11CE), PINNED_NONCE);
        assertEq(exact.length, 52, "fixture must sit exactly on the guard boundary");

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), exact
        );

        assertTrue(result, "a 52-byte payload is long enough to carry the nonce");
    }

    /// @dev Pinning zero must stay distinguishable from never having been initialized.
    function test_check1271SignedAction_pinnedZero_shouldReturnTrue() public {
        _pin(address(this), 0);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(0)
        );

        assertTrue(result, "a pinned nonce of zero must be honoured");
    }

    /*//////////////////////////////////////////////////////////////
                            MISMATCHED NONCE
    //////////////////////////////////////////////////////////////*/

    /// @dev The property the design rests on: unpinned, the signer mints a fresh nonce per
    ///      digest and the session is unbounded.
    function test_check1271SignedAction_mismatchedNonce_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE + 1)
        );

        assertFalse(result, "a non-pinned nonce must be rejected");
    }

    /// @dev Split from the mismatch case: fuzzing two independent nonces and asserting their
    ///      equality only ever exercises the reject path.
    function testFuzz_check1271SignedAction_pinnedNonceAlwaysAccepted(uint256 pinned) public {
        _pin(address(this), pinned);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(pinned)
        );

        assertTrue(result, "the pinned nonce must always be accepted");
    }

    /// @dev Non-zero delta so the mismatch is guaranteed rather than probable.
    function testFuzz_check1271SignedAction_otherNonceAlwaysRejected(
        uint256 pinned,
        uint256 delta
    )
        public
    {
        delta = _bound(delta, 1, type(uint256).max);
        _pin(address(this), pinned);

        unchecked {
            bool result = noncePinPolicy.check1271SignedAction(
                configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(pinned + delta)
            );

            assertFalse(result, "any nonce other than the pinned one must be rejected");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        COMPOSITION REQUIREMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice This policy does NOT bind the payload to the digest, and must never be
    ///         registered on its own.
    /// @dev Characterization test for a deliberate limitation, not a bug.
    ///
    ///      The digest is ignored entirely: the same payload passes against any hash. On its
    ///      own this policy therefore proves nothing, because the caller supplies the payload
    ///      and can put the pinned nonce in it while the real permit carries a different one.
    ///      The pin would appear to hold while the session stayed unpinned in practice.
    ///
    ///      Soundness comes from co-registering Permit2ClaimPolicy in the same list, which
    ///      recomputes the EIP-712 hash from the payload and compares it to the digest.
    ///      Policies in a list are ANDed, so that proves the slice read here belongs to the
    ///      real permit.
    ///
    ///      Note `minPoliciesToEnforce` is 1, so a list holding only this policy satisfies the
    ///      minimum and reverts nothing — the misconfiguration is silent. If this assertion
    ///      ever starts failing because the policy learned to verify the digest itself, delete
    ///      the test and the co-registration requirement along with it.
    function test_check1271SignedAction_ignoresDigest_soRequiresCoRegistration() public {
        _pin(address(this), PINNED_NONCE);

        bytes memory payload = _claimPayload(PINNED_NONCE);

        bool withOneHash = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, keccak256("some digest"), payload
        );
        bool withAnother = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, keccak256("an entirely unrelated digest"), payload
        );

        assertTrue(withOneHash, "payload should pass on its nonce alone");
        assertEq(withAnother, withOneHash, "the digest must make no difference - that is the point");
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @dev Both directions, because a storage-key ordering bug still fails closed one way.
    function test_check1271SignedAction_isolatedPerMultiplexer() public {
        address otherMultiplexer = makeAddr("otherMultiplexer");
        _pin(address(this), PINNED_NONCE);
        _pin(otherMultiplexer, PINNED_NONCE + 1);

        bool ownNonceHere = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );
        bool otherNonceHere = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE + 1)
        );

        assertTrue(ownNonceHere, "each multiplexer must accept its own pin");
        assertFalse(otherNonceHere, "a pin must not leak across multiplexers");

        vm.startPrank(otherMultiplexer);
        bool ownNonceThere = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE + 1)
        );
        bool otherNonceThere = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );
        vm.stopPrank();

        assertTrue(ownNonceThere, "each multiplexer must accept its own pin");
        assertFalse(otherNonceThere, "a pin must not leak across multiplexers");
    }

    /// @notice Pins are isolated per account.
    function test_check1271SignedAction_isolatedPerAccount() public {
        address otherAccount = makeAddr("otherAccount");
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, otherAccount, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "a pin must not leak across accounts");
    }

    /// @notice Pins are isolated per config.
    function test_check1271SignedAction_isolatedPerConfig() public {
        ConfigId otherConfig = ConfigId.wrap(keccak256("other.config"));
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            otherConfig, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "a pin must not leak across configs");
    }
}
