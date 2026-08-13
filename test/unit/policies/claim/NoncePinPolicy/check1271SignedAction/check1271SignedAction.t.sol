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

    /// @notice Only Permit2 gets an answer; every other caller is refused.
    /// @dev The offsets this policy reads are the Permit2 layout. The per-lockTag claim list is
    ///      enabled with the SAME config id and multiplexer as the ERC-1271 list, so installing
    ///      here is a supported configuration rather than an obvious mistake — and on that path
    ///      TheCompact is the caller and the payload has a different shape entirely. Without
    ///      this check the policy would read the wrong bytes and answer confidently.
    function test_check1271SignedAction_nonPermit2Caller_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        address theCompact = makeAddr("theCompact");
        bool result = noncePinPolicy.check1271SignedAction(
            configId, theCompact, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "a caller other than Permit2 must be refused");
    }

    /// @notice Fuzz: no caller except Permit2 is ever answered.
    /// @dev Assumes away the Permit2 case rather than folding both branches into one equality
    ///      assertion. A fuzzed address is essentially never Permit2, so the combined form only
    ///      ever exercised the reject path while reading as though it covered both — and would
    ///      have passed against a body that always returned false. The accept path is covered
    ///      by the non-fuzz tests below, which pass PERMIT2_ADDRESS explicitly.
    function testFuzz_check1271SignedAction_nonPermit2CallerAlwaysRejected(address requestSender)
        public
    {
        vm.assume(requestSender != PERMIT2_ADDRESS);
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, requestSender, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "no caller other than Permit2 may be answered");
    }

    /// @notice A Compact-shaped payload is refused rather than mis-parsed.
    /// @dev The concrete failure the caller check prevents. In the Compact layout the nonce
    ///      sits at [32:64], so reading [20:52] splices the tail of the domain separator onto
    ///      the head of the nonce, leaving the low bits of the real nonce unconstrained. A
    ///      large family of different nonces would then satisfy a single pin while the
    ///      configuration still looked correct. The payload here is built so the misparse
    ///      WOULD match if the caller check were removed.
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

    /// @notice An unconfigured entry must reject, not pass.
    /// @dev The claim policy family fails OPEN when unconfigured (empty mode config means
    ///      "check nothing"). This policy must not inherit that behaviour: a session whose pin
    ///      was never initialized would otherwise be silently unpinned, and unpinned means the
    ///      signer can mint a fresh nonce per digest and spend the session repeatedly.
    function test_check1271SignedAction_uninitialized_shouldReturnFalse() public view {
        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "uninitialized config must fail closed");
    }

    /// @notice An unconfigured entry rejects even a payload carrying nonce zero.
    /// @dev The case the `configured` flag exists for, and the only one that catches its
    ///      removal. An uninitialized entry reads back `nonce == 0`, so without the flag a
    ///      zero-nonce payload compares equal and the policy returns TRUE — fail open on
    ///      exactly the config nobody set up. Every other test pins a non-zero nonce, so the
    ///      comparison masks the missing flag and the suite stays green.
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

    /// @notice A payload holding exactly the arbiter and nonce, and nothing more, is accepted.
    /// @dev Pins the lower boundary of the length guard. Without this every accepted payload is
    ///      the full 84-byte header, so widening the guard anywhere between 53 and 84 bytes
    ///      rejects nothing that the suite tests — a guard broken by a whole word still passes.
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

    /// @notice A pinned nonce of zero is a real pin, not an unconfigured entry.
    /// @dev Guards the `configured` flag: without it, pinning zero would be indistinguishable
    ///      from never having been initialized.
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

    /// @notice Any nonce other than the pinned one is rejected.
    /// @dev This is the property the whole design rests on. Without it the session signer picks
    ///      a fresh nonce per digest, each spend individually replay-protected by Permit2 but
    ///      the session itself unbounded.
    function test_check1271SignedAction_mismatchedNonce_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(PINNED_NONCE + 1)
        );

        assertFalse(result, "a non-pinned nonce must be rejected");
    }

    /// @notice Fuzz: whatever nonce is pinned, that same nonce is accepted.
    /// @dev Split from the mismatch case deliberately. Fuzzing two independent nonces and
    ///      asserting `result == (pinned == presented)` reads as though it covers both
    ///      directions, but two random words are essentially never equal — so it only ever
    ///      exercised the reject path, and would have passed against a body that always
    ///      returned false.
    function testFuzz_check1271SignedAction_pinnedNonceAlwaysAccepted(uint256 pinned) public {
        _pin(address(this), pinned);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, PERMIT2_ADDRESS, account, bytes32(0), _claimPayload(pinned)
        );

        assertTrue(result, "the pinned nonce must always be accepted");
    }

    /// @notice Fuzz: any nonce other than the pinned one is rejected.
    /// @dev Offsets by a non-zero delta so the mismatch is guaranteed rather than probable.
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

    /// @notice Two multiplexers hold independent pins, each accepting only its own.
    /// @dev The caller is the multiplexer. Asserting both directions rather than only that the
    ///      other one fails closed: a storage-key ordering bug would still fail closed, but
    ///      would show up here as one multiplexer accepting the other's nonce.
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
