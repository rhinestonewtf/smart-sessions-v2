// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { TestHelperLib } from "@compact-utils/tests/Environment.sol";

/// @title Is the burn actually mandatory?
/// @notice The design's guarantee is "a settlement that burns cannot be followed by another".
///         That is only exactly-once if EVERY settlement burns. The burn lives inside the
///         pre-claim, which the arbiter runs failure-tolerantly — so anything that makes the
///         pre-claim fail skips the burn while the settlement still completes.
contract OneTimeUseIdBurnSkippable_Test is OneTimeUseIdE2E_Base {
    using TestHelperLib for *;

    /// @dev Same injected consume, but the pre-claim ops carry sigMode EMISSARY_EXECUTION instead
    ///      of the harness default. The signer picks this byte.
    function _injectConsumeWithSigMode(SmartExecutionLib.SigMode mode) internal {
        Execution[] memory ops = new Execution[](1);
        ops[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID))
        });

        $intent.element.mandate.originOps = ops.toOperation(mode);
        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);
    }

    function _useNonce(uint256 nonce) internal {
        $intent.nonce = nonce;
        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);
    }

    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev Does a settlement whose pre-claim uses EMISSARY_EXECUTION still settle, and does it
    ///      burn? If it settles WITHOUT burning, the id is never spent and the session is
    ///      unbounded regardless of the state machine.
    function test_preClaimUnderEmissaryExecution_doesItBurn() public {
        _enableSession(true);
        _injectConsumeWithSigMode(SmartExecutionLib.SigMode.EMISSARY_EXECUTION);
        _useNonce(1337);

        _settleViaPermit2();

        emit log_named_string("settled", _nonceBurned(1337) ? "YES" : "no");
        emit log_named_string("id burned", _burned() ? "YES" : "NO");
    }

    /// @dev The consequence, if the above settles without burning.
    function test_KNOWN_BROKEN_twoSettlementsWhenTheBurnIsSkipped() public {
        _enableSession(true);
        _injectConsumeWithSigMode(SmartExecutionLib.SigMode.EMISSARY_EXECUTION);

        _useNonce(1337);
        _settleViaPermit2();

        _useNonce(4242);
        _settleViaPermit2();

        emit log_named_string("first settled", _nonceBurned(1337) ? "YES" : "no");
        emit log_named_string("second settled", _nonceBurned(4242) ? "YES" : "no");
        emit log_named_string("id burned", _burned() ? "YES" : "NO");

        // ASSERTS THE BROKEN BEHAVIOUR ON PURPOSE. This is the evidence that the design does
        // not deliver exactly-once, kept green so the suite stays honest rather than red. If a
        // future change makes this fail, the burn has been made mandatory and that is the win.
        assertTrue(
            _nonceBurned(1337) && _nonceBurned(4242),
            "KNOWN BROKEN: two settlements, because the burn is skippable"
        );
        assertFalse(_burned(), "and the id was never spent at all");
    }
}
