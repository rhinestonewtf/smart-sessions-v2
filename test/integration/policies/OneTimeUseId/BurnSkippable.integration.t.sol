// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { TestHelperLib } from "@compact-utils/tests/Environment.sol";

/// @title The burn is mandatory
/// @notice Regression for the audit's headline finding. The burn lives inside the pre-claim,
///         which the arbiter runs failure-tolerantly by design — so ANY way of making the
///         pre-claim fail used to skip the burn while the settlement completed anyway. Five
///         vectors were confirmed: a failing sigMode, a starved gas stipend, a decoy id, no
///         pre-claim ops, and a reverting sibling op.
///
///         The settling ERC-1271 check now demands positive proof that THIS settlement burned,
///         so skipping the burn means not settling. All five collapse into one refusal.
contract OneTimeUseIdBurnSkippable_Test is OneTimeUseIdE2E_Base {
    using TestHelperLib for *;

    /// @dev Same injected consume, but the pre-claim ops carry sigMode EMISSARY_EXECUTION instead
    ///      of the harness default. The signer picks this byte.
    function _injectConsumeWithSigMode(SmartExecutionLib.SigMode mode) internal {
        Execution[] memory ops = new Execution[](1);
        ops[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, $intent.nonce))
        });

        $intent.element.mandate.originOps = ops.toOperation(mode);
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
    function test_aSettlementWhosePreClaimNeverRunsCannotSettle() public {
        _enableSession(true);
        $intent.nonce = 1337;
        // AFTER the nonce, because `_useNonce` re-injects with the default sigMode and would
        // silently undo this line.
        _injectConsumeWithSigMode(SmartExecutionLib.SigMode.EMISSARY_EXECUTION);

        bytes memory cd = _preparePermit2Settlement();
        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(1337), "a settlement that skips its burn cannot settle");
        assertFalse(_burned(), "and nothing was burned");
    }

    /// @dev CONTROL. With a working pre-claim the identical settlement completes, so the refusal
    ///      above is the missing burn and not the sigMode or the harness.
    function test_control_aWorkingPreClaimSettles() public {
        _enableSession(true);
        _useNonce(1337);

        _settleViaPermit2();

        assertTrue(_nonceBurned(1337), "the honest settlement lands");
        assertTrue(_burned(), "and burns");
    }
}
