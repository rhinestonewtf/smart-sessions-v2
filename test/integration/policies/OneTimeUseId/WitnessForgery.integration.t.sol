// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";

/// @title Can the executor route nominate a Permit2 settlement?
/// @notice `checkAction` binds the `consume` calldata's FIRST argument (the id) but not its
///         second (the witness). So an executor settlement can burn the id while nominating a
///         Permit2 nonce it does not own — and a Permit2 settlement that skips its own burn then
///         matches that nomination.
contract OneTimeUseIdWitnessForgery_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev An executor settlement whose consume nominates SOMEONE ELSE'S settlement
    function _settleViaExecutorNominating(uint256 executorNonce, uint256 forgedWitness) internal {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, forgedWitness))
        });
        calls[1] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (42))
        });

        IStandaloneIntentExecutor.SingleChainOps memory signedOps;
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = executorNonce;
        signedOps.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
        signedOps.signature = _emissarySig();

        vm.prank(env.solver.addr);
        env.intentExecutor.executeSinglechainOps(signedOps);
    }

    /// @dev A Permit2 claim with a starved pre-claim, so it performs no burn of its own
    function _prepareStarved() internal returns (bytes memory) {
        Types.Order memory order = _getPermit2Order();
        order.packedGasValues = Types.packGasValues(0, 0);
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());

        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                }))
        );
    }

    /// @dev THE attack, and the fix refuses it at the earlier of the two points. An executor
    ///      settlement that tries to NOMINATE is rejected outright — `checkAction` forbids
    ///      `consumeFor` on the action surface, because it cannot tell a legitimate nomination
    ///      from one naming a settlement the caller does not own.
    ///
    ///      Before the split there was a single `consume(id, witness)` whose witness `checkAction`
    ///      did not bind, so this settlement succeeded, nominated Permit2 nonce 4242, and a
    ///      starved Permit2 settlement on that nonce then rode the nomination without burning
    ///      anything. Two spends.
    function test_theExecutorRouteCannotNominateAtAll() public {
        _enableSession(true);
        _useNonce(4242);

        vm.expectRevert();
        _settleViaExecutorNominating({ executorNonce: 0, forgedWitness: 4242 });

        assertFalse(_burned(), "nothing burned");
    }

    /// @dev ...and with the nomination refused, the starved Permit2 settlement has nothing to
    ///      ride. Belt and braces: this is the second half of the same attack, asserted
    ///      independently in case the first refusal ever moves.
    function test_aStarvedPermit2SettlementHasNoNominationToRide() public {
        _enableSession(true);
        _useNonce(4242);

        bytes memory cd = _prepareStarved();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(4242), "nothing settled");
    }

    /// @dev CONTROL. The executor route's PLAIN burn — which nominates nothing — still works.
    function test_control_theExecutorRouteMayStillBurn() public {
        _enableSession(true);

        _settleViaExecutor(0);

        assertTrue(_burned(), "a plain burn is what the action route is for");
    }
}
