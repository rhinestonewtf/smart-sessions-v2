// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ActionData, PolicyData } from "@types/DataTypes.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";

/// @title The executor route cannot nominate a settlement it does not own
/// @notice The executor route burns via `consume`, which nominates nothing. `checkAction` refuses a
///         `consumeFor` on the action surface, so an executor settlement cannot leave a nomination
///         behind for a Permit2 settlement that skipped its own burn to ride. Exactly-once holds
///         across the executor and Permit2 routes, not only within each.
contract OneTimeUseIdWitnessForgery_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    /// @dev Registers `consumeFor` as an action so the attempt reaches `checkAction` directly. A
    ///      real install reaches it via the fallback action instead; the once-policy sits there
    ///      too, so `checkAction` refuses it either way.
    function _extraActions(PolicyData[] memory actionPolicies)
        internal
        view
        override
        returns (ActionData[] memory extra)
    {
        extra = new ActionData[](1);
        extra[0] = ActionData({
            actionTarget: address(oncePolicy),
            actionTargetSelector: IOneTimeUseIdPolicy.consumeFor.selector,
            actionPolicies: actionPolicies
        });
    }

    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev Builds (without executing) an executor settlement whose burn is a `consumeFor`
    ///      nominating a Permit2 nonce it does not own.
    function _buildExecutorNominatingOps(
        uint256 executorNonce,
        uint256 forgedWitness
    )
        internal
        view
        returns (IStandaloneIntentExecutor.SingleChainOps memory signedOps)
    {
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

        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = executorNonce;
        signedOps.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
        signedOps.signature = _emissarySig();
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

    /// @dev The attack, end to end, now closed. An executor settlement tries to nominate Permit2
    ///      nonce 4242 via `consumeFor` — `checkAction` refuses the op, so validation fails and
    ///      nothing burns. With no nomination left behind, a starved Permit2 settlement on 4242 has
    ///      nothing to ride and cannot settle. One burn would need one settlement.
    function test_theExecutorRouteCannotNominateASettlementItDoesNotOwn() public {
        _enableSession(true);
        _useNonce(4242);

        IStandaloneIntentExecutor.SingleChainOps memory ops =
            _buildExecutorNominatingOps({ executorNonce: 0, forgedWitness: 4242 });
        vm.prank(env.solver.addr);
        vm.expectRevert();
        env.intentExecutor.executeSinglechainOps(ops);
        assertFalse(_burned(), "the nominating executor settlement was refused");

        bytes memory cd = _prepareStarved();
        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);
        assertFalse(_nonceBurned(4242), "no borrowed nomination, no second spend");
    }

    /// @dev The second half in isolation: with no executor settlement at all, a starved Permit2
    ///      settlement has no nomination to ride and refuses.
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
