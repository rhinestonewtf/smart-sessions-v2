// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ActionData, PolicyData } from "@types/DataTypes.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { IPermit2IntentExecutor } from "@compact-utils/executor/interfaces/IPermit2Intent.sol";
import { ValidateSignature } from "@compact-utils/executor/VerifySignature/VerifySignature.sol";

/// @title A rogue own-arbiter pre-claim from an EOA (RHI-5798), refused
/// @notice The two-call shape of the ride: an attacker EOA runs the pre-claim as its own arbiter
///         through `verifyExecution` (EMISSARY_EXECUTION), burning with `consumeFor(ID, N)` AND
///         executing X, then the real arbiter settles order N. Refused at the first step: X is not
///         allowed behind a `consumeFor`, so the executor's validation fails and nothing happens.
contract OneTimeUseIdRideViaOwnArbiter_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

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

    function test_ownArbiterPreClaimWithX_isRefused() public {
        _enableSession(true);
        _useNonce(4242);

        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, 4242))
        });
        calls[1] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (777))
        });
        Types.Operation memory ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
        bytes memory sig = _emissarySig();

        vm.prank(makeAddr("attackerArbiter"));
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        IPermit2IntentExecutor(address(env.intentExecutor))
            .executePreClaimOpsWithPermit2Stub(
                env.smartAccount1.account,
                IPermit2IntentExecutor.EIP712Permit2Stub(4242, block.timestamp + 1 days),
                IPermit2IntentExecutor.EIP712Permit2MandateStub(
                    bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0)
                ),
                ops,
                sig
            );

        assertFalse(_burned(), "settlement 1 burned nothing");
        assertTrue(MockTarget(address(env.target)).param() != 777, "and executed nothing");

        // The real arbiter's settlement of order N is then just the honest settlement.
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _preparePermit2Settlement());
        assertTrue(_burned(), "the honest pre-claim burned");
        assertTrue(_nonceBurned(4242), "and settled once");
    }
}
