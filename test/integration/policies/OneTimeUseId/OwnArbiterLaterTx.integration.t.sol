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

/// @title A pre-claim in an earlier transaction cannot pre-authorise a later settlement
/// @notice A Permit2 pre-claim validated through `verifyExecution` burns and nominates the order it
///         names, and a registered op behind the burn runs; the nomination is transient. A
///         settlement of that order in a LATER transaction finds the id burned and no nomination,
///         and is refused. The pre-claim runs in `setUp`, so the test body is that later
///         transaction.
contract OneTimeUseIdOwnArbiterLaterTx_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    uint256 internal constant NONCE = 4242;

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

    function setUp() public override {
        super.setUp();
        _enableSession(true);
        _useNonce(NONCE);

        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, NONCE))
        });
        calls[1] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (777))
        });
        Types.Operation memory ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);

        vm.prank(makeAddr("ownArbiter"));
        IPermit2IntentExecutor(address(env.intentExecutor))
            .executePreClaimOpsWithPermit2Stub(
                env.smartAccount1.account,
                IPermit2IntentExecutor.EIP712Permit2Stub(NONCE, block.timestamp + 1 days),
                IPermit2IntentExecutor.EIP712Permit2MandateStub(
                    bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0)
                ),
                ops,
                _emissarySig()
            );
    }

    function test_thePreClaimBurnedAndRanItsRegisteredOp() public view {
        assertTrue(_burned(), "the pre-claim burned - one session use");
        assertEq(MockTarget(address(env.target)).param(), 777, "and its registered op ran");
    }

    function test_aSettlementOfTheNominatedOrderInALaterTransactionIsRefused() public {
        bytes memory cd = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(NONCE), "no settlement rode a nomination from an earlier tx");
    }
}
