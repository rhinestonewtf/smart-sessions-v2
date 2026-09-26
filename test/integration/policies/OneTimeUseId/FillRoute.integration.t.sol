// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { IPermit2IntentExecutor } from "@compact-utils/executor/interfaces/IPermit2Intent.sol";
import { ValidateSignature } from "@compact-utils/executor/VerifySignature/VerifySignature.sol";

/// @title M3 - the fill route on a chain that is also a source (destinationBurnsAsSource)
/// @notice On a destination chain the fill (`executeTargetOpsWithPermit2Stub`, router-only) runs in
///         its OWN transaction. Its targetOps are validated through `verifyExecution`, so they need
///         a burn of THIS chain's id in THIS transaction: a fill whose targetOps omit the burn is
///         refused, a fill that leads with it settles once. The shipped 61e6c62 `checkAction`
///         refused a burn-less batch the same way (`approved == BURN_NONE -> VALIDATION_FAILED`),
///         so an SDK that omits the destination burn fails identically on both - not a regression.
contract OneTimeUseIdFillRoute_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    function setUp() public override {
        super.setUp();
        _enableSession(true);
    }

    function _fill(Execution[] memory calls, uint256 nonce) internal {
        Types.Operation memory ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
        IPermit2IntentExecutor.EIP712Permit2MandateDestinationStub memory stub =
            IPermit2IntentExecutor.EIP712Permit2MandateDestinationStub({
                sponsor: env.smartAccount1.account,
                arbiter: arbiter,
                minGas: 0,
                notarizedChainId: block.chainid,
                preClaimOpsHash: bytes32(0),
                tokenInHash: bytes32(0),
                qHash: bytes32(0),
                targetStub: IPermit2IntentExecutor.Target({
                    fillExpiry: block.timestamp + 1 hours, tokenOutHash: bytes32(0)
                })
            });

        vm.prank(address(env.router));
        IPermit2IntentExecutor(address(env.intentExecutor))
            .executeTargetOpsWithPermit2Stub(
                env.smartAccount1.account,
                IPermit2IntentExecutor.EIP712Permit2Stub(nonce, block.timestamp + 1 days),
                stub,
                ops,
                _emissarySig()
            );
    }

    /// @dev destinationBurnsAsSource: the fill's targetOps omit the burn -> refused (both
    /// versions).
    function test_fillWithoutItsOwnBurn_isRefused() public {
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (777))
        });

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _fill(calls, 9001);

        assertFalse(_burned(), "nothing burned");
        assertTrue(env.target.param() != 777, "nothing executed");
    }

    /// @dev One burn per chain: a fill leading with this chain's burn settles once; a later
    ///      transaction on this chain is refused.
    function test_fillLeadingWithItsOwnBurn_settlesOnce() public {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID))
        });
        calls[1] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (777))
        });

        _fill(calls, 9001);

        assertTrue(_burned(), "the fill burned this chain's id");
        assertEq(env.target.param(), 777, "and its targetOps ran");

        vm.expectRevert();
        _settleViaExecutor(0, 555);
        assertTrue(env.target.param() != 555, "a later transaction on this chain is refused");
    }
}
