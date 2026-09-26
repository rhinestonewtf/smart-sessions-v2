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

/// @title The fill route on a chain that is also a source
/// @notice On a destination chain the fill (`executeTargetOpsWithPermit2Stub`, router-only) runs in
///         its OWN transaction. Its targetOps are validated through `verifyExecution`, so they need
///         a burn of THIS chain's id in THIS transaction: a fill whose targetOps omit the burn is
///         refused, a fill that leads with it settles once.
abstract contract OneTimeUseIdFillRoute_Base is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    function setUp() public virtual override {
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

    /// @dev A fill leading with this chain's burn, then a registered op
    function _burnLedFill(uint256 nonce) internal {
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
        _fill(calls, nonce);
    }
}

contract OneTimeUseIdFillRoute_Test is OneTimeUseIdFillRoute_Base {
    /// @dev The fill's targetOps omit the burn: refused.
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

    /// @dev A fill leading with this chain's burn settles.
    function test_fillLeadingWithItsOwnBurn_settles() public {
        _burnLedFill(9001);

        assertTrue(_burned(), "the fill burned this chain's id");
        assertEq(env.target.param(), 777, "and its targetOps ran");
    }
}

/// @title The transaction after the fill
/// @notice The fill runs in `setUp`, so every test body is a genuinely later transaction on this
///         chain: with or without a burn, it is refused.
contract OneTimeUseIdFillRoute_LaterTx_Test is OneTimeUseIdFillRoute_Base {
    function setUp() public override {
        super.setUp();
        _burnLedFill(9001);
    }

    function test_theFillBurnedAndRan() public view {
        assertTrue(_burned(), "the fill burned this chain's id");
        assertEq(env.target.param(), 777, "and its targetOps ran");
    }

    function test_aNoBurnSettlementInALaterTransactionIsRefused() public {
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _settleViaExecutorWithoutConsume(0, 555);

        assertTrue(env.target.param() != 555, "no marker crossed the transaction boundary");
    }

    function test_aBurnLedSettlementInALaterTransactionIsRefused() public {
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _settleViaExecutor(0, 555);

        assertTrue(env.target.param() != 555, "the spent id refuses a second burn");
    }
}
