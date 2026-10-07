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

/// @title A pre-claim under every sigMode
/// @notice The sigMode byte picks how a pre-claim is validated. Only the execution-emissary modes
///         reach `checkAction`, burn and run. Under any mode that validates ERC-1271 first the 1271
///         list runs, and `Permit2ClaimPolicy`'s arbiter pin refuses a digest whose arbiter is not
///         the pinned one, so nothing burns and nothing runs.
contract OneTimeUseIdOwnArbiterSigModes_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    uint256 internal constant NONCE = 4242;
    address internal ownArbiter = makeAddr("ownArbiter");

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

    function _preClaimOps(SmartExecutionLib.SigMode mode)
        internal
        view
        returns (Types.Operation memory)
    {
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
        return mode.encode(calls);
    }

    function _preClaim(Types.Operation memory ops, bytes memory sig) internal {
        vm.prank(ownArbiter);
        IPermit2IntentExecutor(address(env.intentExecutor))
            .executePreClaimOpsWithPermit2Stub(
                env.smartAccount1.account,
                IPermit2IntentExecutor.EIP712Permit2Stub(NONCE, block.timestamp + 1 days),
                IPermit2IntentExecutor.EIP712Permit2MandateStub(
                    bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0)
                ),
                ops,
                sig
            );
    }

    /// @dev A 1271 envelope whose claim blob names the caller as arbiter, which is the only blob
    ///      that could recompute this pre-claim's digest.
    function _callerArbiter1271Sig(Types.Operation memory ops) internal returns (bytes memory) {
        $intent.element.arbiter = ownArbiter;
        $intent.element.mandate.originOps = ops;
        return _createSmartSessionSignature(_createPolicyData());
    }

    function setUp() public override {
        super.setUp();
        _enableSession(true);
        _useNonce(NONCE);
    }

    function _assertNothingHappened() internal view {
        assertFalse(_burned(), "nothing burned");
        assertTrue(MockTarget(address(env.target)).param() != 777, "X never executed");
    }

    function test_erc1271_refusedByTheArbiterPin() public {
        Types.Operation memory ops = _preClaimOps(SmartExecutionLib.SigMode.ERC1271);
        bytes memory sig = _callerArbiter1271Sig(ops);

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _preClaim(ops, sig);
        _assertNothingHappened();
    }

    function test_erc1271ThenEmissaryExecution_refused() public {
        Types.Operation memory ops =
            _preClaimOps(SmartExecutionLib.SigMode.ERC1271_EMISSARYEXECUTION);
        bytes memory sig = _callerArbiter1271Sig(ops);

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _preClaim(ops, sig);
        _assertNothingHappened();
    }

    /// @dev EMISSARYEXECUTION_ERC1271 tries `verifyExecution` FIRST, so it reaches `checkAction`
    ///      just like EMISSARY_EXECUTION: the burn happens and the registered X runs. That is one
    ///      session use: it burns the id and nominates transiently, so no later transaction can
    ///      ride it (`OwnArbiterLaterTx`). Only the pure-1271 and 1271-first modes never reach
    ///      `checkAction` and stay refused.
    function test_emissaryExecutionThenErc1271_reachesCheckActionAndRunsOneUse() public {
        Types.Operation memory ops =
            _preClaimOps(SmartExecutionLib.SigMode.EMISSARYEXECUTION_ERC1271);
        bytes memory sig = _emissarySig();

        _preClaim(ops, sig);

        assertTrue(_burned(), "the execution-emissary mode reached checkAction and burned");
        assertEq(MockTarget(address(env.target)).param(), 777, "and its registered X ran once");
    }

    function test_erc1271ThenEmissary_refused() public {
        Types.Operation memory ops = _preClaimOps(SmartExecutionLib.SigMode.ERC1271_EMISSARY);
        bytes memory sig = _callerArbiter1271Sig(ops);

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _preClaim(ops, sig);
        _assertNothingHappened();
    }
}
