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

/// @title The rogue own-arbiter pre-claim under every other sigMode (RHI-5798)
/// @notice The session key picks the sigMode byte. Under `verifyExecution` the batch bound refuses
///         X; under any ERC-1271 mode the 1271 list runs and `Permit2ClaimPolicy`'s arbiter pin
///         refuses a digest whose arbiter is the caller; the hybrids fall back from one refusal
///         into the other.
contract OneTimeUseIdRideOtherSigModes_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    uint256 internal constant NONCE = 4242;
    address internal attacker = makeAddr("attackerArbiter");

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

    function _rogueOps(SmartExecutionLib.SigMode mode)
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

    function _roguePreClaim(Types.Operation memory ops, bytes memory sig) internal {
        vm.prank(attacker);
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

    /// @dev A 1271 envelope whose claim blob names the ATTACKER as arbiter, which is the only blob
    ///      that could recompute the rogue digest (the executor folds msg.sender in as arbiter).
    function _rogue1271Sig(Types.Operation memory ops) internal returns (bytes memory) {
        $intent.element.arbiter = attacker;
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
        Types.Operation memory ops = _rogueOps(SmartExecutionLib.SigMode.ERC1271);
        bytes memory sig = _rogue1271Sig(ops);

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _roguePreClaim(ops, sig);
        _assertNothingHappened();
    }

    function test_erc1271ThenEmissaryExecution_refused() public {
        Types.Operation memory ops = _rogueOps(SmartExecutionLib.SigMode.ERC1271_EMISSARYEXECUTION);
        bytes memory sig = _rogue1271Sig(ops);

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _roguePreClaim(ops, sig);
        _assertNothingHappened();
    }

    function test_emissaryExecutionThenErc1271_refused() public {
        Types.Operation memory ops = _rogueOps(SmartExecutionLib.SigMode.EMISSARYEXECUTION_ERC1271);
        bytes memory sig = _emissarySig();

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _roguePreClaim(ops, sig);
        _assertNothingHappened();
    }

    function test_erc1271ThenEmissary_refused() public {
        Types.Operation memory ops = _rogueOps(SmartExecutionLib.SigMode.ERC1271_EMISSARY);
        bytes memory sig = _rogue1271Sig(ops);

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _roguePreClaim(ops, sig);
        _assertNothingHappened();
    }
}
