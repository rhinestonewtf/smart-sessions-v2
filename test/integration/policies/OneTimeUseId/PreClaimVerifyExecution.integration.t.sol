// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ActionData, PolicyData } from "@types/DataTypes.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

/// @title A Permit2 pre-claim validated through `verifyExecution` can burn with `consumeFor`
/// @notice A Permit2 pre-claim may be validated with an execution-emissary sigMode, in which case
///         its `consumeFor` reaches `checkAction`. Refusing `consumeFor` there makes
///         the Permit2 route unsettleable.
contract OneTimeUseIdPreClaimVerifyExecution_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    /// @dev The pre-claim's `consumeFor` needs an action entry, as a real session's fallback
    ///      action provides; the once-policy sits on it, so it runs through `checkAction`.
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

    /// @dev Pure EMISSARY_EXECUTION (no ERC-1271 fallback), so the pre-claim is validated only by
    ///      `verifyExecution` and a `checkAction` refusal cannot be routed around.
    function _injectConsumeForViaVerifyExecution() internal {
        Execution[] memory ops = new Execution[](1);
        ops[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, $intent.nonce))
        });
        $intent.element.mandate.originOps = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(ops);
        $intent.permit2Hash =
            hashPermit2($intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element);
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);
    }

    function test_permit2PreClaimThroughVerifyExecution_settlesAndBurns() public {
        _enableSession(true);
        _injectConsumeForViaVerifyExecution();

        Types.Order memory order = _getPermit2Order();
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());
        bytes memory cd = abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order,
                    userSigs: Types.Signatures({
                        notarizedClaimSig: $intent.userEmissarySig, preClaimSig: _emissarySig()
                    })
                }))
        );
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertTrue(_burned(), "the pre-claim consumeFor burned the id");
        assertTrue(_nonceBurned($intent.nonce), "and the Permit2 settlement completed");
    }
}
