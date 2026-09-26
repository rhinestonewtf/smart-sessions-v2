// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

/// @title The burn is mandatory
/// @notice Regression for the audit's headline finding. The burn lived inside the pre-claim, which
///         the arbiter runs failure-tolerantly by design - so ANY way of making the pre-claim fail
///         used to skip the burn while the settlement completed anyway.
///
///         Burn-at-validation moves the burn to `checkAction`, which runs inside the pre-claim's
///         validation. A pre-claim that never validates (a withheld or garbled pre-claim
///         signature, so `verifyExecution` cannot parse it) never burns AND never consumes its
///         executor nonce - so the Permit2 settling check, which demands both a matching
///         nomination and a consumed nonce, refuses it.
contract OneTimeUseIdBurnSkippable_Test is OneTimeUseIdE2E_Base {
    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev The settlement a submitter who withholds a valid pre-claim signature would build: the
    ///      pre-claim ops are the honest EMISSARY_EXECUTION burn, but the preClaimSig is garbage,
    ///      so `verifyExecution` cannot parse it and the pre-claim validates FALSE (swallowed).
    function _prepareWithGarbledPreClaimSig() internal returns (bytes memory) {
        Types.Order memory order = _getPermit2Order();
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());

        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order,
                    userSigs: Types.Signatures({
                        notarizedClaimSig: $intent.userEmissarySig, preClaimSig: hex"00"
                    })
                }))
        );
    }

    /// @dev A settlement whose pre-claim never validates cannot settle: no burn, no consumed nonce,
    ///      so the settling check has no nomination to match.
    function test_aSettlementWhosePreClaimNeverRunsCannotSettle() public {
        _enableSession(true);
        _useNonce(1337);

        bytes memory cd = _prepareWithGarbledPreClaimSig();
        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(1337), "a settlement that skips its burn cannot settle");
        assertFalse(_burned(), "and nothing was burned");
    }

    /// @dev CONTROL. With a valid pre-claim signature the identical settlement completes, so the
    ///      refusal above is the missing burn and not the harness.
    function test_control_aWorkingPreClaimSettles() public {
        _enableSession(true);
        _useNonce(1337);

        _settleViaPermit2();

        assertTrue(_nonceBurned(1337), "the honest settlement lands");
        assertTrue(_burned(), "and burns");
    }
}
