// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

/// @title A starved pre-claim
/// @notice A pre-claim that runs out of gas never validates, so it neither burns nor consumes its
///         executor nonce; the settling check then has no nomination to match and refuses.
contract OneTimeUseIdGasStarve_Test is OneTimeUseIdE2E_Base {
    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev Builds the claim with a caller-chosen pre-claim gas stipend
    function _prepareWithStipend(uint128 stipend) internal returns (bytes memory) {
        Types.Order memory order = _getPermit2Order();
        order.packedGasValues = Types.packGasValues(stipend, 0);
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());

        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order,
                    userSigs: Types.Signatures({
                        notarizedClaimSig: $intent.userEmissarySig, preClaimSig: _emissarySig()
                    })
                }))
        );
    }

    /// @dev Starve the pre-claim so `checkAction` never runs: no burn, no nomination, refused.
    function test_aStarvedPreClaimCannotSettle() public {
        _enableSession(true);
        _useNonce(1337);

        bytes memory cd = _prepareWithStipend(0);

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(1337), "nothing settled");
        assertFalse(_burned(), "and nothing burned");
    }

    /// @dev A small but nonzero stipend, short of what validation needs.
    function test_aStarvedPreClaimCannotSettle_atTheMeasuredThreshold() public {
        _enableSession(true);
        _useNonce(1337);

        bytes memory cd = _prepareWithStipend(50_000);

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_burned(), "a starved pre-claim burns nothing and cannot settle");
    }

    /// @dev CONTROL. A funded pre-claim burns and settles, so the refusals above are the missing
    ///      witness and not the stipend plumbing.
    function test_control_aFundedPreClaimSettles() public {
        _enableSession(true);
        _useNonce(1337);

        bytes memory cd = _prepareWithStipend(300_000);
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertTrue(_nonceBurned(1337), "the honest settlement lands");
        assertTrue(_burned(), "and burns");
    }
}
