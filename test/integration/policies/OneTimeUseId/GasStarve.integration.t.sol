// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

/// @title The gas-starvation vector
/// @notice `preClaimGasStipend` is the LOW 128 bits of `packedGasValues`, and only `minGas` (the
///         high half) enters the signed mandate hash — so the submitter picks the gas budget of a
///         call the user signed. Starve it and the pre-claim OOGs, which the arbiter swallows.
///
///         Before the witness fix this settled with `isUsed == false`, repeatedly.
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
                    order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                }))
        );
    }

    /// @dev THE regression for Kevin's blocker. Starve the pre-claim so `consume` never runs —
    ///      the settling check has no witness to match and must refuse.
    function test_aStarvedPreClaimCannotSettle() public {
        _enableSession(true);
        _useNonce(1337);

        bytes memory cd = _prepareWithStipend(0);

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(1337), "nothing settled");
        assertFalse(_burned(), "and nothing burned");
    }

    /// @dev The measured threshold from the audit: 50k skipped the burn, 100k performed it.
    function test_aStarvedPreClaimCannotSettle_atTheMeasuredThreshold() public {
        _enableSession(true);
        _useNonce(1337);

        bytes memory cd = _prepareWithStipend(50_000);

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_burned(), "50k was enough to skip the burn, and is no longer enough to settle");
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
