// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {
    OneTimeUseIdE2E_Base
} from "../../integration/policies/OneTimeUseId/OneTimeUseIdMatrixE2E.integration.t.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

contract A7Starve_PoC is OneTimeUseIdE2E_Base {
    function _settleStarved(uint128 stipend) internal {
        Types.Order memory order = _getPermit2Order();
        order.packedGasValues = Types.packGasValues(stipend, 0);
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_permit2_handleClaim,
                (MockAdapter.ClaimDataPermit2({
                        order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                    }))
            )
        );
    }

    function test_a7_starvedSettlesWithoutBurning() public {
        _enableSession(true);
        uint256 b0 = env.token1.balanceOf($intent.sponsor);
        _settleStarved(1000);
        assertLt(env.token1.balanceOf($intent.sponsor), b0, "sponsor tokens PULLED");
        assertFalse(_burned(), "id NOT burned");
    }

    function test_a7_starvedThenExecutorAlsoSettles() public {
        _enableSession(true);
        _settleStarved(1000);
        assertFalse(_burned(), "nothing burned");
        _settleViaExecutor(0, 43);
        assertEq(env.target.param(), 43, "executor settlement ALSO landed");
    }

    /// @dev funded stipend, second settlement in the SAME tx on a fresh permit2 nonce
    function test_a7_fundedSecondSettlementInSameTx() public {
        _enableSession(true);
        _settleViaPermit2();
        assertTrue(_burned(), "settlement 1 burned");

        $intent.nonce = $intent.nonce + 1;
        _injectConsumeIntoPreClaimOps();

        uint256 b0 = env.token1.balanceOf($intent.sponsor);
        _settleStarved(300_000);
        assertLt(env.token1.balanceOf($intent.sponsor), b0, "SECOND spend landed anyway");
    }
}
