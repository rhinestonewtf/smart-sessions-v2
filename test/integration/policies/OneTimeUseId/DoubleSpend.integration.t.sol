// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";

/// @title Two Permit2 settlements of one session in one transaction
/// @notice Two real Permit2 settlements, distinct nonces, one transaction: the first burns; the
///         second's own pre-claim leads with a burn of a spent id, validates FALSE, and leaves the
///         unlock without a nomination. Only the burning settlement lands.
contract OneTimeUseIdDoubleSpend_Test is OneTimeUseIdE2E_Base {
    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev A fresh Permit2 nonce means Permit2's own bitmap never applies, so this policy is the
    ///      only thing standing between the session and a second spend.
    function test_aSecondPermit2SettlementInTheSameTransactionIsRefused() public {
        _enableSession(true);

        _useNonce(1337);
        _settleViaPermit2();

        assertTrue(_burned(), "settlement one burned the id");
        assertTrue(_nonceBurned(1337), "settlement one really settled");

        // Same transaction, fresh nonce. Prepared before arming expectRevert, because
        // `_createPolicyData` makes an external staticcall that would otherwise absorb it.
        _useNonce(4242);
        bytes memory adapterCalldata = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);

        assertFalse(_nonceBurned(4242), "and nothing settled on the second nonce");
    }

    /// @dev CONTROL. Settlement one alone completes, so the refusal above is the second burn and
    ///      not the harness.
    function test_control_settlementOneAloneStillCompletes() public {
        _enableSession(true);

        _useNonce(1337);
        _settleViaPermit2();

        assertTrue(_nonceBurned(1337), "a lone settlement is unaffected by the poison rule");
    }
}
