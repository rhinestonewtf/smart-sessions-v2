// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";

/// @title The audit's headline finding, end to end
/// @notice Before the fix this test PASSED: two real Permit2 settlements of one session, distinct
///         nonces, one transaction, both landing. The tolerance said "something burned this id in
///         this transaction" — true for settlement two as well, because settlement one had just
///         burned it — so settlement two rode settlement one's marker.
///
///         The fix moves the discrimination to the write side. `consume` is not `view`, so the
///         second one can see the id is already spent, conclude it is not the burn, and poison the
///         transaction. Only the burning settlement is tolerated.
contract OneTimeUseIdDoubleSpend_Test is OneTimeUseIdE2E_Base {
    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev THE regression. A fresh Permit2 nonce means Permit2's own bitmap never applies, so
    ///      this policy is the only thing standing between the session and a second spend.
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

    /// @dev CONTROL. The identical second settlement in a LATER transaction is refused too — for
    /// a
    ///      different reason (the durable burn, not the poison). Kept so a change that fixes one
    ///      path and breaks the other cannot pass silently.
    function test_control_settlementOneAloneStillCompletes() public {
        _enableSession(true);

        _useNonce(1337);
        _settleViaPermit2();

        assertTrue(_nonceBurned(1337), "a lone settlement is unaffected by the poison rule");
    }
}
