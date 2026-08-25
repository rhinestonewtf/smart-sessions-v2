// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";

/// @title OneTimeUseIdPolicy.consume Unit Tests
/// @notice Unit tests for the consume function. `consume` burns the caller's own id and
///         nominates no settlement - the burn for routes gated by `checkAction`, which reads the
///         durable record directly and needs no nomination.
contract OneTimeUseIdPolicy_consume_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /// @notice Test consume burns the id and emits IdConsumed
    function test_consume_burnsTheIdAndEmits() external {
        assertFalse(policy.isConsumed(account, ID_A));

        vm.expectEmit(true, true, false, true);
        emit IOneTimeUseIdPolicy.IdConsumed(account, ID_A);
        _consume(ID_A);

        assertTrue(policy.isConsumed(account, ID_A));
    }

    /// @notice Test a second consume of an already-burned id does not revert
    function test_consume_isIdempotent() external {
        _consume(ID_A);
        _consume(ID_A);

        assertTrue(policy.isConsumed(account, ID_A), "still burned, no revert");
    }

    /// @notice Test consume trusts only msg.sender, so a stranger burns their own record
    function test_consume_isPerAccount() external {
        address stranger = makeAddr("stranger");

        vm.prank(stranger);
        policy.consume(ID_A);

        assertFalse(policy.isConsumed(account, ID_A), "the account's id is untouched");
        assertEq(_validate(cfgA), SUCCESS, "and its session still settles");
    }

    /// @notice Test consuming a different id leaves this one untouched
    function test_consume_isPerId() external {
        _consume(ID_A + 1);

        assertFalse(policy.isConsumed(account, ID_A), "burning another id does not spend this one");
    }

    /// @notice Test consume nominates no settlement, so the settling check still requires proof
    function test_consume_doesNotNominateAnySettlement() external {
        _consume(ID_A);

        assertFalse(
            _settlingCheck(cfgA, WITNESS_1),
            "a plain consume leaves nothing for the settling check to recognise"
        );
    }
}
