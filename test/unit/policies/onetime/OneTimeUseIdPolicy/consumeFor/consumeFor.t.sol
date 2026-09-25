// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

/// @title OneTimeUseIdPolicy.consumeFor Unit Tests
/// @notice Unit tests for the consumeFor function. `consumeFor` burns the caller's own id AND
///         nominates the settlement doing it, so the settling check can later tell its own burn
///         from someone else's.
contract OneTimeUseIdPolicy_consumeFor_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /// @notice Test consumeFor burns the id and its witness settles
    function test_consumeFor_burnsTheIdAndNominatesTheWitness() external {
        assertFalse(policy.isUsed(account, ID_A));

        _consumeFor(ID_A, WITNESS_1);

        assertTrue(policy.isUsed(account, ID_A));
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "the recorded witness settles");
    }

    /// @notice Test a second consumeFor of an already-burned id does not revert
    function test_consumeFor_isIdempotent() external {
        _consumeFor(ID_A, WITNESS_1);
        _consumeFor(ID_A, WITNESS_1);

        assertTrue(policy.isUsed(account, ID_A), "still burned, no revert");
    }

    /// @notice Test consumeFor trusts only msg.sender, so a stranger burns their own record
    function test_consumeFor_isPerAccount() external {
        address stranger = makeAddr("stranger");

        vm.prank(stranger);
        policy.consumeFor(ID_A, WITNESS_1);

        assertFalse(policy.isUsed(account, ID_A), "the account's id is untouched");
        assertEq(_validate(cfgA), SUCCESS, "and its session still settles");
    }

    /// @notice Test consuming a different id leaves this one untouched
    function test_consumeFor_isPerId() external {
        _consumeFor(ID_A + 1, WITNESS_1);

        assertFalse(policy.isUsed(account, ID_A), "burning another id does not spend this one");
    }
}
