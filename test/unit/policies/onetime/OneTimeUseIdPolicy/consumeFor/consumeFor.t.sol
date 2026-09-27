// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";

/// @title OneTimeUseIdPolicy.consumeFor Unit Tests
/// @notice `consumeFor` is the Permit2-route burn OP; validating it burns and nominates. Executing
///         it only checks that validation happened in this transaction, and writes nothing.
contract OneTimeUseIdPolicy_consumeFor_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /// @notice Test consumeFor executes after its validation, and the validated witness settles
    function test_consumeFor_executesAfterItsValidation() external {
        _validateBurnFor(cfgA, WITNESS_1);

        _execConsumeFor(ID_A, WITNESS_1);

        assertTrue(_burned(ID_A));
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "the validated witness settles");
    }

    /// @notice Test consumeFor reverts when no validation preceded it
    function test_consumeFor_revertsWhen_notValidated() external {
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IOneTimeUseIdPolicy.BurnNotValidated.selector, ID_A));
        policy.consumeFor(ID_A, WITNESS_1);

        assertFalse(_burned(ID_A), "nothing spent");
        assertFalse(_settlingCheck(cfgA, WITNESS_1), "nothing nominated");
    }

    /// @notice Test the executed witness cannot replace the validated nomination
    function test_consumeFor_cannotRenominate() external {
        _validateBurnFor(cfgA, WITNESS_1);

        _execConsumeFor(ID_A, WITNESS_2);

        assertTrue(_settlingCheck(cfgA, WITNESS_1), "the validated nomination stands");
        assertFalse(_settlingCheck(cfgA, WITNESS_2), "the executed witness nominates nothing");
    }

    /// @notice Test consumeFor trusts only msg.sender
    function test_consumeFor_isPerAccount() external {
        _validateBurnFor(cfgA, WITNESS_1);

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(abi.encodeWithSelector(IOneTimeUseIdPolicy.BurnNotValidated.selector, ID_A));
        policy.consumeFor(ID_A, WITNESS_1);
    }

    /// @notice Test a validation of one id does not let another id's op execute
    function test_consumeFor_isPerId() external {
        _validateBurnFor(cfgA, WITNESS_1);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IOneTimeUseIdPolicy.BurnNotValidated.selector, ID_B));
        policy.consumeFor(ID_B, WITNESS_1);
    }
}
