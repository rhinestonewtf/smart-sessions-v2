// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Contracts
import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

/// @title OneTimeUseIdPolicy.consume Unit Tests
/// @notice `consume` is the burn OP; the burn itself is its validation. Executing it only checks
///         that validation happened in this transaction, and writes nothing.
contract OneTimeUseIdPolicy_consume_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /// @notice Test consume executes after its validation
    function test_consume_executesAfterItsValidation() external {
        _validateBurn(cfgA);

        _execConsume(ID_A);

        assertTrue(_burned(ID_A), "burned by the validation");
    }

    /// @notice Test consume reverts when no validation preceded it, so a burn op that reached
    ///         execution without `checkAction` (a direct call, a 1271-validated batch) fails
    function test_consume_revertsWhen_notValidated() external {
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IOneTimeUseIdPolicy.BurnNotValidated.selector, ID_A));
        policy.consume(ID_A);

        assertFalse(_burned(ID_A), "and nothing was spent");
        assertEq(_validatePlain(cfgA), FAILED, "and nothing rides");
    }

    /// @notice Test consume writes nothing: it does not spend, nominate or admit anything
    function test_consume_writesNothing() external {
        _validateBurn(cfgA);
        _execConsume(ID_A);
        _execConsume(ID_A);

        assertTrue(_burned(ID_A), "still exactly the validation's burn");
        assertFalse(_settlingCheck(cfgA, WITNESS_1), "no nomination appeared");
        assertFalse(_burned(ID_B), "no other id was touched");
    }

    /// @notice Test consume trusts only msg.sender, so a stranger cannot consume the account's
    ///         validation
    function test_consume_isPerAccount() external {
        _validateBurn(cfgA);

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(abi.encodeWithSelector(IOneTimeUseIdPolicy.BurnNotValidated.selector, ID_A));
        policy.consume(ID_A);
    }

    /// @notice Test a validation of one id does not let another id's op execute
    function test_consume_isPerId() external {
        _validateBurn(cfgA);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IOneTimeUseIdPolicy.BurnNotValidated.selector, ID_B));
        policy.consume(ID_B);
    }

    /// @notice Test the constructor rejects an executor that collides with Permit2 or is zero
    function test_constructor_rejectsInvalidExecutor() external {
        vm.expectRevert(IOneTimeUseIdPolicy.InvalidIntentExecutor.selector);
        new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2), PERMIT2);

        vm.expectRevert(IOneTimeUseIdPolicy.InvalidIntentExecutor.selector);
        new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2), address(0));
    }
}
