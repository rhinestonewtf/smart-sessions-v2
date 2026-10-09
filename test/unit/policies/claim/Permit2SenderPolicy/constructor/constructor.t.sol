// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2SenderPolicy_Unit_Test } from "../Permit2SenderPolicy.t.sol";

// Contracts
import { Permit2SenderPolicy } from "@policies/claim/permit2/Permit2SenderPolicy.sol";

// Interfaces
import { IPermit2SenderPolicy } from "@policies/claim/permit2/interfaces/IPermit2SenderPolicy.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

/// @title Permit2SenderPolicy.constructor Unit Tests
/// @notice The constructor pins a non-zero Permit2
contract Permit2SenderPolicy_constructor_Unit_Test is Permit2SenderPolicy_Unit_Test {
    /// @notice Test the constructor stores Permit2
    function test_constructor_storesPermit2() external view {
        assertEq(address(policy.PERMIT2()), PERMIT2);
    }

    /// @notice Test the constructor reverts on the zero address
    function test_constructor_zeroPermit2_reverts() external {
        vm.expectRevert(IPermit2SenderPolicy.InvalidPermit2.selector);
        new Permit2SenderPolicy(ISignatureTransfer(address(0)));
    }
}
