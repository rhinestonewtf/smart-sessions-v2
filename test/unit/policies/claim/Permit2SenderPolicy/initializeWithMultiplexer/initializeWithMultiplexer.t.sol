// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2SenderPolicy_Unit_Test } from "../Permit2SenderPolicy.t.sol";

// Interfaces
import { IPermit2SenderPolicy } from "@policies/claim/permit2/interfaces/IPermit2SenderPolicy.sol";

/// @title Permit2SenderPolicy.initializeWithMultiplexer Unit Tests
/// @notice Initialization takes no configuration and changes nothing the check reads
contract Permit2SenderPolicy_initializeWithMultiplexer_Unit_Test is Permit2SenderPolicy_Unit_Test {
    /// @notice Test initialization with empty data succeeds
    function test_initializeWithMultiplexer_emptyInitData() external {
        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, "");

        assertTrue(_check(PERMIT2), "Permit2 accepted after init");
        assertFalse(_check(makeAddr("other")), "other sender refused after init");
    }

    /// @notice Test initialization with any data reverts
    function testFuzz_initializeWithMultiplexer_nonEmptyInitData_reverts(bytes calldata initData)
        external
    {
        vm.assume(initData.length != 0);

        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPermit2SenderPolicy.InvalidInitDataLength.selector, initData.length
            )
        );
        policy.initializeWithMultiplexer(account, cfg, initData);
    }
}
