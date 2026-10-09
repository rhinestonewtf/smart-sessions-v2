// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2SenderPolicy_Unit_Test } from "../Permit2SenderPolicy.t.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Permit2SenderPolicy.check1271SignedAction Unit Tests
/// @notice The check accepts a request sent by Permit2 and nothing else, whatever the
///         configuration, account, hash or signature
contract Permit2SenderPolicy_check1271SignedAction_Unit_Test is Permit2SenderPolicy_Unit_Test {
    /// @notice Test a request sent by Permit2 is accepted
    function test_check1271SignedAction_permit2Sender_returnsTrue() external {
        assertTrue(_check(PERMIT2));
    }

    /// @notice Test a request sent by the zero address is refused
    function test_check1271SignedAction_zeroSender_returnsFalse() external {
        assertFalse(_check(address(0)));
    }

    /// @notice Test a request sent by the account itself is refused
    function test_check1271SignedAction_accountSender_returnsFalse() external {
        assertFalse(_check(account));
    }

    /// @notice Test a request sent by any address other than Permit2 is refused
    function testFuzz_check1271SignedAction_otherSender_returnsFalse(address sender) external {
        vm.assume(sender != PERMIT2);

        assertFalse(_check(sender));
    }

    /// @notice Test the result depends on the sender alone
    function testFuzz_check1271SignedAction_dependsOnSenderOnly(
        address caller,
        bytes32 configId,
        address sender,
        address anyAccount,
        bytes32 hash,
        bytes calldata signature
    )
        external
    {
        vm.prank(caller);
        bool result = policy.check1271SignedAction(
            ConfigId.wrap(configId), sender, anyAccount, hash, signature
        );

        assertEq(result, sender == PERMIT2);
    }
}
