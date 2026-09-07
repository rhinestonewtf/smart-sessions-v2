// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title OneTimeUseIdPolicy.usage Unit Tests
/// @notice Unit tests for the usage function
contract OneTimeUseIdPolicy_usage_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /// @notice Test an unconfigured configId reports pinned = 0, consumed = false
    function test_usage_unconfigured_returnsZeroPinned() external view {
        ConfigId never = ConfigId.wrap(keccak256("never.installed"));

        (uint256 pinned, bool consumed, uint256 deadline) =
            policy.usage(never, multiplexer, account);

        assertEq(pinned, 0);
        assertFalse(consumed);
        assertEq(deadline, NO_DEADLINE);
    }

    /// @notice Test a configured, unburned id reports its pinned value and consumed = false
    function test_usage_configuredUnburned_returnsPinnedId() external view {
        (uint256 pinned, bool consumed, uint256 deadline) = policy.usage(cfgA, multiplexer, account);

        assertEq(pinned, ID_A);
        assertFalse(consumed);
        assertEq(deadline, NO_DEADLINE);
    }

    /// @notice Test a burned id reports consumed = true alongside its pinned value
    function test_usage_burnedId_returnsConsumedTrue() external {
        _consume(ID_A);

        (uint256 pinned, bool consumed, uint256 deadline) = policy.usage(cfgA, multiplexer, account);

        assertEq(pinned, ID_A);
        assertTrue(consumed);
        assertEq(deadline, NO_DEADLINE);
    }

    /// @notice Test a configuration pinned with a deadline reports it back
    function test_usage_withDeadline_returnsTheDeadline() external {
        uint256 expiry = block.timestamp + 1 hours;
        _install(cfgA, ID_A, expiry);

        (uint256 pinned, bool consumed, uint256 deadline) = policy.usage(cfgA, multiplexer, account);

        assertEq(pinned, ID_A);
        assertFalse(consumed);
        assertEq(deadline, expiry, "the pinned deadline is readable");
    }
}
