// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Periodic Limit Policy interface
/// @author Rhinestone
/// @notice Types, errors, events and views for the per-period use and amount limit
interface IPeriodicLimitPolicy {
    /// @notice How a period's window is placed in time
    /// @dev `Fixed`: windows are back-to-back from `start`; the window holding `block.timestamp`
    ///      is `[start + k * period, start + (k + 1) * period)`. A late use does not move the
    ///      next window.
    ///      `FromFirstUse`: a window opens at the first use at or after the previous window's end
    ///      and lasts `period`. With `maxUses == 1`, two uses are always at least `period` apart.
    enum PeriodMode {
        Fixed,
        FromFirstUse
    }

    /// @notice A configuration, set at install and read on every check
    /// @param chainId The only chain the limit admits uses on. One multichain enable installs the
    ///        configuration everywhere, but counters are per chain, so pinning one chain keeps
    ///        one signed allowance from becoming one per chain.
    /// @param mode How windows are placed
    /// @param period Window length in seconds; never zero
    /// @param start No use is admitted before it. `Fixed` windows are aligned to it, so it must be
    ///        set explicitly there: a default resolved at install would move on every re-enable.
    ///        Zero means no lower bound (`FromFirstUse` only).
    /// @param maxUses Uses admitted per window; zero means no use limit
    /// @param token The only token an amount-limited action may move; zero iff `maxAmount` is zero
    /// @param maxAmount Token amount admitted per window; zero means no amount limit
    struct PeriodicLimitConfig {
        uint64 chainId;
        PeriodMode mode;
        uint48 period;
        uint48 start;
        uint32 maxUses;
        address token;
        uint256 maxAmount;
    }

    /// @notice What the current window has used
    /// @param windowStart Start of the window the counts belong to; zero if never used
    /// @param uses Uses admitted in that window
    /// @param spent Token amount admitted in that window
    struct PeriodicUsage {
        uint48 windowStart;
        uint208 uses;
        uint256 spent;
    }

    /// @notice Thrown when init data is not one ABI-encoded `PeriodicLimitConfig`
    error InvalidInitDataLength(uint256 length);

    /// @notice Thrown when the period is zero
    error InvalidPeriod();

    /// @notice Thrown when a `Fixed` configuration has no `start`
    error InvalidStart();

    /// @notice Thrown when the chain id is zero
    error InvalidChainId();

    /// @notice Thrown when neither a use limit nor an amount limit is set
    error NoLimitSet();

    /// @notice Thrown when `token` is set without `maxAmount`, or `maxAmount` without `token`
    error InvalidToken(address token, uint256 maxAmount);

    /// @notice Emitted when a use is admitted
    event PeriodicLimitUsed(
        ConfigId indexed configId,
        address indexed multiplexer,
        address indexed account,
        uint48 windowStart,
        uint256 uses,
        uint256 spent
    );

    /// @notice The installed configuration; `period == 0` means not installed
    function getConfig(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        returns (PeriodicLimitConfig memory);

    /// @notice The usage of the window that holds `block.timestamp`: zero counts if no use was
    ///         admitted in it yet
    /// @dev All zero when the configuration is not installed, is pinned to another chain, or
    ///      `start` has not been reached.
    /// @return windowStart Start of that window, or zero for a `FromFirstUse` window that has not
    ///         opened yet
    /// @return uses Uses admitted in that window
    /// @return spent Token amount admitted in that window
    function currentUsage(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint48 windowStart, uint256 uses, uint256 spent);
}
