// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { Session } from "@smartsessions/DataTypes.sol";
import { ResetPeriod, Scope } from "@compact-utils/interfaces/IEmissary.sol";

/// @notice Configuration for the Smart Session Emissary.
/// @dev This configuration is used to set up the Smart Session Emissary with multiple sessions,
///      a scope, a reset period, and an allocator address.
struct SmartSessionEmissaryConfig {
    Session[] sessions;
    Scope scope;
    ResetPeriod resetPeriod;
    address allocator;
}
