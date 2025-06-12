// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

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

/// @notice Configuration for the basic Emissary.
/// @dev This configuration is used to set up the Emissary with a specific allocator,
///      a scope, a reset period, and a stateless validator.
struct EmissaryConfig {
    uint8 configId;
    address allocator;
    Scope scope;
    ResetPeriod resetPeriod;
    IStatelessValidator validator;
    bytes validatorConfig;
}

/// @notice Data structure for enabling an Emissary.
/// @dev This structure contains the signatures, expiration time, nonce, and chain IDs
///      for enabling an Emissary on a specific chain.
struct EmissaryEnable {
    bytes allocatorSig;
    bytes userSig;
    uint256 expires;
    uint256 nonce;
    uint256[] allChainIds;
    uint256 chainIndex;
}
