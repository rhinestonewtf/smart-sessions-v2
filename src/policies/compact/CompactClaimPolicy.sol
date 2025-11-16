// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries

// Types

/// @title CompactClaimPolicy
/// @notice A policy that allows enforcing rules on specific fields of a Compact Claim struct:
///     MultiChainCompact:
///     - arbiter: address
///     - expires: uint256
///     >>> Lock[] TokenIn
///         - token: address
///         - lockTag: bytes12
///     >>> Mandate
///         >>> Target
///             - recipient
///             - targetChain
///             - fillExpiry
///             >>> Token[] TokenOut
///         >>> Op originOps
///             - to
///             - data
///             - value
///         >>> Op destOps
///             - to
///             - data
///             - value
///         >>> Qualification (external policy)

