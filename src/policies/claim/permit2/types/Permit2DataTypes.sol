// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/*//////////////////////////////////////////////////////////////
                         PERMIT2 PROTOCOL
//////////////////////////////////////////////////////////////

The Permit2 protocol uses TokenPermissions for tokenIn, which
does NOT include a lockTag (unlike Compact's Lock struct).

TokenIn (Permit2) format:
┌────────────────────────────────────────────────────────────┐
│              TokenPermissions[] (TokenIn)                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  token (address) - 20 bytes                          │  │
│  │  amount (uint256) - 32 bytes                         │  │
│  │  ─────────────────────────────                       │  │
│  │  NO lockTag - this is the key difference from Compact│  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  Storage: EnumerableSetLib.AddressSet                      │
│  Key: token address                                        │
└────────────────────────────────────────────────────────────┘

//////////////////////////////////////////////////////////////*/

/// @notice Storage configuration for Permit2 tokenIn (no lockTag)
/// @dev Simpler than Compact - just token address per chain
///
/// @param chainId The chain ID (0 for catch-all in MODE_CHECK_CATCHALL)
/// @param token The token address to whitelist
struct Permit2TokenInStorageConfig {
    uint256 chainId;
    address token;
}
