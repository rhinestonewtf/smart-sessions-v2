// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/*//////////////////////////////////////////////////////////////
                         PERMIT2 PROTOCOL
//////////////////////////////////////////////////////////////

The Permit2 protocol uses TokenPermissions for tokenIn

TokenIn (Permit2) format:
┌────────────────────────────────────────────────────────────┐
│              TokenPermissions[] (TokenIn)                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  token (address) - 20 bytes                          │  │
│  │  amount (uint256) - 32 bytes                         │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  Storage: EnumerableSetLib.Bytes32Set                      │
│  Key: bytes32(bytes20(token address))                      │
└────────────────────────────────────────────────────────────┘

//////////////////////////////////////////////////////////////*/

/// @notice Storage configuration for Permit2 tokenIn (no lockTag)
///
/// @param chainId The chain ID (0 for catch-all in MODE_CHECK_CATCHALL)
/// @param token The token address to whitelist
struct Permit2TokenInStorageConfig {
    uint256 chainId;
    address token;
}
