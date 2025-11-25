// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// forgefmt: disable-start
/*//////////////////////////////////////////////////////////////
                         COMPACT PROTOCOL
//////////////////////////////////////////////////////////////

The Compact protocol uses a specific tokenIn format that includes
a lockTag for each token.

TokenIn (Compact) format:
┌────────────────────────────────────────────────────────────┐
│                    Lock[] (TokenIn)                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  token (address) - 20 bytes                          │  │
│  │  lockTag (bytes12) - 12 bytes                        │  │
│  │  ─────────────────────────────                       │  │
│  │  Total: 32 bytes packed per entry                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  Storage: EnumerableSetLib.Bytes32Set                      │
│  Key: packed(token, lockTag) = bytes32                     │
└────────────────────────────────────────────────────────────┘

//////////////////////////////////////////////////////////////*/

/// @notice Storage configuration for Compact tokenIn with lockTag
/// @dev Each entry allows a specific token+lockTag combination on a chain
///
/// Packing format for storage:
/// ┌────────────────────────────────────────────────────────┐
/// │              Packed bytes32 Value                      │
/// │  ┌────────────────────────┬────────────────────────┐   │
/// │  │  token (160 bits)      │  lockTag (96 bits)     │   │
/// │  │  bits [159:0]          │  bits [255:160]        │   │
/// │  └────────────────────────┴────────────────────────┘   │
/// └────────────────────────────────────────────────────────┘
///
/// @param chainId The chain ID (0 for catch-all in MODE_CHECK_CATCHALL)
/// @param token The token address to whitelist
/// @param lockTag The lock tag that must accompany this token
// forgefmt: disable-end
struct CompactTokenInStorageConfig {
    uint256 chainId;
    address token;
    bytes12 lockTag;
}
