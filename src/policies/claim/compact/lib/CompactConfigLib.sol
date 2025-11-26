// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

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

Packing format for storage:
┌────────────────────────────────────────────────────────────┐
│  ┌─────────────────────────────────────────────────┐       │
│  │  token (160 bits)    │  lockTag (96 bits)       │       │
│  │  bits [255:96]       │  bits [95:0]             │       │
│  └─────────────────────────────────────────────────┘       │
└────────────────────────────────────────────────────────────┘

//////////////////////////////////////////////////////////////*/
// forgefmt: disable-end

/// @title Compact Config Library
/// @author Rhinestone
/// @notice Compact-specific configuration initialization for tokenIn with lockTag
/// @dev Used alongside BaseConfigLib for the CompactClaimPolicy.
library CompactConfigLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                      TOKEN IN INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry:  [chainId: 32 bytes][token: 20 bytes][lockTag: 12 bytes] = 64 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  Compact TokenIn Config                                │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (64 bytes):                             │    │
    │  │  ┌────────────────────────────────────────┐    │    │
    │  │  │  chainId (32 bytes)                    │    │    │
    │  │  ├────────────────────────────────────────┤    │    │
    │  │  │  token (20 bytes) | lockTag (12 bytes) │    │    │
    │  │  │  ← 32 bytes total →                    │    │    │
    │  │  └────────────────────────────────────────┘    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 32 + (count × 64) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes Compact tokenIn configs and writes directly to storage
    /// @dev Each entry allows a specific token+lockTag combination on a chain.
    ///      Packs token+lockTag into bytes32 and adds to storage set.
    /// @param $ Storage pointer to write tokenIn to
    /// @param initData Calldata starting with tokenIn config
    /// @return remaining Remaining calldata after all tokenIn configs
    function initializeTokenIn(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        // Decode count (32 bytes)
        uint256 count = uint256(bytes32(initData[0:32]));
        // Initialize offset
        uint256 offset = 32;
        // Loop through each entry
        for (uint256 i = 0; i < count; i++) {
            // Decode chainId (32 bytes)
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            // Read packed token+lockTag directly
            bytes32 packed = bytes32(initData[offset + 32:offset + 64]);
            // Add to storage set
            $.tokenInSet[chainId].add(packed);
            // Advance offset
            offset += 64;
        }
        // Return remaining calldata
        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                            PACKING HELPERS
    //////////////////////////////////////////////////////////////

    Token and lockTag are packed into bytes32 for efficient storage:

    ┌────────────────────────────────────────────────────────┐
    │              Pack Operation                            │
    │                                                        │
    │  token (address, 20 bytes) → shift left 96 bits        │
    │  lockTag (bytes12) → cast to uint96                    │
    │  result = (token << 96) | lockTag                      │
    │                                                        │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │  token (160 bits)    │  lockTag (96 bits)       │   │
    │  │  bits [255:96]       │  bits [95:0]             │   │
    │  └─────────────────────────────────────────────────┘   │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Packs token address and lockTag into a bytes32 value
    /// @dev Token occupies higher 160 bits, lockTag occupies lower 96 bits
    /// @param token The token address to pack
    /// @param lockTag The lock tag to pack
    /// @return packed The packed bytes32 value
    function packTokenIn(
        address token,
        bytes12 lockTag
    )
        internal
        pure
        returns (bytes32 packed)
    {
        packed = bytes32((uint256(uint160(token)) << 96) | uint96(lockTag));
    }
}
