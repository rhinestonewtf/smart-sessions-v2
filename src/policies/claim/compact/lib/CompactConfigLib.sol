// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// forgefmt: disable-start
/*//////////////////////////////////////////////////////////////
                         COMPACT PROTOCOL
//////////////////////////////////////////////////////////////

The Compact protocol uses resource lock IDs that pack token and lockTag.

Resource Lock ID format (from IdLib):
┌────────────────────────────────────────────────────────────┐
│                    Lock ID (uint256)                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  lockTag (bytes12) - 96 bits (high)                  │  │
│  │  token (address) - 160 bits (low)                    │  │
│  │  ─────────────────────────────                       │  │
│  │  id = lockTag.asUint256() | token.asUint256()        │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  Storage: EnumerableSetLib.Bytes32Set per chainId          │
│  Key: bytes32(id) - stored directly, no conversion needed  │
└────────────────────────────────────────────────────────────┘

Packing format (matches Compact IdLib):
┌────────────────────────────────────────────────────────────┐
│  ┌─────────────────────────────────────────────────────┐   │
│  │  lockTag (96 bits)   │  token (160 bits)            │   │
│  │  bits [255:160]      │  bits [159:0]                │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘

//////////////////////////////////////////////////////////////*/
// forgefmt: disable-end

/// @title Compact Config Library
/// @author Rhinestone
/// @notice Compact-specific configuration initialization for tokenIn with lockTag
/// @dev Used alongside BaseConfigLib for the CompactClaimPolicy.
///      Storage format matches Compact's IdLib for zero-conversion validation.
library CompactConfigLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                      TOKEN IN INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry:  [chainId: 32 bytes][id: 32 bytes] = 64 bytes each

    The id is a Compact resource lock ID: [lockTag (96 high) | token (160 low)]

    ┌────────────────────────────────────────────────────────┐
    │  Compact TokenIn Config                                │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                        │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (64 bytes):                             │    │
    │  │  ┌────────────────────────────────────────┐    │    │
    │  │  │  chainId (32 bytes)                    │    │    │
    │  │  ├────────────────────────────────────────┤    │    │
    │  │  │  id (32 bytes)                         │    │    │
    │  │  │  [lockTag (12) | token (20)]           │    │    │
    │  │  └────────────────────────────────────────┘    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 1 + (count × 64) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes Compact tokenIn configs and writes directly to storage
    /// @dev Each entry allows a specific token+lockTag combination on a chain.
    ///      Stores the Compact ID directly - no packing conversion needed.
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
        // Decode count (1 bytes)
        uint8 count = uint8(initData[0]);
        // Initialize offset
        uint256 offset = 1;
        // Loop through each entry
        for (uint8 i = 0; i < count; i++) {
            // Decode chainId (32 bytes)
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            // Read Compact ID directly - [lockTag (96 high) | token (160 low)]
            bytes32 id = bytes32(initData[offset + 32:offset + 64]);
            // Add to storage set
            $.tokenInSet[chainId].add(id);
            // Advance offset
            offset += 64;
        }
        // Return remaining calldata
        remaining = initData[offset:];
    }
}
