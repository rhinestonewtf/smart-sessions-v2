// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Libraries
import { BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// forgefmt: disable-start
/*//////////////////////////////////////////////////////////////
                         PERMIT2 PROTOCOL
//////////////////////////////////////////////////////////////

The Permit2 protocol uses TokenPermissions for tokenIn.

TokenIn (Permit2) format:
┌────────────────────────────────────────────────────────────┐
│              TokenPermissions[] (TokenIn)                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  token (address) - 20 bytes                          │  │
│  │  amount (uint256) - 32 bytes                         │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  Storage: EnumerableSetLib.Bytes32Set per chainId          │
│  Key: bytes32(bytes20(token)) - left-padded address        │
└────────────────────────────────────────────────────────────┘

//////////////////////////////////////////////////////////////*/
// forgefmt: disable-end

/// @title Permit2 Config Library
/// @author Rhinestone
/// @notice Permit2-specific configuration initialization for tokenIn
/// @dev Used alongside BaseConfigLib for the Permit2ClaimPolicy.
library Permit2ConfigLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                      TOKEN IN INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry:  [chainId: 32 bytes][token: 20 bytes] = 52 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  Permit2 TokenIn Config                                │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                        │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (52 bytes):                             │    │
    │  │  ┌────────────────────────────────────────┐    │    │
    │  │  │  chainId (32 bytes)                    │    │    │
    │  │  ├────────────────────────────────────────┤    │    │
    │  │  │  token (20 bytes)                      │    │    │
    │  │  └────────────────────────────────────────┘    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 1 + (count × 52) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes Permit2 tokenIn configs and writes directly to storage
    /// @dev Each entry allows a specific token on a chain.
    ///      Stores as bytes32(bytes20(token)) for set compatibility.
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
        // Slice out count and initialize offset
        (uint8 count, uint256 offset) = initData.sliceUint8(0);

        // Loop through each entry
        for (uint8 i = 0; i < count; i++) {
            // Slice out chainId and token
            uint256 chainId;
            address token;
            (chainId, offset) = initData.sliceUint256(offset);
            (token, offset) = initData.sliceAddress(offset);
            // Write directly to storage (left-padded address as bytes32)
            $.tokenInSet[chainId].add(bytes32(bytes20(token)));
        }
        // Return remaining calldata
        remaining = initData[offset:];
    }
}
