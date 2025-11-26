// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
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

    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                      TOKEN IN INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry:  [chainId: 32 bytes][token: 20 bytes] = 52 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  Permit2 TokenIn Config                                │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
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

    Total size: 32 + (count × 52) bytes

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
        // Decode count (32 bytes)
        uint256 count = uint256(bytes32(initData[0:32]));
        // Start offset after count
        uint256 offset = 32;
        // Loop through each entry
        for (uint256 i = 0; i < count; i++) {
            // Decode chainId (32 bytes)
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            // Decode token (20 bytes)
            address token = address(bytes20(initData[offset + 32:offset + 52]));
            // Write directly to storage (left-padded address as bytes32)
            $.tokenInSet[chainId].add(bytes32(bytes20(token)));
            // Advance offset
            offset += 52;
        }
        // Return remaining calldata
        remaining = initData[offset:];
    }
}
