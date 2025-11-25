// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { CompactTokenInStorageConfig } from "@policies/claim/compact/types/CompactDataTypes.sol";

/// @title Compact Config Library
/// @author Rhinestone
/// @notice Compact-specific configuration decoding for tokenIn with lockTag
/// @dev Used alongside BaseConfigLib for the CompactClaimPolicy
library CompactConfigLib {
    /*//////////////////////////////////////////////////////////////
                      TOKEN IN CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Compact tokenIn includes a lockTag for each token entry.

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

    Total size: 32 + (count * 64) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes Compact tokenIn configurations with lockTag
    /// @dev Each entry allows a specific token+lockTag combination on a chain
    /// @param initData Calldata starting with tokenIn config
    /// @return configs Array of CompactTokenInStorageConfig structs
    /// @return remaining Remaining calldata after all tokenIn configs
    function decodeTokenInConfig(bytes calldata initData)
        internal
        pure
        returns (CompactTokenInStorageConfig[] memory configs, bytes calldata remaining)
    {
        // Read count
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new CompactTokenInStorageConfig[](count);

        // Iterate over each tokenIn entry
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 64;

            // Decode chainId (32 bytes)
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));

            // Decode token address (20 bytes)
            address token = address(bytes20(initData[offset + 32:offset + 52]));

            // Decode lockTag (12 bytes)
            bytes12 lockTag = bytes12(initData[offset + 52:offset + 64]);

            configs[i] = CompactTokenInStorageConfig(chainId, token, lockTag);
        }
        remaining = initData[32 + count * 64:];
    }

    /// @notice Calculates the byte size of tokenIn config in initData
    /// @dev Useful when BaseConfigLib needs to know how many bytes to skip
    /// @param initData Calldata starting with tokenIn config
    /// @return size Total bytes occupied by the tokenIn config
    function getTokenInConfigSize(bytes calldata initData) internal pure returns (uint256 size) {
        uint256 count = uint256(bytes32(initData[0:32]));
        size = 32 + count * 64;
    }

    /*//////////////////////////////////////////////////////////////
                          PACKING HELPERS
    //////////////////////////////////////////////////////////////

    Token and lockTag are packed into bytes32 for efficient storage:

    ┌────────────────────────────────────────────────────────┐
    │              Pack Operation                             │
    │                                                         │
    │  token (address, 20 bytes) → cast to uint160           │
    │  lockTag (bytes12) → shift left 160 bits               │
    │  result = token | (lockTag << 160)                     │
    │                                                         │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │ lockTag (96 bits) │  token (160 bits)           │   │
    │  │ bits [255:160]    │  bits [159:0]               │   │
    │  └─────────────────────────────────────────────────┘   │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Packs token address and lockTag into a bytes32 value
    /// @dev Token occupies lower 160 bits, lockTag occupies upper 96 bits
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
        // Token in lower 160 bits, lockTag in upper 96 bits
        packed = bytes32(uint256(uint160(token))) | (bytes32(lockTag) >> 160);
    }

    /// @notice Unpacks a bytes32 value into token address and lockTag
    /// @dev Inverse of packTokenIn
    /// @param packed The packed bytes32 value
    /// @return token The unpacked token address
    /// @return lockTag The unpacked lock tag
    function unpackTokenIn(bytes32 packed) internal pure returns (address token, bytes12 lockTag) {
        token = address(uint160(uint256(packed)));
        lockTag = bytes12(packed << 160);
    }
}
