// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Calldata Slice Library
/// @author Rhinestone
/// @notice Efficient calldata reading with automatic offset advancement
/// @dev All slice functions return both the value and the new offset,
///      enabling clean sequential reads without manual offset math.
///      Uses assembly for zero-copy calldata access.
library CalldataSliceLib {
    /*//////////////////////////////////////////////////////////////
                            32-BYTE TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Reads a bytes32 value from calldata
    /// @param data The calldata bytes to read from
    /// @param offset The offset to start reading at
    /// @return val The bytes32 value
    /// @return newOffset The offset after the read (offset + 32)
    function sliceBytes32(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 val, uint256 newOffset)
    {
        assembly ("memory-safe") {
            val := calldataload(add(data.offset, offset))
            newOffset := add(offset, 32)
        }
    }

    /// @notice Reads a uint256 value from calldata
    /// @param data The calldata bytes to read from
    /// @param offset The offset to start reading at
    /// @return val The uint256 value
    /// @return newOffset The offset after the read (offset + 32)
    function sliceUint256(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (uint256 val, uint256 newOffset)
    {
        assembly ("memory-safe") {
            val := calldataload(add(data.offset, offset))
            newOffset := add(offset, 32)
        }
    }

    /*//////////////////////////////////////////////////////////////
                            20-BYTE TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Reads an address value from calldata (20 bytes)
    /// @param data The calldata bytes to read from
    /// @param offset The offset to start reading at
    /// @return val The address value
    /// @return newOffset The offset after the read (offset + 20)
    function sliceAddress(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (address val, uint256 newOffset)
    {
        assembly ("memory-safe") {
            val := shr(96, calldataload(add(data.offset, offset)))
            newOffset := add(offset, 20)
        }
    }

    /*//////////////////////////////////////////////////////////////
                            16-BYTE TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Reads a uint128 value from calldata (16 bytes)
    /// @param data The calldata bytes to read from
    /// @param offset The offset to start reading at
    /// @return val The uint128 value
    /// @return newOffset The offset after the read (offset + 16)
    function sliceUint128(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (uint128 val, uint256 newOffset)
    {
        assembly ("memory-safe") {
            val := shr(128, calldataload(add(data.offset, offset)))
            newOffset := add(offset, 16)
        }
    }

    /*//////////////////////////////////////////////////////////////
                            8-BYTE TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Reads a uint64 value from calldata (8 bytes)
    /// @param data The calldata bytes to read from
    /// @param offset The offset to start reading at
    /// @return val The uint64 value
    /// @return newOffset The offset after the read (offset + 8)
    function sliceUint64(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (uint64 val, uint256 newOffset)
    {
        assembly ("memory-safe") {
            val := shr(192, calldataload(add(data.offset, offset)))
            newOffset := add(offset, 8)
        }
    }

    /*//////////////////////////////////////////////////////////////
                            1-BYTE TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Reads a uint8 value from calldata (1 byte)
    /// @param data The calldata bytes to read from
    /// @param offset The offset to start reading at
    /// @return val The uint8 value
    /// @return newOffset The offset after the read (offset + 1)
    function sliceUint8(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (uint8 val, uint256 newOffset)
    {
        assembly ("memory-safe") {
            val := shr(248, calldataload(add(data.offset, offset)))
            newOffset := add(offset, 1)
        }
    }

    /// @notice Reads a bool value from calldata (1 byte)
    /// @dev Any non-zero byte is treated as true
    /// @param data The calldata bytes to read from
    /// @param offset The offset to start reading at
    /// @return val The bool value
    /// @return newOffset The offset after the read (offset + 1)
    function sliceBool(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (bool val, uint256 newOffset)
    {
        assembly ("memory-safe") {
            val := iszero(iszero(shr(248, calldataload(add(data.offset, offset)))))
            newOffset := add(offset, 1)
        }
    }

    /*//////////////////////////////////////////////////////////////
                           ARRAY POINTERS
    //////////////////////////////////////////////////////////////

    These functions create calldata pointers to arrays without copying.
    The caller must ensure the array data is properly formatted.

    ┌────────────────────────────────────────────────────────────┐
    │  Array Layout (for uint256[2][] - token pairs)             │
    │  ┌──────────────────────────────────────────────────────┐  │
    │  │  Entry[0]: [slot0 (32)] [slot1 (32)] = 64 bytes      │  │
    │  │  Entry[1]: [slot0 (32)] [slot1 (32)] = 64 bytes      │  │
    │  │  ... repeat for length entries ...                   │  │
    │  └──────────────────────────────────────────────────────┘  │
    │                                                            │
    │  Note: Length is NOT stored in calldata for our packed     │
    │  format - it's passed separately (already read via         │
    │  sliceUint8). This differs from ABI encoding.              │
    └────────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a calldata pointer to an array of uint256[2] pairs
    /// @dev Used for tokenIn/tokenOut arrays: [id/token, amount] pairs
    ///      Does NOT read length from calldata - length is passed in
    /// @param data The calldata bytes containing the array
    /// @param offset The offset where the array data starts
    /// @param length The number of pairs in the array (read separately)
    /// @return arr Calldata pointer to the array
    /// @return newOffset The offset after the array (offset + length * 64)
    function sliceUint256PairArray(
        bytes calldata data,
        uint256 offset,
        uint256 length
    )
        internal
        pure
        returns (uint256[2][] calldata arr, uint256 newOffset)
    {
        assembly ("memory-safe") {
            arr.offset := add(data.offset, offset)
            arr.length := length
            newOffset := add(offset, mul(length, 64))
        }
    }

    /*//////////////////////////////////////////////////////////////
                           DYNAMIC BYTES
    //////////////////////////////////////////////////////////////

    For reading variable-length byte sequences where the length
    is stored in calldata (as uint256, 32 bytes).

    ┌────────────────────────────────────────────────────────────┐
    │  Dynamic Bytes Layout                                      │
    │  ┌──────────────────────────────────────────────────────┐  │
    │  │  [length: 32 bytes][data: length bytes]              │  │
    │  └──────────────────────────────────────────────────────┘  │
    └────────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Reads a dynamic bytes value with uint256 length prefix
    /// @dev Returns a calldata slice pointing to the data (no copy)
    /// @param data The calldata bytes to read from
    /// @param offset The offset where the length starts
    /// @return val Calldata slice of the bytes data
    /// @return newOffset The offset after length + data
    function sliceBytesWithLength(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (bytes calldata val, uint256 newOffset)
    {
        uint256 length;
        assembly ("memory-safe") {
            length := calldataload(add(data.offset, offset))
        }
        val = data[offset + 32:offset + 32 + length];
        newOffset = offset + 32 + length;
    }

    /// @notice Creates a calldata slice of specified length
    /// @dev Length is passed in, not read from calldata
    /// @param data The calldata bytes to slice from
    /// @param offset The offset where the slice starts
    /// @param length The length of the slice
    /// @return val Calldata slice
    /// @return newOffset The offset after the slice (offset + length)
    function sliceBytes(
        bytes calldata data,
        uint256 offset,
        uint256 length
    )
        internal
        pure
        returns (bytes calldata val, uint256 newOffset)
    {
        val = data[offset:offset + length];
        newOffset = offset + length;
    }
}
