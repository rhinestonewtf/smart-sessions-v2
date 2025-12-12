// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceBytesWithLength Unit Tests
/// @notice Unit tests for the sliceBytesWithLength function
contract CalldataSliceLib_sliceBytesWithLength_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result bytes from slice operation
    bytes internal result;

    /// @notice Result offset from slice operation
    uint256 internal resultOffset;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata and return as memory
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @return The sliced bytes (as memory) and new offset
    function sliceBytesWithLengthExternal(
        bytes calldata _data,
        uint256 _offset
    )
        external
        pure
        returns (bytes memory, uint256)
    {
        (bytes calldata slice, uint256 newOffset) = _data.sliceBytesWithLength(_offset);
        return (slice, newOffset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing with zero length
    function test_sliceBytesWithLength_withZeroLength() external {
        // Arrange
        uint256 length = 0;
        data = abi.encodePacked(length);

        // Act
        (result, resultOffset) = this.sliceBytesWithLengthExternal(data, 0);

        // Assert
        assertEq(result.length, 0);
        assertEq(resultOffset, 32);
    }

    /// @notice Test slicing with non-zero length
    function test_sliceBytesWithLength_withNonZeroLength() external {
        // Arrange
        bytes memory content = hex"deadbeef";
        uint256 length = content.length;
        data = abi.encodePacked(length, content);

        // Act
        (result, resultOffset) = this.sliceBytesWithLengthExternal(data, 0);

        // Assert
        assertEq(result.length, 4);
        assertEq(keccak256(result), keccak256(content));
        assertEq(resultOffset, 36);
    }

    /// @notice Test slicing at non-zero offset
    function test_sliceBytesWithLength_withBytesAtOffset() external {
        // Arrange
        bytes memory content = hex"cafebabe";
        uint256 length = content.length;
        data = abi.encodePacked(bytes32(0), length, content);

        // Act
        (result, resultOffset) = this.sliceBytesWithLengthExternal(data, 32);

        // Assert
        assertEq(result.length, 4);
        assertEq(keccak256(result), keccak256(content));
        assertEq(resultOffset, 68);
    }

    /// @notice Test slicing longer bytes
    function test_sliceBytesWithLength_withLongerBytes() external {
        // Arrange
        bytes memory content = hex"0102030405060708091011121314151617181920";
        uint256 length = content.length;
        data = abi.encodePacked(length, content);

        // Act
        (result, resultOffset) = this.sliceBytesWithLengthExternal(data, 0);

        // Assert
        assertEq(result.length, 20);
        assertEq(keccak256(result), keccak256(content));
        assertEq(resultOffset, 52);
    }

    /// @notice Fuzz test for sliceBytesWithLength
    /// @param _content Random bytes content (bounded to reasonable size)
    function testFuzz_sliceBytesWithLength(bytes calldata _content) external {
        // Bound content length to avoid massive allocations
        vm.assume(_content.length <= 1000);

        // Arrange
        uint256 length = _content.length;
        data = abi.encodePacked(length, _content);

        // Act
        (result, resultOffset) = this.sliceBytesWithLengthExternal(data, 0);

        // Assert
        assertEq(result.length, _content.length);
        assertEq(keccak256(result), keccak256(_content));
        assertEq(resultOffset, 32 + _content.length);
    }
}
