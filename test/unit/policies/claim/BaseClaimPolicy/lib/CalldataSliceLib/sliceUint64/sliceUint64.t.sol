// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceUint64 Unit Tests
/// @notice Unit tests for the sliceUint64 function
contract CalldataSliceLib_sliceUint64_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result value from slice operation
    uint64 internal val;

    /// @notice Expected value for assertions
    uint64 internal expected;

    /// @notice Additional values for sequential read tests
    uint64 internal val1;
    uint64 internal val2;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @return The sliced uint64 and new offset
    function sliceUint64External(
        bytes calldata _data,
        uint256 _offset
    )
        external
        pure
        returns (uint64, uint256)
    {
        return _data.sliceUint64(_offset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing zero value
    function test_sliceUint64_withZeroValue() external {
        // Arrange
        expected = 0;
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceUint64External(data, 0);

        // Assert
        assertEq(val, 0);
        assertEq(newOffset, 8);
    }

    /// @notice Test slicing max uint64 value
    function test_sliceUint64_withMaxValue() external {
        // Arrange
        expected = type(uint64).max;
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceUint64External(data, 0);

        // Assert
        assertEq(val, type(uint64).max);
        assertEq(newOffset, 8);
    }

    /// @notice Test slicing value at non-zero offset
    function test_sliceUint64_withValueAtOffset() external {
        // Arrange
        expected = 1_234_567_890;
        data = abi.encodePacked(bytes32(0), expected);

        // Act
        (val, newOffset) = this.sliceUint64External(data, 32);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 40);
    }

    /// @notice Test that trailing data is not included in result
    function test_sliceUint64_withTrailingData() external {
        // Arrange
        expected = 42;
        uint64 trailing = type(uint64).max;
        data = abi.encodePacked(expected, trailing);

        // Act
        (val, newOffset) = this.sliceUint64External(data, 0);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 8);
    }

    /// @notice Fuzz test for sliceUint64 with random values and offsets
    /// @param _expected Random uint64 value to encode and read
    /// @param _prefixLen Random prefix length (0-255)
    function testFuzz_sliceUint64(uint64 _expected, uint8 _prefixLen) external {
        // Arrange
        bytes memory prefix = new bytes(_prefixLen);
        data = abi.encodePacked(prefix, _expected);

        // Act
        (val, newOffset) = this.sliceUint64External(data, _prefixLen);

        // Assert
        assertEq(val, _expected);
        assertEq(newOffset, uint256(_prefixLen) + 8);
    }
}
