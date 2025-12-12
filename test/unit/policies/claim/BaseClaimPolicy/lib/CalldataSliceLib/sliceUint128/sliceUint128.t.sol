// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceUint128 Unit Tests
/// @notice Unit tests for the sliceUint128 function
contract CalldataSliceLib_sliceUint128_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result value from slice operation
    uint128 internal val;

    /// @notice Expected value for assertions
    uint128 internal expected;

    /// @notice Additional values for sequential read tests
    uint128 internal val1;
    uint128 internal val2;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @return The sliced uint128 and new offset
    function sliceUint128External(
        bytes calldata _data,
        uint256 _offset
    )
        external
        pure
        returns (uint128, uint256)
    {
        return _data.sliceUint128(_offset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing zero value
    function test_sliceUint128_withZeroValue() external {
        // Arrange
        expected = 0;
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceUint128External(data, 0);

        // Assert
        assertEq(val, 0);
        assertEq(newOffset, 16);
    }

    /// @notice Test slicing max uint128 value
    function test_sliceUint128_withMaxValue() external {
        // Arrange
        expected = type(uint128).max;
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceUint128External(data, 0);

        // Assert
        assertEq(val, type(uint128).max);
        assertEq(newOffset, 16);
    }

    /// @notice Test slicing value at non-zero offset
    function test_sliceUint128_withValueAtOffset() external {
        // Arrange
        expected = 12_345_678_901_234_567_890;
        data = abi.encodePacked(bytes32(0), expected);

        // Act
        (val, newOffset) = this.sliceUint128External(data, 32);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 48);
    }

    /// @notice Test that trailing data is not included in result
    function test_sliceUint128_withTrailingData() external {
        // Arrange
        expected = 42;
        uint128 trailing = type(uint128).max;
        data = abi.encodePacked(expected, trailing);

        // Act
        (val, newOffset) = this.sliceUint128External(data, 0);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 16);
    }

    /// @notice Fuzz test for sliceUint128 with random values and offsets
    /// @param _expected Random uint128 value to encode and read
    /// @param _prefixLen Random prefix length (0-255)
    function testFuzz_sliceUint128(uint128 _expected, uint8 _prefixLen) external {
        // Arrange
        bytes memory prefix = new bytes(_prefixLen);
        data = abi.encodePacked(prefix, _expected);

        // Act
        (val, newOffset) = this.sliceUint128External(data, _prefixLen);

        // Assert
        assertEq(val, _expected);
        assertEq(newOffset, uint256(_prefixLen) + 16);
    }
}
