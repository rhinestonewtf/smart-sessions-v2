// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceUint8 Unit Tests
/// @notice Unit tests for the sliceUint8 function
contract CalldataSliceLib_sliceUint8_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result value from slice operation
    uint8 internal val;

    /// @notice Expected value for assertions
    uint8 internal expected;

    /// @notice Additional values for sequential read tests
    uint8 internal val1;
    uint8 internal val2;
    uint8 internal val3;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @return The sliced uint8 and new offset
    function sliceUint8External(
        bytes calldata _data,
        uint256 _offset
    )
        external
        pure
        returns (uint8, uint256)
    {
        return _data.sliceUint8(_offset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing zero value
    function test_sliceUint8_withZeroValue() external {
        // Arrange
        expected = 0;
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceUint8External(data, 0);

        // Assert
        assertEq(val, 0);
        assertEq(newOffset, 1);
    }

    /// @notice Test slicing max uint8 value (255)
    function test_sliceUint8_withMaxValue() external {
        // Arrange
        expected = 255;
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceUint8External(data, 0);

        // Assert
        assertEq(val, 255);
        assertEq(newOffset, 1);
    }

    /// @notice Test slicing value at non-zero offset
    function test_sliceUint8_withValueInMiddle() external {
        // Arrange
        expected = 42;
        data = abi.encodePacked(bytes32(0), expected);

        // Act
        (val, newOffset) = this.sliceUint8External(data, 32);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 33);
    }

    /// @notice Test sequential reads with advancing offset
    function test_sliceUint8_withSequentialReads() external {
        // Arrange
        data = abi.encodePacked(uint8(10), uint8(20), uint8(30));

        // Act
        (val1, offset) = this.sliceUint8External(data, 0);
        (val2, offset) = this.sliceUint8External(data, offset);
        (val3, offset) = this.sliceUint8External(data, offset);

        // Assert
        assertEq(val1, 10);
        assertEq(val2, 20);
        assertEq(val3, 30);
        assertEq(offset, 3);
    }

    /// @notice Fuzz test for sliceUint8 with random values and offsets
    /// @param _expected Random uint8 value to encode and read
    /// @param _prefixLen Random prefix length (0-255)
    function testFuzz_sliceUint8(uint8 _expected, uint8 _prefixLen) external {
        // Arrange
        bytes memory prefix = new bytes(_prefixLen);
        data = abi.encodePacked(prefix, _expected);

        // Act
        (val, newOffset) = this.sliceUint8External(data, _prefixLen);

        // Assert
        assertEq(val, _expected);
        assertEq(newOffset, uint256(_prefixLen) + 1);
    }
}
