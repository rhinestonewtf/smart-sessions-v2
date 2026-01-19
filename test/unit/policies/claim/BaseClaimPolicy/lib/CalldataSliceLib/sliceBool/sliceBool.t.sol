// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceBool Unit Tests
/// @notice Unit tests for the sliceBool function
contract CalldataSliceLib_sliceBool_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result value from slice operation
    bool internal val;

    /// @notice Additional values for sequential read tests
    bool internal val1;
    bool internal val2;
    bool internal val3;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @return The sliced bool and new offset
    function sliceBoolExternal(
        bytes calldata _data,
        uint256 _offset
    )
        external
        pure
        returns (bool, uint256)
    {
        return _data.sliceBool(_offset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing zero byte returns false
    function test_sliceBool_withZeroByte() external {
        // Arrange
        data = abi.encodePacked(uint8(0));

        // Act
        (val, newOffset) = this.sliceBoolExternal(data, 0);

        // Assert
        assertEq(val, false);
        assertEq(newOffset, 1);
    }

    /// @notice Test slicing 0x01 byte returns true
    function test_sliceBool_withOneByte() external {
        // Arrange
        data = abi.encodePacked(uint8(1));

        // Act
        (val, newOffset) = this.sliceBoolExternal(data, 0);

        // Assert
        assertEq(val, true);
        assertEq(newOffset, 1);
    }

    /// @notice Test slicing 0xFF byte returns true
    function test_sliceBool_withNonZeroByte() external {
        // Arrange
        data = abi.encodePacked(uint8(0xFF));

        // Act
        (val, newOffset) = this.sliceBoolExternal(data, 0);

        // Assert
        assertEq(val, true);
        assertEq(newOffset, 1);
    }

    /// @notice Test sequential reads with advancing offset
    function test_sliceBool_withSequentialReads() external {
        // Arrange
        data = abi.encodePacked(uint8(1), uint8(0), uint8(1));

        // Act
        (val1, offset) = this.sliceBoolExternal(data, 0);
        (val2, offset) = this.sliceBoolExternal(data, offset);
        (val3, offset) = this.sliceBoolExternal(data, offset);

        // Assert
        assertEq(val1, true);
        assertEq(val2, false);
        assertEq(val3, true);
        assertEq(offset, 3);
    }

    /// @notice Fuzz test for sliceBool with random values and offsets
    /// @param _value Random uint8 value (will be converted to bool)
    /// @param _prefixLen Random prefix length (0-255)
    function testFuzz_sliceBool(uint8 _value, uint8 _prefixLen) external {
        // Arrange
        bytes memory prefix = new bytes(_prefixLen);
        data = abi.encodePacked(prefix, _value);

        // Act
        (val, newOffset) = this.sliceBoolExternal(data, _prefixLen);

        // Assert
        assertEq(val, _value != 0);
        assertEq(newOffset, uint256(_prefixLen) + 1);
    }
}
