// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceUint256 Unit Tests
/// @notice Unit tests for the sliceUint256 function
contract CalldataSliceLib_sliceUint256_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result value from slice operation
    uint256 internal val;

    /// @notice Expected value for assertions
    uint256 internal expected;

    /// @notice Additional values for sequential read tests
    uint256 internal val1;
    uint256 internal val2;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @return The sliced uint256 and new offset
    function sliceUint256External(
        bytes calldata _data,
        uint256 _offset
    )
        external
        pure
        returns (uint256, uint256)
    {
        return _data.sliceUint256(_offset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing zero value
    function test_sliceUint256_withZeroValue() external {
        // Arrange
        expected = 0;
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceUint256External(data, 0);

        // Assert
        assertEq(val, 0);
        assertEq(newOffset, 32);
    }

    /// @notice Test slicing max uint256 value
    function test_sliceUint256_withMaxValue() external {
        // Arrange
        expected = type(uint256).max;
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceUint256External(data, 0);

        // Assert
        assertEq(val, type(uint256).max);
        assertEq(newOffset, 32);
    }

    /// @notice Test slicing value at non-zero offset
    function test_sliceUint256_withValueAtOffset() external {
        // Arrange
        expected = 12_345_678_901_234_567_890;
        data = abi.encodePacked(bytes32(0), expected);

        // Act
        (val, newOffset) = this.sliceUint256External(data, 32);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 64);
    }

    /// @notice Test sequential reads with advancing offset
    function test_sliceUint256_withSequentialReads() external {
        // Arrange
        uint256 first = 111;
        uint256 second = 222;
        data = abi.encodePacked(first, second);

        // Act
        (val1, offset) = this.sliceUint256External(data, 0);
        (val2, offset) = this.sliceUint256External(data, offset);

        // Assert
        assertEq(val1, first);
        assertEq(val2, second);
        assertEq(offset, 64);
    }

    /// @notice Fuzz test for sliceUint256 with random values and offsets
    /// @param _expected Random uint256 value to encode and read
    /// @param _prefixLen Random prefix length (0-255)
    function testFuzz_sliceUint256(uint256 _expected, uint8 _prefixLen) external {
        // Arrange
        bytes memory prefix = new bytes(_prefixLen);
        data = abi.encodePacked(prefix, _expected);

        // Act
        (val, newOffset) = this.sliceUint256External(data, _prefixLen);

        // Assert
        assertEq(val, _expected);
        assertEq(newOffset, uint256(_prefixLen) + 32);
    }
}
