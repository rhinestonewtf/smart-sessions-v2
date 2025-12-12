// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceBytes32 Unit Tests
/// @notice Unit tests for the sliceBytes32 function
contract CalldataSliceLib_sliceBytes32_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result value from slice operation
    bytes32 internal val;

    /// @notice Expected value for assertions
    bytes32 internal expected;

    /// @notice Additional values for sequential read tests
    bytes32 internal val1;
    bytes32 internal val2;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @return The sliced bytes32 and new offset
    function sliceBytes32External(
        bytes calldata _data,
        uint256 _offset
    )
        external
        pure
        returns (bytes32, uint256)
    {
        return _data.sliceBytes32(_offset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing bytes32 at start of data
    function test_sliceBytes32_withValidBytes32AtStart() external {
        // Arrange
        expected = keccak256("test");
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceBytes32External(data, 0);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 32);
    }

    /// @notice Test slicing bytes32 at non-zero offset
    function test_sliceBytes32_withBytes32AtOffset() external {
        // Arrange
        expected = keccak256("second");
        data = abi.encodePacked(bytes32(0), expected);

        // Act
        (val, newOffset) = this.sliceBytes32External(data, 32);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 64);
    }

    /// @notice Test slicing max bytes32 value
    function test_sliceBytes32_withMaxValue() external {
        // Arrange
        expected = bytes32(type(uint256).max);
        data = abi.encodePacked(expected);

        // Act
        (val, newOffset) = this.sliceBytes32External(data, 0);

        // Assert
        assertEq(val, expected);
        assertEq(newOffset, 32);
    }

    /// @notice Test sequential reads with advancing offset
    function test_sliceBytes32_withSequentialReads() external {
        // Arrange
        bytes32 first = keccak256("first");
        bytes32 second = keccak256("second");
        data = abi.encodePacked(first, second);

        // Act
        (val1, offset) = this.sliceBytes32External(data, 0);
        (val2, offset) = this.sliceBytes32External(data, offset);

        // Assert
        assertEq(val1, first);
        assertEq(val2, second);
        assertEq(offset, 64);
    }

    /// @notice Fuzz test for sliceBytes32 with random values and offsets
    /// @param _expected Random bytes32 value to encode and read
    /// @param _prefixLen Random prefix length (0-255)
    function testFuzz_sliceBytes32(bytes32 _expected, uint8 _prefixLen) external {
        // Arrange
        bytes memory prefix = new bytes(_prefixLen);
        data = abi.encodePacked(prefix, _expected);

        // Act
        (val, newOffset) = this.sliceBytes32External(data, _prefixLen);

        // Assert
        assertEq(val, _expected);
        assertEq(newOffset, uint256(_prefixLen) + 32);
    }
}
