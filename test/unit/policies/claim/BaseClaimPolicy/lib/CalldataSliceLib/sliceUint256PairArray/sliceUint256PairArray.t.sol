// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { CalldataSliceLib_Unit_Test } from "../CalldataSliceLib.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib.sliceUint256PairArray Unit Tests
/// @notice Unit tests for the sliceUint256PairArray function
contract CalldataSliceLib_sliceUint256PairArray_Unit_Test is CalldataSliceLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result array from slice operation
    uint256[2][] internal arr;

    /// @notice Result offset from slice operation
    uint256 internal resultOffset;

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to convert memory to calldata and return as memory
    /// @param _data The data to slice from
    /// @param _offset The offset to start at
    /// @param _length The number of pairs in the array
    /// @return The sliced array (as memory) and new offset
    function sliceUint256PairArrayExternal(
        bytes calldata _data,
        uint256 _offset,
        uint256 _length
    )
        external
        pure
        returns (uint256[2][] memory, uint256)
    {
        (uint256[2][] calldata slice, uint256 newOffset) =
            _data.sliceUint256PairArray(_offset, _length);

        // Copy calldata to memory for return
        uint256[2][] memory result = new uint256[2][](_length);
        for (uint256 i = 0; i < _length; i++) {
            result[i][0] = slice[i][0];
            result[i][1] = slice[i][1];
        }

        return (result, newOffset);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test slicing empty array
    function test_sliceUint256PairArray_withEmptyArray() external {
        // Arrange
        data = new bytes(0);

        // Act
        (arr, resultOffset) = this.sliceUint256PairArrayExternal(data, 0, 0);

        // Assert
        assertEq(arr.length, 0);
        assertEq(resultOffset, 0);
    }

    /// @notice Test slicing single pair
    function test_sliceUint256PairArray_withSinglePair() external {
        // Arrange
        uint256 token = 111;
        uint256 amount = 222;
        data = abi.encodePacked(token, amount);

        // Act
        (arr, resultOffset) = this.sliceUint256PairArrayExternal(data, 0, 1);

        // Assert
        assertEq(arr.length, 1);
        assertEq(arr[0][0], token);
        assertEq(arr[0][1], amount);
        assertEq(resultOffset, 64);
    }

    /// @notice Test slicing multiple pairs
    function test_sliceUint256PairArray_withMultiplePairs() external {
        // Arrange
        uint256 token1 = 111;
        uint256 amount1 = 222;
        uint256 token2 = 333;
        uint256 amount2 = 444;
        uint256 token3 = 555;
        uint256 amount3 = 666;
        data = abi.encodePacked(token1, amount1, token2, amount2, token3, amount3);

        // Act
        (arr, resultOffset) = this.sliceUint256PairArrayExternal(data, 0, 3);

        // Assert
        assertEq(arr.length, 3);
        assertEq(arr[0][0], token1);
        assertEq(arr[0][1], amount1);
        assertEq(arr[1][0], token2);
        assertEq(arr[1][1], amount2);
        assertEq(arr[2][0], token3);
        assertEq(arr[2][1], amount3);
        assertEq(resultOffset, 192);
    }

    /// @notice Test slicing array at non-zero offset
    function test_sliceUint256PairArray_withArrayAtOffset() external {
        // Arrange
        uint256 token = 111;
        uint256 amount = 222;
        data = abi.encodePacked(bytes32(0), token, amount);

        // Act
        (arr, resultOffset) = this.sliceUint256PairArrayExternal(data, 32, 1);

        // Assert
        assertEq(arr.length, 1);
        assertEq(arr[0][0], token);
        assertEq(arr[0][1], amount);
        assertEq(resultOffset, 96);
    }

    /// @notice Fuzz test for sliceUint256PairArray
    /// @param _token1 First token value
    /// @param _amount1 First amount value
    /// @param _token2 Second token value
    /// @param _amount2 Second amount value
    function testFuzz_sliceUint256PairArray(
        uint256 _token1,
        uint256 _amount1,
        uint256 _token2,
        uint256 _amount2
    )
        external
    {
        // Arrange
        data = abi.encodePacked(_token1, _amount1, _token2, _amount2);

        // Act
        (arr, resultOffset) = this.sliceUint256PairArrayExternal(data, 0, 2);

        // Assert
        assertEq(arr.length, 2);
        assertEq(arr[0][0], _token1);
        assertEq(arr[0][1], _amount1);
        assertEq(arr[1][0], _token2);
        assertEq(arr[1][1], _amount2);
        assertEq(resultOffset, 128);
    }
}
