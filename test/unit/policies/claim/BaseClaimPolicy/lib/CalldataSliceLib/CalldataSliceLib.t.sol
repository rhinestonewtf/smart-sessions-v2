// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Libraries
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

/// @title CalldataSliceLib Unit Test Base
/// @notice Base contract for CalldataSliceLib unit tests
/// @dev Provides common state variables used across all slice function tests
contract CalldataSliceLib_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Calldata buffer for test inputs
    bytes internal data;

    /// @notice Current offset position in calldata
    uint256 internal offset;

    /// @notice New offset returned after slice operation
    uint256 internal newOffset;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
    }
}
