// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Libraries
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";

/// @title SmartSessionLens Unit Test Base
/// @notice Base contract for SmartSessionLens unit tests
/// @dev Inherits from SmartSessionEmissary_Unit_Test to reuse setup and helpers
contract SmartSessionLens_Unit_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes12 constant TEST_LOCK_TAG = bytes12(keccak256("testLockTag"));
    bytes12 constant TEST_LOCK_TAG_2 = bytes12(keccak256("testLockTag2"));

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        // Deploy account for lens tests
        instance.deployAccount();
    }
}
