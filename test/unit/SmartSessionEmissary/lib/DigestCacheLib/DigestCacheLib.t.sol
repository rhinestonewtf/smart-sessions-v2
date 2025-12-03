// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Libraries
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

contract DigestCacheLib_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using DigestCacheLib for *;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Test accounts
    address internal account1;
    address internal account2;

    /// @notice Test digests
    bytes32 internal digest1;
    bytes32 internal digest2;
    bytes32 internal digest3;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function
        super.setUp();

        // Setup test accounts
        account1 = makeAddr("account1");
        account2 = makeAddr("account2");

        // Setup test digests
        digest1 = keccak256("digest1");
        digest2 = keccak256("digest2");
        digest3 = keccak256("digest3");

        // Label addresses for better trace output
        vm.label(account1, "Account1");
        vm.label(account2, "Account2");
    }
}
