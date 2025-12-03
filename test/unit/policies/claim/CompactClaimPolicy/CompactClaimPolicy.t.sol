// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { CompactClaimPolicy } from "@policies/claim/compact/CompactClaimPolicy.sol";

contract CompactClaimPolicy_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The CompactClaimPolicy contract instance.
    CompactClaimPolicy internal compactClaimPolicy;

    /*//////////////////////////////////////////////////////////////
                                   SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Deploy the CompactClaimPolicy contract.
        compactClaimPolicy = new CompactClaimPolicy();
    }
}
