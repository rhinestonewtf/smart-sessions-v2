// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { MultiChainClaimPolicy } from "@policies/claim/MultiChainClaimPolicy.sol";

contract MultiChainClaimPolicy_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The MultiChainClaimPolicy contract instance.
    MultiChainClaimPolicy internal multiChainClaimPolicy;

    /*//////////////////////////////////////////////////////////////
                                   SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Deploy the MultiChainClaimPolicy contract.
        multiChainClaimPolicy = new MultiChainClaimPolicy();
    }
}
