// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Contracts
import { MultiChainClaimPolicy } from "@policies/claim-recipient/MultiChainClaimPolicy.sol";

contract MultiChainClaimRecipient_Unit_Test is SmartSessionEmissary_Unit_Test {
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
