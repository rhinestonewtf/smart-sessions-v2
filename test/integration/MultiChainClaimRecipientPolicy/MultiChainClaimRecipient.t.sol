// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Contracts
import { MultiChainClaimRecipientPolicy } from "@mocks/MultiChainClaimRecipientPolicy.sol";

contract MultiChainClaimRecipient_Unit_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The MultiChainClaimRecipientPolicy contract instance.
    MultiChainClaimRecipientPolicy internal multiChainClaimRecipient;

    /*//////////////////////////////////////////////////////////////
                                   SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Deploy the MultiChainClaimRecipientPolicy contract.
        multiChainClaimRecipient = new MultiChainClaimRecipientPolicy();
    }
}
