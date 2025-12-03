// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { Permit2ClaimPolicy } from "@policies/claim/permit2/Permit2ClaimPolicy.sol";

contract Permit2ClaimPolicy_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The Permit2ClaimPolicy contract instance.
    Permit2ClaimPolicy internal permit2ClaimPolicy;
    /// @notice Permit2 address used for testing.
    address internal constant PERMIT2_ADDRESS = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /*//////////////////////////////////////////////////////////////
                                   SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Deploy the Permit2ClaimPolicy contract.
        permit2ClaimPolicy = new Permit2ClaimPolicy(PERMIT2_ADDRESS);
    }
}
