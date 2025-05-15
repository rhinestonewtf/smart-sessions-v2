// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { SmartSessionEmissary } from "@contracts/SmartSessionEmissary.sol";

contract SmartSessionEmissary_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The SmartSessionEmissary contract instance.
    SmartSessionEmissary internal smartSessionEmissary;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();
        // Deploy the SmartSessionEmissary contract.
        smartSessionEmissary = new SmartSessionEmissary(admin.addr);
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/
}
