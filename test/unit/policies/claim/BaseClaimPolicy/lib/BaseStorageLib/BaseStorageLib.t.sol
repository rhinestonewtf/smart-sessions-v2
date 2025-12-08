// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Libraries
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { PolicyConfig } from "@policies/claim/base/types/BaseDataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseStorageLib Unit Tests Base
/// @notice Base contract for BaseStorageLib unit tests
abstract contract BaseStorageLib_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                  STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test configIds
    ConfigId internal configId1;
    ConfigId internal configId2;

    /// @notice Test accounts
    address internal account1;
    address internal account2;

    /// @notice Expected STORAGE_POSITION = keccak256("rhinestone.storage.BaseClaimPolicy") - 1
    bytes32 internal constant EXPECTED_STORAGE_POSITION =
        0xd29377fc0db06555c0d0684662ad4cb507472ae21c689f22e192cb1a507e2989;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Setup test configIds
        configId1 = ConfigId.wrap(bytes32(uint256(1)));
        configId2 = ConfigId.wrap(bytes32(uint256(2)));

        // Setup test accounts
        account1 = makeAddr("account1");
        account2 = makeAddr("account2");
    }
}
