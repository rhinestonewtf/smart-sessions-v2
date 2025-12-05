// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib Unit Test Base
/// @notice Base contract for BaseConfigLib unit tests
/// @dev Provides common state variables and constants used across all function tests
contract BaseConfigLib_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mode values
    uint8 internal constant MODE_SKIP = 0;
    uint8 internal constant MODE_CHECK_STORAGE = 1;
    uint8 internal constant MODE_CHECK_CATCHALL = 2;
    uint8 internal constant MODE_CHECK_SUBPOLICY = 3;

    /// @notice Field IDs
    uint8 internal constant FIELD_ARBITER = 0;
    uint8 internal constant FIELD_EXPIRY = 1;
    uint8 internal constant FIELD_TOKEN_IN = 2;
    uint8 internal constant FIELD_RECIPIENT = 3;
    uint8 internal constant FIELD_FILL_EXPIRY = 4;
    uint8 internal constant FIELD_TOKEN_OUT = 5;
    uint8 internal constant FIELD_ORIGIN_OPS = 6;
    uint8 internal constant FIELD_DEST_OPS = 7;
    uint8 internal constant FIELD_QUALIFICATION = 8;
    uint8 internal constant FIELD_RECIPIENT_IS_SPONSOR = 9;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Policy config for tests
    PolicyConfig internal config;

    /// @notice Raw uint32 mode config for tests
    uint32 internal modeConfig;

    /// @notice Result mode from extraction
    uint8 internal mode;

    /// @notice Calldata buffer for initialization tests
    bytes internal data;

    /// @notice Offset tracking
    uint256 internal offset;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
    }
}
