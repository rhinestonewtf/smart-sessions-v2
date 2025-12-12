// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import {
    FIELD_ARBITER as FILED_ARBITER_CONSTANT,
    FIELD_EXPIRY as FIELD_EXPIRY_CONSTANT,
    FIELD_TOKEN_IN as FIELD_TOKEN_IN_CONSTANT,
    FIELD_RECIPIENT as FIELD_RECIPIENT_CONSTANT,
    FIELD_FILL_EXPIRY as FIELD_FILL_EXPIRY_CONSTANT,
    FIELD_TOKEN_OUT as FIELD_TOKEN_OUT_CONSTANT,
    FIELD_ORIGIN_OPS as FIELD_ORIGIN_OPS_CONSTANT,
    FIELD_DEST_OPS as FIELD_DEST_OPS_CONSTANT,
    FIELD_QUALIFICATION as FIELD_QUALIFICATION_CONSTANT,
    FIELD_RECIPIENT_IS_SPONSOR as FIELD_RECIPIENT_IS_SPONSOR_CONSTANT,
    MODE_SKIP as MODE_SKIP_CONSTANT,
    MODE_CHECK_STORAGE as MODE_CHECK_STORAGE_CONSTANT,
    MODE_CHECK_CATCHALL as MODE_CHECK_CATCHALL_CONSTANT,
    MODE_CHECK_SUBPOLICY as MODE_CHECK_SUBPOLICY_CONSTANT
} from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title BaseConfigLib Unit Test Base
/// @notice Base contract for BaseConfigLib unit tests
/// @dev Provides common state variables and constants used across all function tests
contract BaseConfigLib_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mode values
    uint8 internal constant MODE_SKIP = MODE_SKIP_CONSTANT;
    uint8 internal constant MODE_CHECK_STORAGE = MODE_CHECK_STORAGE_CONSTANT;
    uint8 internal constant MODE_CHECK_CATCHALL = MODE_CHECK_CATCHALL_CONSTANT;
    uint8 internal constant MODE_CHECK_SUBPOLICY = MODE_CHECK_SUBPOLICY_CONSTANT;

    /// @notice Field IDs
    uint8 internal constant FIELD_ARBITER = FILED_ARBITER_CONSTANT;
    uint8 internal constant FIELD_EXPIRY = FIELD_EXPIRY_CONSTANT;
    uint8 internal constant FIELD_TOKEN_IN = FIELD_TOKEN_IN_CONSTANT;
    uint8 internal constant FIELD_RECIPIENT = FIELD_RECIPIENT_CONSTANT;
    uint8 internal constant FIELD_FILL_EXPIRY = FIELD_FILL_EXPIRY_CONSTANT;
    uint8 internal constant FIELD_TOKEN_OUT = FIELD_TOKEN_OUT_CONSTANT;
    uint8 internal constant FIELD_ORIGIN_OPS = FIELD_ORIGIN_OPS_CONSTANT;
    uint8 internal constant FIELD_DEST_OPS = FIELD_DEST_OPS_CONSTANT;
    uint8 internal constant FIELD_QUALIFICATION = FIELD_QUALIFICATION_CONSTANT;
    uint8 internal constant FIELD_RECIPIENT_IS_SPONSOR = FIELD_RECIPIENT_IS_SPONSOR_CONSTANT;

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
