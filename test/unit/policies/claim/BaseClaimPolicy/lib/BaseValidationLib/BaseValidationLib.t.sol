// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "test/Base.t.sol";

// Libraries
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
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
    MODE_CHECK_SUBPOLICY as MODE_CHECK_SUBPOLICY_CONSTANT,
    ANY_ADDRESS as ANY_ADDRESS_CONSTANT,
    ParamRules,
    ParamRule,
    QualificationRulesStorage
} from "@policies/claim/base/types/BaseDataTypes.sol";

import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";

/// @title BaseValidationLib Unit Test Base
/// @notice Base contract for BaseValidationLib unit tests
contract BaseValidationLib_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;
    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint32;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

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

    // Constants
    address internal constant ANY_ADDRESS = ANY_ADDRESS_CONSTANT;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test config ID
    ConfigId internal configId;

    /// @notice Test account (sponsor)
    address internal account;

    /// @notice Test hash for sub-policy validation
    bytes32 internal testHash;

    /// @notice Calldata for validation
    bytes internal data;

    /// @notice Current offset in calldata
    uint256 internal offset;

    /// @notice Policy configuration
    PolicyConfig internal config;

    /// @notice Test chain IDs
    uint256 internal chainId;
    uint256 internal targetChainId;

    /// @notice Test addresses
    address internal arbiter;
    address internal recipient;
    address internal token1;
    address internal token2;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        // Initialize test values
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = address(0x1234);
        testHash = keccak256("test");
        chainId = 1;
        targetChainId = 137;
        arbiter = address(0xA1);
        recipient = address(0xc1);
        token1 = address(0xd1);
        token2 = address(0xd2);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE CONFIG HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds a PolicyConfig with multiple field modes set
    /// @param fieldIds Array of field IDs
    /// @param modes Array of mode values
    /// @return The PolicyConfig with all field modes set
    function _buildConfigMulti(
        uint8[] memory fieldIds,
        uint8[] memory modes
    )
        internal
        pure
        returns (PolicyConfig)
    {
        require(fieldIds.length == modes.length, "Length mismatch");
        uint32 modeConfig = 0;
        for (uint256 i = 0; i < fieldIds.length; i++) {
            modeConfig = BaseConfigLib.setFieldMode(modeConfig, fieldIds[i], modes[i]);
        }
        return PolicyConfig.wrap(modeConfig);
    }

    /*//////////////////////////////////////////////////////////////
                          STORAGE SETUP HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Gets storage pointer for current configId and account
    function _getStorage() internal view returns (BasePolicyStorage storage) {
        return configId.getStorage(account);
    }

    /// @notice Sets up arbiter in storage
    function _setupArbiter(address _arbiter) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.arbiterConfig.add(_arbiter);
    }

    /// @notice Sets up multiple arbiters in storage
    function _setupArbiters(address[] memory _arbiters) internal {
        BasePolicyStorage storage $ = _getStorage();
        for (uint256 i = 0; i < _arbiters.length; i++) {
            $.arbiterConfig.add(_arbiters[i]);
        }
    }

    /// @notice Sets up expiry bounds in storage
    function _setupExpiry(uint128 min, uint128 max) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.expiryConfig = BaseConfigLib.packUint128(min, max);
    }

    /// @notice Sets up recipient for a chain in storage
    function _setupRecipient(uint256 _chainId, address _recipient) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.recipientConfig[_chainId] = _recipient;
    }

    /// @notice Sets up fill expiry bounds for a chain in storage
    function _setupFillExpiry(uint256 _chainId, uint128 min, uint128 max) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.fillExpiryConfig[_chainId] = BaseConfigLib.packUint128(min, max);
    }

    /// @notice Sets up token out whitelist for a chain in storage
    function _setupTokenOut(uint256 _chainId, address _token) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.tokenOutSet[_chainId].add(_token);
    }

    /// @notice Sets up multiple tokens in whitelist for a chain
    function _setupTokensOut(uint256 _chainId, address[] memory _tokens) internal {
        BasePolicyStorage storage $ = _getStorage();
        for (uint256 i = 0; i < _tokens.length; i++) {
            $.tokenOutSet[_chainId].add(_tokens[i]);
        }
    }

    /// @notice Sets up origin ops requirement for a chain
    function _setupOriginOps(uint256 _chainId, bool required) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.originOpsConfig[_chainId] = required;
    }

    /// @notice Sets up dest ops requirement for a chain
    function _setupDestOps(uint256 _chainId, bool required) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.destOpsConfig[_chainId] = required;
    }

    /// @notice Sets up sub-policy address for a field
    function _setupSubPolicy(uint8 fieldId, address policy) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.subPolicies[fieldId] = policy;
    }

    /// @notice Sets up mode config in storage
    function _setupModeConfig(PolicyConfig _config) internal {
        BasePolicyStorage storage $ = _getStorage();
        $.modeConfig = _config;
    }

    /*//////////////////////////////////////////////////////////////
                        QUALIFICATION SETUP HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets up empty qualification rules in storage (no rules - always passes)
    function _setupEmptyQualificationRules(
        uint256 _chainId,
        address _arbiter,
        bool _useArbiterHash
    )
        internal
    {
        BasePolicyStorage storage $ = _getStorage();

        ParamRule[] memory rules = new ParamRule[](0);
        uint256[] memory packedNodes = new uint256[](0);

        $.qualificationConfig[_chainId][_arbiter] = QualificationRulesStorage({
            useArbiterHash: _useArbiterHash,
            rules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: packedNodes })
        });
    }

    /// @notice Sets up a simple EQUAL rule that checks first 32 bytes
    function _setupEqualRule(
        uint256 _chainId,
        address _arbiter,
        bool _useArbiterHash,
        bytes32 _expectedValue
    )
        internal
    {
        BasePolicyStorage storage $ = _getStorage();

        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL, offset: 0, length: 32, ref: _expectedValue
        });

        // Single leaf node pointing to rule 0
        uint256[] memory packedNodes = new uint256[](1);
        packedNodes[0] = 0; // Leaf node: rule index 0

        $.qualificationConfig[_chainId][_arbiter] = QualificationRulesStorage({
            useArbiterHash: _useArbiterHash,
            rules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: packedNodes })
        });
    }
}
