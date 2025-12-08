// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Contracts
import { BaseClaimPolicy } from "@policies/claim/base/BaseClaimPolicy.sol";

// Libraries
import { BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PolicyConfig } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title Mock Base Claim Policy
/// @notice Mock implementation of BaseClaimPolicy for testing base contract logic
/// @dev Provides minimal implementations of abstract functions
contract MockBaseClaimPolicy is BaseClaimPolicy {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Flag to control _validateClaim return value
    bool public validateClaimReturnValue = true;

    /*//////////////////////////////////////////////////////////////
                              SETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the return value for _validateClaim
    function setValidateClaimReturnValue(bool _value) external {
        validateClaimReturnValue = _value;
    }

    /*//////////////////////////////////////////////////////////////
                         ABSTRACT IMPLEMENTATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc BaseClaimPolicy
    /// @dev Minimal implementation - just returns remaining data unchanged
    function _initializeTokenIn(
        BasePolicyStorage storage,
        bytes calldata initData
    )
        internal
        pure
        override
        returns (bytes calldata remaining)
    {
        return initData;
    }

    /// @inheritdoc BaseClaimPolicy
    /// @dev Minimal implementation - returns configurable value
    function _validateClaim(
        ConfigId,
        address,
        bytes32,
        bytes calldata,
        BasePolicyStorage storage,
        PolicyConfig
    )
        internal
        view
        override
        returns (bool)
    {
        return validateClaimReturnValue;
    }
}
