// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { CompactClaimPolicy_Unit_Test } from "../../CompactClaimPolicy.t.sol";

// Libraries
import { CompactValidationLib } from "@policies/claim/compact/lib/CompactValidationLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { PolicyConfig, FIELD_TOKEN_IN } from "@policies/claim/base/types/BaseDataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title CompactValidationLib Unit Test Base
/// @notice Base contract for CompactValidationLib unit tests (also serves as harness)
abstract contract CompactValidationLib_Unit_Test is CompactClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CompactValidationLib for BasePolicyStorage;
    using BaseStorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                            HARNESS FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn and returns results
    function validateTokenIn(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        PolicyConfig config
    )
        external
        view
        returns (bool valid, bytes32 tokenInHash, uint256 newOffset)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return $.validateTokenIn(configId, data, account, offset, chainId, config, HASH);
    }

    /// @notice Adds a token to the whitelist
    function addTokenToWhitelist(uint256 chainId, bytes32 id) external {
        BasePolicyStorage storage $ = configId.getStorage(account);
        $.tokenInSet[chainId].add(id);
    }

    /// @notice Sets a subpolicy for a field
    function setSubPolicy(uint8 fieldId, address subPolicy) external {
        BasePolicyStorage storage $ = configId.getStorage(account);
        $.subPolicies[fieldId] = subPolicy;
    }
}
