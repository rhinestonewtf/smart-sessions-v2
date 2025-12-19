// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2ClaimPolicy_Unit_Test } from "../../Permit2ClaimPolicy.t.sol";

// Libraries
import { Permit2ValidationLib } from "@policies/claim/permit2/lib/Permit2ValidationLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { PolicyConfig, FIELD_TOKEN_IN } from "@policies/claim/base/types/BaseDataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Permit2ValidationLib Unit Test Base
/// @notice Base contract for Permit2ValidationLib unit tests (also serves as harness)
abstract contract Permit2ValidationLib_Unit_Test is Permit2ClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using Permit2ValidationLib for *;
    using BaseStorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                            HARNESS FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn and returns results
    function validateTokenIn(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config
    )
        external
        view
        returns (bool valid, bytes32 tokenInHash, uint256 newOffset)
    {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: msg.sender });
        return
            Permit2ValidationLib.validateTokenIn(configId, data, account, offset, config, $, HASH);
    }

    /// @notice Adds a token to the whitelist
    function addTokenToWhitelist(uint256 chainId, address token) external {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: msg.sender });
        $.tokenInSet[chainId].add(bytes32(bytes20(token)));
    }

    /// @notice Sets a subpolicy for a field
    function setSubPolicy(uint8 fieldId, address subPolicy) external {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexor: msg.sender });
        $.subPolicies[fieldId] = subPolicy;
    }
}
