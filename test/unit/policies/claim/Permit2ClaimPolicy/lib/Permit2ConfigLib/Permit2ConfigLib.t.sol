// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2ClaimPolicy_Unit_Test } from "../../Permit2ClaimPolicy.t.sol";

// Libraries
import { Permit2ConfigLib } from "@policies/claim/permit2/lib/Permit2ConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Permit2ConfigLib Unit Test Base
/// @notice Base contract for Permit2ConfigLib unit tests (also serves as harness)
abstract contract Permit2ConfigLib_Unit_Test is Permit2ClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using Permit2ConfigLib for BasePolicyStorage;
    using BaseStorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                            HARNESS FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes tokenIn and returns remaining calldata length
    function initializeTokenIn(bytes calldata initData) external returns (uint256 remainingLength) {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        bytes calldata remaining = $.initializeTokenIn(initData);
        return remaining.length;
    }

    /// @notice Checks if a token is in the set
    function containsTokenIn(uint256 chainId, address token) external view returns (bool) {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return $.tokenInSet[chainId].contains(bytes32(bytes20(token)));
    }

    /// @notice Returns the length of the tokenIn set for a chain
    function tokenInSetLength(uint256 chainId) external view returns (uint256) {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return $.tokenInSet[chainId].length();
    }
}
