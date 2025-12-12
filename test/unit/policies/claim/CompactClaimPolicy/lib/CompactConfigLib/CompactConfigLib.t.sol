// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { CompactClaimPolicy_Unit_Test } from "../../CompactClaimPolicy.t.sol";

// Libraries
import { CompactConfigLib } from "@policies/claim/compact/lib/CompactConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title CompactConfigLib Unit Test Base
/// @notice Base contract for CompactConfigLib unit tests (also serves as harness)
abstract contract CompactConfigLib_Unit_Test is CompactClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CompactConfigLib for BasePolicyStorage;
    using BaseStorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                            HARNESS FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes tokenIn and returns remaining calldata length
    function initializeTokenIn(bytes calldata initData) external returns (uint256 remainingLength) {
        BasePolicyStorage storage $ = configId.getStorage(account);
        bytes calldata remaining = $.initializeTokenIn(initData);
        return remaining.length;
    }

    /// @notice Checks if a token is in the set
    function containsTokenIn(uint256 chainId, bytes32 id) external view returns (bool) {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return $.tokenInSet[chainId].contains(id);
    }

    /// @notice Returns the length of the tokenIn set for a chain
    function tokenInSetLength(uint256 chainId) external view returns (uint256) {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return $.tokenInSet[chainId].length();
    }
}
