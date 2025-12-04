// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { CompactConfigLib } from "@policies/claim/compact/lib/CompactConfigLib.sol";
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { MODE_SKIP, FIELD_TOKEN_IN } from "@policies/claim/base/types/BaseDataTypes.sol";

// forgefmt: disable-start
/// @title Compact Validation Library
/// @author Rhinestone
/// @notice Compact-specific validation logic for tokenIn with lockTag
/// @dev Used alongside BaseValidationLib for CompactClaimPolicy
///
/// ┌────────────────────────────────────────────────────────────┐
/// │                 Compact TokenIn Validation                 │
/// │                                                            │
/// │  Input (calldata):                                         │
/// │  ┌──────────────────────────────────────────────────────┐  │
/// │  │  length (1 byte)                                     │  │
/// │  │  Lock[]: [id (32) | amount (32)] × length            │  │
/// │  │  id = [lockTag (96 high) | token (160 low)]          │  │
/// │  └──────────────────────────────────────────────────────┘  │
/// │                                                            │
/// │  Mode routing:                                             │
/// │  ┌──────────────┐     ┌──────────────┐                     │
/// │  │  MODE_SKIP   │────►│ Read hash    │                     │
/// │  └──────────────┘     └──────────────┘                     │
/// │                                                            │
/// │  ┌──────────────┐     ┌──────────────┐                     │
/// │  │   STORAGE/   │────►│ Check set    │                     │
/// │  │   CATCHALL   │     └──────────────┘                     │
/// │  └──────────────┘                                          │
/// │                                                            │
/// │  ┌──────────────┐     ┌──────────────┐                     │
/// │  │  SUBPOLICY   │────►│ Call policy  │                     │
/// │  └──────────────┘     └──────────────┘                     │
/// │                                                            │
/// │  Output:                                                   │
/// │  - bool: Validation passed?                                │
/// │  - bytes32: EIP-712 hash of tokenIn array                  │
/// │  - uint256: New offset after tokenIn data                  │
/// └────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
library CompactValidationLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;
    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint8;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                             TOKEN IN
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn with mode-based routing
    /// @dev Handles SKIP, STORAGE, CATCHALL, and SUBPOLICY modes
    /// @param baseStorage Base storage for sub-policy lookup
    /// @param configId The configuration ID
    /// @param account The account performing the action
    /// @param data The calldata containing tokenIn
    /// @param offset Current offset in calldata
    /// @param chainId The chain ID for storage lookup
    /// @param config The policy configuration
    /// @param hash The original hash for sub-policy validation
    /// @return valid True if validation passes
    /// @return tokenInHash The computed EIP-712 hash
    /// @return newOffset Updated offset after tokenIn data
    function validateTokenIn(
        BasePolicyStorage storage baseStorage,
        ConfigId configId,
        bytes calldata data,
        address account,
        uint256 offset,
        uint256 chainId,
        PolicyConfig config,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 tokenInHash, uint256 newOffset)
    {
        // Get field mode
        uint8 mode = config.getFieldMode(FIELD_TOKEN_IN);

        // SKIP: Just read pre-computed hash
        if (mode == MODE_SKIP) {
            return (true, bytes32(data[offset:offset + 32]), offset + 32);
        }

        // STORAGE / CATCHALL: Validate against whitelist
        if (mode.isStorageMode()) {
            return _validateTokenInStorage(baseStorage, data, offset, chainId, mode);
        }

        // SUBPOLICY: Delegate to external policy
        if (mode.isSubPolicyMode()) {
            return _validateTokenInSubPolicy(
                baseStorage, configId, account, data, offset, chainId, hash
            );
        }

        return (false, bytes32(0), 0);
    }

    /*//////////////////////////////////////////////////////////////
                           STORAGE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn against storage whitelist
    /// @dev Packs token+lockTag and checks membership in Bytes32Set
    /// @param baseStorage Base storage pointer
    /// @param data The calldata containing tokenIn
    /// @param offset Current offset in calldata
    /// @param chainId The chain ID (or 0 for catchall)
    /// @param mode The field mode (for catchall handling)
    /// @return valid True if all entries are whitelisted
    /// @return tokenInHash The computed EIP-712 hash
    /// @return newOffset Updated offset
    function _validateTokenInStorage(
        BasePolicyStorage storage baseStorage,
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        uint8 mode
    )
        private
        view
        returns (bool valid, bytes32 tokenInHash, uint256 newOffset)
    {
        // Slice out array length
        uint8 length;
        (length, offset) = data.sliceUint8(offset);

        // Get whitelist (chainId=0 for catchall)
        uint256 effectiveChainId = mode.getEffectiveChainId(chainId);
        EnumerableSetLib.Bytes32Set storage tokenSet = baseStorage.tokenInSet[effectiveChainId];

        // Empty whitelist = not configured
        if (tokenSet.length() == 0) {
            return (false, bytes32(0), 0);
        }

        // Create calldata pointer to array
        uint256[2][] calldata tokenIn;
        (tokenIn, offset) = data.sliceUint256PairArray(offset, length);

        // Validate each entry
        for (uint8 i = 0; i < length; i++) {
            // Reject if not in set (packed token+lockTag)
            if (!tokenSet.contains(bytes32(tokenIn[i][0]))) {
                return (false, bytes32(0), 0);
            }
        }

        // Compute hash
        tokenInHash = EIP712TypeHashLib.hashTokenIn(tokenIn);

        return (true, tokenInHash, offset);
    }

    /*//////////////////////////////////////////////////////////////
                          SUBPOLICY VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn via external sub-policy
    /// @dev Encodes chainId + tokenIn array for sub-policy call
    /// @param baseStorage Base storage pointer for sub-policy lookup
    /// @param configId The configuration ID
    /// @param data The calldata containing tokenIn
    /// @param offset Current offset in calldata
    /// @param chainId The chain ID
    /// @param hash The original hash
    /// @return valid True if sub-policy approves
    /// @return tokenInHash The computed EIP-712 hash
    /// @return newOffset Updated offset
    function _validateTokenInSubPolicy(
        BasePolicyStorage storage baseStorage,
        ConfigId configId,
        address account,
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 tokenInHash, uint256 newOffset)
    {
        // Slice out array length
        uint8 length;
        (length, offset) = data.sliceUint8(offset);

        // Create calldata pointer
        uint256[2][] calldata tokenIn;
        (tokenIn, offset) = data.sliceUint256PairArray(offset, length);

        // Get sub-policy address
        address subPolicy = baseStorage.subPolicies[FIELD_TOKEN_IN];

        // Call sub-policy
        bytes memory tokenInData = abi.encode(chainId, tokenIn);
        valid = I1271Policy(subPolicy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: tokenInData
            });

        if (!valid) return (false, bytes32(0), 0);

        // Compute hash
        tokenInHash = EIP712TypeHashLib.hashTokenIn(tokenIn);

        return (true, tokenInHash, offset);
    }
}
