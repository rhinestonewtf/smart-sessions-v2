// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { CompactPolicyStorage } from "@policies/claim/compact/lib/CompactStorageLib.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

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
/// │  │  length (32 bytes)                                   │  │
/// │  │  Entry[]: [token (20) | lockTag (12)] × length       │  │
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

    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint8;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                             TOKEN IN
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn with mode-based routing
    /// @dev Handles SKIP, STORAGE, CATCHALL, and SUBPOLICY modes
    /// @param configId The configuration ID
    /// @param account The account performing the action
    /// @param data The calldata containing tokenIn
    /// @param offset Current offset in calldata
    /// @param chainId The chain ID for storage lookup
    /// @param config The policy configuration
    /// @param baseStorage Base storage for sub-policy lookup
    /// @param compactStorage Compact storage for tokenIn whitelist
    /// @param hash The original hash for sub-policy validation
    /// @return valid True if validation passes
    /// @return tokenInHash The computed EIP-712 hash
    /// @return newOffset Updated offset after tokenIn data
    function validateTokenIn(
        ConfigId configId,
        bytes calldata data,
        address account,
        uint256 offset,
        uint256 chainId,
        PolicyConfig config,
        BasePolicyStorage storage baseStorage,
        CompactPolicyStorage storage compactStorage,
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
            return _validateTokenInStorage(data, offset, chainId, mode, compactStorage);
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
    /// @param data The calldata containing tokenIn
    /// @param offset Current offset in calldata
    /// @param chainId The chain ID (or 0 for catchall)
    /// @param mode The field mode (for catchall handling)
    /// @param $ Compact storage pointer
    /// @return valid True if all entries are whitelisted
    /// @return tokenInHash The computed EIP-712 hash
    /// @return newOffset Updated offset
    function _validateTokenInStorage(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        uint8 mode,
        CompactPolicyStorage storage $
    )
        private
        view
        returns (bool valid, bytes32 tokenInHash, uint256 newOffset)
    {
        // Decode array length
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Get whitelist (chainId=0 for catchall)
        uint256 effectiveChainId = mode.getEffectiveChainId(chainId);
        EnumerableSetLib.Bytes32Set storage tokenSet = $.tokenInSet[effectiveChainId];

        // Empty whitelist = not configured
        if (tokenSet.length() == 0) {
            return (false, bytes32(0), 0);
        }

        // Create calldata pointer to array
        uint256[2][] calldata tokenIn;
        assembly {
            tokenIn.offset := add(data.offset, offset)
            tokenIn.length := length
        }

        // Validate each entry
        for (uint256 i = 0; i < length; i++) {
            // Pack: [token (20 bytes) | lockTag (12 bytes)]
            bytes32 packed = bytes32(
                (uint256(uint160(address(uint160(tokenIn[i][0])))) << 96)
                    | uint256(uint96(tokenIn[i][1]))
            );

            if (!tokenSet.contains(packed)) {
                return (false, bytes32(0), 0);
            }
        }

        // Compute hash
        tokenInHash = EIP712TypeHashLib.hashTokenIn(tokenIn);

        return (true, tokenInHash, offset + (length * 64));
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
        // Decode array length
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Create calldata pointer
        uint256[2][] calldata tokenIn;
        assembly {
            tokenIn.offset := add(data.offset, offset)
            tokenIn.length := length
        }

        // Get sub-policy address
        address subPolicy = baseStorage.subPolicies[FIELD_TOKEN_IN];

        // Call sub-policy
        bytes memory tokenInData = abi.encode(chainId, tokenIn);
        valid = I1271Policy(subPolicy)
            .check1271SignedAction(configId, msg.sender, account, hash, tokenInData);

        if (!valid) return (false, bytes32(0), 0);

        // Compute hash
        tokenInHash = EIP712TypeHashLib.hashTokenIn(tokenIn);

        return (true, tokenInHash, offset + (length * 64));
    }
}
