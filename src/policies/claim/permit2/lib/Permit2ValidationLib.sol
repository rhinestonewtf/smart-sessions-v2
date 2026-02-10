// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { MODE_SKIP, FIELD_TOKEN_IN } from "@policies/claim/base/types/BaseDataTypes.sol";

// forgefmt: disable-start
/// @title Permit2 Validation Library
/// @author Rhinestone
/// @notice Permit2-specific validation logic for tokenIn (no lockTag)
/// @dev Used alongside BaseValidationLib for Permit2ClaimPolicy
///
/// ┌────────────────────────────────────────────────────────────┐
/// │                 Permit2 TokenIn Validation                 │
/// │                                                            │
/// │  Input (calldata):                                         │
/// │  ┌──────────────────────────────────────────────────────┐  │
/// │  │  length (1 byte)                                     │  │
/// │  │  TokenPermissions[]: [token (32) | amount (32)] each │  │
/// │  └──────────────────────────────────────────────────────┘  │
/// │                                                            │
/// │  Key differences from Compact:                             │
/// │  - No lockTag - just token addresses                       │
/// │  - Uses Bytes32Set with left-padded addresses              │
/// │  - Uses block.chainid for whitelist lookup                 │
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
/// │  - bytes32: EIP-712 hash of TokenPermissions array         │
/// │  - uint256: New offset after tokenIn data                  │
/// └────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
library Permit2ValidationLib {
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
    /// @dev Handles SKIP, STORAGE, CATCHALL, and SUBPOLICY modes.
    ///      Note: Uses block.chainid for whitelist lookup (origin chain context).
    /// @param configId The configuration ID
    /// @param data The calldata containing tokenIn
    /// @param account The account performing the action
    /// @param offset Current offset in calldata
    /// @param config The policy configuration
    /// @param baseStorage Base storage for sub-policy lookup
    /// @param hash The original hash for sub-policy validation
    /// @return valid True if validation passes
    /// @return tokenInHash The computed EIP-712 hash
    /// @return newOffset Updated offset after tokenIn data
    function validateTokenIn(
        ConfigId configId,
        bytes calldata data,
        address account,
        uint256 offset,
        PolicyConfig config,
        BasePolicyStorage storage baseStorage,
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
            (tokenInHash, newOffset) = data.sliceBytes32(offset);
            return (true, tokenInHash, newOffset);
        }

        // STORAGE / CATCHALL: Validate against whitelist
        if (mode.isStorageMode()) {
            return _validateTokenInStorage(baseStorage, data, offset, mode);
        }

        // SUBPOLICY: Delegate to external policy
        if (mode.isSubPolicyMode()) {
            address subPolicy = baseStorage.subPolicies[FIELD_TOKEN_IN];
            return _validateTokenInSubPolicy(configId, account, data, offset, subPolicy, hash);
        }

        return (false, bytes32(0), 0);
    }

    /*//////////////////////////////////////////////////////////////
                           STORAGE VALIDATION
    //////////////////////////////////////////////////////////////

    TokenPermissions layout (per entry):
    ┌────────────────────────────────────────────────────────────┐
    │  [0:32]   token (address, left-padded to 32 bytes)         │
    │  [32:64]  amount (uint256)                                 │
    └────────────────────────────────────────────────────────────┘
    Total: 64 bytes per entry

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn against storage whitelist
    /// @dev Checks token address membership in Bytes32Set.
    ///      Uses block.chainid for lookup (origin chain context).
    /// @param baseStorage Base storage pointer
    /// @param data The calldata containing tokenIn
    /// @param offset Current offset in calldata
    /// @param mode The field mode (for catchall handling)
    /// @return valid True if all entries are whitelisted
    /// @return tokenInHash The computed EIP-712 hash
    /// @return newOffset Updated offset
    function _validateTokenInStorage(
        BasePolicyStorage storage baseStorage,
        bytes calldata data,
        uint256 offset,
        uint8 mode
    )
        private
        view
        returns (bool valid, bytes32 tokenInHash, uint256 newOffset)
    {
        // Slice out array length
        uint8 length;
        (length, offset) = data.sliceUint8(offset);

        // Get whitelist using block.chainid
        uint256 effectiveChainId = mode.getEffectiveChainId(block.chainid);
        EnumerableSetLib.Bytes32Set storage tokenSet = baseStorage.tokenInSet[effectiveChainId];

        // Empty whitelist = not configured
        if (tokenSet.length() == 0) {
            return (false, bytes32(0), 0);
        }

        // Create calldata pointer to array
        uint256[2][] calldata tokenPermissions;
        (tokenPermissions, offset) = data.sliceUint256PairArray(offset, length);

        // Validate each entry (just check token address)
        for (uint256 i = 0; i < length; i++) {
            address token = address(uint160(tokenPermissions[i][0]));
            // Check left-padded address in set
            if (!tokenSet.contains(bytes32(bytes20(token)))) {
                return (false, bytes32(0), 0);
            }
        }

        // Compute hash
        tokenInHash = EIP712TypeHashLib.hashTokenPermissions(tokenPermissions);

        return (true, tokenInHash, offset);
    }

    /*//////////////////////////////////////////////////////////////
                          SUBPOLICY VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn via external sub-policy
    /// @dev Encodes tokenIn array for sub-policy call
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param data The calldata containing tokenIn
    /// @param offset Current offset in calldata
    /// @param subPolicy The sub-policy contract address
    /// @param hash The original hash
    /// @return valid True if sub-policy approves
    /// @return tokenInHash The computed EIP-712 hash
    /// @return newOffset Updated offset
    function _validateTokenInSubPolicy(
        ConfigId configId,
        address account,
        bytes calldata data,
        uint256 offset,
        address subPolicy,
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
        uint256[2][] calldata tokenPermissions;
        (tokenPermissions, offset) = data.sliceUint256PairArray(offset, length);

        // Call sub-policy (no chainId - origin chain context implicit)
        bytes memory tokenInData = abi.encode(tokenPermissions);
        valid = I1271Policy(subPolicy)
            .check1271SignedAction({
                id: configId,
                requestSender: address(0),
                account: account,
                hash: hash,
                signature: tokenInData
            });

        if (!valid) return (false, bytes32(0), 0);

        // Compute hash
        tokenInHash = EIP712TypeHashLib.hashTokenPermissions(tokenPermissions);

        return (true, tokenInHash, offset);
    }
}
