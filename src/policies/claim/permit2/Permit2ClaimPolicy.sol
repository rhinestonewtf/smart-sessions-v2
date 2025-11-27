// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { BaseClaimPolicy } from "@policies/claim/base/BaseClaimPolicy.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { Permit2EIP712 } from "@compact-utils/common/Permit2EIP712.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import { Permit2ConfigLib } from "@policies/claim/permit2/lib/Permit2ConfigLib.sol";
import { Permit2ValidationLib } from "@policies/claim/permit2/lib/Permit2ValidationLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PolicyConfig, FIELD_TOKEN_IN } from "@policies/claim/base/types/BaseDataTypes.sol";

// forgefmt: disable-start
/// @title Permit2 Claim Policy
/// @author Rhinestone
/// @notice Policy for validating Permit2 protocol PermitBatchWitnessTransferFrom signatures
/// @dev Validates claims against configurable rules and recomputes EIP-712 hashes.
///      Key differences from Compact:
///      - arbiter is the Permit2 spender (not inside witness)
///      - No domainSeparator in calldata
///      - No separate chainId field - comes from target.targetChainId
///      - tokenIn uses block.chainid (origin chain)
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Permit2 + Mandate Structure                          │
/// │                                                                         │
/// │  ┌───────────────────────────────────────────────────────────────────┐  │
/// │  │  PermitBatchWitnessTransferFrom                                   │  │
/// │  │  ├── permitted (TokenPermissions[]) ← tokenIn (no lockTag)        │  │
/// │  │  │   └── TokenPermissions { token, amount }                       │  │
/// │  │  ├── spender (address) ← this is the arbiter!                     │  │
/// │  │  ├── nonce (uint256)                                              │  │
/// │  │  ├── deadline (uint256) ← validated as "expires"                  │  │
/// │  │  └── witness (Mandate)                                            │  │
/// │  │      ├── target (Target)                                          │  │
/// │  │      │   ├── recipient                                            │  │
/// │  │      │   ├── targetChainId ← destination chain                    │  │
/// │  │      │   ├── fillExpiry                                           │  │
/// │  │      │   └── tokenOut[]                                           │  │
/// │  │      ├── minGas                                                   │  │
/// │  │      ├── originOpsHash                                            │  │
/// │  │      ├── destOpsHash                                              │  │
/// │  │      └── qualificationHash                                        │  │
/// │  └───────────────────────────────────────────────────────────────────┘  │
/// │                                                                         │
/// │  Hash Computation:                                                      │
/// │  1. targetHash = hash(recipient, tokenOutHash, targetChainId, fillExp)  │
/// │  2. mandateHash = hash(targetHash, minGas, ops, qualification)          │
/// │  3. permitHash = hashPermit2(tokenPermsHash, arbiter, nonce, deadline,  │
/// │                              mandateHash)                               │
/// │  4. Return permitHash directly (no domain separator in calldata)        │
/// └─────────────────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
contract Permit2ClaimPolicy is BaseClaimPolicy, Permit2EIP712 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint32;
    using BaseConfigLib for uint8;
    using BaseStorageLib for ConfigId;
    using Permit2ConfigLib for BasePolicyStorage;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the Permit2ClaimPolicy
    /// @param permit2 The address of the Permit2 contract
    constructor(address permit2) Permit2EIP712(permit2) { }

    /*//////////////////////////////////////////////////////////////
                      TOKEN IN INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc BaseClaimPolicy
    /// @notice Initializes Permit2-specific tokenIn storage (token only, no lockTag)
    /// @dev Writes token addresses directly to storage
    function _initializeTokenIn(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        override
        returns (bytes calldata remaining)
    {
        remaining = $.initializeTokenIn(initData);
    }

    /*//////////////////////////////////////////////////////////////
                         CLAIM VALIDATION
    //////////////////////////////////////////////////////////////*/

    // forgefmt: disable-start
    /// @inheritdoc BaseClaimPolicy
    /// @notice Validates a Permit2 PermitBatchWitnessTransferFrom claim
    /// @dev Parses Permit2 structure, validates fields via BaseValidationLib/Permit2ValidationLib,
    ///      and computes EIP-712 digest to compare against the provided hash.
    /// 
    /// Calldata layout:
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:20]     arbiter (address) - Permit2 spender            │
    /// │  [20:52]    nonce (uint256)                                │
    /// │  [52:84]    deadline (uint256)                             │
    /// │  [84:...]   tokenIn OR tokenPermissionsHash                │
    /// │  [...]      mandate (always parsed, see below)             │
    /// └────────────────────────────────────────────────────────────┘
    ///
    /// Variable encoding based on mode:
    /// ┌─────────────────┬────────────────────────────────────────────┐
    /// │  Field          │  Encoding                                  │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  tokenIn        │  SKIP  → tokenPermissionsHash (32 bytes)   │
    /// │                 │  CHECK → [len (32)] + [TokenPerms[] (64)]  │
    /// │                 │          TokenPerms = [token (32), amt]    │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  mandate        │  Always parsed field-by-field to compute   │
    /// │                 │  mandateHash. Individual fields may be     │
    /// │                 │  hashes or expanded structs (see below).   │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  target         │  If ALL target fields SKIP →               │
    /// │  (in mandate)   │     targetHash (32) + targetChainId (32)   │
    /// │                 │  If ANY target field CHECK →               │
    /// │                 │     recipient (32) + targetChainId (32) +  │
    /// │                 │     fillExpiry (32) + tokenOut             │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  minGas         │  Always uint128 (16 bytes)                 │
    /// │  (in mandate)   │  Not validated, used for hash computation  │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  tokenOut       │  SKIP  → tokenOutHash (32 bytes)           │
    /// │  (in target)    │  CHECK → [len (32)] + [entries (64 each)]  │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  originOps      │  Always originOpsHash (32 bytes)           │
    /// │  (in mandate)   │  Validation checks hash != NO_OPS if req'd │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  destOps        │  Always destOpsHash (32 bytes)             │
    /// │  (in mandate)   │  Validation checks hash != NO_OPS if req'd │
    /// │                 │  Note: Uses targetChainId for lookup       │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  qualification  │  SKIP  → qualificationHash (32 bytes)      │
    /// │  (in mandate)   │  CHECK → [len (32)] + [data]               │
    /// └─────────────────┴────────────────────────────────────────────┘
    ///
    /// Mandate structure (when target fields SKIP):
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:32]     targetHash (bytes32)                           │
    /// │  [32:64]    targetChainId (uint256)                        │
    /// │  [64:80]    minGas (uint128)                               │
    /// │  [80:112]   originOpsHash (bytes32)                        │
    /// │  [112:144]  destOpsHash (bytes32)                          │
    /// │  [144:176]  qualificationHash (bytes32) OR [len + data]    │
    /// └────────────────────────────────────────────────────────────┘
    ///
    /// Mandate structure (when any target field CHECK):
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:32]     recipient (address, left-padded)               │
    /// │  [32:64]    targetChainId (uint256)                        │
    /// │  [64:96]    fillExpiry (uint256)                           │
    /// │  [96:...]   tokenOutHash (32) OR [len + entries]           │
    /// │  [...]      minGas (uint128, 16 bytes)                     │
    /// │  [...]      originOpsHash (bytes32)                        │
    /// │  [...]      destOpsHash (bytes32)                          │
    /// │  [...]      qualificationHash (32) OR [len + data]         │
    /// └────────────────────────────────────────────────────────────┘
    // forgefmt: disable-end
    function _validateClaim(
        ConfigId configId,
        address account,
        bytes32 hash,
        bytes calldata data,
        BasePolicyStorage storage $,
        PolicyConfig config
    )
        internal
        view
        override
        returns (bool valid)
    {
        /*//////////////////////////////////////////////////////////////
                                 DECODE HEADER
        //////////////////////////////////////////////////////////////*/

        // Decode Permit2 header fields
        (address arbiter, uint256 nonce, uint256 deadline) = _decodePermit2Header(data);

        /*//////////////////////////////////////////////////////////////
                                 VALIDATE ARBITER
        //////////////////////////////////////////////////////////////*/

        // In Permit2, arbiter is the spender
        if (!BaseValidationLib.validateArbiter($, arbiter, config, configId, account, hash)) {
            return false;
        }

        /*//////////////////////////////////////////////////////////////
                                VALIDATE DEADLINE
        //////////////////////////////////////////////////////////////*/

        // Deadline is equivalent to expires in Compact
        if (!BaseValidationLib.validateExpiry($, deadline, config, configId, account, hash)) {
            return false;
        }

        /*//////////////////////////////////////////////////////////////
                                 VALIDATE TOKEN IN
        //////////////////////////////////////////////////////////////*/

        // Init tokenPermissions fields
        uint256 offset = 84; // 84 bytes = address(20) + nonce(32) + deadline(32)
        bytes32 tokenPermissionsHash;
        // This validates the tokenIn field
        (valid, tokenPermissionsHash, offset) = Permit2ValidationLib.validateTokenIn(
            configId, data, account, offset, config, $, hash
        );
        // Early return if tokenIn invalid
        if (!valid) return false;

        /*//////////////////////////////////////////////////////////////
                                VALIDATE MANDATE
        //////////////////////////////////////////////////////////////*/

        // Init mandate variables
        bytes32 mandateHash;
        // This validates nested mandate fields:
        //      1) fillExpiry
        //      2) recipient
        //      3) tokenOut
        //      4) originOps
        //      5) destOps
        //      6) qualification
        (valid, mandateHash) = BaseValidationLib.validateMandate(
            $, data, offset, block.chainid, arbiter, config, configId, account, hash
        );
        // Early return if mandate invalid
        if (!valid) return false;

        /*//////////////////////////////////////////////////////////////
                            COMPUTE EIP-712 HASH
        //////////////////////////////////////////////////////////////*/

        // Compute Permit2 digest
        bytes32 digest = _permit2HashTypedData(
            EIP712TypeHashLib.hashPermit2(
                tokenPermissionsHash, arbiter, nonce, deadline, mandateHash
            )
        );

        // Compare digest against expected hash
        return digest == hash;
    }

    /*//////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes the Permit2 header fields from calldata
    function _decodePermit2Header(bytes calldata data)
        internal
        pure
        returns (address arbiter, uint256 nonce, uint256 deadline)
    {
        arbiter = address(bytes20(data[0:20]));
        nonce = uint256(bytes32(data[20:52]));
        deadline = uint256(bytes32(data[52:84]));
    }

    /*//////////////////////////////////////////////////////////////
                                VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the whitelisted tokenIn entries for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID (typically 0 for origin chain)
    /// @return tokens Array of token addresses
    function getTokenInWhitelist(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (address[] memory tokens)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        EnumerableSetLib.Bytes32Set storage tokenSet = $.tokenInSet[chainId];

        uint256 length = tokenSet.length();
        tokens = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            tokens[i] = address(bytes20(bytes32(tokenSet.at(i))));
        }
    }

    /// @notice Checks if a token is whitelisted
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID (typically 0 for origin chain)
    /// @param token The token address
    /// @return True if the token is whitelisted
    function isTokenInWhitelisted(
        ConfigId configId,
        address account,
        uint256 chainId,
        address token
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return $.tokenInSet[chainId].contains(bytes32(bytes20(token)));
    }
}
