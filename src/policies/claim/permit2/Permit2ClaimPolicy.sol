// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { BaseClaimPolicy } from "@policies/claim/base/BaseClaimPolicy.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import {
    Permit2StorageLib,
    Permit2PolicyStorage
} from "@policies/claim/permit2/lib/Permit2StorageLib.sol";
import { Permit2ConfigLib } from "@policies/claim/permit2/lib/Permit2ConfigLib.sol";
import { Permit2ValidationLib } from "@policies/claim/permit2/lib/Permit2ValidationLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { Permit2TokenInStorageConfig } from "@policies/claim/permit2/types/Permit2DataTypes.sol";
import { FIELD_TOKEN_IN } from "@policies/claim/base/types/BaseDataTypes.sol";

// forgefmt: disable-start
/// @title Permit2 Claim Policy
/// @author Rhinestone
/// @notice Policy for validating Permit2 protocol PermitBatchWitnessTransferFrom signatures
/// @dev Validates claims against configurable rules and recomputes EIP-712 hashes.
///      Key differences from Compact:
///      - arbiter is the Permit2 spender (not inside witness)
///      - No domainSeparator in calldata
///      - No separate chainId field - comes from target.targetChainId
///      - tokenIn uses chainId=0 (origin chain)
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
contract Permit2ClaimPolicy is BaseClaimPolicy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint32;
    using BaseConfigLib for uint8;
    using Permit2StorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                      TOKEN IN INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc BaseClaimPolicy
    /// @notice Initializes Permit2-specific tokenIn storage (token only, no lockTag)
    /// @dev Decodes Permit2TokenInStorageConfig[] and stores token addresses.
    ///      Note: Permit2 tokenIn uses chainId from config (typically 0 for origin chain).
    function _initializeTokenIn(
        ConfigId configId,
        address account,
        PolicyConfig modeConfig,
        bytes calldata initData
    )
        internal
        override
        returns (bytes calldata remaining)
    {
        // Check if tokenIn field uses storage mode
        if (!modeConfig.getFieldMode(FIELD_TOKEN_IN).isStorageMode()) {
            return initData;
        }

        // Get storage reference
        Permit2PolicyStorage storage $ = configId.getStorage(account);

        // Decode and store tokenIn whitelist
        Permit2TokenInStorageConfig[] memory configs;
        uint256 bytesConsumed;
        (configs, remaining, bytesConsumed) = Permit2ConfigLib.decodeTokenInConfig(initData);

        // Initialize tokenIn whitelist (token addresses only, no lockTag)
        for (uint256 i = 0; i < configs.length; i++) {
            $.tokenInSet[configs[i].chainId].add(configs[i].token);
        }
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
    /// │  [...]      mandate OR mandateHash                         │
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
    /// │  mandate        │  If ALL mandate fields SKIP →              │
    /// │                 │     mandateHash (32 bytes)                 │
    /// │                 │  If ANY mandate field CHECK →              │
    /// │                 │     decode mandate struct (see below)      │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  target         │  If ALL target fields SKIP →               │
    /// │  (in mandate)   │     targetHash (32) + targetChainId (32)   │
    /// │                 │  If ANY target field CHECK →               │
    /// │                 │     recipient (32) + targetChainId (32) +  │
    /// │                 │     fillExpiry (32) + tokenOut             │
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
    /// │  (in mandate)   │  CHECK → [len (32)] + [flags (1)] + [data] │
    /// │                 │  flags: 0x00 = keccak256                   │
    /// │                 │         0x01 = arbiter.qualificationHash() │
    /// └─────────────────┴────────────────────────────────────────────┘
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
        returns (bool)
    {
        // Get protocol specific storage pointer
        Permit2PolicyStorage storage permit2Storage =
            Permit2StorageLib.getStorage(configId, account);

        /*//////////////////////////////////////////////////////////////
                                 DECODE HEADER
        //////////////////////////////////////////////////////////////*/

        // Decode Permit2 header fields
        address arbiter = address(bytes20(data[0:20]));
        uint256 nonce = uint256(bytes32(data[20:52]));
        uint256 deadline = uint256(bytes32(data[52:84]));

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
        bool tokenInValid;
        // This validates the tokenIn field
        (tokenInValid, tokenPermissionsHash, offset) = Permit2ValidationLib.validateTokenIn(
            configId,
            data,
            account,
            84, //
            config,
            $,
            permit2Storage,
            hash
        );
        if (!tokenInValid) return false;

        /*//////////////////////////////////////////////////////////////
                                VALIDATE MANDATE
        //////////////////////////////////////////////////////////////*/

        // Init mandate variables
        bool mandateValid;
        bytes32 mandateHash;
        // This validates nested mandate fields:
        //      1) fillExpiry
        //      2) recipient
        //      3) tokenOut
        //      4) originOps
        //      5) destOps
        //      6) qualification
        (mandateValid, mandateHash) = BaseValidationLib.validateMandate(
            $, data, offset, block.chainid, arbiter, config, configId, account, hash
        );
        // Early return if mandate invalid
        if (!mandateValid) return false;

        /*//////////////////////////////////////////////////////////////
                            COMPUTE EIP-712 HASH
        //////////////////////////////////////////////////////////////*/

        // Compute Permit2 digest
        bytes32 permitHash = EIP712TypeHashLib.hashPermit2(
            tokenPermissionsHash, arbiter, nonce, deadline, mandateHash
        );

        // Compare against expected hash
        return permitHash == hash;
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
        Permit2PolicyStorage storage $ = configId.getStorage(account);
        EnumerableSetLib.AddressSet storage tokenSet = $.tokenInSet[chainId];

        uint256 length = tokenSet.length();
        tokens = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            tokens[i] = tokenSet.at(i);
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
        Permit2PolicyStorage storage $ = configId.getStorage(account);
        return $.tokenInSet[chainId].contains(token);
    }
}
