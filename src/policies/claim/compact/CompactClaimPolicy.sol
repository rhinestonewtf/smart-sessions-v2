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
    CompactStorageLib,
    CompactPolicyStorage
} from "@policies/claim/compact/lib/CompactStorageLib.sol";
import { CompactConfigLib } from "@policies/claim/compact/lib/CompactConfigLib.sol";
import { CompactValidationLib } from "@policies/claim/compact/lib/CompactValidationLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { DomainLib } from "@the-compact/lib/DomainLib.sol";
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { CompactTokenInStorageConfig } from "@policies/claim/compact/types/CompactDataTypes.sol";
import {
    MODE_SKIP,
    MODE_CHECK_SUBPOLICY,
    FIELD_ARBITER,
    FIELD_EXPIRY,
    FIELD_TOKEN_IN
} from "@policies/claim/base/types/BaseDataTypes.sol";

// forgefmt: disable-start
/// @title Compact Claim Policy
/// @author Rhinestone
/// @notice Policy for validating Compact protocol MultichainCompact signatures
/// @dev Validates claims against configurable rules and recomputes EIP-712 hashes
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    MultichainCompact Structure                          │
/// │                                                                         │
/// │                                                                         │
/// ┌──────────────────────────────────────────────────────────────────────┐  │
/// │  │  MultichainCompact                                                │  │
/// │  │  ├── sponsor (address) - the account                              │  │
/// │  │  ├── nonce (uint256)                                              │  │
/// │  │  ├── expires (uint256) ← validated as "claimExpires"              │  │
/// │  │  └── elements (Element[])                                         │  │
/// │  │      ├── Element[0] (notarized - fully validated)                 │  │
/// │  │      │   ├── arbiter (address)                                    │  │
/// │  │      │   ├── chainId (uint256)                                    │  │
/// │  │      │   ├── tokenIn (Lock[]) ← has lockTag                       │  │
/// │  │      │   └── mandate (Mandate)                                    │  │
/// │  │      │       ├── target (Target)                                  │  │
/// │  │      │       │   ├── recipient                                    │  │
/// │  │      │       │   ├── targetChainId                                │  │
/// │  │      │       │   ├── fillExpiry                                   │  │
/// │  │      │       │   └── tokenOut[]                                   │  │
/// │  │      │       ├── minGas                                           │  │
/// │  │      │       ├── originOpsHash                                    │  │
/// │  │      │       ├── destOpsHash                                      │  │
/// │  │      │       └── qualificationHash                                │  │
/// │  │      └── Element[1..n] (other elements - pre-hashed)              │  │
/// └──────────────────────────────────────────────────────────────────────┘  │
/// │                                                                         │
/// │  Hash Computation:                                                      │
/// │  1. elementHash = hash(arbiter, chainId, commitmentsHash, mandateHash)  │
/// │  2. allElementsHash = hash([elementHash, ...otherElements])             │
/// │  3. compactHash = hash(sponsor, nonce, expires, allElementsHash)        │
/// │  4. digest = compactHash.withDomain(domainSeparator)                    │
/// └─────────────────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
contract CompactClaimPolicy is BaseClaimPolicy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint32;
    using BaseConfigLib for uint8;
    using CompactStorageLib for *;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using EfficientHashLib for bytes32[];
    using DomainLib for bytes32;

    /*//////////////////////////////////////////////////////////////
                      TOKEN IN INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc BaseClaimPolicy
    /// @notice Initializes Compact-specific tokenIn storage (token+lockTag)
    /// @dev Decodes CompactTokenInStorageConfig[] and stores packed bytes32 values
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
        CompactPolicyStorage storage $ = configId.getStorage(account);

        // Decode and store tokenIn whitelist
        CompactTokenInStorageConfig[] memory configs;
        uint256 bytesConsumed;
        (configs, remaining, bytesConsumed) = CompactConfigLib.decodeTokenInConfig(initData);

        // Initialize tokenIn whitelist
        for (uint256 i = 0; i < configs.length; i++) {
            // Pack token + lockTag into bytes32
            bytes32 packed = CompactConfigLib.packTokenIn(configs[i].token, configs[i].lockTag);
            $.tokenInSet[configs[i].chainId].add(packed);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         CLAIM VALIDATION
    //////////////////////////////////////////////////////////////*/

    // forgefmt: disable-start
    /// @inheritdoc BaseClaimPolicy
    /// @notice Validates a MultichainCompact claim
    /// @dev Parses MultichainCompact structure, validates fields via
    ///      BaseValidationLib/CompactValidationLib, and computes EIP-712 digest to compare against
    ///      the provided hash.
    ///
    /// Calldata layout:
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:32]     domainSeparator (bytes32)                      │
    /// │  [32:64]    nonce (uint256)                                │
    /// │  [64:96]    expires (uint256)                              │
    /// │  [96:128]   otherElements length (uint256)                 │
    /// │  [128:...]  otherElements (bytes32 each, pre-hashed)       │
    /// │  [...]      notarized element:                             │
    /// │             ├── arbiter (20 bytes + 12 padding)            │
    /// │             ├── chainId (32 bytes)                         │
    /// │             ├── tokenIn OR commitmentsHash                 │
    /// │             └── mandate OR mandateHash                     │
    /// └────────────────────────────────────────────────────────────┘
    ///
    /// Variable encoding based on mode:
    /// ┌─────────────────┬────────────────────────────────────────────┐
    /// │  Field          │  Encoding                                  │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  tokenIn        │  SKIP  → commitmentsHash (32 bytes)        │
    /// │                 │  CHECK → [len (32)] + [Lock[] (64 each)]   │
    /// │                 │          Lock = [token+lockTag (32), amt]  │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  mandate        │  If ALL mandate fields SKIP →              │
    /// │                 │     mandateHash (32 bytes)                 │
    /// │                 │  If ANY mandate field CHECK →              │
    /// │                 │     decode mandate struct (see below)      │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  target         │  If ALL target fields SKIP →               │
    /// │  (in mandate)   │     targetHash (32) + targetChainId (32)   │
    /// │                 │  If ANY target field CHECK →               │
    /// │                 │     recipient (32) + chainId (32) +        │
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
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  qualification  │  SKIP  → qualificationHash (32 bytes)      │
    /// │  (in mandate)   │  CHECK → [len (32)] + [flags (1)] + [data] │
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
        CompactPolicyStorage storage compactStorage =
            CompactStorageLib.getStorage(configId, account);

        // Decode claim header
        (bytes32 domainSeparator, uint256 nonce, uint256 expires) = _decodeClaimHeader(data);

        /*//////////////////////////////////////////////////////////////
                               VALIDATE EXPIRES
        //////////////////////////////////////////////////////////////*/

        // This validates expires against the claimExpires in config
        if (!BaseValidationLib.validateExpiry($, expires, config, configId, account, hash)) {
            return false;
        }

        // Decode otherElements
        (bytes32[] memory otherElements, uint256 offset) =
            _decodeOtherElements(
                data,
                96 // offset after header (3 * 32 bytes)
            );

        /*//////////////////////////////////////////////////////////////
                        DECODE NOTARIZED ELEMENT HEADER
        //////////////////////////////////////////////////////////////*/

        // Init notarized element variables
        address arbiter;
        uint256 chainId;
        (arbiter, chainId, offset) = _decodeNotarizedElementHeader(data, offset);

        /*//////////////////////////////////////////////////////////////
                               VALIDATE ARBITER
        //////////////////////////////////////////////////////////////*/

        // This validates the arbiter field
        if (!BaseValidationLib.validateArbiter($, arbiter, config, configId, account, hash)) {
            return false;
        }

        /*//////////////////////////////////////////////////////////////
                                VALIDATE TOKEN IN
        //////////////////////////////////////////////////////////////*/

        // Init commitments variables
        bytes32 commitmentsHash;
        bool valid;
        // This validates the tokenIn field
        (valid, commitmentsHash, offset) = CompactValidationLib.validateTokenIn(
            configId, data, account, offset, chainId, config, $, compactStorage, hash
        );
        if (!valid) return false;

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
            $, data, offset, chainId, arbiter, config, configId, account, hash
        );
        // Early return if mandate invalid
        if (!mandateValid) return false;

        /*//////////////////////////////////////////////////////////////
                         COMPUTE EIP-712 DIGEST
        //////////////////////////////////////////////////////////////*/

        // 1. Hash notarized element
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, chainId, commitmentsHash, mandateHash);

        // 2. Build allElements array: [elementHash, ...otherElements]
        uint256 totalLength = otherElements.length + 1;
        bytes32[] memory allElements = EfficientHashLib.malloc(totalLength);
        allElements.set(0, elementHash);
        for (uint256 i; i < otherElements.length; ++i) {
            allElements.set(i + 1, otherElements[i]);
        }

        // 3. Hash all elements
        bytes32 allElementsHash = allElements.hash();

        // 4. Hash MultichainCompact struct
        bytes32 compactHash =
            EIP712TypeHashLib.hashCompact(account, nonce, expires, allElementsHash);

        // 5. Apply domain separator
        bytes32 digest = compactHash.withDomain(domainSeparator);

        // 6. Compare against expected hash
        return digest == hash;
    }

    /*//////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes the header of a MultichainCompact claim
    /// @param data The calldata containing the claim
    /// @return domainSeparator The domain separator
    /// @return nonce The nonce
    /// @return expires The expires timestamp
    function _decodeClaimHeader(bytes calldata data)
        internal
        pure
        returns (bytes32 domainSeparator, uint256 nonce, uint256 expires)
    {
        domainSeparator = bytes32(data[0:32]);
        nonce = uint256(bytes32(data[32:64]));
        expires = uint256(bytes32(data[64:96]));
    }

    /// @notice Decodes otherElements from a MultichainCompact claim
    /// @param data The calldata containing the claim
    /// @return otherElements The array of otherElements (pre-hashed)
    /// @return newOffset The new offset after decoding
    function _decodeOtherElements(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (bytes32[] memory otherElements, uint256 newOffset)
    {
        uint256 otherElementsLength = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        otherElements = new bytes32[](otherElementsLength);
        for (uint256 i = 0; i < otherElementsLength; i++) {
            otherElements[i] = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        newOffset = offset;
    }

    /// @notice Decodes notarized element header from a MultichainCompact claim
    function _decodeNotarizedElementHeader(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (address arbiter, uint256 chainId, uint256 newOffset)
    {
        arbiter = address(bytes20(data[offset:offset + 20]));
        chainId = uint256(bytes32(data[offset + 32:offset + 64]));
        newOffset = offset + 64;
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the whitelisted tokenIn entries for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID
    /// @return tokens Array of packed bytes32 values (token+lockTag)
    function getTokenInWhitelist(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (bytes32[] memory tokens)
    {
        // Get storage reference
        CompactPolicyStorage storage $ = configId.getStorage(account);
        EnumerableSetLib.Bytes32Set storage tokenSet = $.tokenInSet[chainId];

        // Retrieve all tokens
        uint256 length = tokenSet.length();
        tokens = new bytes32[](length);
        for (uint256 i = 0; i < length; i++) {
            tokens[i] = tokenSet.at(i);
        }
    }

    /// @notice Checks if a token+lockTag combination is whitelisted
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID
    /// @param token The token address
    /// @param lockTag The lock tag
    /// @return True if the combination is whitelisted
    function isTokenInWhitelisted(
        ConfigId configId,
        address account,
        uint256 chainId,
        address token,
        bytes12 lockTag
    )
        external
        view
        returns (bool)
    {
        // Get storage reference
        CompactPolicyStorage storage $ = configId.getStorage(account);
        // Pack token + lockTag
        bytes32 packed = CompactConfigLib.packTokenIn(token, lockTag);
        // Check if whitelisted
        return $.tokenInSet[chainId].contains(packed);
    }
}
