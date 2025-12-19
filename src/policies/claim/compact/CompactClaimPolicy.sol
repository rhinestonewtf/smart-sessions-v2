// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { BaseClaimPolicy } from "@policies/claim/base/BaseClaimPolicy.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Interfaces
import { ICompactClaimPolicy } from "@policies/claim/compact/interfaces/ICompactClaimPolicy.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import { CompactConfigLib } from "@policies/claim/compact/lib/CompactConfigLib.sol";
import { CompactValidationLib } from "@policies/claim/compact/lib/CompactValidationLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { DomainLib } from "@the-compact/lib/DomainLib.sol";
import { Bytes32ArrayLib } from "@rhinestone/compact-utils/src/common/Bytes32ArrayLib.sol";
import { IdLib } from "@the-compact/lib/IdLib.sol";
import { EfficiencyLib } from "@the-compact/lib/EfficiencyLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PolicyConfig } from "@policies/claim/base/types/BaseDataTypes.sol";

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
/// │  │      ├── Element[0] (origin - fully validated)                    │  │
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
    using BaseStorageLib for ConfigId;
    using BaseValidationLib for BasePolicyStorage;
    using CompactConfigLib for BasePolicyStorage;
    using CompactValidationLib for BasePolicyStorage;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using Bytes32ArrayLib for bytes32[];
    using DomainLib for bytes32;
    using IdLib for address;
    using EfficiencyLib for bytes12;
    using EfficiencyLib for address;

    /*//////////////////////////////////////////////////////////////
                         TOKEN IN INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc BaseClaimPolicy
    /// @notice Initializes Compact-specific tokenIn storage (token+lockTag)
    /// @dev Writes packed bytes32 values directly to storage
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
    /// │  [...]      element:                                       │
    /// │             ├── arbiter (address)                          │
    /// │             ├── elementIndex (uint256)                     │
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
    /// │                 │     parsed field-by-field (see below)      │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  target         │  If ALL target fields SKIP →               │
    /// │  (in mandate)   │     targetHash (32) + targetChainId (32)   │
    /// │                 │  If ANY target field CHECK →               │
    /// │                 │     recipient (20+12) + targetChainId (32) │
    /// │                 │     + fillExpiry (32) + tokenOut           │
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
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  qualification  │  SKIP  → qualificationHash (32 bytes)      │
    /// │  (in mandate)   │  CHECK → [len (32)] + [data]               │
    /// └─────────────────┴────────────────────────────────────────────┘
    ///
    /// Note: FIELD_RECIPIENT_IS_SPONSOR requires no calldata -
    /// when enabled, it simply enforces recipient == sponsor
    /// during target validation.
    ///
    /// Mandate encoding (when ALL mandate fields SKIP):
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:32]     mandateHash (bytes32)                          │
    /// └────────────────────────────────────────────────────────────┘
    ///
    /// Mandate encoding (when ANY mandate field CHECK, target SKIP):
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:32]     targetHash (bytes32)                           │
    /// │  [32:64]    targetChainId (uint256)                        │
    /// │  [64:80]    minGas (uint128)                               │
    /// │  [80:112]   originOpsHash (bytes32)                        │
    /// │  [112:144]  destOpsHash (bytes32)                          │
    /// │  [144:176]  qualificationHash (bytes32) OR [len + data]    │
    /// └────────────────────────────────────────────────────────────┘
    ///
    /// Mandate encoding (when ANY target field CHECK):
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:20]     recipient (address)                            │
    /// │  [20:52]    targetChainId (uint256)                        │
    /// │  [52:84]    fillExpiry (uint256)                           │
    /// │  [84:...]   tokenOutHash(bytes32) OR [len + entries]       │
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

        (bytes32 domainSeparator, uint256 nonce, uint256 expires) = _decodeClaimHeader(data);

        /*//////////////////////////////////////////////////////////////
                               VALIDATE EXPIRES
        //////////////////////////////////////////////////////////////*/

        if (!$.validateExpiry(expires, config, configId, account, hash)) {
            return false;
        }

        /*//////////////////////////////////////////////////////////////
                             DECODE OTHER ELEMENTS
        //////////////////////////////////////////////////////////////*/

        (bytes32[] calldata otherElements, uint256 offset) = _decodeOtherElements(data, 96);

        /*//////////////////////////////////////////////////////////////
                             VALIDATE & HASH ELEMENT
        //////////////////////////////////////////////////////////////*/

        // Init element validation variables
        bytes32 elementHash;
        uint256 elementIndex;
        // Validates:
        //   1) arbiter
        //   2) tokenIn (commitments)
        //   3) mandate (fillExpiry, recipient, tokenOut, originOps, destOps, qualification)
        (valid, elementHash, elementIndex) =
            _validateAndHashElement(configId, account, hash, data, offset, $, config);
        if (!valid) return false;

        /*//////////////////////////////////////////////////////////////
                             COMPUTE EIP-712 DIGEST
        //////////////////////////////////////////////////////////////*/

        // 1. Insert origin element hash at its index and hash all elements
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);

        // 2. Hash MultichainCompact struct
        bytes32 compactHash =
            EIP712TypeHashLib.hashCompact(account, nonce, expires, allElementsHash);

        // 3. Apply domain separator and compare against expected hash
        return compactHash.withDomain(domainSeparator) == hash;
    }

    /*//////////////////////////////////////////////////////////////
                           ELEMENT VALIDATION
    //////////////////////////////////////////////////////////////

    Validates the element fields and computes its EIP-712 hash.

    ┌────────────────────────────────────────────────────────────┐
    │                    Origin Element                          │
    │  ┌──────────────────────────────────────────────────────┐  │
    │  │  arbiter (address) ← validated against whitelist     │  │
    │  ├──────────────────────────────────────────────────────┤  │
    │  │  elementIndex (uint256) ← position in elements[]     │  │
    │  ├──────────────────────────────────────────────────────┤  │
    │  │  tokenIn (Lock[]) ← validated per mode               │  │
    │  │    Lock = { lockTag, token, amount }                 │  │
    │  ├──────────────────────────────────────────────────────┤  │
    │  │  mandate (Mandate) ← nested validation               │  │
    │  │    ├── target (recipient, tokenOut, fillExpiry)      │  │
    │  │    ├── minGas                                        │  │
    │  │    ├── originOpsHash                                 │  │
    │  │    ├── destOpsHash                                   │  │
    │  │    └── qualification                                 │  │
    │  └──────────────────────────────────────────────────────┘  │
    └────────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates the element and computes its EIP-712 hash
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The expected final hash (for sub-policy validation)
    /// @param data The calldata containing the element
    /// @param offset Current offset in calldata (after otherElements)
    /// @param $ Storage pointer
    /// @param config Policy configuration
    /// @return valid True if all element fields pass validation
    /// @return elementHash The computed EIP-712 hash of the element
    /// @return elementIndex The index where this element belongs in allElements[]
    function _validateAndHashElement(
        ConfigId configId,
        address account,
        bytes32 hash,
        bytes calldata data,
        uint256 offset,
        BasePolicyStorage storage $,
        PolicyConfig config
    )
        internal
        view
        returns (bool valid, bytes32 elementHash, uint256 elementIndex)
    {
        /*//////////////////////////////////////////////////////////////
                             DECODE ELEMENT HEADER
        //////////////////////////////////////////////////////////////*/

        address arbiter;
        (arbiter, elementIndex, offset) = _decodeElementHeader(data, offset);

        /*//////////////////////////////////////////////////////////////
                               VALIDATE ARBITER
        //////////////////////////////////////////////////////////////*/

        if (!$.validateArbiter(arbiter, config, configId, account, hash)) {
            return (false, bytes32(0), 0);
        }

        /*//////////////////////////////////////////////////////////////
                              VALIDATE TOKEN IN
        //////////////////////////////////////////////////////////////*/

        // Init commitmentsHash
        bytes32 commitmentsHash;
        // Validate tokenIn and compute commitmentsHash
        (valid, commitmentsHash, offset) =
            $.validateTokenIn(configId, data, account, offset, block.chainid, config, hash);
        // Early return if invalid
        if (!valid) return (false, bytes32(0), 0);

        /*//////////////////////////////////////////////////////////////
                               VALIDATE MANDATE
        //////////////////////////////////////////////////////////////*/

        // Init mandateHash
        bytes32 mandateHash;
        // Validate mandate and compute mandateHash
        (valid, mandateHash) = $.validateMandate(
            data, offset, block.chainid, arbiter, config, configId, account, hash
        );
        // Early return if invalid
        if (!valid) return (false, bytes32(0), 0);

        /*//////////////////////////////////////////////////////////////
                             COMPUTE ELEMENT HASH
        //////////////////////////////////////////////////////////////*/

        // Compute element hash
        elementHash = EIP712TypeHashLib.hashElementRaw(
            arbiter, block.chainid, commitmentsHash, mandateHash
        );

        // Return success with element hash and index
        return (true, elementHash, elementIndex);
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
        returns (bytes32[] calldata otherElements, uint256 newOffset)
    {
        uint256 length;
        assembly {
            // Load length of otherElements array
            length := calldataload(add(data.offset, offset))

            // Set calldata pointer to otherElements array
            otherElements.offset := add(data.offset, add(offset, 0x20))
            otherElements.length := length
        }
        newOffset = offset + 32 + (length * 32);
    }

    /// @notice Decodes origin element header from a MultichainCompact claim
    function _decodeElementHeader(
        bytes calldata data,
        uint256 offset
    )
        internal
        pure
        returns (address arbiter, uint256 elementIndex, uint256 newOffset)
    {
        arbiter = address(bytes20(data[offset:offset + 20]));
        elementIndex = uint256(bytes32(data[offset + 20:offset + 52]));
        newOffset = offset + 52;
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
        BasePolicyStorage storage $ = configId.getStorage({account: account, multiplexor: msg.sender});
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
        BasePolicyStorage storage $ = configId.getStorage({account: account, multiplexor: msg.sender});
        // Pack token + lockTag
        bytes32 packed = bytes32(lockTag.asUint256() | token.asUint256());
        // Check if whitelisted
        return $.tokenInSet[chainId].contains(packed);
    }

    /// @notice Checks if this contract implements the given interface
    /// @param interfaceID The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceID) public pure override returns (bool) {
        return super.supportsInterface(interfaceID)
            || interfaceID == type(ICompactClaimPolicy).interfaceId;
    }
}
