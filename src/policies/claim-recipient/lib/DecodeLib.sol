// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { ConfigLib, PolicyConfig } from "@policies/claim-recipient/lib/ConfigLib.sol";
import { HashLib } from "@policies/claim-recipient/lib/HashLib.sol";
import { StorageLib, PolicyStorage } from "@policies/claim-recipient/lib/StorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { Lock, Token, Op, ParamRules } from "@policies/claim-recipient/types/DataTypes.sol";

// Temp
import { console } from "@forge-std/console.sol";

/// @title Decode Library
/// @notice Library for extracting and validating MultiChainCompact data passed in signatures
///         It decodes the data, validates it against the policy configuration, and reconstructs
///         the MultiChainCompact struct hash for verification.
library DecodeLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 private constant EMPTY_EXECUTIONS_HASH =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    /*//////////////////////////////////////////////////////////////
                                EXTRACT
    //////////////////////////////////////////////////////////////*/

    /// @notice Extracts and validates the MultiChainCompact data from the signature
    function extractAndValidate(
        bytes calldata signature,
        PolicyConfig config,
        ConfigId configId,
        address account
    )
        internal
        view
        returns (bool valid, bytes32 compactHash)
    {
        return _decodeAndValidate(signature, config, configId, account);
    }

    /*//////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes the MultiChainCompact data and validates it against the policy config and
    ///         stored configurations.
    /// @param data The MultiChainCompact data to decode
    /// @param config The policy configuration to validate against
    /// @param configId The configuration ID for the policy
    /// @param account The account to validate against
    /// @return valid True if the data is valid, false otherwise
    /// @return compactHash The hash of the decoded MultiChainCompact struct
    function _decodeAndValidate(
        bytes calldata data,
        PolicyConfig config,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 compactHash)
    {
        // Decode fixed header
        address sponsor = address(bytes20(data[0:20]));
        uint256 nonce = uint256(bytes32(data[20:52]));
        uint256 expires = uint256(bytes32(data[52:84]));

        // Decode otherElements first (always at offset 84)
        (bytes32[] memory otherElements, uint256 notarizedElementOffset) =
            _decodeOtherElements(data, 84);

        // Decode and validate notarized element
        (bool elementValid, bytes32 elementHash) =
            _validateNotarizedElement(data, notarizedElementOffset, config, configId, account);
        if (!elementValid) {
            return (false, bytes32(0));
        }

        // Hash the MultichainCompact struct
        compactHash = HashLib.hashCompact(sponsor, nonce, expires, elementHash, otherElements);
        return (true, compactHash);
    }

    /// @notice Validates the Element struct and returns its hash
    /// @param data The MultiChainCompact data to validate
    /// @param offset The offset in the data where the element starts
    /// @param config The policy configuration to validate against
    /// @param configId The configuration ID for the policy
    /// @param account The account to validate against
    /// @return valid True if the element is valid, false otherwise
    /// @return elementHash The hash of the validated notarized element
    function _validateNotarizedElement(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 elementHash)
    {
        // Decode element header
        address arbiter = address(bytes20(data[offset:offset + 20]));
        uint256 chainId = uint256(bytes32(data[offset + 32:offset + 64]));
        offset += 64;

        // Init commitmentsHash
        bytes32 commitmentsHash;

        // If checkTokenIn is enabled, validate tokenIn and recalculate commitmentsHash
        if (config.hasCheckTokenIn()) {
            bool tokenInValid;
            (tokenInValid, commitmentsHash, offset) =
                _validateTokenIn(data, offset, chainId, configId, account);
            if (!tokenInValid) {
                return (false, bytes32(0));
            }
        }
        // If checkTokenIn is not enabled, read commitmentsHash directly
        else {
            commitmentsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Validate mandate and get mandateHash
        (bool mandateValid, bytes32 mandateHash) =
            _validateMandate(data, offset, config, configId, account);
        if (!mandateValid) {
            return (false, bytes32(0));
        }

        // Calculate Element struct hash
        elementHash = HashLib.hashElement(arbiter, chainId, commitmentsHash, mandateHash);
        return (true, elementHash);
    }

    /// @notice Validates the Mandate struct and returns its hash
    /// @param data The MultiChainCompact data to validate
    /// @param offset The offset in the data where the mandate starts
    /// @param config The policy configuration to validate against
    /// @param configId The configuration ID for the policy
    /// @param account The account to validate against
    /// @return valid True if the mandate is valid, false otherwise
    /// @return mandateHash The hash of the validated mandate
    function _validateMandate(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 mandateHash)
    {
        // Init targetHash
        bytes32 targetHash;

        // If checkRecipientAndTargetChain or checkTokenOut is enabled, validate target and
        // recalculate targetHash
        if (config.hasCheckRecipientAndTargetChain() || config.hasCheckTokenOut()) {
            bool targetValid;
            (targetValid, targetHash, offset) =
                _validateTarget(data, offset, config, configId, account);
            if (!targetValid) {
                return (false, bytes32(0));
            }
        }
        // If not enabled, read targetHash directly
        else {
            targetHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Init preClaimOpsHash
        bytes32 preClaimOpsHash;

        // If checkPreClaimOps is enabled, validate preClaimOps and recalculate preClaimOpsHash
        if (config.hasCheckPreClaimOps()) {
            bool preClaimValid;
            (preClaimValid, preClaimOpsHash, offset) =
                _validatePreClaimOps(data, offset, configId, account);
            if (!preClaimValid) {
                return (false, bytes32(0));
            }
        }
        // If not enabled, read preClaimOpsHash directly
        else {
            preClaimOpsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Init targetOpsHash
        bytes32 targetOpsHash;

        // If checkHasExecutions is enabled, check if executions hash equals EMPTY_EXECUTIONS_HASH
        if (config.hasCheckHasExecutions()) {
            // Read targetOpsHash and check if it matches EMPTY_EXECUTIONS_HASH
            targetOpsHash = bytes32(data[offset:offset + 32]);
            offset += 32;

            // If targetOpsHash is EMPTY_EXECUTIONS_HASH, it means no executions are present
            // so we return false
            if (targetOpsHash == EMPTY_EXECUTIONS_HASH) {
                return (false, bytes32(0));
            }
        }
        // If not enabled, read targetOpsHash directly
        else {
            targetOpsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Init qualificationHash
        bytes32 qualificationHash;

        // If checkQualification is enabled, validate qualification and recalculate
        // qualificationHash
        if (config.hasCheckQualification()) {
            bool qualificationValid;
            (qualificationValid, qualificationHash, offset) =
                _validateQualification(data, offset, configId, account);
            if (!qualificationValid) {
                return (false, bytes32(0));
            }
        }
        // If not enabled, read qualificationHash directly
        else {
            qualificationHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Calculate Mandate struct hash
        mandateHash =
            HashLib.hashMandate(targetHash, preClaimOpsHash, targetOpsHash, qualificationHash);
        return (true, mandateHash);
    }

    /// @notice Validates the Target struct and returns its hash
    /// @param data The MultiChainCompact data to validate
    /// @param offset The offset in the data where the target starts
    /// @param config The policy configuration to validate against
    /// @param configId The configuration ID for the policy
    /// @param account The account to validate against
    /// @return valid True if the target is valid, false otherwise
    /// @return targetHash The hash of the validated target
    /// @return newOffset The new offset after reading the target data
    function _validateTarget(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 targetHash, uint256 newOffset)
    {
        // Decode target header
        address recipient = address(bytes20(data[offset:offset + 20]));
        uint256 targetChain = uint256(bytes32(data[offset + 32:offset + 64]));
        uint256 fillExpires = uint256(bytes32(data[offset + 64:offset + 96]));
        offset += 96;

        // Validate recipient and targetChain if required
        if (config.hasCheckRecipientAndTargetChain()) {
            // Get storage pointer
            PolicyStorage storage $ = StorageLib.getPolicyStorage();

            // Load the recipient configuration for the account
            address expectedRecipient =
                $.recipientConfig[configId][msg.sender][account][targetChain];

            if (recipient != expectedRecipient) {
                return (false, bytes32(0), offset);
            }
        }

        // Init tokenOutHash
        bytes32 tokenOutHash;

        // If checkTokenOut is enabled, validate tokenOut and recalculate tokenOutHash
        if (config.hasCheckTokenOut()) {
            bool tokenOutValid;
            (tokenOutValid, tokenOutHash, offset) =
                _validateTokenOut(data, offset, configId, account, targetChain);
            if (!tokenOutValid) {
                return (false, bytes32(0), offset);
            }
        }
        // If not enabled, read tokenOutHash directly
        else {
            tokenOutHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Calculate Target struct hash
        targetHash = HashLib.hashTarget(recipient, tokenOutHash, targetChain, fillExpires);
        return (true, targetHash, offset);
    }

    /*//////////////////////////////////////////////////////////////
                            VALIDATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates the Lock structs and returns their hashes
    /// @param data The MultiChainCompact data to validate
    /// @param offset The offset in the data where the tokenIn starts
    /// @param chainId The chain ID for the tokenIn validation
    /// @param configId The configuration ID for the policy
    /// @param account The account to validate against
    /// @return valid True if the tokenIn is valid, false otherwise
    /// @return commitmentsHash The hash of the validated Lock structs
    /// @return newOffset The new offset after reading the tokenIn data
    function _validateTokenIn(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 commitmentsHash, uint256 newOffset)
    {
        // Decode tokenIn header
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Get storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Parse each Lock struct
        Lock[] memory locks = new Lock[](length);
        for (uint256 i = 0; i < length; i++) {
            locks[i] = Lock({
                lockTag: bytes12(data[offset:offset + 12]),
                token: address(bytes20(data[offset + 12:offset + 32])),
                amount: uint256(bytes32(data[offset + 32:offset + 64]))
            });
            offset += 64;

            // Validate token address
            if (
                $.tokenInConfig[configId][msg.sender][account][chainId].token != address(0)
                    && $.tokenInConfig[configId][msg.sender][account][chainId].token != locks[i].token
            ) {
                return (false, bytes32(0), offset);
            }
            // Validate amount against min and max limits
            if (
                locks[i].amount < $.tokenInConfig[configId][msg.sender][account][chainId].minAmount
                    || locks[i].amount
                        > $.tokenInConfig[configId][msg.sender][account][chainId].maxAmount
            ) {
                return (false, bytes32(0), offset);
            }
        }

        // Calculate Lock structs hash
        commitmentsHash = HashLib.hashCommitments(locks);
        return (true, commitmentsHash, offset);
    }

    /// @notice Validates the Token structs and returns their hash
    /// @param data The MultiChainCompact data to validate
    /// @param offset The offset in the data where the tokenOut starts
    /// @param configId The configuration ID for the policy
    /// @param account The account to validate against
    /// @param chainId The chain ID for the tokenOut validation
    /// @return valid True if the tokenOut is valid, false otherwise
    /// @return tokenOutHash The hash of the validated Token structs
    /// @return newOffset The new offset after reading the tokenOut data
    function _validateTokenOut(
        bytes calldata data,
        uint256 offset,
        ConfigId configId,
        address account,
        uint256 chainId
    )
        private
        view
        returns (bool valid, bytes32 tokenOutHash, uint256 newOffset)
    {
        // Decode tokenOut header
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Get storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Parse each Token struct
        Token[] memory tokens = new Token[](length);
        for (uint256 i = 0; i < length; i++) {
            tokens[i] = Token({
                token: address(bytes20(data[offset:offset + 20])),
                amount: uint256(bytes32(data[offset + 20:offset + 52]))
            });
            offset += 52;

            // Validate token address
            if (
                $.tokenOutConfig[configId][msg.sender][account][chainId].token != address(0)
                    && $.tokenOutConfig[configId][msg.sender][account][chainId].token != tokens[i].token
            ) {
                return (false, bytes32(0), offset);
            }
            // Validate amount against min and max limits
            if (
                tokens[i].amount
                    < $.tokenOutConfig[configId][msg.sender][account][chainId].minAmount
                    || tokens[i].amount
                        > $.tokenOutConfig[configId][msg.sender][account][chainId].maxAmount
            ) {
                return (false, bytes32(0), offset);
            }
        }

        // Calculate Token structs hash
        tokenOutHash = HashLib.hashTokenOut(tokens);
        return (true, tokenOutHash, offset);
    }

    /// @notice Validates the preClaimOps Op structs and returns their hash
    /// @param data The MultiChainCompact data to validate
    /// @param offset The offset in the data where the preClaimOps starts
    /// @param configId The configuration ID for the policy
    /// @param account The account to validate against
    /// @return valid True if the preClaimOps are valid, false otherwise
    /// @return preClaimOpsHash The hash of the validated preClaimOps
    /// @return newOffset The new offset after reading the preClaimOps data
    function _validatePreClaimOps(
        bytes calldata data,
        uint256 offset,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 preClaimOpsHash, uint256 newOffset)
    {
        // Decode preClaimOps header
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Init Op array
        Op[] memory ops = new Op[](length);

        // Get storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Load the preClaimOps configuration for the account
        ParamRules memory preClaimOpsConfig = $.preClaimOpsConfig[configId][account][msg.sender];

        // Parse each Op struct
        for (uint256 i = 0; i < length; i++) {
            uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
            offset += 32;
            ops[i] = Op({ data: data[offset:offset + dataLength] });
            offset += dataLength;
        }

        // TODO: ArgPolicy validation goes here
        preClaimOpsConfig;

        // Calculate preClaimOps hash
        preClaimOpsHash = HashLib.hashOps(ops);
        return (true, preClaimOpsHash, offset);
    }

    /// @notice Validates the Qualification struct and returns its hash
    /// @param data The MultiChainCompact data to validate
    /// @param offset The offset in the data where the qualification starts
    /// @param configId The configuration ID for the policy
    /// @param account The account to validate against
    /// @return valid True if the qualification is valid, false otherwise
    function _validateQualification(
        bytes calldata data,
        uint256 offset,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        // Decode qualification header
        uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
        bytes32 qualificationTypehash = bytes32(data[offset + 32:offset + 64]);
        offset += 32;

        // Extract qualification data
        bytes memory qualificationData = data[offset:offset + dataLength + 32];

        // Get storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Load the qualification configuration for the account
        ParamRules memory qualificationConfig =
            $.qualificationConfig[configId][account][msg.sender][qualificationTypehash];

        // TODO: ArgPolicy validation goes here
        qualificationConfig;

        // Calculate qualification hash
        qualificationHash = HashLib.hashQualification(qualificationData);
        return (true, qualificationHash, offset + dataLength);
    }

    /// @notice Decodes the other (non-notarized) elements from the MultiChainCompact data
    /// @param data The MultiChainCompact data to decode
    /// @param offset The offset in the data where the other elements start
    /// @return elements The decoded other elements as an array of bytes32
    /// @return newOffset The new offset after reading the other elements
    function _decodeOtherElements(
        bytes calldata data,
        uint256 offset
    )
        private
        pure
        returns (bytes32[] memory, uint256 newOffset)
    {
        // Decode the length of the other elements
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Initialize the array to hold the other elements
        bytes32[] memory elements = new bytes32[](length);

        // Parse each element
        for (uint256 i = 0; i < length; i++) {
            elements[i] = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        return (elements, offset);
    }
}
