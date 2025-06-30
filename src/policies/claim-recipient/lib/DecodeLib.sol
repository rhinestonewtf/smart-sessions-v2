// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { ConfigLib, PolicyConfig } from "@policies/claim-recipient/lib/ConfigLib.sol";
import { HashLib } from "@policies/claim-recipient/lib/HashLib.sol";

// Types
import { Lock, Token, Op } from "@policies/claim-recipient/types/DataTypes.sol";

// Temp
import { console } from "@forge-std/console.sol";

/// @title Decode Library
/// @notice Library for extracting and validating MultiChainCompact data passed in signatures
library DecodeLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                EXTRACT
    //////////////////////////////////////////////////////////////*/

    function extractAndValidate(
        bytes calldata signature,
        PolicyConfig config
    )
        internal
        pure
        returns (bool valid, bytes32 compactHash)
    {
        return _decodeAndValidate(signature, config);
    }

    /*//////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    function _decodeAndValidate(
        bytes calldata data,
        PolicyConfig config
    )
        private
        pure
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
            _validateElement(data, notarizedElementOffset, config);
        if (!elementValid) {
            return (false, bytes32(0));
        }

        // Hash the MultichainCompact struct
        compactHash = HashLib.hashCompact(sponsor, nonce, expires, elementHash, otherElements);
        return (true, compactHash);
    }

    function _validateElement(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config
    )
        private
        pure
        returns (bool valid, bytes32 elementHash)
    {
        address arbiter = address(bytes20(data[offset:offset + 20]));
        uint256 chainId = uint256(bytes32(data[offset + 32:offset + 64]));
        offset += 64;

        bytes32 commitmentsHash;
        if (config.hasCheckTokenIn()) {
            bool tokenInValid;
            (tokenInValid, commitmentsHash, offset) = _validateTokenIn(data, offset, chainId);
            if (!tokenInValid) {
                return (false, bytes32(0));
            }
        } else {
            commitmentsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        (bool mandateValid, bytes32 mandateHash) = _validateMandate(data, offset, config);
        if (!mandateValid) {
            return (false, bytes32(0));
        }

        elementHash = HashLib.hashElement(arbiter, chainId, commitmentsHash, mandateHash);
        return (true, elementHash);
    }

    function _validateMandate(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config
    )
        private
        pure
        returns (bool valid, bytes32 mandateHash)
    {
        bytes32 targetHash;
        if (config.hasCheckRecipientAndTargetChain() || config.hasCheckTokenOut()) {
            bool targetValid;
            (targetValid, targetHash, offset) = _validateTarget(data, offset, config);
            if (!targetValid) {
                return (false, bytes32(0));
            }
        } else {
            targetHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        bytes32 preClaimOpsHash;
        if (config.hasCheckPreClaimOps()) {
            bool preClaimValid;
            (preClaimValid, preClaimOpsHash, offset) = _validatePreClaimOps(data, offset);
            if (!preClaimValid) {
                return (false, bytes32(0));
            }
        } else {
            preClaimOpsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        bytes32 targetOpsHash;
        if (config.hasCheckHasExecutions()) {
            bool hasExecutions;
            (hasExecutions, targetOpsHash, offset) = _validateHasExecutions(data, offset);
            if (!hasExecutions) {
                return (false, bytes32(0));
            }
        } else {
            targetOpsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        bytes32 qualificationHash;
        if (config.hasCheckQualification()) {
            bool qualificationValid;
            (qualificationValid, qualificationHash, offset) = _validateQualification(data, offset);
            if (!qualificationValid) {
                return (false, bytes32(0));
            }
        } else {
            qualificationHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        mandateHash =
            HashLib.hashMandate(targetHash, preClaimOpsHash, targetOpsHash, qualificationHash);
        return (true, mandateHash);
    }

    function _validateTarget(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config
    )
        private
        pure
        returns (bool valid, bytes32 targetHash, uint256 newOffset)
    {
        address recipient = address(bytes20(data[offset:offset + 20]));
        uint256 targetChain = uint256(bytes32(data[offset + 32:offset + 64]));
        uint256 fillExpires = uint256(bytes32(data[offset + 64:offset + 96]));
        offset += 96;

        if (config.hasCheckRecipientAndTargetChain()) {
            if (recipient != params.expectedRecipient || targetChain != params.expectedTargetChain)
            {
                return (false, bytes32(0), offset);
            }
        }

        bytes32 tokenOutHash;
        if (config.hasCheckTokenOut()) {
            bool tokenOutValid;
            (tokenOutValid, tokenOutHash, offset) = _validateTokenOut(data, offset, params);
            if (!tokenOutValid) {
                return (false, bytes32(0), offset);
            }
        } else {
            tokenOutHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        targetHash = HashLib.hashTarget(recipient, tokenOutHash, targetChain, fillExpires);
        return (true, targetHash, offset);
    }

    /*//////////////////////////////////////////////////////////////
                            VALIDATION HELPERS
    //////////////////////////////////////////////////////////////*/

    function _validateTokenIn(
        bytes calldata data,
        uint256 offset,
        uint256 chainId
    )
        private
        pure
        returns (bool valid, bytes32 commitmentsHash, uint256 newOffset)
    {
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        Lock[] memory locks = new Lock[](length);
        for (uint256 i = 0; i < length; i++) {
            locks[i] = Lock({
                lockTag: bytes12(data[offset:offset + 12]),
                token: address(bytes20(data[offset + 12:offset + 32])),
                amount: uint256(bytes32(data[offset + 32:offset + 64]))
            });
            offset += 64;

            // Validate token and amount
            if (
                params.expectedTokenInToken != address(0)
                    && params.expectedTokenInToken != locks[i].token
            ) {
                return (false, bytes32(0), offset);
            }
            if (
                locks[i].amount < uint256(params.minTokenInAmount)
                    || locks[i].amount > uint256(params.maxTokenInAmount)
            ) {
                return (false, bytes32(0), offset);
            }
        }

        commitmentsHash = HashLib.hashCommitments(locks);
        return (true, commitmentsHash, offset);
    }

    function _validateTokenOut(
        bytes calldata data,
        uint256 offset
    )
        private
        pure
        returns (bool valid, bytes32 tokenOutHash, uint256 newOffset)
    {
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        Token[] memory tokens = new Token[](length);
        for (uint256 i = 0; i < length; i++) {
            tokens[i] = Token({
                token: address(bytes20(data[offset:offset + 20])),
                amount: uint256(bytes32(data[offset + 20:offset + 52]))
            });
            offset += 52;

            // Validate token and amount
            if (
                params.expectedTokenOutToken != address(0)
                    && params.expectedTokenOutToken != tokens[i].token
            ) {
                return (false, bytes32(0), offset);
            }
            if (
                tokens[i].amount < uint256(params.minTokenOutAmount)
                    || tokens[i].amount > uint256(params.maxTokenOutAmount)
            ) {
                return (false, bytes32(0), offset);
            }
        }

        tokenOutHash = HashLib.hashTokenOut(tokens);
        return (true, tokenOutHash, offset);
    }

    function _validateHasExecutions(
        bytes calldata data,
        uint256 offset
    )
        private
        pure
        returns (bool hasExecutions, bytes32 targetOpsHash, uint256 newOffset)
    {
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        Op[] memory ops = new Op[](length);
        uint256 totalDataSize = 0;

        for (uint256 i = 0; i < length; i++) {
            uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
            offset += 32;
            ops[i] = Op({ data: data[offset:offset + dataLength] });
            offset += dataLength;
            totalDataSize += dataLength;
        }

        targetOpsHash = HashLib.hashOps(ops);
        return (totalDataSize > 0, targetOpsHash, offset);
    }

    function _validatePreClaimOps(
        bytes calldata data,
        uint256 offset
    )
        private
        pure
        returns (bool valid, bytes32 preClaimOpsHash, uint256 newOffset)
    {
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        Op[] memory ops = new Op[](length);
        for (uint256 i = 0; i < length; i++) {
            uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
            offset += 32;
            ops[i] = Op({ data: data[offset:offset + dataLength] });
            offset += dataLength;
        }

        // TODO: ArgPolicy validation goes here
        preClaimOpsHash = HashLib.hashOps(ops);
        return (true, preClaimOpsHash, offset);
    }

    function _validateQualification(
        bytes calldata data,
        uint256 offset
    )
        private
        pure
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        bytes memory qualificationData = data[offset:offset + dataLength];

        // TODO: ArgPolicy validation goes here
        qualificationHash = HashLib.hashQualification(qualificationData);
        return (true, qualificationHash, offset + dataLength);
    }

    function _decodeOtherElements(
        bytes calldata data,
        uint256 offset
    )
        private
        pure
        returns (bytes32[] memory, uint256 newOffset)
    {
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        bytes32[] memory elements = new bytes32[](length);
        for (uint256 i = 0; i < length; i++) {
            elements[i] = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        return (elements, offset);
    }
}
