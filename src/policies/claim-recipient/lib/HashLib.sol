// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { Lock, Token, Op } from "@policies/claim-recipient/types/DataTypes.sol";

/// @title Hash Library
/// @notice Library for hashing MultichainCompact structures with EIP712 compliance
library HashLib {
    /*//////////////////////////////////////////////////////////////
                               TYPEHASHES
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 typehash for the `Lock` struct.
    bytes32 internal constant TYPEHASH_LOCK =
        keccak256("Lock(bytes12 lockTag,address token,uint256 amount)");

    /// @notice EIP-712 typehash for the `Token` struct.
    bytes32 internal constant TYPEHASH_TOKEN = keccak256("Token(address token,uint256 amount)");

    /// @notice EIP-712 typehash for the `Op` struct.
    bytes32 internal constant TYPEHASH_OP = keccak256("Op(address to,uint256 value,bytes data)");

    /// @notice EIP-712 typehash for the `Target` struct.
    bytes32 internal constant TYPEHASH_TARGET = keccak256(
        bytes(
            "Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpires)Token(address token,uint256 amount)"
        )
    );

    /// @notice EIP-712 typehash for the `Mandate` struct.
    bytes32 internal constant TYPEHASH_MANDATE = keccak256(
        bytes(
            "Mandate(Target target,Op[] preClaimOps,Op[] targetOps,bytes32 q)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpires)Op(address to,uint256 value,bytes data)Token(address token,uint256 amount)"
        )
    );

    /// @notice EIP-712 typehash for the `Element` struct.
    bytes32 internal constant TYPEHASH_ELEMENT = keccak256(
        bytes(
            "Element(address arbiter,uint256 chainId,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(Target target,Op[] preClaimOps,Op[] targetOps,bytes32 q)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpires)Op(address to,uint256 value,bytes data)Token(address token,uint256 amount)"
        )
    );

    /// @notice EIP-712 typehash for the `MultichainCompact` struct.
    bytes32 internal constant TYPEHASH_COMPACT = keccak256(
        bytes(
            "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Element(address arbiter,uint256 chainId,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(Target target,Op[] preClaimOps,Op[] targetOps,bytes32 q)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpires)Op(address to,uint256 value,bytes data)Token(address token,uint256 amount)"
        )
    );

    /*//////////////////////////////////////////////////////////////
                                  HASH
    //////////////////////////////////////////////////////////////*/

    function hashCommitments(Lock[] memory commitments) internal pure returns (bytes32) {
        // TODO: Implement proper EIP712 commitment hashing
        return keccak256(abi.encode(commitments));
    }

    function hashTokenOut(Token[] memory tokens) internal pure returns (bytes32) {
        // TODO: Implement proper EIP712 token hashing
        return keccak256(abi.encode(tokens));
    }

    function hashOps(Op[] memory ops) internal pure returns (bytes32) {
        // TODO: Implement proper EIP712 ops hashing
        return keccak256(abi.encode(ops));
    }

    function hashQualification(bytes memory data) internal pure returns (bytes32) {
        // TODO: Implement proper EIP712 qualification hashing
        return keccak256(data);
    }

    function hashTarget(
        address recipient,
        bytes32 tokenOutHash,
        uint256 targetChain,
        uint256 fillExpires
    )
        internal
        pure
        returns (bytes32)
    {
        // TODO: Implement proper EIP712 target hashing
        return keccak256(abi.encode(recipient, tokenOutHash, targetChain, fillExpires));
    }

    function hashMandate(
        bytes32 targetHash,
        bytes32 preClaimOpsHash,
        bytes32 targetOpsHash,
        bytes32 qualificationHash
    )
        internal
        pure
        returns (bytes32)
    {
        // TODO: Implement proper EIP712 mandate hashing
        return keccak256(abi.encode(targetHash, preClaimOpsHash, targetOpsHash, qualificationHash));
    }

    function hashElement(
        address arbiter,
        uint256 chainId,
        bytes32 commitmentsHash,
        bytes32 mandateHash
    )
        internal
        pure
        returns (bytes32)
    {
        // TODO: Implement proper EIP712 element hashing
        return keccak256(abi.encode(arbiter, chainId, commitmentsHash, mandateHash));
    }

    function hashCompact(
        address sponsor,
        uint256 nonce,
        uint256 expires,
        bytes32 notarizedElementHash,
        bytes32[] memory otherElements
    )
        internal
        pure
        returns (bytes32)
    {
        // TODO: Implement proper EIP712 compact hashing
        return keccak256(
            abi.encode(
                sponsor,
                nonce,
                expires,
                notarizedElementHash,
                keccak256(abi.encodePacked(otherElements))
            )
        );
    }
}
