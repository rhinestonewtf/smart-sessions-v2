// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

struct Lock {
    bytes12 lockTag;
    address token;
    uint256 amount;
}

struct Token {
    address token;
    uint256 amount;
}

/// @title Hash Library
/// @notice Library for hashing MultichainCompact structures with EIP712 compliance
// solhint-disable max-line-length
library HashLib {
    /*//////////////////////////////////////////////////////////////
                               TYPEHASHES
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 typehash for the `Lock` struct.
    bytes32 internal constant TYPEHASH_LOCK =
        keccak256(bytes("Lock(bytes12 lockTag,address token,uint256 amount)"));

    /// @notice EIP-712 typehash for the `Token` struct.
    bytes32 internal constant TYPEHASH_TOKEN =
        keccak256(bytes("Token(address token,uint256 amount)"));

    /// @notice EIP-712 typehash for the `Op` struct.
    bytes32 internal constant TYPEHASH_OP = keccak256("Op(address to,uint256 value,bytes data)");

    /// @notice EIP-712 typehash for the `Target` struct - FIXED: removed claimProofer
    bytes32 internal constant TYPEHASH_TARGET = keccak256(
        bytes(
            "Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)"
        )
    );

    /// @notice EIP-712 typehash for the `Mandate` struct - FIXED: removed claimProofer from Target
    bytes32 internal constant TYPEHASH_MANDATE = keccak256(
        bytes(
            "Mandate(Target target,Op[] originOps,Op[] destOps,bytes32 q)Op(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)"
        )
    );

    /// @notice EIP-712 typehash for the `Element` struct - FIXED: removed claimProofer from Target
    bytes32 internal constant TYPEHASH_ELEMENT = keccak256(
        bytes(
            "Element(address arbiter,uint256 chainId,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(Target target,Op[] originOps,Op[] destOps,bytes32 q)Op(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)"
        )
    );

    /// @notice EIP-712 typehash for the `MultichainCompact` struct - FIXED: removed claimProofer
    /// from Target
    bytes32 internal constant TYPEHASH_COMPACT = keccak256(
        bytes(
            "MultichainCompact(address sponsor,uint256 nonce,uint256 expires,Element[] elements)Element(address arbiter,uint256 chainId,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(Target target,Op[] originOps,Op[] destOps,bytes32 q)Op(address to,uint256 value,bytes data)Target(address recipient,Token[] tokenOut,uint256 targetChain,uint256 fillExpiry)Token(address token,uint256 amount)"
        )
    );

    /*//////////////////////////////////////////////////////////////
                                  HASH
    //////////////////////////////////////////////////////////////*/

    function hashCommitments(Lock[] memory commitments) internal pure returns (bytes32) {
        bytes32[] memory commitmentHashes = new bytes32[](commitments.length);

        for (uint256 i = 0; i < commitments.length; i++) {
            commitmentHashes[i] = keccak256(
                abi.encode(
                    TYPEHASH_LOCK,
                    commitments[i].lockTag,
                    commitments[i].token,
                    commitments[i].amount
                )
            );
        }
        return keccak256(abi.encodePacked(commitmentHashes));
    }

    function hashTokenOut(Token[] memory tokens) internal pure returns (bytes32) {
        bytes32[] memory tokenHashes = new bytes32[](tokens.length);

        for (uint256 i = 0; i < tokens.length; i++) {
            tokenHashes[i] =
                keccak256(abi.encode(TYPEHASH_TOKEN, tokens[i].token, tokens[i].amount));
        }
        return keccak256(abi.encodePacked(tokenHashes));
    }

    function hashQualification(bytes memory data) internal pure returns (bytes32) {
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
        return
            keccak256(
                abi.encode(TYPEHASH_TARGET, recipient, tokenOutHash, targetChain, fillExpires)
            );
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
        return keccak256(
            abi.encode(
                TYPEHASH_MANDATE, targetHash, preClaimOpsHash, targetOpsHash, qualificationHash
            )
        );
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
        return
            keccak256(abi.encode(TYPEHASH_ELEMENT, arbiter, chainId, commitmentsHash, mandateHash));
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
        bytes32[] memory allElements = new bytes32[](otherElements.length + 1);
        allElements[0] = notarizedElementHash;
        for (uint256 i = 0; i < otherElements.length; i++) {
            allElements[i + 1] = otherElements[i];
        }

        return keccak256(
            abi.encode(
                TYPEHASH_COMPACT, sponsor, nonce, expires, keccak256(abi.encodePacked(allElements))
            )
        );
    }
}
