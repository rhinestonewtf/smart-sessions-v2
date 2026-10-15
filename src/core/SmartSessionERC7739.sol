// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.25;

import { EIP712 } from "@solady/utils/EIP712.sol";

/// @notice ERC1271 mixin with nested EIP-712 approach.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
abstract contract SmartSessionERC7739 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC1271 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether the `hash` and `signature` are valid. `nestedHash` is the ERC-7739
    /// `TypedDataSign` hash the signature covers, zero when not using ERC-7739.
    /// Override if you need non-ECDSA logic.
    function _erc1271IsValidSignatureNowCalldata(
        address sender,
        bytes32 hash,
        bytes32 nestedHash,
        bytes calldata signature,
        bytes32 appDomainSeparator,
        bytes calldata contents
    )
        internal
        view
        virtual
        returns (bool);

    /// @dev Unwraps and returns the signature.
    function _erc1271UnwrapSignature(bytes calldata signature)
        internal
        view
        virtual
        returns (bytes calldata result)
    {
        result = signature;
        /// @solidity memory-safe-assembly
        assembly {
            // Unwraps the ERC6492 wrapper if it exists.
            // See: https://eips.ethereum.org/EIPS/eip-6492
            if eq(
                calldataload(add(result.offset, sub(result.length, 0x20))),
                mul(0x6492, div(not(mload(0x60)), 0xffff)) // `0x6492...6492`.
            ) {
                let o := add(result.offset, calldataload(add(result.offset, 0x40)))
                result.length := calldataload(o)
                result.offset := add(o, 0x20)
            }
        }
    }

    /// @dev ERC1271 signature validation (Nested EIP-712 workflow).
    /// @dev Currently known as ERC-7739
    /// https://ethereum-magicians.org/t/erc-7739-readable-typed-signatures-for-smart-accounts/20513
    /// This forwards signature verification to an appropriate ISessionValidator
    /// see: `_erc1271IsValidSignatureNowCalldata`.
    /// It also uses a nested EIP-712 approach to prevent signature replays when a single EOA
    /// owns multiple smart contract accounts,
    /// while still enabling wallet UIs (e.g. Metamask) to show the EIP-712 values.
    ///
    /// Crafted for phishing resistance, efficiency, flexibility.
    /// __________________________________________________________________________________________
    ///
    /// Glossary:
    ///
    /// - `APP_DOMAIN_SEPARATOR`: The domain separator of the `hash` passed in by the application.
    ///   Provided by the front end. Intended to be the domain separator of the contract
    ///   that will call `isValidSignature` on this account.
    ///
    /// - `ACCOUNT_DOMAIN_SEPARATOR`: The domain separator of this account.
    ///   See: `EIP712._domainSeparator()`.
    /// __________________________________________________________________________________________
    ///
    /// For the `TypedDataSign` workflow, the final hash will be:
    /// ```
    ///     keccak256(\x19\x01 ‖ APP_DOMAIN_SEPARATOR ‖
    ///         hashStruct(TypedDataSign({
    ///             contents: hashStruct(originalStruct),
    ///             name: keccak256(bytes(eip712Domain().name)),
    ///             version: keccak256(bytes(eip712Domain().version)),
    ///             chainId: eip712Domain().chainId,
    ///             verifyingContract: eip712Domain().verifyingContract,
    ///             salt: eip712Domain().salt,
    ///             extensions: keccak256(abi.encodePacked(eip712Domain().extensions))
    ///         }))
    ///     )
    /// ```
    /// where `‖` denotes the concatenation operator for bytes.
    /// The order of the fields is important: `contents` comes before `name`.
    ///
    /// The signature will be `r ‖ s ‖ v ‖ APP_DOMAIN_SEPARATOR ‖ encodeData ‖
    /// contentsDescription
    ///     ‖ uint16(encodeData.length / 32) ‖ uint16(contentsDescription.length)`,
    /// where `encodeData` is the EIP-712 `encodeData` of the original struct.
    ///
    /// Unlike ERC-7739, which appends the `contents` struct hash, `contents` is derived as
    /// `keccak256(keccak256(contentsType) ‖ encodeData)`, so a session can only sign the
    /// content types it allows. The `APP_DOMAIN_SEPARATOR` and `contents` are then used to
    /// verify that `hash` is correct. `contentsType` must be the app's EIP-712 `encodeType`,
    /// primary type first, so an explicit-mode description only works when it is already in
    /// that order.
    /// __________________________________________________________________________________________
    ///
    /// `PersonalSign` is not supported.
    /// __________________________________________________________________________________________
    ///
    /// The signed `TypedDataSign` hash is the same as in ERC-7739, but the appended data is not,
    /// so standard ERC-7739 signature encoders do not produce it.

    function _erc1271IsValidSignatureViaNestedEIP712(
        address sender,
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        virtual
        returns (bool result)
    {
        bytes calldata contents = signature;
        uint256 t = uint256(uint160(address(this)));
        // Forces the compiler to pop the variables after the scope, avoiding stack-too-deep.
        if (t != uint256(0)) {
            (
                ,
                string memory name,
                string memory version,
                uint256 chainId,
                address verifyingContract,
                bytes32 salt,
            ) = EIP712(msg.sender).eip712Domain();
            /// @solidity memory-safe-assembly
            assembly {
                t := mload(0x40) // Grab the free memory pointer.
                // Skip 2 words for the `typedDataSignTypehash` and `contents` struct hash.
                mstore(add(t, 0x40), keccak256(add(name, 0x20), mload(name)))
                mstore(add(t, 0x60), keccak256(add(version, 0x20), mload(version)))
                mstore(add(t, 0x80), chainId)
                mstore(add(t, 0xa0), shr(96, shl(96, verifyingContract)))
                mstore(add(t, 0xc0), salt)
                mstore(0x40, add(t, 0xe0)) // Allocate the memory.
            }
        }
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            // The last 4 bytes of the signature are `uint16(encodeData.length / 32)` and
            // `uint16(contentsDescription.length)`.
            let c := shr(224, calldataload(add(signature.offset, sub(signature.length, 4))))
            for { } 1 { } {
                // Total length of appended data (32 + encodeData.length + c + 4).
                let o := add(add(0x24, shl(5, shr(16, c))), and(c, 0xffff))
                c := and(c, 0xffff) // `contentsDescription.length`.
                // Reject if the appended data is invalid or leaves no 64-byte header.
                if or(lt(signature.length, add(o, 0x40)), iszero(c)) {
                    t := 0 // Set `t` to 0, denoting that the signature is rejected.
                    break
                }
                o := add(signature.offset, sub(signature.length, o)) // Offset of appended data.
                // Only use the `TypedDataSign` workflow.
                // `TypedDataSign({ContentsName} contents,string name,...){ContentsType}`.
                mstore(m, "TypedDataSign(") // Store the start of `TypedDataSign`'s type encoding.
                let p := add(m, 0x0e) // Advance 14 bytes to skip "TypedDataSign(".
                // Set the offset and length of `contents`.
                contents.offset := sub(add(signature.offset, signature.length), add(c, 4))
                contents.length := c
                calldatacopy(p, contents.offset, c) // Copy `contentsName`, optimistically.
                mstore(add(p, c), 40) // Store a '(' after the end.
                if iszero(eq(byte(0, mload(sub(add(p, c), 1))), 41)) {
                    let e := 0 // Length of `contentsName` in explicit mode.
                    for { let q := sub(add(p, c), 1) } 1 { } {
                        e := add(e, 1) // Scan backwards until we encounter a ')'.
                        if iszero(gt(lt(e, c), eq(byte(0, mload(sub(q, e))), 41))) {
                            break
                        }
                    }
                    c := sub(c, e) // Truncate `contentsDescription` to `contentsType`.
                    calldatacopy(p, add(contents.offset, c), e) // Copy `contentsName`.
                    mstore8(add(p, e), 40) // Store a '(' exactly right after the end.
                }
                // `d & 1 == 1` means that `contentsName` is invalid.
                let d := shr(byte(0, mload(p)), 0x7fffffe000000000000010000000000) // Starts with
                // `[a-z(]`.
                // Advance `p` until we encounter '('.
                for { } iszero(eq(byte(0, mload(p)), 40)) { p := add(p, 1) } {
                    d := or(shr(byte(0, mload(p)), 0x120100000001), d) // Has a byte in ", )\x00".
                }
                mstore(p, " contents,string name,string") // Store the rest of the encoding.
                mstore(add(p, 0x1c), " version,uint256 chainId,address")
                mstore(add(p, 0x3c), " verifyingContract,bytes32 salt)")
                p := add(p, 0x5c)
                calldatacopy(p, contents.offset, c) // Copy `contentsType`.
                mstore(t, keccak256(m, sub(add(p, c), m))) // Store `typedDataSignTypehash`.
                // Derive `contents` from `contentsType` and `encodeData`, so that the allowed
                // `contentsDescription` is bound to the struct that was signed.
                mstore(m, keccak256(p, c)) // Store the `contentsType` typehash.
                let n := sub(contents.offset, add(o, 0x20)) // `encodeData.length`.
                calldatacopy(add(m, 0x20), add(o, 0x20), n) // Copy `encodeData`.
                mstore(add(t, 0x20), keccak256(m, add(0x20, n))) // Store `contents` struct hash.
                mstore(0x00, 0x1901) // Store the "\x19\x01" prefix.
                calldatacopy(0x20, o, 0x20) // Copy the `APP_DOMAIN_SEPARATOR`.
                mstore(0x40, mload(add(t, 0x20))) // Copy `contents`.
                // Reject if the reconstructed hash doesn't match, or if `APP_DOMAIN_SEPARATOR` is
                // zero (direct mode). Solady falls back to `PersonalSign` here, which is not
                // supported.
                if or(xor(keccak256(0x1e, 0x42), hash), iszero(mload(0x20))) {
                    t := 0
                    break
                }
                mstore(0x40, keccak256(t, 0xe0)) // `hashStruct(typedDataSign)`.
                // Store the final hash, corrupted if `contentsName` is invalid, at `t`, and the
                // `APP_DOMAIN_SEPARATOR` after it. Passed through memory: two more stack slots
                // here exceed the stack limit.
                mstore(t, keccak256(0x1e, add(0x42, and(1, d))))
                mstore(add(t, 0x20), mload(0x20))
                signature.length := sub(o, signature.offset) // Truncate the signature.
                break
            }
            mstore(0x40, m) // Restore the free memory pointer.
        }
        if (t == uint256(0)) return false;
        bytes32 nestedHash;
        bytes32 appDomainSeparator;
        /// @solidity memory-safe-assembly
        assembly {
            nestedHash := mload(t)
            appDomainSeparator := mload(add(t, 0x20))
        }
        result = _erc1271IsValidSignatureNowCalldata(
            sender, hash, nestedHash, signature, appDomainSeparator, contents
        );
    }
}
