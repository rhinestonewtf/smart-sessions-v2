// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

// Libraries
import { SignatureLib } from "@lib/SignatureLib.sol";
import { WebAuthn } from "@webauthn/WebAuthn.sol";
import { LibSort } from "@solady/utils/LibSort.sol";

// Types
import { WebAuthVerificationContext } from "@types/DataTypes.sol";

// @title Stateless Validation
// @notice Abstract contract that implements ECDSA and Passkey stateless validation logic
abstract contract StatelessValidation {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using LibSort for *;

    /*//////////////////////////////////////////////////////////////
                                 ECDSA
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a signature against a hash and data using ECDSA
    function _validateSignatureWithDataECDSA(
        bytes32 hash,
        bytes calldata signature,
        bytes memory data
    )
        internal
        view
        returns (bool)
    {
        // decode the threshold and owners
        (uint256 _threshold, address[] memory _owners) = abi.decode(data, (uint256, address[]));

        // check that owners are sorted and uniquified
        if (!_owners.isSortedAndUniquified()) {
            return false;
        }

        // check that threshold is set
        if (_threshold == 0) {
            return false;
        }

        // recover the signers from the signatures using ecrecover
        uint256 sigCount = signature.length / 65;
        address[] memory signers = new address[](sigCount);
        for (uint256 i = 0; i < sigCount; i++) {
            // recover the signer from the hash and signature
            address signer = SignatureLib.recoverECDSA(hash, signature[i * 65:(i + 1) * 65]);
            // store the signer
            signers[i] = signer;
        }

        // sort and uniquify the signers to make sure a signer is not reused
        signers.sort();
        signers.uniquifySorted();

        // check if the signers are owners
        uint256 validSigners;
        for (uint256 i = 0; i < sigCount; i++) {
            (bool found,) = _owners.searchSorted(signers[i]);
            if (found) {
                validSigners++;
            }
        }

        // check if the threshold is met and return the result
        if (validSigners >= _threshold) {
            // if the threshold is met, return true
            return true;
        }
        // if the threshold is not met, return false
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                                PASSKEY
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a signature with external credential data
    /// @dev Used for stateless validation without pre-registered credentials
    /// @param hash Hash of the data to validate
    /// @param signature WebAuthn signature data
    /// @param data Encoded credential details and threshold
    /// @return bool True if the signature is valid, false otherwise
    function _validateSignatureWithDataPasskey(
        bytes32 hash,
        bytes calldata signature,
        bytes memory data
    )
        internal
        view
        returns (bool)
    {
        // Decode the threshold and credentials
        WebAuthVerificationContext memory context = abi.decode(data, (WebAuthVerificationContext));
        // Make sure the credentials are unique and sorted
        context.credentialIds.sort();
        context.credentialIds.uniquifySorted();

        // Decode signature
        // Format: abi.encode(WebAuthn.WebAuthnAuth[])
        WebAuthn.WebAuthnAuth[] memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth[]));

        // Check that arrays have matching lengths
        uint256 credentialsLength = context.credentialIds.length;
        if (credentialsLength != context.credentialData.length) {
            return false;
        }

        // Check that threshold is valid
        if (context.threshold == 0 || context.threshold > credentialsLength) {
            return false;
        }

        // Cache lengths
        uint256 sigCount = auth.length;

        // Check number of signatures
        if (sigCount == 0 || sigCount < context.threshold) {
            return false;
        }

        // Track valid signatures
        uint256 validCount;

        // Verify each signature
        for (uint256 i; i < sigCount; ++i) {
            // Challenge is the hash to be signed
            bytes memory challenge = abi.encode(hash);

            // IMPORTANT:
            // **********************************************************************
            // * We assume here that signatures are ordered to match credential IDs *
            // **********************************************************************

            // Verify the signature against the credential at the same index
            bool valid = WebAuthn.verify(
                challenge,
                context.credentialData[i].requireUV,
                auth[i],
                context.credentialData[i].pubKeyX,
                context.credentialData[i].pubKeyY,
                context.usePrecompile
            );

            if (valid) {
                ++validCount;

                // Early return if threshold is met
                if (validCount >= context.threshold) {
                    return true;
                }
            }
        }

        // If we reach this, we didn't meet the threshold
        return false;
    }
}
