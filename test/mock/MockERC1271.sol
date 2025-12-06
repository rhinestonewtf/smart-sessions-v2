// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Interfaces
import { IERC1271, EIP1271_MAGIC_VALUE } from "@modulekit/module-bases/interfaces/IERC1271.sol";
// Libraries
import { SignatureLib } from "@lib/SignatureLib.sol";
/// @notice Mock ERC1271 contract for testing

contract MockERC1271 is IERC1271 {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes4 constant INVALID_SIGNATURE_SELECTOR = 0xffffffff;

    bool public shouldReturnValid = true;
    address public owner;

    constructor(address _initialOwner) {
        owner = _initialOwner;
    }

    function setShouldReturnValid(bool _shouldReturn) external {
        shouldReturnValid = _shouldReturn;
    }

    function setOwner(address _owner) external {
        owner = _owner;
    }

    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        override
        returns (bytes4)
    {
        if (!shouldReturnValid) {
            return INVALID_SIGNATURE_SELECTOR;
        }

        // Simple mock: check if signature contains the hash
        if (signature.length >= 32 && bytes32(signature[0:32]) == hash) {
            return EIP1271_MAGIC_VALUE;
        }

        // Or check if it's a valid ECDSA signature from owner
        if (signature.length == 65 && owner != address(0)) {
            address recovered = recoverECDSA(hash, signature);
            if (recovered == owner) {
                return EIP1271_MAGIC_VALUE;
            }
        }

        return INVALID_SIGNATURE_SELECTOR;
    }

    /*//////////////////////////////////////////////////////////////
                                 ECDSA
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates an ECDSA signature for a given hash, only supports 65-byte signatures.
    /// @param hash The hash to validate the signature against
    /// @param signature The ECDSA signature to validate
    /// @return result The address that signed the hash
    function recoverECDSA(
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        returns (address result)
    {
        /// @solidity memory-safe-assembly
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let m := mload(0x40) // Cache free memory pointer
            mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // 'v'
            calldatacopy(0x40, signature.offset, 0x40) // Copy 'r' and 's'
            mstore(0x00, hash) // Store the hash
            result := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)) // Call ecrecover
            // `returndatasize() will be '0x20' if successful, otherwise it will be '0'.
            if iszero(returndatasize()) {
                mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0x00) // Restore the zero slot
            mstore(0x40, m) // Restore free memory pointer
        }
    }
}
