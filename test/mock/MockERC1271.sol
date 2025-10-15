// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Interfaces
import { IERC1271, EIP1271_MAGIC_VALUE } from "@modulekit/module-bases/interfaces/IERC1271.sol";
// Libraries
import { SignatureLib } from "@lib/SignatureLib.sol";
/// @notice Mock ERC1271 contract for testing

contract MockERC1271 is IERC1271 {
    /* //////////////////////////////////////////////////////////////
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

    function isValidSignature(bytes32 hash, bytes calldata signature)
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
            address recovered = SignatureLib.recoverECDSA(hash, signature);
            if (recovered == owner) {
                return EIP1271_MAGIC_VALUE;
            }
        }

        return INVALID_SIGNATURE_SELECTOR;
    }
}
