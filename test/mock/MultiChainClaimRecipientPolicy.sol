// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@forge-std/interfaces/IERC165.sol";

// Contracts
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

import { console } from "@forge-std/console.sol";

/// @title MultiChainClaimRecipientPolicy
/// @notice A policy that allows enforcing rules on the claim recipient of a MultiChainClaim struct
///         The hash of the MultiChainClaim struct hash is reconstructed using the EIP-712
///         standard and passed data within the signature
contract MultiChainClaimRecipientPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Target {
        address recipient;
        bytes32 tokenOut;
        uint256 targetChain;
        uint256 fillExpires;
    }

    struct Mandate {
        Target target;
        bytes32 preClaimOps;
        bytes32 targetOps;
        bytes32 q;
    }

    struct Element {
        address arbiter;
        uint256 chainId;
        bytes32 commitments;
        Mandate mandate;
    }

    struct MultichainCompact {
        address sponsor;
        uint256 nonce;
        uint256 expires;
        Element notarizedElement;
        bytes32[] otherElements;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping to store the recipient configuration for each account and config ID
    /// @dev ConfigId => multiple addresses => user account => allowed recipient address
    mapping(
        ConfigId id
            => mapping(
                address msgSender => mapping(address userOpSender => address allowedRecipient)
            )
    ) internal $recipientConfig;

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the policy with a initializeWithMultiplexer
    /// @param account The account to initialize
    /// @param configId The configuration ID for the policy
    /// @param initData The initialization data containing the recipient address
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        // Parse the recipient address from the initData
        address recipient = abi.decode(initData, (address));
        $recipientConfig[configId][msg.sender][account] = recipient;
        console.logBytes32(ConfigId.unwrap(configId));
        console.log("MultiChainClaimRecipientPolicy initialized for account:", account);
        console.log("Recipient address set to:", recipient);
    }

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

    function check1271SignedAction(
        ConfigId id,
        address, /*sender*/
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        override
        returns (bool)
    {
        // Load the allowed recipient address for the given config ID and multiplexer
        address allowedRecipient = $recipientConfig[id][msg.sender][account];

        console.log("Checking MultiChainClaimRecipientPolicy for account:", account);
        console.log("Allowed recipient:", allowedRecipient);
        console.log("Signature:");
        console.log("multiplexer:", msg.sender);
        console.logBytes32(ConfigId.unwrap(id));
        console.logBytes(signature);

        // Decode data from the signature to reconstruct the MultiChainClaim struct
        // abi.encodePacked(dataLength,data,signature)

        // Extract extraStuff length (first 32 bytes)
        uint256 extraStuffLength;
        assembly {
            extraStuffLength := calldataload(signature.offset)
        }

        // Extract extraStuff
        bytes memory extraStuff = new bytes(extraStuffLength);
        assembly {
            calldatacopy(add(extraStuff, 0x20), add(signature.offset, 0x20), extraStuffLength)
        }

        console.log("Extra stuff:");
        console.logBytes(extraStuff);

        // Decode the extraStuff to get the MultichainCompact struct
        MultichainCompact memory multichainCompact = abi.decode(extraStuff, (MultichainCompact));

        console.log("Decoded MultichainCompact:");
        console.log("Sponsor:", multichainCompact.sponsor);
        console.log("Nonce:", multichainCompact.nonce);
        console.log("Expires:", multichainCompact.expires);
        console.log("Notarized Element Arbiter:", multichainCompact.notarizedElement.arbiter);
        console.log("Notarized Element ChainId:", multichainCompact.notarizedElement.chainId);
        console.log(
            "Target Recipient:", multichainCompact.notarizedElement.mandate.target.recipient
        );

        // Check if the recipient matches the allowed recipient
        address actualRecipient = multichainCompact.notarizedElement.mandate.target.recipient;
        if (actualRecipient != allowedRecipient) {
            console.log("Recipient mismatch!");
            console.log("Expected:", allowedRecipient);
            console.log("Actual:", actualRecipient);
            return false;
        }

        // Rehash the MultichainCompact to verify integrity
        bytes32 recomputedHash = _rehashMultichainCompact(multichainCompact);

        console.log("Original hash:");
        console.logBytes32(hash);
        console.log("Recomputed hash:");
        console.logBytes32(recomputedHash);

        // Verify that the recomputed hash matches the provided hash
        if (recomputedHash != hash) {
            console.log("Hash mismatch!");
            return false;
        }

        console.log("All checks passed!");
        return true;
    }

    function _rehashMultichainCompact(MultichainCompact memory multichainCompact)
        internal
        view
        returns (bytes32)
    {
        // Hash the target attributes
        bytes32 targetHash = _hashTargetAttributes(
            multichainCompact.notarizedElement.mandate.target.recipient,
            multichainCompact.notarizedElement.mandate.target.tokenOut,
            multichainCompact.notarizedElement.mandate.target.targetChain,
            multichainCompact.notarizedElement.mandate.target.fillExpires
        );

        // Hash the mandate
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            multichainCompact.notarizedElement.mandate.preClaimOps,
            multichainCompact.notarizedElement.mandate.targetOps,
            multichainCompact.notarizedElement.mandate.q
        );

        // Hash the notarized element
        bytes32 notarizedElementHash = EIP712TypeHashLib.hashElementRaw(
            multichainCompact.notarizedElement.arbiter,
            multichainCompact.notarizedElement.chainId,
            multichainCompact.notarizedElement.commitments,
            mandateHash
        );

        // Create the full elements array (notarized element + other elements)
        bytes32[] memory allElements = new bytes32[](multichainCompact.otherElements.length + 1);
        allElements[0] = notarizedElementHash;
        for (uint256 i = 0; i < multichainCompact.otherElements.length; i++) {
            allElements[i + 1] = multichainCompact.otherElements[i];
        }

        // Hash the complete MultichainCompact
        bytes32 hash = keccak256(
            abi.encode(
                EIP712TypeHashLib.TYPEHASH_COMPACT,
                multichainCompact.sponsor,
                multichainCompact.nonce,
                multichainCompact.expires,
                keccak256(abi.encodePacked(allElements))
            )
        );

        console.log("Recomputed MultichainCompact hash:");
        console.logBytes32(hash);

        return hash;
    }

    function _hashTargetAttributes(
        address recipient,
        bytes32 tokenOut,
        uint256 targetChain,
        uint256 fillExpires
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                EIP712TypeHashLib.TYPEHASH_TARGET, recipient, tokenOut, targetChain, fillExpires
            )
        );
    }

    /// @notice Checks if the policy supports the given interface ID
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        // Check if the interface ID matches the I1271Policy interface
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(I1271Policy).interfaceId
        );
    }

    function __QUALIFIER_EIP712Hash(bytes calldata) public pure returns (bytes32) {
        revert();
    }
}
