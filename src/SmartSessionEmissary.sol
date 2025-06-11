// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { EmissaryBase } from "./EmissaryBase.sol";
import { SmartSessionMixin } from "./SmartSessionMixin.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries

// Types

/// @title Smart Session Emissary
/// @notice An extended emissary contract that supports multiple verification modes including
///         SmartSessions, traditional stateless validators, and ECDSA/Passkey configurations.
contract SmartSessionEmissary is EmissaryBase, SmartSessionMixin, ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the SmartSessionEmissary contract
    /// @param compact The address of The Compact contract
    /// @param owner The address of the contract owner
    constructor(address compact, address owner) EmissaryBase(compact) SmartSessionMixin(owner) { }

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies claims with mode-based dispatch to appropriate verification method
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The hash of the claim being verified (for traditional modes)
    /// @param claimHash The claim hash being verified (for SmartSession mode)
    /// @param emissaryData Data containing mode byte and mode-specific verification data
    /// @param lockTag The lock tag associated with the claim
    /// @return The selector if valid, otherwise 0xFFFFFFFF
    function verifyClaim(
        address sponsor,
        bytes32 digest,
        bytes32 claimHash,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        external
        view
        override
        returns (bytes4)
    {
        // ERC-7739 support detection
        // Prevent recursive session authorization
        // Extract mode from first byte of emissaryData
        // Mode-based dispatch
        return bytes4(0xFFFFFFFF);
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions using mode-based dispatch
    /// @param account The account for which the policies are being enforced
    /// @param hash The hash of the user operation
    /// @param emissaryData Data containing mode and mode-specific execution data
    /// @param executions The execution data for the user operation
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function verifyExecution(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        bytes calldata executions
    )
        external
        override
        onlyWhitelistedSource
        returns (bytes4)
    {
        // Extract mode from first byte
        // Mode-based dispatch for execution verification
        return bytes4(0xFFFFFFFF);
    }
}
