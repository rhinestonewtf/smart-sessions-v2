// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { ERC7579ValidatorBase } from "@modulekit/module-bases/ERC7579ValidatorBase.sol";

// Constants
import { Constants } from "@compact-utils/types/Constants.sol";
import { MODULE_TYPE_VALIDATOR } from "@modulekit/ModuleKit.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Types
import { PackedUserOperation } from "@modulekit/external/ERC4337.sol";

/// @title Permit2CompatibilityValidator
/// @notice A validator that allows Smart Session emissary contracts to be used with
///         Permit2 signature validation
contract Permit2CompatibilityValidator is ERC7579ValidatorBase {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when a function is not supported
    error NotSupported();

    /// @notice Thrown when a function is called by an unauthorized sender
    error InvalidSender();

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Address of the Smart Session Emissary contract
    ISmartSessionEmissary public immutable SMART_SESSION_EMISSARY;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Constructor to set the Smart Session Emissary address
    /// @parm smartSessionEmissary The address of the Smart Session Emissary contract
    constructor(address smartSessionEmissary) {
        SMART_SESSION_EMISSARY = ISmartSessionEmissary(smartSessionEmissary);
    }

    /*//////////////////////////////////////////////////////////////
                               VALIDATION
    //////////////////////////////////////////////////////////////*/

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        virtual
        override
        returns (bytes4)
    {
        // Only allow calls from the PERMIT2 contract
        require(sender == address(Constants.PERMIT2), InvalidSender());
        // Decode lockTag from the first 12 bytes of data
        bytes12 lockTag = bytes12(data[:12]);
        // Delegate to the Smart Session Emissary for signature verification
        return SMART_SESSION_EMISSARY.verifyClaim({
            sponsor: msg.sender,
            digest: hash,
            claimHash: bytes32(0),
            emissaryData: data[12:],
            lockTag: lockTag
        });
    }

    /*//////////////////////////////////////////////////////////////
                              7579 CONFIG
    //////////////////////////////////////////////////////////////*/

    function onInstall(bytes calldata) external override { }

    function onUninstall(bytes calldata) external override { }

    function isModuleType(uint256 moduleTypeId) external view override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view override returns (bool) { }

    /*//////////////////////////////////////////////////////////////
                              UNSUPPORTED
    //////////////////////////////////////////////////////////////*/

    /// @notice Stub to satisfy the interface, always reverts
    function validateUserOp(
        PackedUserOperation calldata,
        bytes32
    )
        external
        virtual
        override
        returns (ValidationData)
    {
        revert NotSupported();
    }
}
