// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Mock Time-Based Policy
/// @notice Example policy that validates signatures based on time windows and signers
/// @dev This policy demonstrates a realistic use case for 1271 validation
contract MockTimeBasedPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct PolicyConfig {
        address allowedSigner;
        uint256 validAfter;
        uint256 validUntil;
        uint256 maxAmount;
    }

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Stores policy configurations per configId and account
    mapping(ConfigId => mapping(address => PolicyConfig)) public configs;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotInitialized();
    error SignerNotAllowed();
    error OutsideTimeWindow();
    error AmountTooHigh();

    /*//////////////////////////////////////////////////////////////
                              FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize policy with time window and signer constraints
    /// @param account The account this policy is being initialized for
    /// @param configId The configuration ID for this policy instance
    /// @param initData Encoded (allowedSigner, validAfter, validUntil, maxAmount)
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        (address allowedSigner, uint256 validAfter, uint256 validUntil, uint256 maxAmount) =
            abi.decode(initData, (address, uint256, uint256, uint256));

        require(validUntil > validAfter, "Invalid time window");
        require(allowedSigner != address(0), "Invalid signer");

        configs[configId][account] = PolicyConfig({
            allowedSigner: allowedSigner,
            validAfter: validAfter,
            validUntil: validUntil,
            maxAmount: maxAmount
        });
    }

    /// @notice Validate signature based on time window and signer
    /// @param configId The configuration ID to use
    /// @param account The account that enabled this policy
    /// @param data Encoded validation data: (signer, amount, timestamp)
    /// @return True if validation passes, reverts otherwise
    function check1271SignedAction(
        ConfigId configId,
        address, // multiplexor
        address account,
        bytes32, // hash
        bytes calldata data
    )
        external
        view
        override
        returns (bool)
    {
        PolicyConfig memory config = configs[configId][account];

        if (config.allowedSigner == address(0)) revert NotInitialized();

        // Decode validation data
        (address signer, uint256 amount, uint256 timestamp) =
            abi.decode(data, (address, uint256, uint256));

        // Check signer
        if (signer != config.allowedSigner) revert SignerNotAllowed();

        // Check time window
        if (timestamp < config.validAfter || timestamp > config.validUntil) {
            revert OutsideTimeWindow();
        }

        // Check amount
        if (amount > config.maxAmount) revert AmountTooHigh();

        return true;
    }

    /// @notice ERC-165 support
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(I1271Policy).interfaceId;
    }
}
