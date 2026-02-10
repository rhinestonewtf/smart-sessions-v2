// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Mock Time-Based Policy
/// @notice Example policy that validates signatures based on time windows and signers
contract MockTimeBasedPolicy is I1271Policy {
    struct PolicyConfig {
        address allowedSigner;
        uint256 validAfter;
        uint256 validUntil;
        uint256 maxAmount;
    }

    mapping(ConfigId => mapping(address => PolicyConfig)) public configs;

    error NotInitialized();
    error SignerNotAllowed();
    error OutsideTimeWindow();
    error AmountTooHigh();

    /// @notice Initialize policy with time window and signer constraints
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

        configs[configId][account] = PolicyConfig({
            allowedSigner: allowedSigner,
            validAfter: validAfter,
            validUntil: validUntil,
            maxAmount: maxAmount
        });
    }

    /// @notice Validate signature based on time window and signer
    function check1271SignedAction(
        ConfigId configId,
        address, // multiplexer
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
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId || interfaceId == type(I1271Policy).interfaceId;
    }
}
