// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IActionPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";

// Libraries
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

// Contracts
import { Ownable } from "solady/auth/Ownable.sol";

struct TargetConfig {
    address target;
    bool allowed;
}

// forgefmt: disable-start
/// @title Intent Execution Policy
/// @author Rhinestone
/// @notice Action policy that restricts execution targets to a whitelisted set of addresses
///         managed by the contract owner. For ERC20 `approve` calls, validates that the spender
///         is either the paymaster or a whitelisted address.
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                       Validation Logic                                  │
/// │                                                                         │
/// │  checkAction(target, data)                                              │
/// │  │                                                                      │
/// │  ├── selector == approve(address,uint256)?                              │
/// │  │   ├── YES → spender ∈ {paymaster, whitelistedTargets} → ALLOW        │
/// │  │   │         otherwise                                 → DENY         │
/// │  │   │                                                                  │
/// │  │   └── NO  → target ∈ whitelistedTargets               → ALLOW        │
/// │  │             otherwise                                 → DENY         │
/// │  │                                                                      │
/// └─────────────────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
contract IntentExecutionPolicy is IActionPolicy, Ownable {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev ERC20 `approve(address,uint256)` function selector
    bytes4 internal constant APPROVE_SELECTOR = IERC20.approve.selector;

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Paymaster address allowed as spender in approve calls
    address public paymaster;

    /// @notice Set of whitelisted target addresses
    mapping(address target => bool isWhitelisted) public whitelistedTargets;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Emitted when a target address is added or removed from the whitelist
    event TargetWhitelisted(address indexed target, bool allowed);
    /// @dev Emitted when the paymaster address is updated
    event PaymasterSet(address indexed paymaster);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _owner The owner address with permission to manage the whitelist
    /// @param _paymaster The initial paymaster address allowed as spender in approve calls
    constructor(address _owner, address _paymaster) {
        _initializeOwner(_owner);
        paymaster = _paymaster;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Add or remove multiple addresses from the target whitelist
    /// @param entries Array of target/allowed pairs
    function setWhitelistedTargets(TargetConfig[] calldata entries) external onlyOwner {
        for (uint256 i; i < entries.length; i++) {
            whitelistedTargets[entries[i].target] = entries[i].allowed;
            emit TargetWhitelisted(entries[i].target, entries[i].allowed);
        }
    }

    /// @notice Update the paymaster address
    /// @param _paymaster The new paymaster address
    function setPaymaster(address _paymaster) external onlyOwner {
        paymaster = _paymaster;
        emit PaymasterSet(_paymaster);
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice No per-session configuration needed; whitelist is managed globally by owner
    function initializeWithMultiplexer(address, ConfigId, bytes calldata) external override { }

    /*//////////////////////////////////////////////////////////////
                          ACTION VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates an action against the whitelist policy
    /// @dev If the call is an ERC20 `approve`, validates the spender is the paymaster or
    ///      a whitelisted address. Otherwise, validates the target is whitelisted.
    /// @param target The target contract being called
    /// @param data The calldata of the action
    /// @return VALIDATION_SUCCESS if allowed, VALIDATION_FAILED otherwise
    function checkAction(
        ConfigId,
        address,
        address target,
        uint256,
        bytes calldata data
    )
        external
        view
        returns (uint256)
    {
        // If the target is whitelisted, allow immediately without further checks
        if (whitelistedTargets[target]) {
            return VALIDATION_SUCCESS;
        }

        // otherwise If selector is `approve(address,uint256)`, validate the spender
        if (data.length >= 4 && bytes4(data[0:4]) == APPROVE_SELECTOR) {
            if (data.length >= 36) {
                address spender = address(bytes20(data[16:36]));
                if (spender == paymaster || whitelistedTargets[spender]) {
                    return VALIDATION_SUCCESS;
                }
            }
            return VALIDATION_FAILED;
        }

        return VALIDATION_FAILED;
    }

    /*//////////////////////////////////////////////////////////////
                              ERC165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC165 interface support
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(IActionPolicy).interfaceId
                || interfaceId == type(IERC165).interfaceId;
    }
}
