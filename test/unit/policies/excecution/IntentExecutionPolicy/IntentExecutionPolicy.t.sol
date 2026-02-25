// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "@forge-std/Test.sol";

// Contracts
import { IntentExecutionPolicy } from "@policies/excecution/IntentExecutionPolicy.sol";

// Interfaces
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

// Libraries
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title IntentExecutionPolicy Unit Test Base
/// @notice Base test contract for IntentExecutionPolicy unit tests
abstract contract IntentExecutionPolicy_Unit_Test is Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 internal constant SUCCESS = VALIDATION_SUCCESS;
    uint256 internal constant FAILED = VALIDATION_FAILED;

    bytes4 internal constant APPROVE_SELECTOR = IERC20.approve.selector;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    IntentExecutionPolicy internal policy;

    ConfigId internal configId;
    address internal owner;
    address internal paymasterAddr;

    // Test addresses
    address internal whitelistedTarget1;
    address internal whitelistedTarget2;
    address internal nonWhitelistedTarget;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        // Set up test values
        configId = ConfigId.wrap(bytes32(uint256(1)));
        owner = makeAddr("owner");
        paymasterAddr = makeAddr("paymaster");

        // Set up test addresses
        whitelistedTarget1 = makeAddr("whitelistedTarget1");
        whitelistedTarget2 = makeAddr("whitelistedTarget2");
        nonWhitelistedTarget = makeAddr("nonWhitelistedTarget");

        // Deploy policy with initial whitelisted targets
        address[] memory initialTargets = new address[](2);
        initialTargets[0] = whitelistedTarget1;
        initialTargets[1] = whitelistedTarget2;
        policy = new IntentExecutionPolicy(owner, paymasterAddr, initialTargets);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds an ERC20 approve calldata
    /// @param spender The spender address
    /// @param amount The amount to approve
    /// @return The encoded approve calldata
    function _encodeApprove(address spender, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC20.approve.selector, spender, amount);
    }

    /// @notice Builds a non-approve calldata with a given selector
    /// @param selector The function selector
    /// @return The encoded calldata
    function _encodeCall(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(selector);
    }
}
