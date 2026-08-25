// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "@forge-std/Test.sol";
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Contracts
import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";

// Interfaces
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title OneTimeUseIdPolicy.isConsumed Unit Tests
/// @notice Unit tests for the isConsumed function
contract OneTimeUseIdPolicy_isConsumed_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /// @notice Test isConsumed returns false before any burn
    function test_isConsumed_returnsFalseInitially() external view {
        assertFalse(policy.isConsumed(account, ID_A));
    }

    /// @notice Test isConsumed returns true after the id is burned
    function test_isConsumed_returnsTrueAfterConsume() external {
        _consume(ID_A);

        assertTrue(policy.isConsumed(account, ID_A));
    }
}

/// @title The cross-transaction half of isConsumed's durability
/// @notice Split into its own contract deliberately. Transient storage survives every call
///         inside one test body - a forge test body IS one transaction - but it IS cleared
///         between `setUp` and the body. Burning in `setUp` is therefore the only way to prove
///         the DURABLE record, rather than the transient tolerance, crossed the boundary.
contract OneTimeUseIdPolicy_isConsumed_CrossTransaction_Unit_Test is Test {
    OneTimeUseIdPolicy internal policy;

    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address internal multiplexer = makeAddr("multiplexer");
    address internal account = makeAddr("account");

    ConfigId internal cfg = ConfigId.wrap(keccak256("session.A"));
    uint256 internal constant ID = 0xBEEF;
    uint256 internal constant WITNESS = 1337;

    /// @dev The burn happens HERE, so the test body below runs in a different transaction
    function setUp() public {
        policy = new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2), makeAddr("intentExecutor"));

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(ID)));

        vm.prank(account);
        policy.consumeFor(ID, WITNESS);
    }

    /// @notice Test the durable burn survives across the transaction boundary
    function test_isConsumed_durableBurnSurvivesSetUp() external view {
        assertTrue(policy.isConsumed(account, ID), "the durable record crossed the boundary");
    }
}
