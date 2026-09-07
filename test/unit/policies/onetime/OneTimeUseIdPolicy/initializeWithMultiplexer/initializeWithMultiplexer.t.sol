// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title OneTimeUseIdPolicy.initializeWithMultiplexer Unit Tests
/// @notice Unit tests for the initializeWithMultiplexer function
contract OneTimeUseIdPolicy_initializeWithMultiplexer_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                              INIT DATA SHAPE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test reverts when initData is not exactly two words
    function test_initializeWithMultiplexer_revertsWhen_initDataNot64Bytes() external {
        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(IOneTimeUseIdPolicy.InvalidInitDataLength.selector, uint256(63))
        );
        policy.initializeWithMultiplexer(account, ConfigId.wrap(keccak256("short")), new bytes(63));
    }

    /// @notice Test reverts when initData carries an id but no deadline
    function test_initializeWithMultiplexer_revertsWhen_deadlineOmitted() external {
        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(IOneTimeUseIdPolicy.InvalidInitDataLength.selector, uint256(32))
        );
        policy.initializeWithMultiplexer(
            account, ConfigId.wrap(keccak256("no.deadline")), abi.encodePacked(bytes32(ID_A))
        );
    }

    /// @notice Test reverts when the id is zero
    function test_initializeWithMultiplexer_revertsWhen_idIsZero() external {
        vm.prank(multiplexer);
        vm.expectRevert(IOneTimeUseIdPolicy.InvalidId.selector);
        policy.initializeWithMultiplexer(
            account,
            ConfigId.wrap(keccak256("zero")),
            abi.encodePacked(bytes32(0), bytes32(NO_DEADLINE))
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 DEADLINE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test reverts when the deadline has already passed
    function test_initializeWithMultiplexer_revertsWhen_deadlineAlreadyPassed() external {
        vm.warp(1000);
        uint256 past = block.timestamp - 1;

        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IOneTimeUseIdPolicy.DeadlineInPast.selector, past, block.timestamp
            )
        );
        policy.initializeWithMultiplexer(
            account,
            ConfigId.wrap(keccak256("past")),
            abi.encodePacked(bytes32(ID_A), bytes32(past))
        );
    }

    /// @notice Test the current timestamp is accepted, matching the inclusive read rule
    function test_initializeWithMultiplexer_acceptsDeadlineAtCurrentTimestamp() external {
        vm.warp(1000);
        _install(cfgA, ID_A, block.timestamp);

        assertEq(_validate(cfgA), SUCCESS, "a deadline of now is still valid in this block");
    }

    /// @notice Test a zero deadline pins a session that never expires
    function test_initializeWithMultiplexer_zeroDeadlineNeverExpires() external {
        _install(cfgA, ID_A, NO_DEADLINE);

        vm.warp(block.timestamp + 3650 days);

        assertEq(_validate(cfgA), SUCCESS, "zero means no expiry");
    }

    /*//////////////////////////////////////////////////////////////
                            PER-MULTIPLEXER SCOPING
    //////////////////////////////////////////////////////////////*/

    /// @notice Test a rogue multiplexer that never installed sees no configuration
    function test_initializeWithMultiplexer_anotherMultiplexerSeesNothing() external {
        address rogue = makeAddr("rogue");

        vm.prank(rogue);
        uint256 result = policy.checkAction(cfgA, account, address(0), 0, "");

        assertEq(result, FAILED, "a different multiplexer has no configuration");
    }

    /*//////////////////////////////////////////////////////////////
                              RE-INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test re-initializing a burned id does not restore the spend
    function test_initializeWithMultiplexer_reEnablingOnABurnedId_doesNotRestoreTheSpend()
        external
    {
        _consumeFor(ID_A, WITNESS_1);
        _install(cfgA, ID_A);

        assertEq(_validate(cfgA), FAILED, "a stale pin denies");
    }

    /// @notice Test re-initializing with a fresh id settles again
    function test_initializeWithMultiplexer_reEnablingOnAFreshId_settlesAgain() external {
        _consumeFor(ID_A, WITNESS_1);
        _install(cfgA, ID_A + 99);

        assertEq(_validate(cfgA), SUCCESS, "a fresh pin is a fresh spend");
    }
}
