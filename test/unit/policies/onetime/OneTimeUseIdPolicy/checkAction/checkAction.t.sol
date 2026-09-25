// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "@forge-std/Test.sol";
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Contracts
import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title OneTimeUseIdPolicy.checkAction Unit Tests
/// @notice Unit tests for the checkAction function
contract OneTimeUseIdPolicy_checkAction_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 SCOPING
    //////////////////////////////////////////////////////////////*/

    /// @notice Test an unconfigured configId fails closed
    function test_checkAction_unconfigured_returnsFailed() external {
        ConfigId never = ConfigId.wrap(keccak256("never.installed"));

        assertEq(_validate(never), FAILED, "an unconfigured slot fails closed");
    }

    /*//////////////////////////////////////////////////////////////
                            SPEND STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test an unburned id lets the batch through
    function test_checkAction_unburnedId_returnsSuccess() external {
        assertEq(_validate(cfgA), SUCCESS, "an unburned id must let the batch through");
    }

    /// @notice Test a burned id refuses every further settlement
    function test_checkAction_burnedId_returnsFailed() external {
        assertEq(_validate(cfgA), SUCCESS, "settlement one validates");

        _consumeFor(ID_A, WITNESS_1);

        assertEq(_validate(cfgA), FAILED, "settlement two must be refused");
    }

    /// @notice Test the burn is visible from every action slot pinned to the same id
    function test_checkAction_burnVisibleAcrossActionSlots() external {
        ConfigId cfgC = ConfigId.wrap(keccak256("session.A.slot.2"));
        _install(cfgC, ID_A);

        _consumeFor(ID_A, WITNESS_1);

        assertEq(_validate(cfgA), FAILED, "slot A sees the burn");
        assertEq(_validate(cfgC), FAILED, "the other slot on the same session sees the same burn");
    }

    /// @notice Test every execution in a batch validates while the id stays unburned
    function test_checkAction_validatesEveryExecutionInABatch() external {
        for (uint256 i; i < 8; ++i) {
            assertEq(
                _validate(i % 2 == 0 ? cfgA : cfgB),
                SUCCESS,
                "every execution in one settlement must validate"
            );
        }
    }

    /// @notice Test checkAction does not itself burn the id
    function test_checkAction_doesNotBurn() external {
        _validate(cfgA);

        assertFalse(policy.isUsed(account, ID_A), "validation must not consume the id");
    }

    /*//////////////////////////////////////////////////////////////
                         THE consume SELF-CALL
    //////////////////////////////////////////////////////////////*/

    /// @notice Test a session may burn its own id via the executor route
    function test_checkAction_consumeOwnId_returnsSuccess() external {
        bytes memory burnOwn = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_B));

        uint256 result = _checkAction(cfgB, address(policy), burnOwn);

        assertEq(result, SUCCESS, "its own id is permitted");
    }

    /// @notice Test a session may not name another session's id in a consume call
    function test_checkAction_consumeForeignId_returnsFailed() external {
        bytes memory burnSomeoneElse = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_A));

        uint256 result = _checkAction(cfgB, address(policy), burnSomeoneElse);

        assertEq(result, FAILED, "session B may not burn session A's id");
    }

    /// @notice Test an action unrelated to this policy passes once the session's burn led the batch
    function test_checkAction_unrelatedAction_afterTheBurn_returnsSuccess() external {
        _validateBurn(cfgB);
        uint256 result = _checkAction(cfgB, makeAddr("someToken"), hex"a9059cbb");

        assertEq(result, SUCCESS, "the id binding only applies to self-calls");
    }

    /*//////////////////////////////////////////////////////////////
                         THE BURN MUST LEAD THE BATCH
    //////////////////////////////////////////////////////////////*/

    /// @notice Test an execution validated before any burn is refused, so a batch that never burns
    ///         cannot settle
    function test_checkAction_executionBeforeTheBurn_returnsFailed() external {
        assertEq(_validatePlain(cfgA), FAILED, "no burn validated yet");
        assertEq(
            _checkAction(cfgA, makeAddr("someToken"), hex"a9059cbb"),
            FAILED,
            "not even an unrelated call"
        );
    }

    /// @notice Test another session's burn does not approve this session's executions
    function test_checkAction_anotherSessionsBurn_doesNotApproveThisOne() external {
        assertEq(_validateBurn(cfgB), SUCCESS, "session B's own burn validates");

        assertEq(_validatePlain(cfgA), FAILED, "session A still needs its own burn");
    }

    /// @notice Test a burn validated under one multiplexer does not approve executions under
    /// another
    function test_checkAction_burnUnderAnotherMultiplexer_doesNotApproveThisOne() external {
        address otherMultiplexer = makeAddr("otherMultiplexer");
        vm.prank(otherMultiplexer);
        policy.initializeWithMultiplexer(account, cfgA, abi.encodePacked(bytes32(ID_A), bytes32(0)));
        vm.prank(otherMultiplexer);
        policy.checkAction(
            cfgA, account, address(policy), 0, abi.encodeCall(policy.consume, (ID_A))
        );

        assertEq(
            _validatePlain(cfgA), FAILED, "this multiplexer's session still needs its own burn"
        );
    }

    /*//////////////////////////////////////////////////////////////
                  BEHIND consumeFor ONLY A PERMIT2 APPROVAL RUNS
    //////////////////////////////////////////////////////////////*/

    function _consumeForBurn(ConfigId cfg) internal returns (uint256) {
        return _checkAction(
            cfg, address(policy), abi.encodeCall(policy.consumeFor, (pinnedId[cfg], WITNESS_1))
        );
    }

    function _approve(address spender) internal pure returns (bytes memory) {
        return abi.encodeCall(IERC20.approve, (spender, type(uint256).max));
    }

    /// @notice Test a consumeFor burn does not open the batch: the Permit2-route burn is reachable
    ///         from a permissionless pre-claim the session key can run as its own arbiter
    function test_checkAction_consumeForBurn_refusesAPlainExecution() external {
        assertEq(_consumeForBurn(cfgA), SUCCESS, "the burn itself validates");

        assertEq(_validatePlain(cfgA), FAILED, "nothing else runs behind a consumeFor");
        assertEq(
            _checkAction(cfgA, makeAddr("someToken"), hex"a9059cbb"),
            FAILED,
            "not a transfer either"
        );
    }

    /// @notice Test the one op a real Permit2 pre-claim needs still runs behind consumeFor
    function test_checkAction_consumeForBurn_approvesAPermit2Approval() external {
        _consumeForBurn(cfgA);

        assertEq(
            _checkAction(cfgA, makeAddr("someToken"), _approve(PERMIT2)),
            SUCCESS,
            "approving PERMIT2 moves nothing on its own"
        );
    }

    /// @notice Test an approval of anyone but PERMIT2 is refused behind consumeFor
    function test_checkAction_consumeForBurn_refusesOtherSpender() external {
        _consumeForBurn(cfgA);

        assertEq(
            _checkAction(cfgA, makeAddr("someToken"), _approve(makeAddr("attacker"))),
            FAILED,
            "an approval to any other spender is a spend"
        );
    }

    /// @notice Test a PERMIT2 approval carrying value is refused
    function test_checkAction_consumeForBurn_refusesApprovalWithValue() external {
        _consumeForBurn(cfgA);

        vm.prank(multiplexer);
        uint256 result =
            policy.checkAction(cfgA, account, makeAddr("someToken"), 1, _approve(PERMIT2));

        assertEq(result, FAILED, "value would leave the account");
    }

    /// @notice Test a PERMIT2 approval with bytes appended is refused
    function test_checkAction_consumeForBurn_refusesApprovalWithTrailingBytes() external {
        _consumeForBurn(cfgA);

        assertEq(
            _checkAction(cfgA, makeAddr("someToken"), abi.encodePacked(_approve(PERMIT2), hex"00")),
            FAILED,
            "only the exact approve shape"
        );
    }

    /// @notice Test a consume validated after a consumeFor does not lift the restriction
    function test_checkAction_consumeForBurn_notLiftedByALaterConsume() external {
        _consumeForBurn(cfgA);
        assertEq(_validateBurn(cfgA), SUCCESS, "a second burn still validates");

        assertEq(_validatePlain(cfgA), FAILED, "the consumeFor still bounds the batch");
    }

    /*//////////////////////////////////////////////////////////////
                  THE consumeFor SELF-CALL NAMES ITS OWN ID
    //////////////////////////////////////////////////////////////*/

    /// @notice Test a consumeFor naming the session's own id passes, so a Permit2 pre-claim that
    ///         enables the session in the same settlement can still burn
    function test_checkAction_consumeForOwnId_returnsSuccess() external {
        bytes memory nominateOwn = abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_B, WITNESS_1));

        uint256 result = _checkAction(cfgB, address(policy), nominateOwn);

        assertEq(result, SUCCESS, "a burn of the session's own id is allowed");
    }

    /// @notice Test the executor route may not nominate a settlement for another session's id
    function test_checkAction_consumeForForeignId_returnsFailed() external {
        bytes memory nominateOther =
            abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_A, WITNESS_1));

        uint256 result = _checkAction(cfgB, address(policy), nominateOther);

        assertEq(result, FAILED, "and certainly not another session's id");
    }

    /// @notice Test a malformed consume self-call (selector-only calldata) fails closed
    function test_checkAction_malformedConsume_failsClosed() external {
        bytes memory malformed = abi.encodePacked(IOneTimeUseIdPolicy.consume.selector);

        uint256 result = _checkAction(cfgB, address(policy), malformed);

        assertEq(result, FAILED, "malformed consume calldata must fail closed");
    }

    /// @notice Test a consumeFor carrying its own id but no witness word fails closed
    function test_checkAction_truncatedConsumeFor_failsClosed() external {
        bytes memory truncated = abi.encodePacked(IOneTimeUseIdPolicy.consumeFor.selector, ID_B);

        uint256 result = _checkAction(cfgB, address(policy), truncated);

        assertEq(result, FAILED, "a consumeFor without its witness must fail closed");
    }

    /// @notice Test a self-call with no selector (calldata shorter than 4 bytes) fails closed
    function test_checkAction_selectorlessSelfCall_failsClosed() external {
        uint256 result = _checkAction(cfgB, address(policy), hex"0011");

        assertEq(result, FAILED, "a self-call with no selector must fail closed");
    }

    /*//////////////////////////////////////////////////////////////
                                 DEADLINE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test the executor route settles while the deadline is in the future
    function test_checkAction_beforeDeadline_succeeds() external {
        vm.warp(1000);
        _install(cfgA, ID_A, block.timestamp + 1 hours);

        assertEq(_validate(cfgA), SUCCESS, "unexpired and unburned settles");
    }

    /// @notice Test the executor route refuses once the deadline has passed
    function test_checkAction_afterDeadline_fails() external {
        vm.warp(1000);
        _install(cfgA, ID_A, block.timestamp + 1 hours);

        vm.warp(block.timestamp + 1 hours + 1);

        assertEq(_validate(cfgA), FAILED, "an expired authorization cannot settle");
    }

    /// @notice Test the deadline is inclusive of the block it names
    function test_checkAction_atDeadline_succeeds() external {
        vm.warp(1000);
        uint256 expiry = block.timestamp + 1 hours;
        _install(cfgA, ID_A, expiry);

        vm.warp(expiry);

        assertEq(_validate(cfgA), SUCCESS, "valid in the block the deadline names");
    }

    /// @notice Test the deadline refuses the burn's own op, not just later executions
    function test_checkAction_afterDeadline_refusesTheConsumeOp() external {
        vm.warp(1000);
        _install(cfgA, ID_A, block.timestamp + 1 hours);

        vm.warp(block.timestamp + 1 hours + 1);

        // A well-formed `consume` naming this session's own id, which would otherwise pass.
        bytes memory data = abi.encodeWithSelector(OneTimeUseIdPolicy.consume.selector, ID_A);

        assertEq(
            _checkAction(cfgA, address(policy), data),
            FAILED,
            "an expired session cannot even dispatch its own burn"
        );
    }

    /// @notice Test expiry does not depend on the id being unburned
    function test_checkAction_afterDeadline_failsEvenWhenUnburned() external {
        vm.warp(1000);
        _install(cfgA, ID_A, block.timestamp + 1 hours);
        vm.warp(block.timestamp + 2 hours);

        (, bool consumed,) = policy.usage(cfgA, multiplexer, account);

        assertFalse(consumed, "the id was never burned");
        assertEq(_validate(cfgA), FAILED, "expiry alone is enough to refuse");
    }
}

/// @title The cross-transaction half of checkAction's strictness
/// @notice Split into its own contract deliberately. Transient storage survives every call
///         inside one test body - a forge test body IS one transaction - but it IS cleared
///         between `setUp` and the body. Burning in `setUp` is therefore the only way to observe
///         a LATER transaction.
contract OneTimeUseIdPolicy_checkAction_CrossTransaction_Unit_Test is Test {
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
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(ID), bytes32(0)));

        vm.prank(account);
        policy.consumeFor(ID, WITNESS);
    }

    /// @notice Test a burn from an earlier transaction still refuses the action surface
    function test_checkAction_crossTransactionBurnAlsoRefuses() external {
        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(cfg, account, address(0), 0, ""),
            VALIDATION_FAILED,
            "the action surface does not tolerate a burn from an earlier transaction either"
        );
    }
}
