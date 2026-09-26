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
import { Paymaster } from "@compact-utils/executor/StandaloneIntent/aux/Paymaster.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title OneTimeUseIdPolicy.checkAction Unit Tests
/// @notice Unit tests for the checkAction function: the burn happens HERE, when the session's own
///         burn op is validated, and every other op of the transaction rides it.
contract OneTimeUseIdPolicy_checkAction_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 SCOPING
    //////////////////////////////////////////////////////////////*/

    /// @notice Test an unconfigured configId fails closed
    function test_checkAction_unconfigured_returnsFailed() external {
        ConfigId never = ConfigId.wrap(keccak256("never.installed"));

        assertEq(_validateBurn(never), FAILED, "an unconfigured slot cannot burn");
        assertEq(_validatePlain(never), FAILED, "and fails closed on every op");
    }

    /*//////////////////////////////////////////////////////////////
                          THE BURN IS THE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test validating the session's own consume burns the id, durably, at once
    function test_checkAction_validatingTheBurn_burnsTheId() external {
        assertFalse(_burned(ID_A));

        vm.expectEmit(true, true, false, true);
        emit IOneTimeUseIdPolicy.IdConsumed(account, ID_A);
        assertEq(_validateBurn(cfgA), SUCCESS, "the burn validates");

        assertTrue(_burned(ID_A), "and the id is spent before anything executes");
    }

    /// @notice Test an unburned id lets the batch through once its burn led
    function test_checkAction_burnThenPlain_returnsSuccess() external {
        assertEq(_validate(cfgA), SUCCESS, "a burn-led batch validates");
    }

    /// @notice Test an execution validated before any burn is refused, so a batch that never burns
    ///         cannot settle
    function test_checkAction_executionBeforeTheBurn_returnsFailed() external {
        assertEq(_validatePlain(cfgA), FAILED, "no burn validated yet");
        assertEq(
            _checkAction(cfgA, makeAddr("someToken"), hex"a9059cbb"),
            FAILED,
            "not even an unrelated call"
        );
        assertFalse(_burned(ID_A), "and nothing was spent");
    }

    /// @notice Test every execution of the burning transaction validates, across batches
    function test_checkAction_validatesEveryExecutionInTheBurningTransaction() external {
        _validateBurn(cfgA);
        for (uint256 i; i < 8; ++i) {
            assertEq(_validatePlain(cfgA), SUCCESS, "every later op in the transaction passes");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        ONE BURN PER TRANSACTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test a second consume in the same transaction is refused
    function test_checkAction_secondConsumeInTheTransaction_returnsFailed() external {
        assertEq(_validateBurn(cfgA), SUCCESS, "the first burn validates");

        assertEq(_validateBurn(cfgA), FAILED, "the second is refused");
        assertEq(_validatePlain(cfgA), SUCCESS, "the batch behind the first still runs");
    }

    /// @notice Test a consumeFor after a consume is refused, so the burning transaction can hold
    ///         at most one nomination
    function test_checkAction_consumeForAfterConsume_returnsFailed() external {
        _validateBurn(cfgA);

        assertEq(_validateBurnFor(cfgA, WITNESS_1), FAILED, "no second burn, no nomination");
        assertFalse(_settlingCheck(cfgA, WITNESS_1), "so nothing settles on it");
    }

    /// @notice Test a second consumeFor is refused and does not replace the first nomination
    function test_checkAction_secondConsumeFor_returnsFailedAndKeepsTheNomination() external {
        assertEq(_validateBurnFor(cfgA, WITNESS_1), SUCCESS, "the first burn nominates");

        assertEq(_validateBurnFor(cfgA, WITNESS_2), FAILED, "the second is refused");
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "the first nomination stands");
        assertFalse(_settlingCheck(cfgA, WITNESS_2), "the second never existed");
    }

    /// @notice Test the burn is shared by every action slot pinned to the same id
    function test_checkAction_burnSharedAcrossActionSlots() external {
        ConfigId cfgC = ConfigId.wrap(keccak256("session.A.slot.2"));
        _install(cfgC, ID_A);

        assertEq(_validateBurn(cfgA), SUCCESS, "slot A burns");

        assertEq(_validateBurn(cfgC), FAILED, "the other slot cannot burn the same id again");
        assertEq(_validatePlain(cfgC), SUCCESS, "but its ops ride the same burn");
    }

    /*//////////////////////////////////////////////////////////////
                      A LATER TRANSACTION IS REFUSED
    //////////////////////////////////////////////////////////////*/

    // See OneTimeUseIdPolicy_checkAction_CrossTransaction_Unit_Test below.

    /*//////////////////////////////////////////////////////////////
                         WHOSE BURN COUNTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test another session's burn does not approve this session's executions
    function test_checkAction_anotherSessionsBurn_doesNotApproveThisOne() external {
        assertEq(_validateBurn(cfgB), SUCCESS, "session B's own burn validates");

        assertEq(_validatePlain(cfgA), FAILED, "session A still needs its own burn");
        assertFalse(_burned(ID_A), "and A's id is unspent");
    }

    /// @notice Test a burn validated under another multiplexer neither spends this one's record
    ///         nor approves its executions
    function test_checkAction_burnUnderAnotherMultiplexer_changesNothingHere() external {
        address otherMultiplexer = makeAddr("otherMultiplexer");
        vm.prank(otherMultiplexer);
        policy.initializeWithMultiplexer(account, cfgA, abi.encodePacked(bytes32(ID_A), bytes32(0)));

        vm.prank(otherMultiplexer);
        uint256 result = policy.checkAction(
            cfgA, account, address(policy), 0, abi.encodeCall(policy.consume, (ID_A))
        );
        assertEq(result, SUCCESS, "the other multiplexer burns its own record");

        assertTrue(policy.isUsed(otherMultiplexer, account, ID_A), "under its own key");
        assertFalse(_burned(ID_A), "not under this multiplexer's");
        assertEq(_validatePlain(cfgA), FAILED, "this multiplexer's session still needs its burn");
        assertEq(_validate(cfgA), SUCCESS, "and can still perform it");
    }

    /*//////////////////////////////////////////////////////////////
                    THE BURN OP NAMES THE SESSION'S OWN ID
    //////////////////////////////////////////////////////////////*/

    /// @notice Test a session may not name another session's id in a consume call
    function test_checkAction_consumeForeignId_returnsFailed() external {
        bytes memory burnSomeoneElse = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_A));

        assertEq(_checkAction(cfgB, address(policy), burnSomeoneElse), FAILED);
        assertFalse(_burned(ID_A), "session A's id is untouched");
    }

    /// @notice Test a consumeFor naming the session's own id passes and nominates
    function test_checkAction_consumeForOwnId_returnsSuccessAndNominates() external {
        assertEq(_validateBurnFor(cfgB, WITNESS_1), SUCCESS);

        assertTrue(_burned(ID_B), "burned");
        assertTrue(_settlingCheck(cfgB, WITNESS_1), "and nominated");
    }

    /// @notice Test the executor route may not nominate a settlement for another session's id
    function test_checkAction_consumeForForeignId_returnsFailed() external {
        bytes memory nominateOther =
            abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_A, WITNESS_1));

        assertEq(_checkAction(cfgB, address(policy), nominateOther), FAILED);
        assertFalse(_settlingCheck(cfgA, WITNESS_1), "no nomination for A");
    }

    /// @notice Test a consume does not nominate any settlement
    function test_checkAction_consume_doesNotNominate() external {
        _validateBurn(cfgA);

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "nothing for the settling check to match");
    }

    /// @notice Test a burn op carrying value is refused (the burn ops are not payable)
    function test_checkAction_burnWithValue_returnsFailed() external {
        vm.prank(multiplexer);
        uint256 result = policy.checkAction(
            cfgA, account, address(policy), 1, abi.encodeCall(policy.consume, (ID_A))
        );

        assertEq(result, FAILED);
        assertFalse(_burned(ID_A));
    }

    /// @notice Test a malformed consume self-call (selector-only calldata) fails closed
    function test_checkAction_malformedConsume_failsClosed() external {
        bytes memory malformed = abi.encodePacked(IOneTimeUseIdPolicy.consume.selector);

        assertEq(_checkAction(cfgB, address(policy), malformed), FAILED);
    }

    /// @notice Test a consumeFor carrying its own id but no witness word fails closed
    function test_checkAction_truncatedConsumeFor_failsClosed() external {
        bytes memory truncated = abi.encodePacked(IOneTimeUseIdPolicy.consumeFor.selector, ID_B);

        assertEq(_checkAction(cfgB, address(policy), truncated), FAILED);
        assertFalse(_burned(ID_B));
    }

    /// @notice Test a self-call with no selector (calldata shorter than 4 bytes) fails closed
    function test_checkAction_selectorlessSelfCall_failsClosed() external {
        assertEq(_checkAction(cfgB, address(policy), hex"0011"), FAILED);
    }

    /// @notice Test a non-burn self-call is a plain execution: refused before the burn, admitted
    ///         after it
    function test_checkAction_nonBurnSelfCall_isAPlainExecution() external {
        bytes memory view_ = abi.encodeCall(policy.isUsed, (multiplexer, account, ID_A));

        assertEq(_checkAction(cfgA, address(policy), view_), FAILED, "before the burn");
        _validateBurn(cfgA);
        assertEq(_checkAction(cfgA, address(policy), view_), SUCCESS, "after it");
    }

    /// @notice Test an action unrelated to this policy passes once the session's burn led the batch
    function test_checkAction_unrelatedAction_afterTheBurn_returnsSuccess() external {
        _validateBurn(cfgB);

        assertEq(_checkAction(cfgB, makeAddr("someToken"), hex"a9059cbb"), SUCCESS);
    }

    /*//////////////////////////////////////////////////////////////
                  ONE GAS-REFUND CALLBACK PER TRANSACTION (H1)
    //////////////////////////////////////////////////////////////*/

    function _refundCallback() internal pure returns (bytes memory) {
        return abi.encodeCall(Paymaster.callbackAllowMaxAmount, (address(0), 1 ether));
    }

    /// @notice Test the pinned selector is the Paymaster's callback selector
    function test_checkAction_refundCallbackSelector_matchesThePaymaster() external pure {
        assertEq(Paymaster.callbackAllowMaxAmount.selector, bytes4(0x482ac196));
    }

    /// @notice Test the refund callback is admitted once behind the burn
    function test_checkAction_refundCallback_admittedOncePerTransaction() external {
        _validateBurn(cfgA);

        assertEq(_checkAction(cfgA, makeAddr("paymaster"), _refundCallback()), SUCCESS, "first");
        assertEq(_checkAction(cfgA, makeAddr("paymaster"), _refundCallback()), FAILED, "second");
        assertEq(_checkAction(cfgA, makeAddr("elsewhere"), _refundCallback()), FAILED, "any target");
        assertEq(_validatePlain(cfgA), SUCCESS, "other ops still ride the burn");
    }

    /// @notice Test the refund callback needs the burn like any other op
    function test_checkAction_refundCallback_beforeTheBurn_returnsFailed() external {
        assertEq(_checkAction(cfgA, makeAddr("paymaster"), _refundCallback()), FAILED);
    }

    /// @notice Test the once-per-transaction bound is per (multiplexer, account, id)
    function test_checkAction_refundCallback_isPerSession() external {
        _validateBurn(cfgA);
        _validateBurn(cfgB);

        assertEq(_checkAction(cfgA, makeAddr("paymaster"), _refundCallback()), SUCCESS);
        assertEq(_checkAction(cfgB, makeAddr("paymaster"), _refundCallback()), SUCCESS, "B's own");
        assertEq(_checkAction(cfgB, makeAddr("paymaster"), _refundCallback()), FAILED);
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

        assertEq(_validateBurn(cfgA), FAILED, "an expired session cannot even burn");
        assertEq(_validatePlain(cfgA), FAILED, "nor run anything");
        assertFalse(_burned(ID_A), "and nothing was spent");
    }

    /// @notice Test the deadline is inclusive of the block it names
    function test_checkAction_atDeadline_succeeds() external {
        vm.warp(1000);
        uint256 expiry = block.timestamp + 1 hours;
        _install(cfgA, ID_A, expiry);

        vm.warp(expiry);

        assertEq(_validate(cfgA), SUCCESS, "valid in the block the deadline names");
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

/// @title The cross-transaction half of checkAction
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

    /// @dev The burn happens HERE, so the test body below runs in a different transaction
    function setUp() public {
        policy = new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2), makeAddr("intentExecutor"));

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(ID), bytes32(0)));

        vm.prank(multiplexer);
        policy.checkAction(cfg, account, address(policy), 0, abi.encodeCall(policy.consume, (ID)));
        assertTrue(policy.isUsed(multiplexer, account, ID), "setUp burned");
    }

    /// @notice Test a burn from an earlier transaction refuses every op and every further burn
    function test_checkAction_laterTransaction_isRefused() external {
        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(cfg, account, address(0), 0, ""),
            VALIDATION_FAILED,
            "a plain op in a later transaction is refused"
        );

        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(
                cfg, account, address(policy), 0, abi.encodeCall(policy.consume, (ID))
            ),
            VALIDATION_FAILED,
            "and so is another burn"
        );
    }
}
