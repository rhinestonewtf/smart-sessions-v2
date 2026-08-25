// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title Audit regressions
/// @notice Every test here reproduced a working exploit before its fix. They are kept as the
///         permanent record that it stays closed.
///
///         The two ERC-1271 checks of one settlement arrive from DIFFERENT callers, and the
///         policy now treats them differently:
///
///           pre-claim check  <- the executor  : runs BEFORE the burn, so it can only ask
///                                               "is this unspent?" — and its refusal is
///                                               swallowed by the arbiter anyway
///           settling check   <- Permit2       : runs AFTER the burn, moves the money, and is
///                                               the only refusal that is not swallowed — so it
///                                               demands positive proof that THIS settlement
///                                               burned
contract OneTimeUseIdAuditRegressions_Test is Test {
    OneTimeUseIdPolicy internal policy;

    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address internal executor = makeAddr("intentExecutor");

    address internal multiplexer = makeAddr("multiplexer");
    address internal account = makeAddr("account");

    ConfigId internal cfgA = ConfigId.wrap(keccak256("session.A"));
    ConfigId internal cfgB = ConfigId.wrap(keccak256("session.B"));

    uint256 internal constant ID_A = 0xBEEF;
    uint256 internal constant ID_B = 0xCAFE;

    /// @dev Stands in for a settlement's Permit2 nonce
    uint256 internal constant WITNESS_1 = 1337;
    uint256 internal constant WITNESS_2 = 4242;

    function setUp() public {
        policy = new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2));

        vm.startPrank(multiplexer);
        policy.initializeWithMultiplexer(account, cfgA, abi.encodePacked(bytes32(ID_A)));
        policy.initializeWithMultiplexer(account, cfgB, abi.encodePacked(bytes32(ID_B)));
        vm.stopPrank();
    }

    /// @dev A claim blob shaped like `Permit2ClaimPolicy`'s: arbiter(20) ‖ nonce(32) ‖ …
    function _blob(uint256 nonce) internal pure returns (bytes memory) {
        return abi.encodePacked(address(0xA4B17E4), bytes32(nonce), bytes32(uint256(99)));
    }

    /// @dev The check that moves the money
    function _settlingCheck(ConfigId c, uint256 nonce) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(c, PERMIT2, account, bytes32(0), _blob(nonce));
    }

    /// @dev The pre-claim check, which runs before the burn
    function _preClaimCheck(ConfigId c, uint256 nonce) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(c, executor, account, bytes32(0), _blob(nonce));
    }

    function _validate(ConfigId c) internal returns (uint256) {
        vm.prank(multiplexer);
        return policy.checkAction(c, account, address(0), 0, "");
    }

    function _settlementBurns(uint256 id, uint256 witness) internal {
        vm.prank(account);
        policy.consumeFor(id, witness);
    }

    /// @dev The action route's burn, which nominates nothing
    function _actionBurns(uint256 id) internal {
        vm.prank(account);
        policy.consume(id);
    }

    /*//////////////////////////////////////////////////////////////
                        AN HONEST SETTLEMENT COMPLETES
    //////////////////////////////////////////////////////////////*/

    function test_theHonestSettlementCompletes() public {
        assertTrue(_preClaimCheck(cfgA, WITNESS_1), "pre-claim, nothing burned yet");
        _settlementBurns(ID_A, WITNESS_1);
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "settling check, proof presented");
    }

    /*//////////////////////////////////////////////////////////////
              F1 — A SECOND SETTLEMENT CANNOT RIDE THE FIRST
    //////////////////////////////////////////////////////////////*/

    /// @dev Was: the tolerance was a bare "something burned in this transaction" flag, so a
    ///      second settlement read it as its own. It did not even need its own `consume`.
    function test_F1_aSecondSettlementCannotRideTheFirstsBurn() public {
        _settlementBurns(ID_A, WITNESS_1);
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "settlement one completes");

        // Settlement two, different nonce, SAME transaction. It never calls consume — which was
        // the whole attack, because the poison rule only fired if the attacker volunteered it.
        assertFalse(_settlingCheck(cfgA, WITNESS_2), "settlement two cannot ride it");
    }

    /// @dev ...and it cannot help itself by calling consume either: the id is already spent, so
    ///      the nomination is cleared rather than re-issued.
    function test_F1_aSecondSettlementCannotRenominateItself() public {
        _settlementBurns(ID_A, WITNESS_1);
        _settlementBurns(ID_A, WITNESS_2);

        assertFalse(_settlingCheck(cfgA, WITNESS_2), "a repeat consume nominates nothing");
        assertFalse(_settlingCheck(cfgA, WITNESS_1), "and revokes the original nomination");
    }

    /*//////////////////////////////////////////////////////////////
                  F2 — THE BURN IS NOW MANDATORY, NOT OPTIONAL
    //////////////////////////////////////////////////////////////*/

    /// @dev THE headline fix. The burn lives in the pre-claim, which the arbiter is designed to
    ///      let fail — so it was skippable five different ways and the settlement completed
    ///      anyway. Demanding positive proof at the settling check inverts that: skipping the
    ///      burn now means not settling.
    function test_F2_aSettlementThatSkipsItsBurnCannotSettle() public {
        assertTrue(_preClaimCheck(cfgA, WITNESS_1), "the pre-claim check still passes");

        // ...and then the burn does not happen — starved gas, a failing sigMode, a decoy id, a
        // reverting sibling op, or no pre-claim at all. All identical from here.

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "so the settlement cannot complete");
    }

    /// @dev A burn that nominates a DIFFERENT settlement does not help either
    function test_F2_aBurnNominatingAnotherSettlementDoesNotCount() public {
        _settlementBurns(ID_A, WITNESS_2);

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "the nomination must name THIS settlement");
    }

    /*//////////////////////////////////////////////////////////////
                    F3 — ONE SESSION CANNOT BURN ANOTHER'S ID
    //////////////////////////////////////////////////////////////*/

    function test_F3_aSessionMayNotAuthoriseBurningAnotherSessionsId() public {
        bytes memory burnSomeoneElse = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_A));

        vm.prank(multiplexer);
        uint256 result = policy.checkAction(cfgB, account, address(policy), 0, burnSomeoneElse);

        assertEq(result, VALIDATION_FAILED, "session B may not burn session A's id");
    }

    function test_F3_control_aSessionMayBurnItsOwnId() public {
        bytes memory burnOwn = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_B));

        vm.prank(multiplexer);
        uint256 result = policy.checkAction(cfgB, account, address(policy), 0, burnOwn);

        assertEq(result, VALIDATION_SUCCESS, "its own id is permitted");
    }

    function test_F3_control_anUnrelatedActionIsUnaffected() public {
        vm.prank(multiplexer);
        uint256 result = policy.checkAction(cfgB, account, makeAddr("someToken"), 0, hex"a9059cbb");

        assertEq(result, VALIDATION_SUCCESS, "the binding only applies to self-calls");
    }

    /// @dev The binding must cover `consumeFor` too, not just `consume`. Without it a second
    ///      session on the account could name another session's id here and brick it permanently.
    function test_F3_aSessionMayNotBurnAnotherSessionsIdViaConsumeFor() public {
        bytes memory burnSomeoneElse =
            abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_A, WITNESS_1));

        vm.prank(multiplexer);
        uint256 result = policy.checkAction(cfgB, account, address(policy), 0, burnSomeoneElse);

        assertEq(result, VALIDATION_FAILED, "session B may not consumeFor session A's id");
    }

    function test_F3_control_aSessionMayConsumeForItsOwnId() public {
        bytes memory burnOwn = abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_B, WITNESS_1));

        vm.prank(multiplexer);
        uint256 result = policy.checkAction(cfgB, account, address(policy), 0, burnOwn);

        assertEq(result, VALIDATION_SUCCESS, "its own id is permitted");
    }

    /*//////////////////////////////////////////////////////////////
                              THE ACTION SURFACE
    //////////////////////////////////////////////////////////////*/

    function test_theActionSurfaceStaysStrict() public {
        assertEq(_validate(cfgA), VALIDATION_SUCCESS, "unspent");
        _settlementBurns(ID_A, WITNESS_1);
        assertEq(_validate(cfgA), VALIDATION_FAILED, "spent, with no tolerance at all");
    }

    /*//////////////////////////////////////////////////////////////
                                  SHAPE
    //////////////////////////////////////////////////////////////*/

    /// @dev Permit2 does not reserve nonce zero, so a settlement on it must be spendable. The
    ///      nomination is hashed precisely so no witness value collides with "nothing nominated".
    function test_aSettlementOnPermit2NonceZeroCanSettle() public {
        vm.prank(account);
        policy.consumeFor(ID_A, 0);

        vm.prank(multiplexer);
        assertTrue(
            policy.check1271SignedAction(cfgA, PERMIT2, account, bytes32(0), _blob(0)),
            "nonce zero is a valid settlement"
        );
    }

    /// @dev ...and the top of the range too, which a naive `witness + 1` sentinel would break
    function test_aSettlementOnTheMaxNonceCanSettle() public {
        vm.prank(account);
        policy.consumeFor(ID_A, type(uint256).max);

        vm.prank(multiplexer);
        assertTrue(
            policy.check1271SignedAction(
                cfgA, PERMIT2, account, bytes32(0), _blob(type(uint256).max)
            ),
            "the max nonce is a valid settlement"
        );
    }

    /// @dev PINS A KNOWN GAP, deliberately. The action surface does NOT stop a caller from
    ///      nominating, and that is a build requirement on the orchestrator rather than a control
    ///      here - see WHO IS TRUSTED on the policy.
    ///
    ///      A ban used to live here. It never ran: a permissive `FALLBACK_ACTIONID` routes
    ///      `consumeFor` around any guard on this surface, so the ban read as protection while
    ///      `checkAction` appeared zero times in the trace. If you are adding it back because
    ///      this test failed, read that block first - the guard is not the missing piece.
    function test_theActionSurfaceDoesNotForbidNominating() public {
        bytes memory nominate = abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_B, 4242));

        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(cfgB, account, address(policy), 0, nominate),
            VALIDATION_SUCCESS,
            "nominating is bounded by the signed ops, not by this surface"
        );
    }

    function test_control_theActionSurfaceStillAllowsAPlainBurn() public {
        bytes memory burn = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_B));

        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(cfgB, account, address(policy), 0, burn),
            VALIDATION_SUCCESS,
            "a plain burn of its own id is what the action route is for"
        );
    }

    function test_aShortBlobIsRefused() public {
        _settlementBurns(ID_A, WITNESS_1);

        vm.prank(multiplexer);
        assertFalse(
            policy.check1271SignedAction(cfgA, PERMIT2, account, bytes32(0), hex"1234"),
            "a blob too short to carry a nonce cannot prove anything"
        );
    }

    function test_unconfigured_refused() public {
        ConfigId never = ConfigId.wrap(keccak256("never"));

        assertFalse(_settlingCheck(never, WITNESS_1), "fails closed");
        assertEq(_validate(never), VALIDATION_FAILED, "on both surfaces");
    }
}
