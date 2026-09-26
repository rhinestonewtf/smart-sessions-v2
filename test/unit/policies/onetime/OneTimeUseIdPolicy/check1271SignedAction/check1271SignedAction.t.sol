// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "@forge-std/Test.sol";
import {
    OneTimeUseIdPolicy_Unit_Test,
    MockPermit2NonceExecutor
} from "../OneTimeUseIdPolicy.t.sol";

// Contracts
import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";

// Interfaces
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title OneTimeUseIdPolicy.check1271SignedAction Unit Tests
/// @notice The settling check, from Permit2, demands the nomination this transaction's burn
///         recorded for the presented nonce. Every other caller - the executor included - is
///         refused: an ERC-1271 validation carries no burn.
contract OneTimeUseIdPolicy_check1271SignedAction_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 SCOPING
    //////////////////////////////////////////////////////////////*/

    /// @notice Test an unconfigured configId fails closed
    function test_check1271SignedAction_unconfigured_returnsFalse() external {
        ConfigId never = ConfigId.wrap(keccak256("never"));

        assertFalse(_settlingCheck(never, WITNESS_1));
    }

    /*//////////////////////////////////////////////////////////////
                       EVERY NON-PERMIT2 CALLER IS REFUSED
    //////////////////////////////////////////////////////////////*/

    /// @notice Test the executor's ERC-1271 read is refused, burn or no burn
    function test_check1271SignedAction_executorCaller_returnsFalse() external {
        assertFalse(_executorCheck(cfgA, WITNESS_1), "unburned: refused");

        _validateBurnFor(cfgA, WITNESS_1);
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "the same blob settles for Permit2");
        assertFalse(_executorCheck(cfgA, WITNESS_1), "burned and nominated: still refused");
    }

    /// @notice Test a caller that is neither Permit2 nor the executor (e.g. the Compact route) is
    ///         refused
    function test_check1271SignedAction_unknownCaller_failsClosed() external {
        _validateBurnFor(cfgA, WITNESS_1);

        vm.prank(multiplexer);
        assertFalse(
            policy.check1271SignedAction(
                cfgA, makeAddr("theCompact"), account, bytes32(0), _blob(WITNESS_1)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                       THE SETTLING CHECK - PROOF REQUIRED
    //////////////////////////////////////////////////////////////*/

    /// @notice Test the honest path: the pre-claim's consumeFor is validated (burn + nomination),
    ///         then the settling check presents the same nonce
    function test_check1271SignedAction_honestSettlement_completes() external {
        assertEq(_validateBurnFor(cfgA, WITNESS_1), SUCCESS, "the pre-claim burned");

        assertTrue(_settlingCheck(cfgA, WITNESS_1), "settling check, proof presented");
    }

    /// @notice Test a nomination cannot carry a Permit2 settlement whose own pre-claim never ran
    function test_check1271SignedAction_nominationWithoutItsPreClaim_returnsFalse() external {
        _validateBurnFor(cfgA, WITNESS_1);
        MockPermit2NonceExecutor(executor).setUnconsumed(WITNESS_1);

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "the order's own pre-claim never ran");
    }

    /// @notice Test a signature too short to carry a nonce is refused
    function test_check1271SignedAction_shortBlobIsRefused() external {
        _validateBurnFor(cfgA, WITNESS_1);

        vm.prank(multiplexer);
        assertFalse(policy.check1271SignedAction(cfgA, PERMIT2, account, bytes32(0), hex"1234"));
    }

    /// @notice Test a second settlement cannot ride the first settlement's burn
    function test_check1271SignedAction_secondSettlementCannotRideTheFirstsBurn() external {
        _validateBurnFor(cfgA, WITNESS_1);
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "settlement one completes");

        assertFalse(_settlingCheck(cfgA, WITNESS_2), "settlement two cannot ride it");
    }

    /// @notice Test a second settlement cannot nominate itself: its burn is refused at validation
    function test_check1271SignedAction_secondSettlementCannotNominateItself() external {
        _validateBurnFor(cfgA, WITNESS_1);
        assertEq(_validateBurnFor(cfgA, WITNESS_2), FAILED, "the second burn is refused");

        assertFalse(_settlingCheck(cfgA, WITNESS_2), "so it has no nomination");
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "and the first keeps its own");
    }

    /// @notice Test a settlement whose burn was never validated cannot settle
    function test_check1271SignedAction_skippedBurnCannotSettle() external {
        assertFalse(_settlingCheck(cfgA, WITNESS_1));
    }

    /// @notice Test a burn nominating a different settlement's witness does not count
    function test_check1271SignedAction_burnNominatingAnotherSettlementDoesNotCount() external {
        _validateBurnFor(cfgA, WITNESS_2);

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "the nomination must name THIS settlement");
    }

    /// @notice Test a plain consume nominates nothing, so no Permit2 order settles on it
    function test_check1271SignedAction_consumeNominatesNothing() external {
        _validateBurn(cfgA);

        assertFalse(_settlingCheck(cfgA, WITNESS_1));
    }

    /// @notice Test a nomination under another multiplexer does not settle here
    function test_check1271SignedAction_nominationUnderAnotherMultiplexer_returnsFalse() external {
        address other = makeAddr("otherMultiplexer");
        vm.prank(other);
        policy.initializeWithMultiplexer(account, cfgA, abi.encodePacked(bytes32(ID_A), bytes32(0)));
        vm.prank(other);
        policy.checkAction(
            cfgA, account, address(policy), 0, abi.encodeCall(policy.consumeFor, (ID_A, WITNESS_1))
        );

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "the real multiplexer sees no nomination");
    }

    /*//////////////////////////////////////////////////////////////
                                  SHAPE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test Permit2 nonce zero is a valid settlement witness
    function test_check1271SignedAction_permit2NonceZero_canSettle() external {
        _validateBurnFor(cfgA, 0);

        assertTrue(_settlingCheck(cfgA, 0));
    }

    /// @notice Test the max uint256 nonce is a valid settlement witness
    function test_check1271SignedAction_maxNonce_canSettle() external {
        _validateBurnFor(cfgA, type(uint256).max);

        assertTrue(_settlingCheck(cfgA, type(uint256).max));
    }

    /*//////////////////////////////////////////////////////////////
                                 DEADLINE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test the settling check passes on a proven burn before the deadline
    function test_check1271SignedAction_beforeDeadline_settles() external {
        vm.warp(1000);
        _install(cfgA, ID_A, block.timestamp + 1 hours);

        _validateBurnFor(cfgA, WITNESS_1);

        assertTrue(_settlingCheck(cfgA, WITNESS_1));
    }

    /// @notice Test the settling check refuses a proven burn once the deadline has passed
    function test_check1271SignedAction_afterDeadline_refusesEvenAProvenBurn() external {
        vm.warp(1000);
        _install(cfgA, ID_A, block.timestamp + 1 hours);

        // The nomination is transient, so burn first, then cross the deadline in the same
        // transaction: the settling read must still refuse.
        _validateBurnFor(cfgA, WITNESS_1);
        vm.warp(block.timestamp + 1 hours + 1);

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "the deadline outranks a proven burn");
    }

    /// @notice Test the deadline is inclusive on the settling surface
    function test_check1271SignedAction_atDeadline_settles() external {
        vm.warp(1000);
        uint256 expiry = block.timestamp + 1 hours;
        _install(cfgA, ID_A, expiry);

        vm.warp(expiry);
        _validateBurnFor(cfgA, WITNESS_1);

        assertTrue(_settlingCheck(cfgA, WITNESS_1));
    }

    /// @notice Test a zero deadline leaves the settling check unbounded in time
    function test_check1271SignedAction_zeroDeadline_settlesLongAfterInstall() external {
        _install(cfgA, ID_A, NO_DEADLINE);

        vm.warp(block.timestamp + 3650 days);
        _validateBurnFor(cfgA, WITNESS_1);

        assertTrue(_settlingCheck(cfgA, WITNESS_1));
    }
}

/// @title The cross-transaction half of the settling check
/// @notice Split into its own contract deliberately. Transient storage survives every call
///         inside one test body - a forge test body IS one transaction - but it IS cleared
///         between `setUp` and the body. Burning in `setUp` is therefore the only way to observe
///         a LATER transaction.
contract OneTimeUseIdPolicy_check1271SignedAction_CrossTransaction_Unit_Test is Test {
    OneTimeUseIdPolicy internal policy;

    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address internal multiplexer = makeAddr("multiplexer");
    address internal account = makeAddr("account");

    ConfigId internal cfg = ConfigId.wrap(keccak256("session.A"));
    uint256 internal constant ID = 0xBEEF;
    uint256 internal constant WITNESS = 1337;

    /// @dev The burn happens HERE, so the test body below runs in a different transaction
    function setUp() public {
        policy = new OneTimeUseIdPolicy(
            ISignatureTransfer(PERMIT2), address(new MockPermit2NonceExecutor())
        );

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(ID), bytes32(0)));

        vm.prank(multiplexer);
        policy.checkAction(
            cfg, account, address(policy), 0, abi.encodeCall(policy.consumeFor, (ID, WITNESS))
        );
    }

    function _blob(uint256 nonce) internal pure returns (bytes memory) {
        return abi.encodePacked(address(0xA4B17E4), bytes32(nonce), bytes32(uint256(9)));
    }

    /// @notice Test the nomination does not survive into a later transaction
    function test_check1271SignedAction_crossTransactionBurnIsRefused() external {
        vm.prank(multiplexer);
        bool ok = policy.check1271SignedAction(cfg, PERMIT2, account, bytes32(0), _blob(WITNESS));

        assertFalse(ok, "a later transaction must be refused");
    }
}
