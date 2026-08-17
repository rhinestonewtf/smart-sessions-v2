// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "@forge-std/Test.sol";

import { SettlementOncePolicy } from "@policies/once/SettlementOncePolicy.sol";
import { MockPermit2Bitmap } from "./MockPermit2Bitmap.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title Exactly-once from the ACTION surface
/// @notice The same cross-family matrix PR #53 proves on the 1271 multiplexer, rebuilt on the
/// action surface for the executor route. If this holds, the executor route does not need a
/// 1271-path settlement policy - the ops are constrained by ArgPolicy and the count by this.
///
/// The four orderings, and who closes each:
///
///   Across  -> Eco       Permit2 itself, one bitmap, no policy involved
///   executor-> executor  this policy's own flag
///   Permit2 -> executor  this policy, action half reads Permit2's bitmap
///   executor-> Permit2   this policy, 1271 half reads the flag the action half burned
contract ActionSurfaceOnce_Test is Test {
    SettlementOncePolicy internal policy;
    MockPermit2Bitmap internal permit2;

    address internal account;
    address internal multiplexer;
    address internal target;
    ConfigId internal configId;

    uint256 internal constant PINNED = 1337;

    function setUp() public {
        permit2 = new MockPermit2Bitmap();
        policy = new SettlementOncePolicy(ISignatureTransfer(address(permit2)));

        account = makeAddr("account");
        multiplexer = makeAddr("smartSessionEmissary");
        target = makeAddr("relayRouter");
        configId = ConfigId.wrap(keccak256("settlement.once"));

        _enable(PINNED);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _enable(uint256 nonce) internal {
        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, configId, abi.encodePacked(bytes32(nonce)));
    }

    /// @dev The executor route: SmartSessionEmissary calls checkAction as the multiplexer
    function _executorSettles() internal returns (bool) {
        vm.prank(multiplexer);
        return policy.checkAction(configId, account, target, 0, hex"deadbeef") == VALIDATION_SUCCESS;
    }

    /// @dev A Permit2 claim payload: arbiter (20 bytes) then the nonce
    function _permit2Payload(uint256 nonce) internal view returns (bytes memory) {
        return abi.encodePacked(target, nonce, block.timestamp + 1);
    }

    function _permit2Settles(uint256 nonce) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(
            configId, address(0), account, keccak256("digest"), _permit2Payload(nonce)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          EACH ROUTE WORKS ALONE
    //////////////////////////////////////////////////////////////*/

    function test_executorSettlesFirst() public {
        assertTrue(_executorSettles(), "the executor route must be open");
    }

    function test_permit2SettlesFirst() public {
        assertTrue(_permit2Settles(PINNED), "the Permit2 route must be open");
    }

    /*//////////////////////////////////////////////////////////////
                            THE FOUR ORDERINGS
    //////////////////////////////////////////////////////////////*/

    /// @dev The diagonal the 1271 multiplexer closes by reading the executor's nonce. Here it is
    ///      closed by reading a flag this policy burned itself - no nonce visibility required.
    function test_executorThenPermit2_refused() public {
        assertTrue(_executorSettles(), "the executor route must be open");

        assertFalse(_permit2Settles(PINNED), "the executor spend must close the Permit2 route");
    }

    /// @dev The other diagonal. Permit2 burns its bitmap before it validates, so the action half
    ///      reads that bitmap directly - the same cross-family read the multiplexer performs.
    function test_permit2ThenExecutor_refused() public {
        permit2.burn(account, PINNED);

        assertFalse(_executorSettles(), "the Permit2 spend must close the executor route");
    }

    /// @dev Within-family, executor side. On the 1271 design this is free - the executor refuses a
    ///      second burn of its own nonce. Here the flag closes it even for a DIFFERENT nonce,
    ///      which is the case that produced eleven settlements when the pin lived on the action
    ///      surface with no state of its own.
    function test_executorThenExecutor_refused() public {
        assertTrue(_executorSettles(), "the first executor settlement must pass");

        assertFalse(_executorSettles(), "a second executor settlement must be refused");
    }

    /// @dev The exploit that killed NoncePinPolicy, stated as a test. The old action policy read
    ///      only Permit2's bitmap, which does not move when the executor settles - so every
    ///      executor settlement looked like the first. Ten repeats must all fail here.
    function test_executorCannotRepeatWhilePermit2BitmapIsUntouched() public {
        assertTrue(_executorSettles(), "the first executor settlement must pass");

        for (uint256 i; i < 10; ++i) {
            assertFalse(_executorSettles(), "no further executor settlement may pass");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        NEVER CHECK YOUR OWN CONSUMABLE
    //////////////////////////////////////////////////////////////*/

    /// @dev Permit2 burns its nonce BEFORE it validates the signature, so by the time this policy
    ///      runs the bitmap already reads spent for the settlement in front of it. The 1271 half
    ///      must therefore not read Permit2's bitmap, or it would reject every legitimate claim.
    function test_permit2DoesNotCheckItsOwnConsumable() public {
        permit2.burn(account, PINNED);

        assertTrue(
            _permit2Settles(PINNED), "a Permit2 settlement must not be refused by its own burn"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 THE PIN
    //////////////////////////////////////////////////////////////*/

    function test_permit2OnAnotherNonce_refused() public {
        assertFalse(_permit2Settles(PINNED + 1), "an unpinned Permit2 settlement must be refused");
    }

    function testFuzz_onlyThePinnedNoncePasses(uint256 pinned, uint256 presented) public {
        vm.assume(pinned != presented);
        _enable(pinned);

        assertFalse(_permit2Settles(presented), "only the pinned nonce may settle");
    }

    /*//////////////////////////////////////////////////////////////
                               FAIL CLOSED
    //////////////////////////////////////////////////////////////*/

    function test_unconfigured_refused() public {
        ConfigId fresh = ConfigId.wrap(keccak256("never.configured"));

        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(fresh, account, target, 0, hex""),
            VALIDATION_FAILED,
            "an unconfigured action must fail closed"
        );

        vm.prank(multiplexer);
        assertFalse(
            policy.check1271SignedAction(
                fresh, address(0), account, keccak256("d"), _permit2Payload(PINNED)
            ),
            "an unconfigured claim must fail closed"
        );
    }

    function test_payloadTooShortForNonce_refused() public {
        vm.prank(multiplexer);
        assertFalse(
            policy.check1271SignedAction(
                configId, address(0), account, keccak256("d"), abi.encodePacked(target, uint128(0))
            ),
            "a payload that cannot contain a nonce must be refused"
        );
    }

    /// @dev Storage is keyed on the calling multiplexer, so another caller sees an unconfigured
    ///      session rather than this one's state
    function test_anotherMultiplexerSeesNothing() public {
        address other = makeAddr("otherMultiplexer");

        vm.prank(other);
        assertEq(
            policy.checkAction(configId, account, target, 0, hex""),
            VALIDATION_FAILED,
            "a different multiplexer must not reach this configuration"
        );
    }

    /*//////////////////////////////////////////////////////////////
                              RE-ENABLE
    //////////////////////////////////////////////////////////////*/

    /// @dev Re-enabling restores the single spend, matching the multiplexer's generation bump.
    ///      Documented rather than assumed: a re-enable is a new authorisation, not a top-up of
    ///      the old one, and the quorum re-signing is what makes that legitimate.
    function test_reEnableRestoresTheSpend() public {
        assertTrue(_executorSettles(), "the first settlement must pass");
        assertFalse(_executorSettles(), "the second must not");

        _enable(PINNED);

        assertTrue(_executorSettles(), "a re-enabled session may settle again");
    }

    /*//////////////////////////////////////////////////////////////
                        THE GAP THIS DESIGN CANNOT CLOSE
    //////////////////////////////////////////////////////////////*/

    /// @dev The install-time requirement, made visible. checkAction fires once per execution in
    ///      the batch, so a settlement whose batch touches this policy's actionId TWICE burns the
    ///      spend on its own first action and fails on its second. The policy cannot detect this -
    ///      it sees two indistinguishable calls - so the actionId must be chosen to occur exactly
    ///      once per settlement. This test exists so that constraint is not folklore.
    function test_twoActionsInOneSettlementConsumeTwoSpends() public {
        assertTrue(_executorSettles(), "first action in the batch");

        assertFalse(
            _executorSettles(),
            "second action in the SAME settlement is indistinguishable from a second settlement"
        );
    }
}
