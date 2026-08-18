// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "@forge-std/Test.sol";

import { SettlementOncePolicy } from "@policies/once/SettlementOncePolicy.sol";
import { MockPermit2Bitmap } from "./MockPermit2Bitmap.sol";

import { ConfigId, PermissionId, ActionId } from "@smartsessions/DataTypes.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title Exactly-once from the ACTION surface, on the REAL ConfigIds
/// @notice The same cross-family matrix PR #53 proves on the 1271 multiplexer, rebuilt on the
/// action surface for the executor route.
///
/// The first version of this file fed ONE hand-made `configId` to both surfaces and passed while
/// the contract was broken. SmartSessions derives a DIFFERENT ConfigId per policy slot, so that
/// aliasing is a shape production can never produce. This file derives both ids with `IdLib`, the
/// same library the multiplexer uses, so the two halves are addressed exactly as they are in a
/// real deployment:
///
///   action  keccak(account, keccak(permissionId, actionId))
///   1271    keccak(account, keccak("ERC1271: ", permissionId))
contract ActionSurfaceOnce_Test is Test {
    using IdLib for *;

    SettlementOncePolicy internal policy;
    MockPermit2Bitmap internal permit2;

    address internal account;
    address internal multiplexer;
    address internal target;

    PermissionId internal permissionId;
    ActionId internal actionId;

    /// @dev The two ids SmartSessions really hands the two surfaces
    ConfigId internal cfgAction;
    ConfigId internal cfg1271;

    uint256 internal constant PINNED = 1337;
    bytes4 internal constant SELECTOR = bytes4(0x12345678);

    function setUp() public {
        permit2 = new MockPermit2Bitmap();
        policy = new SettlementOncePolicy(ISignatureTransfer(address(permit2)));

        account = makeAddr("account");
        multiplexer = makeAddr("smartSessionEmissary");
        target = makeAddr("relayRouter");

        permissionId = PermissionId.wrap(keccak256("bridge.session"));
        actionId = IdLib.toActionId(target, SELECTOR);

        cfgAction = IdLib.toConfigId(IdLib.toActionPolicyId(permissionId, actionId), account);
        cfg1271 = IdLib.toConfigId(IdLib.toErc1271PolicyId(permissionId), account);

        _enable(PINNED);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev A real enable installs BOTH surfaces, each with its own ConfigId and its own initData
    function _enable(uint256 nonce) internal {
        vm.startPrank(multiplexer);
        policy.initializeWithMultiplexer(account, cfgAction, abi.encodePacked(bytes32(nonce)));
        policy.initializeWithMultiplexer(account, cfg1271, abi.encodePacked(bytes32(nonce)));
        vm.stopPrank();
    }

    function _executorSettles() internal returns (bool) {
        vm.prank(multiplexer);
        return
            policy.checkAction(cfgAction, account, target, 0, hex"deadbeef") == VALIDATION_SUCCESS;
    }

    /// @dev A Permit2 claim payload: arbiter (20 bytes) then the nonce
    function _permit2Payload(uint256 nonce) internal view returns (bytes memory) {
        return abi.encodePacked(target, nonce, block.timestamp + 1);
    }

    function _permit2Settles(uint256 nonce) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(
            cfg1271, address(0), account, keccak256("digest"), _permit2Payload(nonce)
        );
    }

    /*//////////////////////////////////////////////////////////////
                         THE IDS REALLY DO DIFFER
    //////////////////////////////////////////////////////////////*/

    /// @dev The premise of this whole file. If this ever fails, the rest proves nothing.
    function test_theTwoSurfacesGetDifferentConfigIds() public view {
        assertTrue(
            ConfigId.unwrap(cfgAction) != ConfigId.unwrap(cfg1271),
            "the surfaces must be addressed by different ids, as in production"
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

    /// @dev The diagonal that was silently open when the spend was keyed on ConfigId. This is the
    ///      test the original file could not have failed, because it aliased the two ids.
    function test_executorThenPermit2_refused() public {
        assertTrue(_executorSettles(), "the executor route must be open");

        assertFalse(_permit2Settles(PINNED), "the executor spend must close the Permit2 route");
    }

    function test_permit2ThenExecutor_refused() public {
        permit2.burn(account, PINNED);

        assertFalse(_executorSettles(), "the Permit2 spend must close the executor route");
    }

    function test_executorThenExecutor_refused() public {
        assertTrue(_executorSettles(), "the first executor settlement must pass");

        assertFalse(_executorSettles(), "a second executor settlement must be refused");
    }

    /// @dev The eleven-settlements exploit, restated. The old NoncePinPolicy read only Permit2's
    ///      bitmap, which never moves when the executor settles, so every repeat looked like the
    ///      first. All ten repeats must fail here.
    function test_executorCannotRepeatWhilePermit2BitmapIsUntouched() public {
        assertTrue(_executorSettles(), "the first executor settlement must pass");

        for (uint256 i; i < 10; ++i) {
            assertFalse(_executorSettles(), "no further executor settlement may pass");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        NEVER CHECK YOUR OWN CONSUMABLE
    //////////////////////////////////////////////////////////////*/

    /// @dev Permit2 burns its nonce BEFORE validating the signature, so the bitmap already reads
    ///      spent for the settlement in front of us. The 1271 half must not read it.
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
                cfg1271, address(0), account, keccak256("d"), abi.encodePacked(target, uint128(0))
            ),
            "a payload that cannot contain a nonce must be refused"
        );
    }

    function test_anotherMultiplexerSeesNothing() public {
        address other = makeAddr("otherMultiplexer");

        vm.prank(other);
        assertEq(
            policy.checkAction(cfgAction, account, target, 0, hex""),
            VALIDATION_FAILED,
            "a different multiplexer must not reach this configuration"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        LIMITATIONS, ASSERTED NOT ASSUMED
    //////////////////////////////////////////////////////////////*/

    /// @dev The install-time requirement, at the policy's own surface: two calls are two spends,
    ///      and the policy cannot tell whether they came from one batch or two settlements.
    ///
    ///      This drives `checkAction` directly, so it does NOT exercise the batch iteration in
    ///      `PolicyLibV2.checkBatch7579Exec` that would produce the two calls in production. It
    ///      asserts the policy's behaviour given two calls, not that a batch produces them.
    function test_twoCallsConsumeTwoSpends() public {
        assertTrue(_executorSettles(), "first action in the batch");

        assertFalse(
            _executorSettles(),
            "second action in the SAME settlement is indistinguishable from a second settlement"
        );
    }

    /// @dev The third install-time requirement, made visible: the two surfaces carry separate
    ///      initData and nothing can check they agree. Pin different nonces and the halves key
    ///      different records, so the exclusion silently stops working - exactly the failure the
    ///      ConfigId keying had. This test documents that it is now a CONFIG error rather than an
    ///      unavoidable one.
    function test_mismatchedPinsBreakTheExclusion() public {
        vm.startPrank(multiplexer);
        policy.initializeWithMultiplexer(account, cfgAction, abi.encodePacked(bytes32(PINNED)));
        policy.initializeWithMultiplexer(account, cfg1271, abi.encodePacked(bytes32(PINNED + 1)));
        vm.stopPrank();

        assertTrue(_executorSettles(), "executor settles under its own pin");

        assertTrue(
            _permit2Settles(PINNED + 1),
            "and the Permit2 route stays open, because the halves keyed different records"
        );
    }

    /// @dev Re-enable restores the spend, matching #53's generation bump.
    function test_reEnableRestoresTheSpend() public {
        assertTrue(_executorSettles(), "the first settlement must pass");
        assertFalse(_executorSettles(), "the second must not");

        _enable(PINNED);

        assertTrue(_executorSettles(), "a re-enabled session may settle again");
    }
}
