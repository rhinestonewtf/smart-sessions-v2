// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "@forge-std/Test.sol";
import { TestHelperLib, CompactEnvironment } from "@compact-utils/tests/Environment.sol";

import { SettlementOncePolicy } from "@policies/once/SettlementOncePolicy.sol";

import { ConfigId, PermissionId, ActionId } from "@smartsessions/DataTypes.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { VALIDATION_SUCCESS } from "erc7579/interfaces/IERC7579Module.sol";

/// @title SettlementOncePolicy against the REAL Permit2
/// @notice Drives the policy against the canonical Permit2 deployed by `CompactEnvironment`
/// rather than a mock bitmap, and against the REAL ConfigId derivations.
///
/// NOTE on what this does NOT establish. `_burnRealPermit2Nonce` computes the word and bit itself
/// and calls `invalidateUnorderedNonces`, so Permit2's own `bitmapPositions()` is not exercised on
/// the burn side — the formula is still hand-written, just in the test instead of a mock. The
/// arithmetic IS genuinely cross-checked, but by `SettlementOnceMatrixE2E`, where a real
/// settlement burns via `_useUnorderedNonce` and the policy has to find the bit Permit2 wrote.
///
/// It also uses the REAL ConfigId derivations, so the two halves are addressed exactly as
/// SmartSessions addresses them:
///
///   action  keccak(account, keccak(permissionId, actionId))
///   1271    keccak(account, keccak("ERC1271: ", permissionId))
///
/// What this does NOT close: settlements are not routed through an arbiter, and the executor
/// route's own consumable is this policy's internal flag rather than a real burn. Stated plainly
/// so the coverage is not overread.
contract SettlementOnceRealPermit2_Test is Test, CompactEnvironment {
    using TestHelperLib for *;
    using IdLib for *;

    SettlementOncePolicy internal policy;

    address internal account;
    address internal multiplexer;
    address internal target;

    PermissionId internal permissionId;
    ActionId internal actionId;
    ConfigId internal cfgAction;
    ConfigId internal cfg1271;

    /// @dev Two distinct arbiters — "Across" and "Eco" — sharing one Permit2 nonce
    address internal acrossArbiter;
    address internal ecoArbiter;

    uint256 internal constant PINNED = 1337;
    bytes4 internal constant SELECTOR = bytes4(0x12345678);

    function setUp() public virtual {
        _deployCompact();

        account = env.smartAccount1.account == address(0)
            ? makeAddr("account")
            : env.smartAccount1.account;
        multiplexer = makeAddr("smartSessionEmissary");
        target = makeAddr("relayRouter");

        acrossArbiter = makeAddr("acrossArbiter");
        ecoArbiter = makeAddr("ecoArbiter");

        permissionId = PermissionId.wrap(keccak256("bridge.session"));
        actionId = IdLib.toActionId(target, SELECTOR);
        cfgAction = IdLib.toConfigId(IdLib.toActionPolicyId(permissionId, actionId), account);
        cfg1271 = IdLib.toConfigId(IdLib.toErc1271PolicyId(permissionId), account);

        // The REAL Permit2
        policy = new SettlementOncePolicy(ISignatureTransfer(address(env.permit2)));

        _enable(PINNED);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev A real enable installs BOTH surfaces, each with its own ConfigId and initData
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

    function _permit2Settles(address arbiter, uint256 nonce) internal returns (bool) {
        bytes memory payload = abi.encodePacked(arbiter, nonce, block.timestamp + 1);
        vm.prank(multiplexer);
        return policy.check1271SignedAction(
            cfg1271, address(env.permit2), account, keccak256("digest"), payload
        );
    }

    /// @dev Burns a nonce on the REAL Permit2, the same bitmap a settlement writes
    function _burnRealPermit2Nonce(uint256 nonce) internal {
        vm.prank(account);
        env.permit2.invalidateUnorderedNonces(nonce >> 8, 1 << (nonce & 0xff));
    }

    /// @dev Reads the real bitmap independently of the policy's own arithmetic
    function _realPermit2Burned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap(account, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /*//////////////////////////////////////////////////////////////
                        THE IDS REALLY DO DIFFER
    //////////////////////////////////////////////////////////////*/

    /// @dev The premise of the whole file. If these ever alias, nothing below proves anything.
    function test_theTwoSurfacesGetDifferentConfigIds() public view {
        assertTrue(
            ConfigId.unwrap(cfgAction) != ConfigId.unwrap(cfg1271),
            "the surfaces must be addressed by different ids, as in production"
        );
    }

    /*//////////////////////////////////////////////////////////////
                 THE POLICY READS REAL PERMIT2 STATE
    //////////////////////////////////////////////////////////////*/

    function test_bothRoutesOpenAgainstRealPermit2() public {
        assertFalse(_realPermit2Burned(PINNED), "the real bitmap starts clean");

        assertTrue(_permit2Settles(acrossArbiter, PINNED), "the Permit2 route must be open");
        assertTrue(_executorSettles(), "the executor route must be open");
    }

    /// @dev The check a mock could never make: the policy's own word/bit derivation has to land
    ///      on the slot Permit2 actually wrote.
    function test_policyReadMatchesRealPermit2Bitmap() public {
        _burnRealPermit2Nonce(PINNED);

        assertTrue(_realPermit2Burned(PINNED), "the real contract records the burn");

        assertFalse(_executorSettles(), "the policy must read the same bit Permit2 wrote");
    }

    /// @dev Fuzzed over word boundaries, where a wrong shift would silently disagree
    function testFuzz_policyReadMatchesRealPermit2Bitmap(uint256 nonce) public {
        _enable(nonce);

        assertTrue(_executorSettles(), "unburned: the executor route is open");

        _enable(nonce); // restore the spend consumed by the assertion above
        _burnRealPermit2Nonce(nonce);

        assertFalse(_executorSettles(), "burned on the real contract: the route must close");
    }

    /*//////////////////////////////////////////////////////////////
                ACROSS AND ECO SHARE ONE REAL NONCE
    //////////////////////////////////////////////////////////////*/

    /// @dev Establishes the STRUCTURAL half of the premise only: Permit2's bitmap is keyed
    ///      (owner, nonce) with no arbiter component, so an arbiter cannot have its own nonce
    ///      space. It does NOT settle via either arbiter — no contention is demonstrated here.
    ///      A real two-arbiter contention test still does not exist on this branch.
    function test_permit2BitmapHasNoArbiterComponent() public {
        assertTrue(acrossArbiter != ecoArbiter, "two distinct arbiters");

        _burnRealPermit2Nonce(PINNED);

        assertTrue(
            _realPermit2Burned(PINNED), "one bitmap bit, regardless of which arbiter spent it"
        );

        // Permit2 itself rejects the second spend; this policy deliberately does not read its own
        // consumable, so it must still say yes
        assertTrue(
            _permit2Settles(ecoArbiter, PINNED),
            "the policy must not reject a Permit2 claim on Permit2's own burn"
        );
    }

    /// @dev …but the executor route must see that spend, because it is another family's
    /// consumable
    function test_acrossSpendClosesTheExecutorRoute() public {
        _burnRealPermit2Nonce(PINNED);

        assertFalse(_executorSettles(), "an Across spend must close the executor route");
    }

    /*//////////////////////////////////////////////////////////////
                    THE CROSS-SURFACE DIAGONAL, ON REAL IDS
    //////////////////////////////////////////////////////////////*/

    /// @dev The bug the audit found, retested here against real Permit2 and real ConfigIds: the
    ///      executor half burns a record the 1271 half must be able to read.
    function test_executorThenPermit2_refused() public {
        assertTrue(_executorSettles(), "the executor route is open");

        assertFalse(
            _permit2Settles(acrossArbiter, PINNED),
            "the executor spend must close the Permit2 route"
        );
    }
}
