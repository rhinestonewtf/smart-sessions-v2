// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "@forge-std/Test.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";

// Contracts under test
import { BridgeSessionPolicy } from "@policies/bridge/BridgeSessionPolicy.sol";
import {
    StaticIntentExecutorPolicy
} from "@policies/settlementlayer/intentExecutorStatic/StaticIntentExecutorPolicy.sol";
import { RelayAdapter } from "@policies/settlementlayer/shared/adapters/RelayAdapter.sol";
import { RelayCalldataLib } from "@policies/settlementlayer/shared/lib/RelayCalldataLib.sol";

// Mocks — only for the two consumables, which are external chain state
import { MockPermit2Bitmap, MockIntentExecutorNonces } from "@mocks/MockSettlementLayer.sol";

// Shared builders from the settlement-layer suite, so the payload is byte-identical to the one
// the real policy is tested against there
import { IntentExecutorTestUtils } from "../../settlementlayer/IntentExecutorTestUtils.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { BridgeSessionStorageLib } from "@policies/bridge/lib/BridgeSessionStorageLib.sol";
import {
    LAYER_INTENT_EXECUTOR,
    INTENT_EXECUTOR_NONCE_START,
    PERMIT2_NONCE_START,
    NONCE_LENGTH
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";
import { NO_GASREFUND } from "@policies/settlementlayer/shared/types/IntentExecutorDataTypes.sol";

/// @title BridgeSessionPolicy over the REAL settlement-layer policy
/// @notice Everything else in this suite exercises the executor layer through a stand-in. This
/// drives `StaticIntentExecutorPolicy` from PR #46 as an actual sub-policy, with the payload built
/// by that suite's own helpers — so the bytes are identical to what the real policy is tested
/// against, and the pin is read out of a genuine SingleChainOps blob.
contract BridgeSessionPolicy_realExecutorLayer_Test is Test, IntentExecutorTestUtils {
    using BridgeSessionStorageLib for ConfigId;

    BridgeSessionPolicy internal policy;
    StaticIntentExecutorPolicy internal executorLayer;
    RelayAdapter internal adapter;

    MockPermit2Bitmap internal permit2;
    MockIntentExecutorNonces internal executor;

    ConfigId internal configId = ConfigId.wrap(keccak256("bridge.session.real"));
    address internal multiplexer;
    address internal account;
    address internal intentExecutor;
    address internal relayRouter;
    address internal ieAdapter;
    address internal token;
    address internal recipient;

    uint256 internal constant PINNED = 1337;
    uint256 internal constant MAX_EX_RATE = 1e20;

    function setUp() public {
        adapter = new RelayAdapter();
        executorLayer = new StaticIntentExecutorPolicy(adapter);

        permit2 = new MockPermit2Bitmap();
        executor = new MockIntentExecutorNonces();
        policy = new BridgeSessionPolicy(address(executor), address(permit2));

        multiplexer = makeAddr("smartSession");
        account = makeAddr("account");
        intentExecutor = makeAddr("intentExecutor");
        relayRouter = makeAddr("relayRouter");
        ieAdapter = makeAddr("ieAdapter");
        token = makeAddr("usdc");
        recipient = makeAddr("recipient");

        // The settlement policy's own configuration, exactly as its suite builds it
        bytes memory layerInit = bytes.concat(
            abi.encodePacked(intentExecutor, uint8(0), uint256(MAX_EX_RATE), uint8(1), token),
            abi.encodePacked(relayRouter, ieAdapter, uint8(1), recipient, uint8(1), token)
        );

        bytes memory initData = abi.encodePacked(
            bytes32(PINNED),
            uint8(1),
            uint8(LAYER_INTENT_EXECUTOR),
            address(executorLayer),
            uint256(layerInit.length),
            layerInit
        );

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _routerCall(bytes4 sel, uint256 value) internal view returns (Execution memory) {
        return
            Execution({ target: relayRouter, value: value, callData: abi.encodeWithSelector(sel) });
    }

    function _erc20Call(
        bytes4 sel,
        address arg,
        uint256 amount
    )
        internal
        view
        returns (Execution memory)
    {
        return
            Execution({
                target: token, value: 0, callData: abi.encodeWithSelector(sel, arg, amount)
            });
    }

    function _calls() internal view returns (Execution[] memory calls) {
        calls = new Execution[](2);
        calls[0] = _erc20Call(RelayCalldataLib.SEL_ERC20_APPROVE, relayRouter, 100);
        calls[1] = _routerCall(RelayCalldataLib.SEL_RELAY_MULTICALL, 0);
    }

    /// @dev A real SingleChainOps settlement on `nonce`, with this policy's layer tag in front
    function _settlement(uint256 nonce)
        internal
        view
        returns (bytes32 digest, bytes memory tagged)
    {
        Execution[] memory calls = _calls();
        digest = _digest(intentExecutor, account, nonce, calls, NO_GASREFUND);
        tagged = abi.encodePacked(
            uint8(LAYER_INTENT_EXECUTOR), _blobSansGasRefund(account, nonce, calls)
        );
    }

    function _check(bytes32 digest, bytes memory tagged) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(configId, address(0), account, digest, tagged);
    }

    /*//////////////////////////////////////////////////////////////
                          THE REAL POLICY VALIDATES
    //////////////////////////////////////////////////////////////*/

    /// @dev The whole point: a genuine settlement, through the genuine settlement policy,
    ///      multiplexed by this one, with the pin read from the real payload.
    function test_realExecutorSettlement_validates() public {
        (bytes32 digest, bytes memory tagged) = _settlement(PINNED);

        assertTrue(_check(digest, tagged), "a real pinned settlement must validate");
    }

    /// @dev The settlement policy is genuinely consulted — its own ACL still applies underneath.
    ///      A call to an address its adapter does not permit must be refused even though the pin
    ///      and the exclusion both pass.
    function test_settlementPolicyAclStillApplies() public {
        Execution[] memory calls = new Execution[](1);
        calls[0] = _erc20Call(RelayCalldataLib.SEL_ERC20_TRANSFER, makeAddr("notWhitelisted"), 1);

        bytes32 digest = _digest(intentExecutor, account, PINNED, calls, NO_GASREFUND);
        bytes memory tagged = abi.encodePacked(
            uint8(LAYER_INTENT_EXECUTOR), _blobSansGasRefund(account, PINNED, calls)
        );

        vm.prank(multiplexer);
        vm.expectRevert();
        policy.check1271SignedAction(configId, address(0), account, digest, tagged);
    }

    /*//////////////////////////////////////////////////////////////
                            THE PIN, ON REAL BYTES
    //////////////////////////////////////////////////////////////*/

    /// @dev The defect this design exists to fix, now against a real payload: a settlement on any
    ///      other nonce must be refused, even though it is perfectly valid to the settlement
    ///      policy itself.
    function test_realSettlementOnAnotherNonce_refused() public {
        (bytes32 digest, bytes memory tagged) = _settlement(PINNED + 1);

        assertFalse(_check(digest, tagged), "an unpinned settlement must be refused");
    }

    /// @dev The offset was previously trusted, not proven — there was no counterpart in this repo
    ///      to assert it against. There is now. This pins `INTENT_EXECUTOR_NONCE_START` to the
    ///      layout the real settlement policy's own payload builder produces.
    function test_nonceOffsetMatchesTheRealPayloadLayout() public view {
        bytes memory blob = _blobSansGasRefund(account, PINNED, _calls());

        uint256 read;
        for (uint256 i; i < NONCE_LENGTH; ++i) {
            read = (read << 8) | uint8(blob[INTENT_EXECUTOR_NONCE_START + i]);
        }

        assertEq(read, PINNED, "the pin must sit exactly where the policy reads it");
    }

    /// @dev The Permit2 side of the same claim. `Permit2ClaimPolicy` reads a header of
    ///      `arbiter ‖ nonce ‖ deadline` with no prefix, so the pin sits at 20. This asserts
    /// the
    ///      layout only — the Permit2 policy's own behaviour is covered by its suite, and this
    ///      policy's dispatch to it by the stand-in in `exactlyOnce`.
    function test_permit2NonceOffsetMatchesTheRealHeaderLayout() public {
        bytes memory header = abi.encodePacked(makeAddr("arbiter"), PINNED, block.timestamp + 1);

        uint256 read;
        for (uint256 i; i < NONCE_LENGTH; ++i) {
            read = (read << 8) | uint8(header[PERMIT2_NONCE_START + i]);
        }

        assertEq(read, PINNED, "the pin must sit exactly where the policy reads it");
    }

    /*//////////////////////////////////////////////////////////////
                            THE UNBOUND VERIFIER
    //////////////////////////////////////////////////////////////*/

    /// @dev Init accepts a sub-policy configured for a settlement contract this multiplexer does
    ///      not watch. `supportsInterface` proves the layer is an `I1271Policy`; nothing proves it
    ///      verifies against the same executor `spentElsewhere` reads nonces from.
    ///
    ///      That gap voids the guarantee. A settlement bound to the configured executor burns ITS
    ///      nonce, while the exclusion check reads this multiplexer's immutable and finds it
    ///      clean, so the Permit2 route stays open and the session spends twice.
    ///
    ///      Enforcing it in code was declined in favour of the install-time requirement documented
    ///      on `BridgeSessionPolicy`. This test exists so the decision stays visible and so the
    ///      day someone adds the check, a red test tells them the doc needs deleting.
    ///
    ///      It also reads on this file's own setUp, which means every other assertion here runs
    ///      against a mismatched pair - fine for the offsets and the pin, which do not touch the
    ///      executor address, but worth knowing when reading the exclusion cases below.
    function test_initAcceptsASubPolicyBoundToADifferentExecutor() public {
        address watched = address(policy.INTENT_EXECUTOR());

        // `getIntentExecutor` keys on msg.sender, so read it as the multiplexer that installed it
        vm.prank(address(policy));
        address verified = executorLayer.getIntentExecutor(
            configId.toLayerConfigId(multiplexer, 1, LAYER_INTENT_EXECUTOR), account
        );

        assertTrue(verified != address(0), "the sub-policy is initialized");
        assertTrue(
            verified != watched,
            "this file's setUp already diverges - if this ever fails, the setUp was fixed"
        );
    }

    /*//////////////////////////////////////////////////////////////
                       CROSS-LAYER EXCLUSION, ON REAL BYTES
    //////////////////////////////////////////////////////////////*/

    /// @dev Permit2 already settled this nonce, so the executor route must close
    function test_permit2AlreadySettled_refusesRealSettlement() public {
        permit2.burn(account, PINNED);

        (bytes32 digest, bytes memory tagged) = _settlement(PINNED);

        assertFalse(_check(digest, tagged), "the Permit2 spend must close the executor route");
    }

    /// @dev A spend in one of the executor's OTHER namespaces also closes it — this settlement
    ///      burns standalone, so compact and permit2-stub remain real evidence of a prior spend
    function test_compactNamespaceSettled_refusesRealSettlement() public {
        executor.burnCompact(PINNED, account);

        (bytes32 digest, bytes memory tagged) = _settlement(PINNED);

        assertFalse(_check(digest, tagged), "a compact spend must close the standalone route");
    }

    /// @dev And its own namespace does NOT close it — the executor burns standalone before it
    ///      validates, so this reads as spent during the very settlement being validated
    function test_ownStandaloneBurn_doesNotRefuse() public {
        executor.burnStandalone(PINNED, account);

        (bytes32 digest, bytes memory tagged) = _settlement(PINNED);

        assertTrue(_check(digest, tagged), "a settlement must not be refused by its own burn");
    }
}
