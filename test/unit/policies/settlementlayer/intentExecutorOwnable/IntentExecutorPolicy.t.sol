// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "@forge-std/Test.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";

import {
    IBaseIntentExecutorPolicy
} from "@policies/settlementlayer/shared/interfaces/IBaseIntentExecutorPolicy.sol";
import {
    IntentExecutorPolicy,
    LayerStamp
} from "@policies/settlementlayer/intentExecutorOwnable/IntentExecutorPolicy.sol";
import { RelayAdapter } from "@policies/settlementlayer/shared/adapters/RelayAdapter.sol";
import { CCTPAdapter } from "@policies/settlementlayer/shared/adapters/CCTPAdapter.sol";
import { RhinoAdapter } from "@policies/settlementlayer/shared/adapters/RhinoAdapter.sol";
import { RelayCalldataLib } from "@policies/settlementlayer/shared/lib/RelayCalldataLib.sol";
import { RhinoCalldataLib } from "@policies/settlementlayer/shared/lib/RhinoCalldataLib.sol";
import { CCTPCalldataLib } from "@policies/settlementlayer/shared/lib/CCTPCalldataLib.sol";

import { IntentExecutorTestUtils } from "../IntentExecutorTestUtils.sol";

/// @notice Adversarial tests for `IntentExecutorPolicy` (ownable, registry-backed).
///         Covers: registry permissioning, install-time layer freezing, per-call hint
///         dispatch, adapter revert bubbling, and the new error surface from typed errors.
contract IntentExecutorPolicy_Adversarial_Test is Test, IntentExecutorTestUtils {
    IntentExecutorPolicy internal policy;
    RelayAdapter internal relayA;
    CCTPAdapter internal cctpA;
    RhinoAdapter internal rhinoA;

    ConfigId internal configId = ConfigId.wrap(bytes32(uint256(0x0001)));
    address internal owner;
    address internal account;
    address internal intentExecutor;
    address internal relayRouter;
    address internal recipient;
    address internal token;
    address internal bridge;
    address internal messenger;
    bytes32 internal mintRecipient;
    uint32 internal constant CCTP_DOMAIN = 3;
    uint256 internal constant NONCE = 1;

    function setUp() public {
        owner = makeAddr("owner");
        policy = new IntentExecutorPolicy(owner);
        relayA = new RelayAdapter();
        cctpA = new CCTPAdapter();
        rhinoA = new RhinoAdapter();

        vm.startPrank(owner);
        policy.setAdapter(keccak256("RELAY"), address(relayA));
        policy.setAdapter(keccak256("CCTP"), address(cctpA));
        policy.setAdapter(keccak256("RHINO"), address(rhinoA));
        vm.stopPrank();

        account = makeAddr("account");
        intentExecutor = makeAddr("intentExecutor");
        relayRouter = makeAddr("relayRouter");
        recipient = makeAddr("recipient");
        token = makeAddr("usdc");
        bridge = makeAddr("rhinoBridge");
        messenger = makeAddr("tokenMessenger");
        mintRecipient = bytes32(uint256(uint160(makeAddr("dstAccount"))));

        bytes memory baseHeader = abi.encodePacked(
            intentExecutor,
            uint8(0),
            uint256(0),
            uint8(0) // no gas token whitelist for brevity
        );
        bytes memory tail = abi.encodePacked(
            uint8(2), // two layers: Relay + Rhino
            // --- layer 0: RELAY ---
            keccak256("RELAY"),
            uint16(_relayConfig().length),
            _relayConfig(),
            // --- layer 1: RHINO ---
            keccak256("RHINO"),
            uint16(_rhinoConfig().length),
            _rhinoConfig()
        );
        policy.initializeWithMultiplexer(account, configId, bytes.concat(baseHeader, tail));
    }

    /*//////////////////////////////////////////////////////////////
                              REGISTRY
    //////////////////////////////////////////////////////////////*/

    function test_revertWhen_setAdapterByNonOwner() public {
        vm.expectRevert(); // solady Ownable.Unauthorized
        policy.setAdapter(keccak256("NEW"), address(relayA));
    }

    function test_revertWhen_setAdapterLayerIdMismatch() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IntentExecutorPolicy.LayerIdMismatch.selector, keccak256("WRONG"), relayA.layerId()
            )
        );
        vm.prank(owner);
        policy.setAdapter(keccak256("WRONG"), address(relayA));
    }

    function test_ownerSwapAdapter_doesntAffectInstalledSession() public {
        // Pre-condition: a happy-path Relay call works.
        Execution[] memory calls = _justRelayRouter();
        (bytes32 h, bytes memory data) = _build(calls, _hintVector(_hintsAll(0)));
        assertTrue(policy.check1271SignedAction(configId, address(0), account, h, data));

        // Owner swaps Relay's adapter implementation. The installed session has stamped
        // the old `address(relayA)` into storage — it must keep using that. We swap to a
        // *new* RelayAdapter instance (different bytecode address) — the install-time
        // stamp ensures behaviour doesn't change.
        RelayAdapter newRelay = new RelayAdapter();
        vm.prank(owner);
        policy.setAdapter(keccak256("RELAY"), address(newRelay));

        // Same call must still validate (the session is still stamped to the *old*
        // adapter address, which lives on at `relayA`).
        assertTrue(policy.check1271SignedAction(configId, address(0), account, h, data));

        // Inspecting the installed layers proves the session is bound to the old adapter:
        LayerStamp[] memory layers = policy.getInstalledLayers(configId, account);
        assertEq(layers[0].adapter, address(relayA));
    }

    /*//////////////////////////////////////////////////////////////
                              INSTALL
    //////////////////////////////////////////////////////////////*/

    function test_revertWhen_installReferencesUnknownLayer() public {
        bytes memory baseHeader = abi.encodePacked(intentExecutor, uint8(0), uint256(0), uint8(0));
        bytes memory tail = abi.encodePacked(uint8(1), keccak256("UNKNOWN"), uint16(0));
        ConfigId cid = ConfigId.wrap(bytes32(uint256(0x9999)));
        address acct = makeAddr("acct2");
        vm.expectRevert(
            abi.encodeWithSelector(IntentExecutorPolicy.UnknownLayer.selector, keccak256("UNKNOWN"))
        );
        policy.initializeWithMultiplexer(acct, cid, bytes.concat(baseHeader, tail));
    }

    function test_revertWhen_installListsDuplicateLayer() public {
        bytes memory baseHeader = abi.encodePacked(intentExecutor, uint8(0), uint256(0), uint8(0));
        bytes memory tail = abi.encodePacked(
            uint8(2),
            keccak256("RELAY"),
            uint16(_relayConfig().length),
            _relayConfig(),
            keccak256("RELAY"),
            uint16(_relayConfig().length),
            _relayConfig()
        );
        ConfigId cid = ConfigId.wrap(bytes32(uint256(0x9998)));
        address acct = makeAddr("acct3");
        vm.expectRevert(
            abi.encodeWithSelector(
                IntentExecutorPolicy.DuplicateLayerInstall.selector, keccak256("RELAY")
            )
        );
        policy.initializeWithMultiplexer(acct, cid, bytes.concat(baseHeader, tail));
    }

    function test_installFailsFast_onMalformedAdapterConfig() public {
        bytes memory baseHeader = abi.encodePacked(intentExecutor, uint8(0), uint256(0), uint8(0));
        // Relay config blob shorter than the 41-byte minimum header.
        bytes memory badConfig = new bytes(10);
        bytes memory tail =
            abi.encodePacked(uint8(1), keccak256("RELAY"), uint16(badConfig.length), badConfig);
        ConfigId cid = ConfigId.wrap(bytes32(uint256(0x9997)));
        address acct = makeAddr("acct4");
        vm.expectRevert(RelayAdapter.RelayInvalidConfig.selector);
        policy.initializeWithMultiplexer(acct, cid, bytes.concat(baseHeader, tail));
    }

    /*//////////////////////////////////////////////////////////////
                          DISPATCH / HINTS
    //////////////////////////////////////////////////////////////*/

    function test_dispatchesToCorrectLayer() public view {
        // Op[0] is a Relay router call → hint = 0 (Relay slot).
        // Op[1] is a Rhino depositWithId → hint = 1 (Rhino slot).
        Execution[] memory calls = new Execution[](2);
        calls[0] = _relayRouterCall();
        calls[1] = _rhinoDeposit();
        uint8[] memory hints = new uint8[](2);
        hints[0] = 0;
        hints[1] = 1;
        (bytes32 h, bytes memory data) = _build(calls, _hintVector(hints));
        assertTrue(policy.check1271SignedAction(configId, address(0), account, h, data));
    }

    function test_revertWhen_hintCrossesLayers() public {
        // Mark a Relay-shaped call with the Rhino layer hint — Rhino adapter sees a
        // non-bridge non-token target and rejects. We don't assert the exact `bytes`
        // payload (depends on solidity selector encoding); just that AdapterRejected
        // surfaces with the Rhino layerId.
        Execution[] memory calls = new Execution[](1);
        calls[0] = _relayRouterCall();
        uint8[] memory hints = new uint8[](1);
        hints[0] = 1; // Rhino slot
        (bytes32 h, bytes memory data) = _build(calls, _hintVector(hints));
        // Adapter throws `RhinoTargetDeny` because relayRouter isn't bridge/token.
        bytes memory inner =
            abi.encodeWithSelector(RhinoAdapter.RhinoTargetDeny.selector, uint256(0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IntentExecutorPolicy.AdapterRejected.selector, uint256(0), keccak256("RHINO"), inner
            )
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function testFuzz_revertWhen_hintOutOfRange(uint8 hint) public {
        vm.assume(hint >= 2); // we installed 2 layers
        Execution[] memory calls = new Execution[](1);
        calls[0] = _relayRouterCall();
        uint8[] memory hints = new uint8[](1);
        hints[0] = hint;
        (bytes32 h, bytes memory data) = _build(calls, _hintVector(hints));
        vm.expectRevert(
            abi.encodeWithSelector(
                IntentExecutorPolicy.LayerHintOutOfRange.selector, uint256(0), hint, uint256(2)
            )
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function test_revertWhen_hintVectorTruncated() public {
        Execution[] memory calls = new Execution[](2);
        calls[0] = _relayRouterCall();
        calls[1] = _relayRouterCall();
        // Build the digest assuming 2 calls but ship only 1 hint byte + wrong callCount.
        bytes32 h =
            _digest(intentExecutor, account, NONCE, calls, _gasRefundHash(address(0), 0, false));
        bytes memory base = _blobSansGasRefund(account, NONCE, calls);
        bytes memory hintsBlob = abi.encodePacked(uint8(1), uint8(0)); // header says 1, vector len
        // 1
        bytes memory data = bytes.concat(base, hintsBlob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IntentExecutorPolicy.LayerHintsTruncated.selector, uint256(2), data.length
            )
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    /*//////////////////////////////////////////////////////////////
                          ADAPTER BUBBLING
    //////////////////////////////////////////////////////////////*/

    function testFuzz_adapterRejection_bubblesTypedError(address spender) public {
        vm.assume(spender != relayRouter);
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({
            target: token,
            value: 0,
            callData: abi.encodeWithSelector(RelayCalldataLib.SEL_ERC20_APPROVE, spender, 1)
        });
        uint8[] memory hints = new uint8[](1);
        hints[0] = 0; // Relay slot
        (bytes32 h, bytes memory data) = _build(calls, _hintVector(hints));
        bytes memory inner =
            abi.encodeWithSelector(RelayAdapter.RelayApproveBadSpender.selector, uint256(0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IntentExecutorPolicy.AdapterRejected.selector, uint256(0), keccak256("RELAY"), inner
            )
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _relayConfig() internal view returns (bytes memory) {
        // relayRouter || ieAdapter (0) || 1 recipient || token whitelist [token]
        return abi.encodePacked(
            relayRouter,
            address(0), // no ie adapter for this test
            uint8(1),
            recipient,
            uint8(1),
            token
        );
    }

    function _rhinoConfig() internal view returns (bytes memory) {
        return abi.encodePacked(bridge, uint8(1), token);
    }

    function _justRelayRouter() internal view returns (Execution[] memory calls) {
        calls = new Execution[](1);
        calls[0] = _relayRouterCall();
    }

    function _relayRouterCall() internal view returns (Execution memory) {
        return Execution({
            target: relayRouter,
            value: 0,
            callData: abi.encodeWithSelector(RelayCalldataLib.SEL_RELAY_MULTICALL)
        });
    }

    function _rhinoDeposit() internal view returns (Execution memory) {
        return Execution({
            target: bridge,
            value: 0,
            callData: abi.encodeWithSelector(
                RhinoCalldataLib.SEL_DEPOSIT_WITH_ID, token, 1, uint256(0x1234)
            )
        });
    }

    function _hintsAll(uint8 slot) internal pure returns (uint8[] memory hints) {
        hints = new uint8[](1);
        hints[0] = slot;
    }

    function _hintVector(uint8[] memory hints) internal pure returns (bytes memory v) {
        v = abi.encodePacked(uint8(hints.length));
        for (uint256 i; i < hints.length; i++) {
            v = bytes.concat(v, abi.encodePacked(hints[i]));
        }
    }

    function _build(
        Execution[] memory calls,
        bytes memory hintsBlob
    )
        internal
        view
        returns (bytes32 h, bytes memory data)
    {
        h = _digest(intentExecutor, account, NONCE, calls, _gasRefundHash(address(0), 0, false));
        data = bytes.concat(_blobSansGasRefund(account, NONCE, calls), hintsBlob);
    }
}
