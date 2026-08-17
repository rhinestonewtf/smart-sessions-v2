// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {
    Permit2ClaimPolicy_Integration_Test
} from "../Permit2ClaimPolicy/Permit2ClaimPolicy.integration.t.sol";

import { MockAdapter } from "@mocks/MockAdapter.sol";
import { BridgeSessionPolicy } from "@policies/bridge/BridgeSessionPolicy.sol";
import { MockSettlementLayerPolicy } from "@mocks/MockSettlementLayer.sol";

import { PolicyData } from "@types/DataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { FIELD_ARBITER, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";
import {
    LAYER_PERMIT2,
    LAYER_INTENT_EXECUTOR
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

/// @title The bridge session, end to end
/// @notice A REAL Permit2 settlement, routed through the arbiter, with `BridgeSessionPolicy`
/// fronting the REAL `Permit2ClaimPolicy` as its layer-0 sub-policy.
///
/// The chain exercised here:
///
///   router -> MockAdapter.handlePermit2 -> Permit2Arbiter._unlockPermit2
///          -> Permit2.permitWitnessTransferFrom   (burns the real bitmap)
///          -> account.isValidSignature            (msg.sender == Permit2)
///          -> SmartSessionEmissary -> checkERC1271
///          -> BridgeSessionPolicy.check1271SignedAction
///          -> Permit2ClaimPolicy.check1271SignedAction
///
/// Nothing on that path is a stand-in except the layer-1 sub-policy, which no Permit2 settlement
/// reaches. This is the test that shows the multiplexer works in the position it will actually
/// occupy, rather than being driven directly with hand-built calldata.
contract BridgeSessionEndToEnd_Test is Permit2ClaimPolicy_Integration_Test {
    BridgeSessionPolicy internal bridge;
    MockSettlementLayerPolicy internal executorLayer;

    /// @dev matches `$intent.nonce` from the parent setUp
    uint256 internal constant PINNED = 1337;

    function setUp() public virtual override {
        super.setUp();

        executorLayer = new MockSettlementLayerPolicy(keccak256("unused-on-this-path"));

        // The REAL Permit2 and the REAL IntentExecutor
        bridge = new BridgeSessionPolicy(address(env.intentExecutor), address(env.permit2));
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Enables a session whose single ERC-1271 policy is the multiplexer, carrying the REAL
    ///      Permit2ClaimPolicy at layer 0 with the arbiter config the parent's tests use.
    function _enableBridgeSession(address expectedArbiter) internal {
        activeFieldMode = FIELD_ARBITER;

        bytes memory permit2Init = abi.encodePacked(
            _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE), uint8(1), expectedArbiter
        );

        bytes memory bridgeInit = abi.encodePacked(
            bytes32(PINNED),
            uint8(2),
            uint8(LAYER_PERMIT2),
            address(permit2ClaimPolicy),
            uint256(permit2Init.length),
            permit2Init,
            uint8(LAYER_INTENT_EXECUTOR),
            address(executorLayer),
            uint256(4),
            bytes4(0xdeadbeef)
        );

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(bridge), initData: bridgeInit });

        vm.prank(env.smartAccount1.account);
        _enableSession(policyDatas, "bridgeSalt");
    }

    /// @dev The policy blob the settlement carries, with the layer tag the multiplexer strips
    function _taggedPolicyData() internal view returns (bytes memory) {
        return abi.encodePacked(uint8(LAYER_PERMIT2), _createPolicyData());
    }

    /// @dev Builds the order and signature WITHOUT touching the router. Kept separate so a
    ///      negative test can put `expectRevert` immediately before the claim — `expectRevert`
    ///      binds to the next external call, and preparing the payload makes several.
    function _prepareSettlement() internal returns (bytes memory adapterCalldata) {
        Types.Order memory order = _getPermit2Order();
        $intent.userEmissarySig = _createSmartSessionSignature(_taggedPolicyData());

        adapterCalldata = abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                }))
        );
    }

    /// @dev Drives a real Permit2 settlement through the router
    function _settleThroughPermit2() internal returns (uint256 gas) {
        bytes memory adapterCalldata = _prepareSettlement();
        gas = _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /// @dev Reads the REAL Permit2 bitmap
    function _realPermit2Burned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /*//////////////////////////////////////////////////////////////
                        A REAL SETTLEMENT, MULTIPLEXED
    //////////////////////////////////////////////////////////////*/

    /// @dev The whole point: a genuine Permit2 settlement validates through the multiplexer and
    ///      the real claim policy underneath it, and burns the real nonce.
    function test_realPermit2SettlementThroughTheMultiplexer() public {
        _enableBridgeSession(arbiter);

        assertFalse(_realPermit2Burned(PINNED), "the real bitmap starts clean");

        uint256 gas = _settleThroughPermit2();

        assertTrue(gas > 0, "the settlement must go through");
        assertTrue(_realPermit2Burned(PINNED), "and must burn the real Permit2 nonce");
    }

    /// @dev The multiplexer does not weaken the sub-policy: the real Permit2ClaimPolicy's arbiter
    ///      allowlist still applies underneath it.
    function test_subPolicyAclStillAppliesUnderTheMultiplexer() public {
        _enableBridgeSession(makeAddr("someOtherArbiter"));

        bytes memory adapterCalldata = _prepareSettlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /// @dev The pin is enforced against a real settlement: an order on any other nonce must be
    ///      refused even though the claim policy itself would accept it.
    function test_realSettlementOnAnUnpinnedNonce_refused() public {
        _enableBridgeSession(arbiter);

        $intent.nonce = PINNED + 1;

        bytes memory adapterCalldata = _prepareSettlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /*//////////////////////////////////////////////////////////////
                    THE DIAGONAL, AFTER A REAL SETTLEMENT
    //////////////////////////////////////////////////////////////*/

    /// @dev The cross-family exclusion, measured against state a real settlement produced rather
    ///      than a burn the test performed itself. After Permit2 really settles, the executor
    ///      route must read that and close.
    function test_realPermit2SettlementClosesTheExecutorRoute() public {
        _enableBridgeSession(arbiter);
        _settleThroughPermit2();

        assertTrue(_realPermit2Burned(PINNED), "the real settlement burned the bitmap");

        bytes memory executorPayload = abi.encodePacked(
            uint8(LAYER_INTENT_EXECUTOR),
            uint8(0),
            uint8(0),
            $intent.sponsor,
            bytes32(PINNED),
            uint256(0)
        );

        vm.prank(address(smartSessionEmissary));
        bool allowed = bridge.check1271SignedAction(
            _bridgeConfigId(),
            address(env.intentExecutor),
            $intent.sponsor,
            keccak256("executor-digest"),
            executorPayload
        );

        assertFalse(allowed, "a real Permit2 settlement must close the executor route");
    }

    /// @dev The configId SmartSessions hands the multiplexer on the 1271 surface
    function _bridgeConfigId() internal view returns (ConfigId) {
        return
            IdLib.toConfigId(
                IdLib.toErc1271PolicyId(defaultPermissionId), env.smartAccount1.account
            );
    }
}
