// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {
    Permit2ClaimPolicy_Integration_Test
} from "../Permit2ClaimPolicy/Permit2ClaimPolicy.integration.t.sol";

import { MockAdapter } from "@mocks/MockAdapter.sol";
import { BridgeSessionPolicy } from "@policies/bridge/BridgeSessionPolicy.sol";
import {
    StaticIntentExecutorPolicy
} from "@policies/settlementlayer/intentExecutorStatic/StaticIntentExecutorPolicy.sol";
import { RelayAdapter } from "@policies/settlementlayer/shared/adapters/RelayAdapter.sol";
import { RelayCalldataLib } from "@policies/settlementlayer/shared/lib/RelayCalldataLib.sol";

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { PolicyData } from "@types/DataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";
import { FIELD_ARBITER, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";
import {
    LAYER_PERMIT2,
    LAYER_INTENT_EXECUTOR
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";

/// @title The full matrix, end to end
/// @notice Every ordering of (Permit2 OR IntentExecutor) AND ONLY ONCE, driven through real
/// contracts with `BridgeSessionPolicy` fronting the REAL `Permit2ClaimPolicy` at layer 0 and the
/// REAL `StaticIntentExecutorPolicy` at layer 1. No stand-ins anywhere.
///
///   Permit2 route   router -> arbiter -> Permit2.permitWitnessTransferFrom
///                           -> account.isValidSignature (msg.sender == Permit2)
///
///   executor route  solver -> StandaloneIntentExecutor.executeSinglechainOps
///                           -> sigMode ERC1271
///                           -> account.isValidSignature (msg.sender == the executor)
///
/// Both land on SmartSession -> BridgeSessionPolicy -> the real sub-policy for that layer.
contract BridgeSessionMatrixE2E_Test is Permit2ClaimPolicy_Integration_Test {
    using SmartExecutionLib for *;

    BridgeSessionPolicy internal bridge;
    StaticIntentExecutorPolicy internal executorLayer;
    RelayAdapter internal relayAdapter;

    address internal relayRouter;
    address internal ieAdapter;
    address internal recipient2;

    /// @dev matches `$intent.nonce` from the parent setUp
    uint256 internal constant PINNED = 1337;
    uint256 internal constant MAX_EX_RATE = 1e20;

    function setUp() public virtual override {
        super.setUp();

        relayRouter = makeAddr("relayRouter");
        ieAdapter = makeAddr("ieAdapter");
        recipient2 = makeAddr("relayRecipient");

        relayAdapter = new RelayAdapter();
        executorLayer = new StaticIntentExecutorPolicy(relayAdapter);

        // The REAL IntentExecutor and the REAL Permit2
        bridge = new BridgeSessionPolicy(address(env.intentExecutor), address(env.permit2));
    }

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    /// @dev One ERC-1271 policy — the multiplexer — carrying BOTH real sub-policies
    function _enableBridgeSession() internal {
        activeFieldMode = FIELD_ARBITER;

        bytes memory permit2Init = abi.encodePacked(
            _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE), uint8(1), arbiter
        );

        bytes memory executorInit = bytes.concat(
            abi.encodePacked(
                address(env.intentExecutor),
                uint8(0),
                uint256(MAX_EX_RATE),
                uint8(1),
                address(env.token1)
            ),
            abi.encodePacked(
                relayRouter, ieAdapter, uint8(1), recipient2, uint8(1), address(env.token1)
            )
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
            uint256(executorInit.length),
            executorInit
        );

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(bridge), initData: bridgeInit });

        vm.prank(env.smartAccount1.account);
        _enableSession(policyDatas, "matrixSalt");
    }

    /*//////////////////////////////////////////////////////////////
                          PERMIT2 ROUTE (REAL)
    //////////////////////////////////////////////////////////////*/

    function _preparePermit2Settlement() internal returns (bytes memory) {
        Types.Order memory order = _getPermit2Order();
        $intent.userEmissarySig = _createSmartSessionSignature(
            abi.encodePacked(uint8(LAYER_PERMIT2), _createPolicyData())
        );

        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                }))
        );
    }

    function _settleViaPermit2() internal {
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _preparePermit2Settlement());
    }

    /*//////////////////////////////////////////////////////////////
                         EXECUTOR ROUTE (REAL)
    //////////////////////////////////////////////////////////////*/

    /// @dev Ops the executor policy's Relay ACL permits
    function _relayCalls() internal view returns (Execution[] memory calls) {
        calls = new Execution[](2);
        calls[0] = Execution({
            target: address(env.token1),
            value: 0,
            callData: abi.encodeWithSelector(
                RelayCalldataLib.SEL_ERC20_APPROVE, relayRouter, uint256(100)
            )
        });
        calls[1] = Execution({
            target: relayRouter,
            value: 0,
            callData: abi.encodeWithSelector(RelayCalldataLib.SEL_RELAY_MULTICALL)
        });
    }

    /// @dev The policy blob must carry the SAME ops the executor validates — the digest covers
    ///      them, including the sigMode byte.
    function _executorSig(
        uint256 nonce,
        Types.Operation memory ops
    )
        internal
        view
        returns (bytes memory)
    {
        return _createSmartSessionSignature(
            abi.encodePacked(
                uint8(LAYER_INTENT_EXECUTOR),
                uint8(0), // VARIANT_SINGLE_CHAIN
                uint8(0), // no gas refund
                env.smartAccount1.account,
                bytes32(nonce),
                abi.encode(ops)
            )
        );
    }

    function _settleViaExecutor(uint256 nonce) internal {
        Types.Operation memory ops = SmartExecutionLib.SigMode.ERC1271.encode(_relayCalls());

        IStandaloneIntentExecutor.SingleChainOps memory signedOps;
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = nonce;
        signedOps.ops = ops;
        signedOps.signature = _executorSig(nonce, ops);

        vm.prank(env.solver.addr);
        env.intentExecutor.executeSinglechainOps(signedOps);
    }

    function _permit2Burned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /*//////////////////////////////////////////////////////////////
                        EITHER ROUTE WORKS ALONE
    //////////////////////////////////////////////////////////////*/

    function test_permit2RouteSettles() public {
        _enableBridgeSession();

        _settleViaPermit2();

        assertTrue(_permit2Burned(PINNED), "the real Permit2 nonce is burned");
    }

    function test_executorRouteSettles() public {
        _enableBridgeSession();

        _settleViaExecutor(PINNED);

        assertTrue(
            env.intentExecutor.isStandaloneIntentNonceConsumed(PINNED, $intent.sponsor),
            "the real standalone nonce is burned"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          ...BUT ONLY ONE OF THEM
    //////////////////////////////////////////////////////////////*/

    /// @dev ORDERING 3: Permit2 -> executor, both real
    function test_permit2ThenExecutor_refused() public {
        _enableBridgeSession();

        _settleViaPermit2();

        vm.expectRevert();
        _settleViaExecutor(PINNED);
    }

    /// @dev ORDERING 4: executor -> Permit2, both real
    function test_executorThenPermit2_refused() public {
        _enableBridgeSession();

        _settleViaExecutor(PINNED);

        bytes memory adapterCalldata = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /// @dev ORDERING 2: executor -> executor, same nonce. Closed by the executor itself.
    function test_executorThenExecutorSameNonce_refused() public {
        _enableBridgeSession();

        _settleViaExecutor(PINNED);

        vm.expectRevert();
        _settleViaExecutor(PINNED);
    }

    /// @dev ORDERING 2, the case the executor does NOT close: a fresh nonce. Only the pin can
    ///      refuse this, and it is the eleven-settlements shape.
    function test_executorOnAFreshNonce_refusedByThePin() public {
        _enableBridgeSession();

        vm.expectRevert();
        _settleViaExecutor(PINNED + 1);
    }

    /// @dev And no later nonce works either
    function test_noFurtherExecutorSettlementOnAnyNonce() public {
        _enableBridgeSession();

        _settleViaExecutor(PINNED);

        for (uint256 i = 1; i <= 5; ++i) {
            vm.expectRevert();
            _settleViaExecutor(PINNED + i);
        }
    }
}
