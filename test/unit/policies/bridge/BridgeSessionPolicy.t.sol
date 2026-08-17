// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { BridgeSessionPolicy } from "@policies/bridge/BridgeSessionPolicy.sol";

// Mocks
import {
    MockPermit2Bitmap,
    MockIntentExecutorNonces,
    MockSettlementLayerPolicy
} from "@mocks/MockSettlementLayer.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    LAYER_PERMIT2,
    LAYER_INTENT_EXECUTOR,
    PERMIT2_NONCE_START,
    INTENT_EXECUTOR_NONCE_START
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";

/// @title BridgeSessionPolicy Unit Test Base
/// @notice One session, two settlement layers, one pinned nonce
abstract contract BridgeSessionPolicy_Unit_Test is Base_Test {
    BridgeSessionPolicy internal policy;
    MockPermit2Bitmap internal permit2;
    MockIntentExecutorNonces internal executor;

    MockSettlementLayerPolicy internal permit2Layer;
    MockSettlementLayerPolicy internal executorLayer;

    address internal account;
    address internal multiplexer;
    ConfigId internal configId;

    uint256 internal constant PINNED = 1337;
    bytes32 internal constant DIGEST = keccak256("the settlement digest");

    function setUp() public virtual override {
        super.setUp();

        permit2 = new MockPermit2Bitmap();
        executor = new MockIntentExecutorNonces();
        policy = new BridgeSessionPolicy(address(executor), address(permit2));

        // Both layers accept the same digest, so a mis-routed tag is not rejected merely because
        // the two mocks disagree - it has to be rejected by the policy's own logic
        permit2Layer = new MockSettlementLayerPolicy(DIGEST);
        executorLayer = new MockSettlementLayerPolicy(DIGEST);

        account = makeAddr("account");
        multiplexer = makeAddr("smartSession");
        configId = ConfigId.wrap(keccak256("bridge.session"));
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev A session permitting both layers, pinned to `nonce`
    function _enable(uint256 nonce) internal {
        bytes memory initData = abi.encodePacked(
            bytes32(nonce),
            uint8(2),
            uint8(LAYER_PERMIT2),
            address(permit2Layer),
            uint256(4),
            bytes4(0xdeadbeef),
            uint8(LAYER_INTENT_EXECUTOR),
            address(executorLayer),
            uint256(4),
            bytes4(0xfeedface)
        );

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @dev A Permit2 claim payload carrying `nonce` at its own offset, with the layer tag
    function _permit2Payload(uint256 nonce) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint8(LAYER_PERMIT2), address(0xA11CE), bytes32(nonce), uint256(1_800_000_000)
        );
    }

    /// @dev A SingleChainOps payload carrying `nonce` at its own offset, with the layer tag
    function _executorPayload(uint256 nonce) internal view returns (bytes memory) {
        return abi.encodePacked(
            uint8(LAYER_INTENT_EXECUTOR), uint8(0), uint8(0), account, bytes32(nonce), uint256(0)
        );
    }

    /// @dev The configId a settlement policy is keyed by, for a given generation and layer
    function _layerConfigId(uint256 generation, uint8 layer) internal view returns (ConfigId) {
        return ConfigId.wrap(keccak256(abi.encode(configId, multiplexer, generation, layer)));
    }

    /// @dev The settlement contract that really calls the account for a given layer. The policy
    ///      binds the unsigned layer tag against this, so a test that passes `address(0)` here is
    ///      testing a call no settlement can make.
    function _settlerFor(uint8 layer) internal view returns (address) {
        return layer == LAYER_PERMIT2 ? address(permit2) : address(executor);
    }

    /// @dev Drives a settlement with the requestSender the tagged layer actually implies
    function _check(bytes memory payload) internal returns (bool) {
        require(payload.length > 0, "payload must carry a layer tag");
        return _check(payload, _settlerFor(uint8(payload[0])));
    }

    /// @dev Drives a settlement with an explicit requestSender, for the mis-routing cases
    function _check(bytes memory payload, address requestSender) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(configId, requestSender, account, DIGEST, payload);
    }
}
