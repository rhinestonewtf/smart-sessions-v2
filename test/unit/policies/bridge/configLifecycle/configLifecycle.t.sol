// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import {
    BridgeSessionPolicy_Unit_Test
} from "@test/unit/policies/bridge/BridgeSessionPolicy.t.sol";

// Interfaces
import { IBridgeSessionPolicy } from "@policies/bridge/interfaces/IBridgeSessionPolicy.sol";

// Mocks
import { MockSettlementLayerPolicy } from "@mocks/MockSettlementLayer.sol";

// Types
import {
    LAYER_PERMIT2,
    LAYER_INTENT_EXECUTOR
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";

/// @title BridgeSessionPolicy — configuration lifecycle
/// @notice Two defects found in audit, both about what initialization fails to forbid or erase.
contract BridgeSessionPolicy_configLifecycle_Test is BridgeSessionPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                       ONE POLICY PER LAYER
    //////////////////////////////////////////////////////////////*/

    /// @dev The layer tag is not signed. It selects the nonce offset AND which consumable is
    ///      skipped, and the only thing making that safe is that a mis-tagged payload reaches a
    ///      DIFFERENT policy which rejects it on its own digest binding. One policy on two layers
    ///      removes that defence: the attacker tags the other layer, the nonce is read at the
    ///      wrong offset, a value they choose satisfies the pin, and the consumable that WAS
    ///      spent is the one being skipped.
    function test_onePolicyMayNotServeTwoLayers() public {
        bytes memory initData = abi.encodePacked(
            bytes32(PINNED),
            uint8(2),
            uint8(LAYER_PERMIT2),
            address(permit2Layer),
            uint256(4),
            bytes4(0xdeadbeef),
            uint8(LAYER_INTENT_EXECUTOR),
            address(permit2Layer), // the SAME policy again
            uint256(4),
            bytes4(0xfeedface)
        );

        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBridgeSessionPolicy.DuplicateLayerPolicy.selector, address(permit2Layer)
            )
        );
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    /// @dev Distinct policies are the supported shape and must still install
    function test_distinctPoliciesPerLayer_allowed() public {
        _enable(PINNED);

        assertEq(
            policy.getLayerPolicy(configId, multiplexer, account, LAYER_PERMIT2),
            address(permit2Layer)
        );
        assertEq(
            policy.getLayerPolicy(configId, multiplexer, account, LAYER_INTENT_EXECUTOR),
            address(executorLayer)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       RE-ENABLE MUST NOT LEAVE STALE LAYERS
    //////////////////////////////////////////////////////////////*/

    /// @dev permissionId is derived from the session validator, its init data and the salt - it
    ///      covers NO policy content. So re-enabling a session with a narrower layer set lands on
    ///      this same slot, and `layerPolicy` is a mapping that cannot be enumerated to clear.
    ///      Without the generation bump the dropped layer stays live and settles through a route
    ///      the operator explicitly removed.
    function test_reEnableWithFewerLayers_dropsTheRemovedLayer() public {
        _enable(PINNED);
        assertTrue(_check(_executorPayload(PINNED)), "the executor layer starts permitted");

        // Re-enable, this time permitting ONLY the Permit2 layer
        bytes memory narrowed = abi.encodePacked(
            bytes32(PINNED),
            uint8(1),
            uint8(LAYER_PERMIT2),
            address(permit2Layer),
            uint256(4),
            bytes4(0xdeadbeef)
        );

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, configId, narrowed);

        assertTrue(_check(_permit2Payload(PINNED)), "the retained layer still settles");
        assertFalse(
            _check(_executorPayload(PINNED)), "the dropped layer must not survive the re-enable"
        );
        assertEq(
            policy.getLayerPolicy(configId, multiplexer, account, LAYER_INTENT_EXECUTOR),
            address(0),
            "and must read as uninstalled"
        );
    }

    /// @dev A re-enable that swaps a layer's policy must not leave the old one reachable
    function test_reEnableWithDifferentPolicy_replacesIt() public {
        _enable(PINNED);

        MockSettlementLayerPolicy replacement = new MockSettlementLayerPolicy(DIGEST);

        bytes memory swapped = abi.encodePacked(
            bytes32(PINNED),
            uint8(1),
            uint8(LAYER_PERMIT2),
            address(replacement),
            uint256(4),
            bytes4(0xdeadbeef)
        );

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, configId, swapped);

        assertEq(
            policy.getLayerPolicy(configId, multiplexer, account, LAYER_PERMIT2),
            address(replacement),
            "the new policy is installed"
        );
        assertTrue(_check(_permit2Payload(PINNED)), "and it validates");
    }

    /// @dev Each generation's settlement config is separate, so a re-enabled layer starts from the
    ///      configuration it was just given rather than inheriting the previous one
    function test_reEnableGivesTheLayerAFreshConfig() public {
        _enable(PINNED);

        bytes memory first =
            permit2Layer.getConfig(address(policy), _layerConfigId(1, LAYER_PERMIT2), account);
        assertEq(first.length, 4, "generation 1 config exists");

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(
            account,
            configId,
            abi.encodePacked(
                bytes32(PINNED),
                uint8(1),
                uint8(LAYER_PERMIT2),
                address(permit2Layer),
                uint256(8),
                bytes8(0x0102030405060708)
            )
        );

        bytes memory second =
            permit2Layer.getConfig(address(policy), _layerConfigId(2, LAYER_PERMIT2), account);
        assertEq(second.length, 8, "generation 2 has its own config");
    }
}
