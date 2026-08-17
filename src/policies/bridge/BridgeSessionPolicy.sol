// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IBridgeSessionPolicy } from "@policies/bridge/interfaces/IBridgeSessionPolicy.sol";
import { IIntentExecutorNonces } from "@policies/bridge/interfaces/IIntentExecutorNonces.sol";
import { I1271Policy, IPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Libraries
import { BridgeSessionStorageLib } from "@policies/bridge/lib/BridgeSessionStorageLib.sol";
import { BridgeSessionValidationLib } from "@policies/bridge/lib/BridgeSessionValidationLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    BridgeSession,
    LAYER_COUNT,
    LAYER_PERMIT2,
    LAYER_TAG_LENGTH
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";

// forgefmt: disable-start
/// @title Bridge Session Policy
/// @author Rhinestone
/// @notice One session across several settlement layers, spendable exactly once
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                            Why this exists                              │
/// │                                                                         │
/// │  A quorum signs days ahead; the route is only known at settle time. So   │
/// │  the session must authorise every layer up front and still permit one    │
/// │  spend across all of them.                                              │
/// │                                                                         │
/// │  `erc1271Policies` is an AND, so settlement-layer policies cannot sit    │
/// │  side by side - a Permit2 claim would have to satisfy the executor       │
/// │  policy too. The OR therefore lives INSIDE one policy, with the layers   │
/// │  underneath it as settlement policies.                                   │
/// │                                                                         │
/// │  One entry in the list, one pinned nonce in one place, and one rule:     │
/// │  every layer except the one settling must not have spent it.            │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// @dev Uniqueness WITHIN a layer is free - each settlement layer already refuses a second spend of
///      the same nonce, before any policy runs. This policy only closes the cross-layer cases.
/// @dev The layer tag is not covered by the signed digest. It does not need to be: a wrong tag
///      routes to a settlement policy that then fails its own digest binding, because the digest
///      is fixed by whichever settlement contract called the account. Only the tag matching the
///      real caller can produce a digest equal to `hash`.
/// @dev That argument has a precondition, and it is an INSTALL-TIME REQUIREMENT this contract
///      cannot verify: every settlement policy installed here must recompute its own EIP-712
///      digest and compare it against `hash`. `supportsInterface` proves an interface, not that
///      behaviour. Install one that validates loosely and mis-routing stops failing closed - the
///      pin is then read at the wrong layer's offset, against a value the caller chooses, while
///      the consumable actually spent is the one being skipped. Rejecting one policy on two
///      layers closes the easiest way to get a non-discriminating validator into a slot; it does
///      not close the general case.
/// @dev A SECOND INSTALL-TIME REQUIREMENT, and the sharper of the two: each sub-policy must be
///      configured for the SAME settlement contract this policy reads nonces from. The executor
///      sub-policy pins its own `intentExecutor` at init and uses it as the EIP-712
///      `verifyingContract`; this policy reads consumables from its own `INTENT_EXECUTOR`
///      immutable. Nothing here binds the two - `supportsInterface` proves the layer is an
///      `I1271Policy`, not that it watches the same contract.
///
///      Diverge them and the guarantee is void, silently: a settlement validates against the
///      configured executor and burns ITS nonce, while `spentElsewhere` reads this policy's
///      immutable, finds it clean, and leaves the Permit2 route open. The session spends twice
///      with every individual check passing. There is no revert and no event - the only symptom
///      is the second spend.
///
///      Deliberately not enforced in code: `getIntentExecutor` would let this contract read the
///      value back after init and reject a mismatch, at the cost of the multiplexer knowing one
///      sub-policy's concrete type. That tradeoff was declined, so the check belongs to whoever
///      builds the init data. Verify it there.
/// @dev What is actually guaranteed: at most one settlement THROUGH THIS SESSION, on one chain.
///      That is narrower than "the account spends once", and the gap is not theoretical - the
///      intent executor exposes `executeOpsWithoutSignature`, which moves the account's value with
///      no signature, no nonce burned and no policy consulted at all, gated only on a whitelisted
///      arbiter. Nothing a session policy can do reaches that path, because it never enters
///      session validation. Same for any other session the account has enabled.
/// @dev Limits, all of them real: the guarantee is per chain, not per session; any whitelisted
///      arbiter can end the session by settling for zero, since Permit2 burns the nonce before it
///      reads the unsigned transfer details; and it bounds settlements, not signature validations.
// forgefmt: disable-end
contract BridgeSessionPolicy is IBridgeSessionPolicy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BridgeSessionStorageLib for ConfigId;
    using BridgeSessionValidationLib for BridgeSession;

    /*//////////////////////////////////////////////////////////////
                               IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The intent executor whose consumed nonces mark an executor settlement
    IIntentExecutorNonces public immutable INTENT_EXECUTOR;

    /// @notice The Permit2 deployment whose bitmap marks an arbiter settlement
    ISignatureTransfer public immutable PERMIT2;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param intentExecutor The intent executor to consult for executor-side settlements
    /// @param permit2 The Permit2 deployment to consult for arbiter-side settlements
    constructor(address intentExecutor, address permit2) {
        INTENT_EXECUTOR = IIntentExecutorNonces(intentExecutor);
        PERMIT2 = ISignatureTransfer(permit2);
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolicy
    /// @notice Pins the nonce and installs a settlement policy per permitted layer
    /// @dev Init data, packed:
    ///        [0:32]   pinned nonce
    ///        [32]     layer count
    ///        then per layer:
    ///        [..]     layer id      (1 byte)
    ///        [..]     policy        (20 bytes)
    ///        [..]     init length   (32 bytes)
    ///        [..]     init data
    /// @param account The account this configuration belongs to
    /// @param configId The configuration ID
    /// @param initData The pinned nonce followed by the layer configurations
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        if (initData.length < 33) revert InvalidInitDataLength(initData.length);

        BridgeSession storage $session =
            configId.getStorage({ account: account, multiplexer: msg.sender });

        $session.configured = true;
        $session.nonce = uint256(bytes32(initData[0:32]));

        // A re-enable can land on this same slot with a NARROWER layer set - permissionId covers
        // no policy content - and layerPolicy is a mapping that cannot be enumerated to clear. The
        // bump orphans every entry from the previous generation instead.
        uint256 generation = $session.generation + 1;
        $session.generation = generation;

        uint8 count = uint8(initData[32]);
        uint256 offset = 33;
        uint256 seen;
        address[] memory installed = new address[](count);

        for (uint8 i; i < count; ++i) {
            uint8 layer = uint8(initData[offset]);
            if (layer >= LAYER_COUNT) revert UnknownLayer(layer);
            if (seen & (1 << layer) != 0) revert DuplicateLayer(layer);
            seen |= 1 << layer;
            offset += 1;

            address policy = address(bytes20(initData[offset:offset + 20]));
            if (policy == address(0)) revert MissingLayerPolicy();
            if (!IERC165(policy).supportsInterface(type(I1271Policy).interfaceId)) {
                revert InvalidLayerPolicy(policy);
            }

            // One policy may not serve two layers. The layer tag is unsigned and selects both the
            // nonce offset and which consumable is skipped; the only thing making that safe is
            // that a mis-tagged payload reaches a DIFFERENT policy, which rejects it on its own
            // digest binding. Share one policy across layers and that defence disappears.
            for (uint8 j; j < i; ++j) {
                if (installed[j] == policy) revert DuplicateLayerPolicy(policy);
            }
            installed[i] = policy;
            offset += 20;

            uint256 length = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            $session.layerPolicy[BridgeSessionStorageLib.toLayerKey(generation, layer)] = policy;

            IPolicy(policy)
                .initializeWithMultiplexer({
                    account: account,
                    configId: configId.toLayerConfigId(msg.sender, generation, layer),
                    initData: initData[offset:offset + length]
                });
            offset += length;
        }

        emit PolicySet(configId, msg.sender, account);
    }

    /*//////////////////////////////////////////////////////////////
                          SIGNATURE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc I1271Policy
    /// @notice Permits one settlement, on the pinned nonce, through one permitted layer
    /// @dev The payload carries a one-byte layer tag, which this policy strips before handing the
    ///      rest to that layer's settlement policy unchanged
    /// @return True if the settlement may proceed
    function check1271SignedAction(
        ConfigId id,
        address requestSender,
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        override
        returns (bool)
    {
        if (signature.length < LAYER_TAG_LENGTH) return false;

        uint8 layer = uint8(signature[0]);
        if (layer >= LAYER_COUNT) return false;

        // BIND THE TAG TO THE REAL CALLER. The tag is not covered by the signed digest, and it
        // selects both the nonce offset and the consumable that gets skipped - so trusting it is
        // trusting the settler. `requestSender` is the address that actually called the account's
        // `isValidSignature`, i.e. the settlement contract itself, and it is not caller-chosen.
        //
        // This also makes the install-time requirements enforceable rather than documented: a
        // sub-policy configured for a DIFFERENT settlement contract validates digests produced by
        // that contract, and a settlement through it arrives with a `requestSender` that is not
        // ours, so it is refused here before the sub-policy is ever consulted.
        if (requestSender != _expectedSettlerFor(layer)) return false;

        BridgeSession storage $session =
            id.getStorage({ account: account, multiplexer: msg.sender });

        uint256 generation = $session.generation;
        address policy = $session.layerPolicy[BridgeSessionStorageLib.toLayerKey(generation, layer)];
        if (policy == address(0)) return false;

        bytes calldata payload = signature[LAYER_TAG_LENGTH:];

        bool pinned = $session.validate({
            executor: INTENT_EXECUTOR,
            permit2: PERMIT2,
            layer: layer,
            account: account,
            payload: payload
        });
        if (!pinned) return false;

        return I1271Policy(policy)
            .check1271SignedAction({
                id: id.toLayerConfigId(msg.sender, generation, layer),
                requestSender: requestSender,
                account: account,
                hash: hash,
                signature: payload
            });
    }

    /// @notice The settlement contract a given layer's settlements must actually come from
    /// @dev Layers are settlement FAMILIES, and each family has exactly one contract that calls
    ///      the account. Across and Eco are both the Permit2 layer because they settle through
    ///      the same Permit2 deployment - which is also why one bitmap covers both.
    /// @param layer The settlement layer, already bounds-checked by the caller
    /// @return The address that must have called `isValidSignature` for this layer
    function _expectedSettlerFor(uint8 layer) internal view returns (address) {
        return layer == LAYER_PERMIT2 ? address(PERMIT2) : address(INTENT_EXECUTOR);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeSessionPolicy
    function getPinnedNonce(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        override
        returns (bool configured, uint256 nonce)
    {
        BridgeSession storage $session =
            configId.getStorage({ account: account, multiplexer: multiplexer });

        return ($session.configured, $session.nonce);
    }

    /// @inheritdoc IBridgeSessionPolicy
    function getLayerPolicy(
        ConfigId configId,
        address multiplexer,
        address account,
        uint8 layer
    )
        external
        view
        override
        returns (address policy)
    {
        BridgeSession storage $session =
            configId.getStorage({ account: account, multiplexer: multiplexer });

        return $session.layerPolicy[BridgeSessionStorageLib.toLayerKey($session.generation, layer)];
    }

    /*//////////////////////////////////////////////////////////////
                                 ERC165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC165 interface support
    /// @dev Probed at install time; a wrong id makes the policy uninstallable on that surface
    /// @param interfaceId The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(I1271Policy).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
