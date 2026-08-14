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

        // The settlement policies key their own storage on THIS policy's address, a constant, so
        // they are handed an ID derived from the real multiplexer. See BridgeSessionStorageLib.
        ConfigId layerConfigId = configId.toLayerConfigId(msg.sender);

        uint8 count = uint8(initData[32]);
        uint256 offset = 33;
        uint256 seen;

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
            offset += 20;

            uint256 length = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            $session.layerPolicy[layer] = policy;

            IPolicy(policy)
                .initializeWithMultiplexer({
                    account: account,
                    configId: layerConfigId,
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

        BridgeSession storage $session =
            id.getStorage({ account: account, multiplexer: msg.sender });

        address policy = $session.layerPolicy[layer];
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
                id: id.toLayerConfigId(msg.sender),
                requestSender: requestSender,
                account: account,
                hash: hash,
                signature: payload
            });
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

        return $session.layerPolicy[layer];
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
