// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title MockPermit2Bitmap
/// @notice Stand-in for Permit2's public nonce bitmap
contract MockPermit2Bitmap {
    mapping(address owner => mapping(uint256 word => uint256 bits)) public nonceBitmap;

    /// @notice Marks a nonce consumed using Permit2's own word/bit split
    function burn(address owner, uint256 nonce) external {
        nonceBitmap[owner][nonce >> 8] |= uint256(1) << (nonce & 0xff);
    }
}

/// @title MockIntentExecutorNonces
/// @notice Stand-in for the executor's three consumed-nonce namespaces
contract MockIntentExecutorNonces {
    uint8 internal constant STANDALONE = 0;
    uint8 internal constant PERMIT2_STUB = 1;
    uint8 internal constant COMPACT = 2;

    mapping(uint8 family => mapping(uint256 nonce => mapping(address account => bool))) internal
        $consumed;

    function burnStandalone(uint256 nonce, address account) external {
        $consumed[STANDALONE][nonce][account] = true;
    }

    function burnPermit2Stub(uint256 nonce, address account) external {
        $consumed[PERMIT2_STUB][nonce][account] = true;
    }

    function burnCompact(uint256 nonce, address account) external {
        $consumed[COMPACT][nonce][account] = true;
    }

    function isStandaloneIntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool)
    {
        return $consumed[STANDALONE][nonce][account];
    }

    function isPermit2IntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool)
    {
        return $consumed[PERMIT2_STUB][nonce][account];
    }

    function isCompactIntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool)
    {
        return $consumed[COMPACT][nonce][account];
    }
}

/// @title MockSettlementLayerPolicy
/// @notice Stand-in for a settlement-layer policy sitting under BridgeSessionPolicy
/// @dev Faithful in the two ways that matter: it keys its own config on (msg.sender, configId,
///      account) like every real policy, and it binds the payload to the digest, which is what
///      makes a mis-routed layer tag fail closed. `expectedHash` stands in for the EIP-712
///      recomputation a real policy does.
contract MockSettlementLayerPolicy {
    mapping(
        address multiplexer => mapping(bytes32 configId => mapping(address account => bytes))
    ) internal $config;

    /// @notice The digest this layer will accept, standing in for a recomputed EIP-712 digest
    bytes32 public expectedHash;

    constructor(bytes32 expectedHash_) {
        expectedHash = expectedHash_;
    }

    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
    {
        $config[msg.sender][ConfigId.unwrap(configId)][account] = initData;
    }

    function getConfig(
        address multiplexer,
        ConfigId configId,
        address account
    )
        external
        view
        returns (bytes memory)
    {
        return $config[multiplexer][ConfigId.unwrap(configId)][account];
    }

    /// @dev Accepts only when it was configured for this (multiplexer, configId, account) AND the
    ///      digest matches - the two properties a real settlement policy provides
    function check1271SignedAction(
        ConfigId configId,
        address,
        address account,
        bytes32 hash,
        bytes calldata
    )
        external
        view
        returns (bool)
    {
        if ($config[msg.sender][ConfigId.unwrap(configId)][account].length == 0) return false;

        return hash == expectedHash;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId || interfaceId == type(I1271Policy).interfaceId;
    }
}
