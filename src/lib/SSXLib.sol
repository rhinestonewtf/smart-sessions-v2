// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { EnumerableMapLib } from "solady/utils/EnumerableMapLib.sol";
import { IdLib } from "@the-compact/lib/IdLib.sol";

struct Permission {
    EnumerableMapLib.AddressToBytes32Map localPermission;
    address externalPermission;
}

enum PermissionMode {
    IGNORE,
    COMPARE,
    LOCAL_MAPPING,
    EXTERNAL_POLICY
}

library PermissionIdLib {
    function toCompactPolicyId(bytes32 permissionId) internal pure returns (bytes32 configId) {
        configId = keccak256(abi.encodePacked("ERC1271: ", permissionId));
    }

    function extractPermissionId(bytes calldata emissaryData) internal pure returns (bytes32) {
        return bytes32(emissaryData[:32]);
    }
}

library ConfigBitMapLib {
    using ConfigBitMapLib for bytes1;
    using IdLib for uint256;
    using EnumerableMapLib for EnumerableMapLib.AddressToBytes32Map;

    /* //////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 internal constant NO_EXEC =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    // Byte position constants for configuration bitmap (single source of truth)
    uint8 internal constant BYTE_IS_ENABLED = 31;
    uint8 internal constant BYTE_ANY_TARGET_CHAIN_ID = 30;
    uint8 internal constant BYTE_ARBITER_ID = 30;
    uint8 internal constant BYTE_PRE_CLAIM_OPS = 28;
    uint8 internal constant BYTE_TARGET_OPS = 27;
    uint8 internal constant BYTE_CLAIM_EXPIRY = 26;
    uint8 internal constant BYTE_FILL_EXPIRY = 25;
    uint8 internal constant BYTE_RECIPIENT = 3;
    uint8 internal constant BYTE_TOKEN_OUT = 2;
    uint8 internal constant BYTE_TOKEN_IN = 1;

    /* //////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function getPermissionMode(bytes1 flag) internal pure returns (PermissionMode mode) {
        mode = PermissionMode(uint8(flag));
    }

    // byte32 global enable
    // 0: isEnabled:false
    // 1: isEnabled:true
    function isEnabled(bytes32 configFlag) internal pure returns (bool) {
        return configFlag[BYTE_IS_ENABLED] == bytes1(0x01);
    }

    // byte31
    function isAnyTargetChainId(bytes32 configFlag) internal pure returns (bool) {
        return configFlag[BYTE_ANY_TARGET_CHAIN_ID] == bytes1(0x01);
    }

    // byte30
    function isInspectArbiterId(bytes32 configFlag, address arbiter) internal pure returns (bool) {
        // return configFlag;
    }

    // byte 28 preclaimops
    function inspectPreClaimOps(bytes32 configFlag, bytes32 preClaimOps)
        internal
        pure
        returns (bool)
    {
        if (preClaimOps == NO_EXEC) return true;
        else return configFlag[BYTE_PRE_CLAIM_OPS] == bytes1(0x01);
    }

    // byte 27 target ops
    function inspectTargetOps(bytes32 configFlag, bytes32 targetOps) internal pure returns (bool) {
        if (targetOps == NO_EXEC) return true;
        else return configFlag[BYTE_TARGET_OPS] == bytes1(0x01);
    }

    // byte 26 claimExpires
    function isInspectClaimExpiry(bytes32 configFlag, uint256 providedValue, uint256 maxValue)
        internal
        pure
        returns (bool)
    {
        bytes1 flag = configFlag[BYTE_CLAIM_EXPIRY];
        PermissionMode mode = flag.getPermissionMode();

        if (mode == PermissionMode.IGNORE) {
            return false;
        } else if (mode == PermissionMode.COMPARE) {
            return providedValue <= maxValue;
        }
    }

    // byte 25 claimExpires
    function isInspectFillExpiry(bytes32 configFlag, uint256 providedValue, uint256 maxValue)
        internal
        pure
        returns (bool)
    {
        bytes1 flag = configFlag[BYTE_FILL_EXPIRY];
        PermissionMode mode = flag.getPermissionMode();

        if (mode == PermissionMode.IGNORE) {
            return false;
        } else if (mode == PermissionMode.COMPARE) {
            return providedValue <= maxValue;
        }
    }

    // byte3 recipient flag
    // | 0 : not ispect
    // | 1 : use mapping
    // | 2 : use external policy
    function inspectRecipient(
        bytes32 configFlag,
        address recipient,
        address sponsor,
        Permission storage $permission
    )
        internal
        view
        returns (bool)
    {
        bytes1 flag = configFlag[BYTE_RECIPIENT];
        PermissionMode mode = flag.getPermissionMode();

        if (mode == PermissionMode.IGNORE) {
            return true;
        } else if (mode == PermissionMode.COMPARE) {
            return recipient == sponsor;
        } else if (mode == PermissionMode.LOCAL_MAPPING) {
            // check local mapping
            return $permission.localPermission.contains(recipient);
        } else if (mode == PermissionMode.EXTERNAL_POLICY) {
            address policy = $permission.externalPermission;
            // call policy
            // return
        }
    }

    // byte2 tokenOut flag
    // | 0 : not ispect
    // | 1 : use mapping
    // | 2 : use external policy
    function inspectTokenOuts(
        bytes32 configFlag,
        uint256[2][] memory tokenOut,
        Permission storage $permission
    )
        internal
        view
        returns (bool)
    {
        bytes1 flag = configFlag[BYTE_TOKEN_OUT];
        PermissionMode mode = flag.getPermissionMode();
        if (mode == PermissionMode.IGNORE) {
            return true;
        } else if (mode == PermissionMode.LOCAL_MAPPING) {
            for (uint256 i; i < tokenOut.length; i++) {
                if (!$permission.localPermission.contains(tokenOut[i][0].toAddress())) {
                    return false;
                }
            }
            return true;
        } else if (mode == PermissionMode.EXTERNAL_POLICY) {
            address policy = $permission.externalPermission;
        }
    }

    // byte1 tokenIns flag
    // | 0 : not ispect
    // | 1 : use mapping
    // | 2 : use external policy
    function inspectTokenIns(
        bytes32 configFlag,
        uint256[2][] memory tokenIn,
        Permission storage $permission
    )
        internal
        view
        returns (bool)
    {
        bytes1 flag = configFlag[BYTE_TOKEN_IN];
        PermissionMode mode = flag.getPermissionMode();
        if (mode == PermissionMode.IGNORE) {
            return true;
        } else if (mode == PermissionMode.LOCAL_MAPPING) {
            for (uint256 i; i < tokenIn.length; i++) {
                if (!$permission.localPermission.contains(tokenIn[i][0].toAddress())) {
                    return false;
                }
            }
            return true;
        } else if (mode == PermissionMode.EXTERNAL_POLICY) {
            address policy = $permission.externalPermission;
        }
    }
}
