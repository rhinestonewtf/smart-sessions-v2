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

    function getPermissionMode(bytes1 flag) internal pure returns (PermissionMode mode) {
        mode = PermissionMode(uint8(flag));
    }

    // byte32 global enable
    // 0: isEnabled:false
    // 1: isEnabled:true
    function isEnabled(bytes32 configFlag) internal pure returns (bool) {
        return configFlag[31] == bytes1(0x01);
    }

    // byte31
    function isAnyTargetChainId(bytes32 configFlag) internal pure returns (bool) {
        return configFlag[30] == bytes1(0x01);
    }

    // byte30
    function isInspectArbiterId(bytes32 configFlag, address arbiter) internal pure returns (bool) {
        // return configFlag;
    }

    // byte29 target chain
    function isAnyTargetChainId(bytes32 configFlag) internal pure returns (bool) {
        return configFlag[29] == bytes1(0x01);
    }

    // byte 28 preclaimops
    function allowPreClaimOps(bytes32 configFlag) internal pure returns (bool) {
        return configFlag[28] == bytes1(0x01);
    }

    // byte 27 target ops
    function allowTargetOps(bytes32 configFlag) internal pure returns (bool) {
        return configFlag[27] == bytes1(0x01);
    }

    // byte 26 claimExpires
    function isInspectClaimExpiry(bytes32 configFlag, uint256 providedValue, uint256 maxValue)
        internal
        pure
        returns (bool)
    {
        bytes1 flag = configFlag[26];
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
        bytes1 flag = configFlag[25];
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
        address recipient,
        address sponsor,
        bytes32 configFlag,
        Permission storage $permission
    )
        internal
        pure
        returns (bool)
    {
        bytes1 flag = configFlag[3];
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
        uint256[2][] memory tokenOut,
        bytes32 configFlag,
        Permission storage $permission
    )
        internal
        pure
        returns (bool)
    {
        bytes1 flag = configFlag[2];
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
        uint256[2][] memory tokenIn,
        bytes32 configFlag,
        Permission storage $permission
    )
        internal
        pure
        returns (bool)
    {
        bytes1 flag = configFlag[1];
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
