library PermissionIdLib {
    function toCompactPolicyId(bytes32 permissionId) internal pure returns (bytes32 configId) {
        configId = keccak256(abi.encodePacked("ERC1271: ", permissionId));
    }

    function extractPermissionId(bytes calldata emissaryData) internal pure returns (bytes32) {
        return bytes32(emissaryData[:32]);
    }
}

library ConfigBitMapLib {
    function isEnabled(uint8 configBitmap) internal returns (bool) { }
    function isAnyTargetChainId(uint8 configBitmap) internal returns (bool) { }
    function isInspectArbiterId(uint8 configBitmap) internal returns (bool) { }

    // recipient
    function isSponsorEqRecipient(uint8 configBitmap) internal returns (bool) { }
    function isRecipientViaPolicy(uint8 configBitmap) internal returns (bool) { }

    // tokenIn
    function isInspectTokenIn(uint8 configBitmap) internal returns (bool) { }

    // tokenOut
    function isInspectTokenOut(uint8 configBitmap) internal returns (bool) { }

    // preclaimops
    function allowPreClaimOps(uint8 configBitmap) internal returns (bool) { }
    // target ops
    function allowTargetOps(uint8 configBitmap) internal returns (bool) { }
    // timestamps
    function isInspectClaimExpiry(uint8 configBitmap) internal returns (bool) { }
    function isInspectFillExpiry(uint8 configBitmap) internal returns (bool) { }
}
