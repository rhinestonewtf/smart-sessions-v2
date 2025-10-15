library PermissionIdLib {
    function toCompactPolicyId(bytes32 permissionId) internal pure returns (bytes32 configId) {
        configId = keccak256(abi.encodePacked("ERC1271: ", permissionId));
    }

    function extractPermissionId(bytes calldata emissaryData) internal pure returns (bytes32) {
        return bytes32(emissaryData[:32]);
    }
}

library ConfigBitMapLib {
    function isVanillaQHash(bytes calldata data) internal returns (bytes32 hash) { }
    function isSponsorEqRecipient(uint8 configBitmap) internal returns (bool) { }
    function isInspectTokenIn(uint8 configBitmap) internal returns (bool) { }
    function isInspectTokenOut(uint8 configBitmap) internal returns (bool) { }
    function isInspectTargetChainId(uint8 configBitmap) internal returns (bool) { }
    function isTargetOps(uint8 configBitmap) internal returns (bool) { }
    function isPreClaimOps(uint8 configBitmap) internal returns (bool) { }
}
