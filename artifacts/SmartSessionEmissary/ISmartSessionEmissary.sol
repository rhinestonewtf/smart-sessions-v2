// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

library IEmissary {
    struct EmissaryConfig {
        uint8 configId;
        address allocator;
        Scope scope;
        ResetPeriod resetPeriod;
        address validator;
        bytes validatorConfig;
    }

    struct EmissaryEnable {
        bytes allocatorSig;
        bytes userSig;
        uint256 expires;
        uint256 nonce;
        uint256[] allChainIds;
        uint256 chainIndex;
    }
}

library Types {
    struct Operation {
        bytes data;
    }
}

interface Interface {
    type PolicyType is uint8;
    type ResetPeriod is uint8;
    type Scope is uint8;
    type SmartSessionMode is uint8;
    type PermissionId is bytes32;

    error ChainIdMismatch(uint64 providedChainId);
    error ForbiddenValidationData();
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);
    error IncorrectType();
    error InvalidActionId();
    error InvalidAllocatorSignature();
    error InvalidDataLength();
    error InvalidEmissaryEnableData();
    error InvalidISessionValidator(address sessionValidator);
    error InvalidNonce();
    error InvalidPermissionId(PermissionId permissionId);
    error InvalidPermissionId(PermissionId permissionId);
    error InvalidSelfCall();
    error InvalidSignature();
    error InvalidTarget();
    error InvalidUserSignature();
    error NoExecutionsInBatch();
    error NoPoliciesSet(PermissionId permissionId);
    error NotSet();
    error PolicyViolation(PermissionId permissionId, address policy);
    error Reentrancy();
    error SignerNotFound(PermissionId permissionId, address account);
    error UnauthorizedSource();
    error UnsafeFallbackNotAllowed();
    error UnsupportedPolicy(address policy);
    error UnsupportedSmartSessionMode(SmartSessionMode mode);

    event EmissaryConfigUpdated(address indexed account, address indexed validator, bytes12 indexed lockTag);
    event PolicyEnabled(PermissionId permissionId, PolicyType policyType, address policy, address smartAccount);
    event SessionValidatorEnabled(PermissionId permissionId, address sessionValidator, address smartAccount);
    event SmartSessionEmissaryConfigEnabled(
        address indexed account, PermissionId permissionId, bytes12 indexed lockTag
    );

    fallback() external;

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function INTENT_EXECUTOR() external view returns (address);
    function LENS() external view returns (address);
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
    function getConfig(address account, uint8 configId, address validator, bytes12 lockTag)
        external
        view
        returns (bytes memory config);
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes memory signature)
        external
        view
        returns (bytes4 result);
    function setConfig(
        address account,
        IEmissary.EmissaryConfig memory config,
        IEmissary.EmissaryEnable memory enableData
    ) external;
    function verifyClaim(address sponsor, bytes32 digest, bytes32, bytes memory emissaryData, bytes12 lockTag)
        external
        view
        returns (bytes4);
    function verifyExecution(
        address sponsor,
        bytes32 digest,
        bytes memory emissaryData,
        Types.Operation memory executions
    ) external returns (bytes4);
}
