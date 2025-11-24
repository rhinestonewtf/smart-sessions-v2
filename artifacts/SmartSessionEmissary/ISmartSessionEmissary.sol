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
    type ActionId is bytes32;
    type PermissionId is bytes32;

    struct ActionData {
        bytes4 actionTargetSelector;
        address actionTarget;
        PolicyData[] actionPolicies;
    }

    struct ChainDigest {
        uint64 chainId;
        bytes32 sessionDigest;
    }

    struct DisableSession {
        uint8 chainDigestIndex;
        ChainDigest[] hashesAndChainIds;
    }

    struct ERC7739Context {
        bytes32 appDomainSeparator;
        string[] contentNames;
    }

    struct ERC7739Data {
        ERC7739Context[] allowedERC7739Content;
        PolicyData[] erc1271Policies;
    }

    struct EnableSession {
        uint8 chainDigestIndex;
        ChainDigest[] hashesAndChainIds;
        Session sessionToEnable;
    }

    struct PolicyData {
        address policy;
        bytes initData;
    }

    struct Session {
        address sessionValidator;
        bytes sessionValidatorInitData;
        bytes32 salt;
        ActionData[] actions;
        PolicyData[] claimPolicies;
        ERC7739Data erc7739Policies;
    }

    struct SmartSessionEmissaryConfig {
        Scope scope;
        ResetPeriod resetPeriod;
        address allocator;
        PermissionId permissionId;
    }

    struct SmartSessionEmissaryDisable {
        bytes allocatorSig;
        bytes userSig;
        uint256 expires;
        DisableSession session;
    }

    struct SmartSessionEmissaryEnable {
        bytes allocatorSig;
        bytes userSig;
        uint256 expires;
        EnableSession session;
    }

    error ChainIdMismatch(uint64 providedChainId);
    error ForbiddenValidationData();
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);
    error IncorrectType();
    error InvalidActionId();
    error InvalidAllocatorSignature();
    error InvalidAllocatorSignature();
    error InvalidData();
    error InvalidDataLength();
    error InvalidEmissaryConfig();
    error InvalidEmissaryDisableData();
    error InvalidEmissaryEnableData();
    error InvalidEnableSignature(address account, bytes32 hash);
    error InvalidISessionValidator(address sessionValidator);
    error InvalidNonce();
    error InvalidPermissionId(PermissionId permissionId);
    error InvalidPermissionId(PermissionId permissionId);
    error InvalidSelfCall();
    error InvalidSession(PermissionId permissionId);
    error InvalidSignature();
    error InvalidTarget();
    error InvalidUserSignature();
    error InvalidUserSignature();
    error NoExecutionsInBatch();
    error NoPoliciesSet(PermissionId permissionId);
    error NotSet();
    error PolicyViolation(PermissionId permissionId, address policy);
    error SignerNotFound(PermissionId permissionId, address account);
    error SmartSessionModuleAlreadyInstalled();
    error UnauthorizedSource();
    error UnsafeFallbackNotAllowed();
    error UnsupportedExecutionType();
    error UnsupportedPolicy(address policy);
    error UnsupportedSelector();

    event EmissaryConfigUpdated(address indexed account, address indexed validator, bytes12 indexed lockTag);
    event NonceIterated(bytes12 lockTag, address indexed account, uint256 nonce);
    event PolicyEnabled(PermissionId permissionId, PolicyType policyType, address policy, address smartAccount);
    event SessionCreated(PermissionId permissionId, address account);
    event SessionRemoved(PermissionId permissionId, address smartAccount);
    event SessionValidatorDisabled(PermissionId permissionId, address sessionValidator, address smartAccount);
    event SessionValidatorEnabled(PermissionId permissionId, address sessionValidator, address smartAccount);
    event SmartSessionEmissaryConfigUpdated(
        address indexed account, PermissionId permissionId, bytes12 indexed lockTag
    );
    event WhitelistStatusUpdated(address source, bool status);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function INTENT_EXECUTOR() external view returns (address);
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
    function getActionPolicies(address account, PermissionId permissionId, ActionId actionId, bytes12 lockTag)
        external
        view
        returns (address[] memory);
    function getConfig(address account, uint8 configId, address validator, bytes12 lockTag)
        external
        view
        returns (bytes memory config);
    function getERC1271Policies(address account, PermissionId permissionId) external view returns (address[] memory);
    function getEnabledActions(address account, PermissionId permissionId, bytes12 lockTag)
        external
        view
        returns (bytes32[] memory);
    function getNonce(address sponsor, bytes12 lockTag) external view returns (uint256);
    function getPermissionId(Session memory session) external pure returns (PermissionId permissionId);
    function getSessionDigest(address account, Session memory data, bytes12 lockTag, uint256 expires)
        external
        view
        returns (bytes32);
    function getSessionValidatorAndConfig(address account, PermissionId permissionId)
        external
        view
        returns (address sessionValidator, bytes memory sessionValidatorData);
    function isInitialized(address smartAccount) external view returns (bool);
    function isModuleType(uint256 typeID) external pure returns (bool);
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes memory signature)
        external
        view
        returns (bytes4 result);
    function onInstall(bytes memory data) external;
    function onUninstall(bytes memory) external;
    function removeConfig(
        address account,
        SmartSessionEmissaryConfig memory config,
        SmartSessionEmissaryDisable memory disableData
    ) external;
    function revokeNonce(bytes12 lockTag) external;
    function setConfig(
        address account,
        IEmissary.EmissaryConfig memory config,
        IEmissary.EmissaryEnable memory enableData
    ) external;
    function setConfig(
        address account,
        SmartSessionEmissaryConfig memory config,
        SmartSessionEmissaryEnable memory enableData
    ) external;
    function verifyClaim(address sponsor, bytes32 digest, bytes32 claimHash, bytes memory emissaryData, bytes12 lockTag)
        external
        view
        returns (bytes4);
    function verifyExecution(
        address sponsor,
        bytes32 digest,
        bytes memory emissaryData,
        Types.Operation memory executions,
        bytes12 lockTag
    ) external returns (bytes4);
}
