// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/// @title CalculateTypehashes
/// @notice Script to calculate all EIP-712 typehashes for HashLibV2
/// @dev Run with: forge script script/CalculateTypehashes.s.sol -vvvv
contract CalculateTypehashes is Script {
    function run() public pure {
        console2.log("=== HashLibV2 Typehashes ===\n");

        // ============================================
        // BASE TYPES (from SmartSessions, unchanged)
        // ============================================

        string memory policyData = "PolicyData(address policy,bytes initData)";
        console2.log("POLICY_DATA_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(policyData)));
        console2.log("");

        string memory actionData =
            "ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)PolicyData(address policy,bytes initData)";
        console2.log("ACTION_DATA_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(actionData)));
        console2.log("");

        string memory erc7739Context =
            "ERC7739Context(bytes32 appDomainSeparator,string[] contentName)";
        console2.log("ERC7739_CONTEXT_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(erc7739Context)));
        console2.log("");

        string memory erc7739Data =
            "ERC7739Data(ERC7739Context[] allowedERC7739Content,PolicyData[] erc1271Policies)ERC7739Context(bytes32 appDomainSeparator,string[] contentName)PolicyData(address policy,bytes initData)";
        console2.log("ERC7739_DATA_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(erc7739Data)));
        console2.log("");

        // ============================================
        // NEW TYPES FOR HashLibV2
        // ============================================

        console2.log("=== NEW HashLibV2 Types ===\n");

        // LockTagData - NEW
        // References: PolicyData
        string memory lockTagData =
            "LockTagData(bytes12 lockTag,PolicyData[] claimPolicies)PolicyData(address policy,bytes initData)";
        console2.log("LOCKTAG_DATA_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(lockTagData)));
        console2.log("");

        // SignedPermissions - MODIFIED
        // References: ActionData, ERC7739Data, LockTagData (alphabetically with their deps)
        string memory signedPermissions =
            "SignedPermissions(ActionData[] actions,ERC7739Data erc7739Policies,LockTagData lockTagPolicies,bool permitGenericPolicy)ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)ERC7739Context(bytes32 appDomainSeparator,string[] contentName)ERC7739Data(ERC7739Context[] allowedERC7739Content,PolicyData[] erc1271Policies)LockTagData(bytes12 lockTag,PolicyData[] claimPolicies)PolicyData(address policy,bytes initData)";
        console2.log("SIGNED_PERMISSIONS_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(signedPermissions)));
        console2.log("");

        // SignedSession - MODIFIED
        // References: SignedPermissions (and all its deps)
        string memory signedSession =
            "SignedSession(address account,uint256 expires,uint256 nonce,SignedPermissions permissions,bytes32 salt,address sessionValidator,bytes sessionValidatorInitData,address smartSessionEmissary)ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)ERC7739Context(bytes32 appDomainSeparator,string[] contentName)ERC7739Data(ERC7739Context[] allowedERC7739Content,PolicyData[] erc1271Policies)LockTagData(bytes12 lockTag,PolicyData[] claimPolicies)PolicyData(address policy,bytes initData)SignedPermissions(ActionData[] actions,ERC7739Data erc7739Policies,LockTagData lockTagPolicies,bool permitGenericPolicy)";
        console2.log("SESSION_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(signedSession)));
        console2.log("");

        // ============================================
        // CHAIN/MULTICHAIN TYPES
        // ============================================

        console2.log("=== Chain Types ===\n");

        // ChainSession
        string memory chainSession =
            "ChainSession(uint64 chainId,SignedSession session)ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)ERC7739Context(bytes32 appDomainSeparator,string[] contentName)ERC7739Data(ERC7739Context[] allowedERC7739Content,PolicyData[] erc1271Policies)LockTagData(bytes12 lockTag,PolicyData[] claimPolicies)PolicyData(address policy,bytes initData)SignedPermissions(ActionData[] actions,ERC7739Data erc7739Policies,LockTagData lockTagPolicies,bool permitGenericPolicy)SignedSession(address account,uint256 expires,uint256 nonce,SignedPermissions permissions,bytes32 salt,address sessionValidator,bytes sessionValidatorInitData,address smartSessionEmissary)";
        console2.log("CHAIN_SESSION_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(chainSession)));
        console2.log("");

        // MultiChainSession
        string memory multiChainSession =
            "MultiChainSession(ChainSession[] sessionsAndChainIds)ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)ChainSession(uint64 chainId,SignedSession session)ERC7739Context(bytes32 appDomainSeparator,string[] contentName)ERC7739Data(ERC7739Context[] allowedERC7739Content,PolicyData[] erc1271Policies)LockTagData(bytes12 lockTag,PolicyData[] claimPolicies)PolicyData(address policy,bytes initData)SignedPermissions(ActionData[] actions,ERC7739Data erc7739Policies,LockTagData lockTagPolicies,bool permitGenericPolicy)SignedSession(address account,uint256 expires,uint256 nonce,SignedPermissions permissions,bytes32 salt,address sessionValidator,bytes sessionValidatorInitData,address smartSessionEmissary)";
        console2.log("MULTICHAIN_SESSION_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(multiChainSession)));
        console2.log("");

        // ============================================
        // DISABLE TYPES
        // ============================================

        console2.log("=== Disable Types ===\n");

        // SignedPermissionDisable
        string memory signedPermissionDisable =
            "SignedPermissionDisable(address account,bytes32 permissionId,bytes12 lockTag,uint256 expires,uint256 nonce)";
        console2.log("SIGNED_PERMISSION_DISABLE_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(signedPermissionDisable)));
        console2.log("");

        // ChainDisable
        string memory chainDisable =
            "ChainDisable(uint64 chainId,SignedPermissionDisable disable)SignedPermissionDisable(address account,bytes32 permissionId,bytes12 lockTag,uint256 expires,uint256 nonce)";
        console2.log("CHAIN_DISABLE_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(chainDisable)));
        console2.log("");

        // MultiChainDisable
        string memory multiChainDisable =
            "MultiChainDisable(ChainDisable[] disablesAndChainIds)ChainDisable(uint64 chainId,SignedPermissionDisable disable)SignedPermissionDisable(address account,bytes32 permissionId,bytes12 lockTag,uint256 expires,uint256 nonce)";
        console2.log("MULTICHAIN_DISABLE_TYPEHASH:");
        console2.logBytes32(keccak256(bytes(multiChainDisable)));
        console2.log("");

        // ============================================
        // DOMAIN SEPARATOR
        // ============================================

        console2.log("=== Domain Separator ===\n");

        string memory domainType = "EIP712Domain(string name,string version)";
        bytes32 domainTypehash = keccak256(bytes(domainType));
        console2.log("_MULTICHAIN_DOMAIN_TYPEHASH:");
        console2.logBytes32(domainTypehash);
        console2.log("");

        bytes32 domainSeparator = keccak256(
            abi.encode(domainTypehash, keccak256("SmartSessionEmissary"), keccak256("1"))
        );
        console2.log("_MULTICHAIN_DOMAIN_SEPARATOR:");
        console2.logBytes32(domainSeparator);
        console2.log("");
    }
}
