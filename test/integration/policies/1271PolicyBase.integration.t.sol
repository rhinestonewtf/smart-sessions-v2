// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import {
    SmartSessionEmissary_Integration_Base_Test
} from "@test/integration/Base.integration.t.sol";

// Interfaces
import { IERC1271, EIP1271_MAGIC_VALUE } from "@modulekit/module-bases/interfaces/IERC1271.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { AccountInstance, ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { IS_VALID_SIG_1271, IS_VALID_SIG_1271_7739, SignatureMode } from "@lib/ModeLib.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";

// Types
import {
    PermissionId,
    PolicyData,
    ActionData,
    ERC7739Data,
    ERC7739Context
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title Policy 1271 Integration Test Base
/// @author Rhinestone
/// @notice Abstract base contract for testing ERC-1271 signature validation policies
abstract contract Policy1271_Integration_Test is SmartSessionEmissary_Integration_Base_Test {
    using ModuleKitHelpers for *;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
    }

    /*//////////////////////////////////////////////////////////////
                     DIRECT MODE SESSION SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session for Direct Mode validation (simple account-bound signatures)
    /// @dev Direct mode requires explicitly enabling domain 0 to prevent accidental bypass
    function enableDirectModeSession(
        AccountInstance memory account,
        address policy,
        bytes memory policyInitData,
        address signer
    )
        internal
        returns (PermissionId)
    {
        PolicyData[] memory policies = new PolicyData[](1);
        policies[0] = PolicyData({ policy: policy, initData: policyInitData });

        // Enable domain 0 with empty content name for direct mode
        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0] = ERC7739Context({
            appDomainSeparator: bytes32(0), // Domain 0 = direct mode
            contentNames: new string[](1)
        });
        allowedContent[0].contentNames[0] = ""; // Empty string for direct mode

        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: allowedContent, erc1271Policies: policies });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(ownableValidator)),
            salt: keccak256(abi.encodePacked("directMode", block.timestamp)),
            sessionValidatorInitData: createValidatorInitData(signer),
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        return enableSession(account, session);
    }

    /// @notice Enables a Direct Mode session using the default test wallet
    function enableDirectModeSession(
        AccountInstance memory account,
        address policy,
        bytes memory policyInitData
    )
        internal
        returns (PermissionId)
    {
        return enableDirectModeSession(account, policy, policyInitData, testWallet.addr);
    }

    /*//////////////////////////////////////////////////////////////
                     ERC7739 MODE SESSION SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session for ERC7739 Mode validation (nested EIP-712 typed data)
    function enableERC7739Session(
        AccountInstance memory account,
        address policy,
        bytes memory policyInitData,
        address signer,
        bytes32 appDomainSeparator,
        string[] memory contentTypes,
        string[] memory contentNames
    )
        internal
        returns (PermissionId)
    {
        require(contentTypes.length == contentNames.length, "Content arrays mismatch");

        PolicyData[] memory policies = new PolicyData[](1);
        policies[0] = PolicyData({ policy: policy, initData: policyInitData });

        // Build full content names with format: "TypeDefinitionName"
        string[] memory fullContentNames = new string[](contentTypes.length);
        for (uint256 i = 0; i < contentTypes.length; i++) {
            fullContentNames[i] = string(abi.encodePacked(contentTypes[i], contentNames[i]));
        }

        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0] = ERC7739Context({
            appDomainSeparator: appDomainSeparator, contentNames: fullContentNames
        });

        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: allowedContent, erc1271Policies: policies });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(ownableValidator)),
            salt: keccak256(abi.encodePacked("erc7739", block.timestamp)),
            sessionValidatorInitData: createValidatorInitData(signer),
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        return enableSession(account, session);
    }

    /// @notice Enables an ERC7739 session using the default test wallet
    function enableERC7739Session(
        AccountInstance memory account,
        address policy,
        bytes memory policyInitData,
        bytes32 appDomainSeparator,
        string[] memory contentTypes,
        string[] memory contentNames
    )
        internal
        returns (PermissionId)
    {
        return enableERC7739Session(
            account,
            policy,
            policyInitData,
            testWallet.addr,
            appDomainSeparator,
            contentTypes,
            contentNames
        );
    }

    /*//////////////////////////////////////////////////////////////
                     DIRECT MODE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a signature in Direct Mode using default test wallet
    function validateDirectMode(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 hash,
        bytes memory policyData
    )
        internal
        view
        returns (bool valid)
    {
        return
            validateDirectModeWithKey(
                account, permissionId, hash, testWallet.privateKey, policyData
            );
    }

    /// @notice Validates a signature in Direct Mode using specific private key
    function validateDirectModeWithKey(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 hash,
        uint256 privateKey,
        bytes memory policyData
    )
        internal
        view
        returns (bool valid)
    {
        // Direct mode: sign account-bound hash
        bytes32 digestToSign = ECDSA.toEthSignedMessageHash(abi.encode(account.account, hash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digestToSign);
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        return
            validateDirectModeWithSignature(account, permissionId, hash, validatorSig, policyData);
    }

    /// @notice Validates a signature in Direct Mode using pre-created signature
    function validateDirectModeWithSignature(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 hash,
        bytes memory validatorSignature,
        bytes memory policyData
    )
        internal
        view
        returns (bool valid)
    {
        uint256 policyDataOffset = 64 + validatorSignature.length;

        bytes memory signature = abi.encodePacked(
            address(smartSessionEmissary),
            bytes1(SignatureMode.unwrap(IS_VALID_SIG_1271)),
            permissionId,
            policyDataOffset,
            validatorSignature,
            policyData
        );

        // Pass original hash to isValidSignature
        try IERC1271(account.account).isValidSignature(hash, signature) returns (bytes4 result) {
            return result == EIP1271_MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /*//////////////////////////////////////////////////////////////
                     ERC7739 MODE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates typed data signature in ERC7739 mode using default wallet
    function validateERC7739(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 appDomainSeparator,
        string memory contentType,
        string memory contentName,
        bytes memory typedDataPayload,
        bytes memory policyData
    )
        internal
        view
        returns (bool valid)
    {
        return validateERC7739WithKey(
            account,
            permissionId,
            appDomainSeparator,
            contentType,
            contentName,
            typedDataPayload,
            testWallet.privateKey,
            policyData
        );
    }

    /// @notice Validates ERC7739 signature with specific private key
    function validateERC7739WithKey(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 appDomainSeparator,
        string memory contentType,
        string memory contentName,
        bytes memory typedDataPayload,
        uint256 privateKey,
        bytes memory policyData
    )
        internal
        view
        returns (bool valid)
    {
        // Compute all the hashes
        bytes32 contentHash = keccak256(typedDataPayload);
        bytes32 typedDataSignHash =
            _computeTypedDataSignHash(account.account, contentHash, contentType, contentName);

        // Final digest to sign
        bytes32 digestToSign =
            keccak256(abi.encodePacked("\x19\x01", appDomainSeparator, typedDataSignHash));

        // Sign it
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digestToSign);

        // Build ERC7739 wrapper parts
        bytes memory contentsDescription = abi.encodePacked(contentType, contentName);

        // CRITICAL: policyData goes BEFORE the ERC7739 wrapper ending
        // Structure: [r,s,v (65)] [policyData] [appDomain] [contentHash] [description] [uint16]
        bytes memory signatureBody = abi.encodePacked(
            r,
            s,
            v, // 65 bytes - validator sig
            policyData, // Policy data BEFORE wrapper
            appDomainSeparator, // 32 bytes
            contentHash, // 32 bytes
            contentsDescription, // variable
            uint16(contentsDescription.length) // 2 bytes - MUST be at the end
        );

        // policyDataOffset points past the 65-byte ECDSA sig
        uint256 policyDataOffset = 64 + 65;

        bytes memory signature = abi.encodePacked(
            address(smartSessionEmissary),
            bytes1(SignatureMode.unwrap(IS_VALID_SIG_1271_7739)),
            permissionId,
            policyDataOffset,
            signatureBody
        );

        // Message hash for ERC7739
        bytes32 messageHash =
            keccak256(abi.encodePacked("\x19\x01", appDomainSeparator, contentHash));

        try IERC1271(account.account).isValidSignature(messageHash, signature) returns (
            bytes4 result
        ) {
            return result == EIP1271_MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /*//////////////////////////////////////////////////////////////
                         SIGNATURE HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Helper to sign account-bound hash for direct mode
    function signDirectMode(
        address account,
        bytes32 hash,
        uint256 privateKey
    )
        internal
        pure
        returns (bytes memory signature)
    {
        bytes32 digestToSign = ECDSA.toEthSignedMessageHash(abi.encode(account, hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digestToSign);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Computes TypedDataSign hash for ERC7739
    function _computeTypedDataSignHash(
        address account,
        bytes32 contentHash,
        string memory contentType,
        string memory contentName
    )
        internal
        view
        returns (bytes32)
    {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = EIP712(address(account)).eip712Domain();

        bytes32 typeHash = keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                contentName,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentType
            )
        );

        return keccak256(
            abi.encode(
                typeHash,
                contentHash,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract,
                salt
            )
        );
    }
}
