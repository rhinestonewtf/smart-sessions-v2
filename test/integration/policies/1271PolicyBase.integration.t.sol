// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import {
    SmartSessionEmissaryMock as SmartSessionEmissary
} from "@mocks/SmartSessionEmissaryMock.sol";
import { OwnableValidator } from "@mocks/MockOwnableValidator.sol";
import {
    SmartSessionCompatibilityFallback
} from "@smartsessions/SmartSessionCompatibilityFallback.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";

// Interfaces
import { IERC1271, EIP1271_MAGIC_VALUE } from "@modulekit/module-bases/interfaces/IERC1271.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { AccountInstance, ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { IS_VALID_SIG_1271, IS_VALID_SIG_1271_7739, SignatureMode } from "@lib/ModeLib.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

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
import {
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { CALLTYPE_STATIC } from "erc7579/lib/ModeLib.sol";

/// @title Policy 1271 Integration Test Base
/// @author Rhinestone
/// @notice Abstract base contract for testing ERC-1271 signature validation policies
abstract contract Policy1271_Integration_Test is Base_Test {
    using ModuleKitHelpers for *;

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    address internal constant MOCK_INTENT_EXECUTOR =
        address(0x1234567890123456789012345678901234567890);

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The SmartSessionEmissary contract instance
    SmartSessionEmissary internal smartSessionEmissary;

    /// @notice Ownable validator for real ECDSA signature validation
    OwnableValidator internal ownableValidator;

    /// @notice Default test wallet used when no specific signer is provided
    Vm.Wallet internal testWallet;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        // Deploy SmartSessionEmissary with mock intent executor
        smartSessionEmissary = new SmartSessionEmissary(MOCK_INTENT_EXECUTOR);

        // Deploy ownable validator
        ownableValidator = new OwnableValidator();

        // Create default test wallet
        testWallet = vm.createWallet("testSigner");
    }

    /*//////////////////////////////////////////////////////////////
                            ACCOUNT SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets up a smart account with SmartSessionEmissary as a validator module
    /// @dev Also installs EIP712 domain fallback handler for ERC7739 support
    /// @param account The account instance to configure
    function setupAccountWithEmissary(AccountInstance memory account) internal {
        // Install SmartSessionEmissary as validator
        account.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSessionEmissary), data: ""
        });

        // Install fallback for EIP712 domain queries (needed for ERC7739)
        bytes memory fallbackData = abi.encode(
            bytes4(0x84b0196e), // eip712Domain selector
            CALLTYPE_STATIC,
            ""
        );
        account.installModule({
            moduleTypeId: MODULE_TYPE_FALLBACK, module: address(fallbackModule), data: fallbackData
        });
    }

    /*//////////////////////////////////////////////////////////////
                     DIRECT MODE SESSION SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session for Direct Mode validation (simple account-bound signatures)
    /// @dev Direct mode requires explicitly enabling domain 0 to prevent accidental bypass
    /// @param account The account to enable the session on
    /// @param policy The policy contract that will validate signature data
    /// @param policyInitData Initialization data for the policy (e.g., allowed signers, amounts)
    /// @param signer The address that will sign messages for this session
    /// @return permissionId The unique identifier for this enabled session
    function enableDirectModeSession(
        AccountInstance memory account,
        address policy,
        bytes memory policyInitData,
        address signer
    )
        internal
        returns (PermissionId)
    {
        vm.prank(account.account);

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

        // Initialize OwnableValidator with threshold = 1 and single owner
        address[] memory owners = new address[](1);
        owners[0] = signer;
        bytes memory validatorInitData = abi.encode(uint256(1), owners);

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(ownableValidator)),
            salt: keccak256(abi.encodePacked("directMode", block.timestamp)),
            sessionValidatorInitData: validatorInitData,
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory ids = smartSessionEmissary.enableSessions(sessions, bytes12(0));
        return ids[0];
    }

    /// @notice Enables a Direct Mode session using the default test wallet
    /// @param account The account to enable the session on
    /// @param policy The policy contract address
    /// @param policyInitData Policy initialization data
    /// @return permissionId The session permission ID
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
    /// @dev This mode is used for user-facing signatures that need wallet UI support
    /// @param account The account to enable the session on
    /// @param policy The policy contract that will validate signature data
    /// @param policyInitData Initialization data for the policy
    /// @param signer The address that will sign typed data
    /// @param appDomainSeparator The EIP-712 domain of the application requesting signatures
    /// @param contentTypes Array of EIP-712 type definitions (e.g., "Permit(address owner,uint256
    /// value)") @param contentNames Array of type names (e.g., "Permit") - must match contentTypes
    /// length
    /// @return permissionId The unique identifier for this enabled session
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

        vm.prank(account.account);

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

        // Initialize OwnableValidator with threshold = 1 and single owner
        address[] memory owners = new address[](1);
        owners[0] = signer;
        bytes memory validatorInitData = abi.encode(uint256(1), owners);

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(ownableValidator)),
            salt: keccak256(abi.encodePacked("erc7739", block.timestamp)),
            sessionValidatorInitData: validatorInitData,
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory ids = smartSessionEmissary.enableSessions(sessions, bytes12(0));
        return ids[0];
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
    /// @param account The account that should validate the signature
    /// @param permissionId The session permission to use
    /// @param hash The message hash to validate (any bytes32)
    /// @param policyData Additional data passed to the policy for validation
    /// @return valid True if signature passes all checks
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
    /// @param account The account that should validate the signature
    /// @param permissionId The session permission to use
    /// @param hash The message hash to validate
    /// @param privateKey The private key to sign with
    /// @param policyData Additional data for policy validation
    /// @return valid True if signature is valid
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
    /// @param account The account validating
    /// @param permissionId The session permission
    /// @param hash The original message hash (NOT the account-bound hash)
    /// @param validatorSignature The validator signature (must be for account-bound hash)
    /// @param policyData Policy validation data
    /// @return valid True if valid
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
        bytes memory signature = _createSmartSessionSignature(
            SignatureMode.unwrap(IS_VALID_SIG_1271), permissionId, validatorSignature, policyData
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
    /// @param account The account validating the signature
    /// @param permissionId The session permission to use
    /// @param appDomainSeparator The app's EIP-712 domain separator
    /// @param contentType The full type definition (e.g., "Permit(address owner,uint256 value)")
    /// @param contentName The type name (e.g., "Permit")
    /// @param typedDataPayload The encoded typed data
    /// @param policyData Additional policy validation data
    /// @return valid True if signature is valid
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

    /// @notice Validates ERC7739 with pre-created signature and wrapper
    /// @param validatorSigWithWrapper Must include r,s,v + appDomain + contentHash + description +
    /// length
    function validateERC7739WithSignature(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 appDomainSeparator,
        bytes32 contentHash,
        bytes memory validatorSigWithWrapper,
        bytes memory policyData
    )
        internal
        view
        returns (bool valid)
    {
        bytes memory signature = _createSmartSessionSignature(
            SignatureMode.unwrap(IS_VALID_SIG_1271_7739),
            permissionId,
            validatorSigWithWrapper,
            policyData
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

    /// @notice Creates a SmartSession signature with all components
    /// @param mode Either IS_VALID_SIG_1271 (0x02) or IS_VALID_SIG_7739 (0x03)
    /// @param permissionId The session permission ID
    /// @param validatorSignature The session validator's signature (or sig + wrapper for 7739)
    /// @param policyData Data passed to the policy for validation
    /// @return Full signature in SmartSession format
    function _createSmartSessionSignature(
        bytes1 mode,
        PermissionId permissionId,
        bytes memory validatorSignature,
        bytes memory policyData
    )
        internal
        view
        returns (bytes memory)
    {
        uint256 policyDataOffset = 64 + validatorSignature.length;

        return abi.encodePacked(
            address(smartSessionEmissary),
            mode,
            permissionId,
            policyDataOffset,
            validatorSignature,
            policyData
        );
    }

    /// @notice Helper to sign account-bound hash for direct mode
    /// @param account The account address to bind to
    /// @param hash The original message hash
    /// @param privateKey The key to sign with
    /// @return signature The validator signature (r,s,v format)
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

    /// @notice Creates an EIP-712 domain separator for testing
    /// @param appName The application name
    /// @param appVersion The application version
    /// @return The domain separator hash
    function createAppDomainSeparator(
        string memory appName,
        string memory appVersion
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(appName)),
                keccak256(bytes(appVersion)),
                block.chainid,
                address(0xC0FFEE)
            )
        );
    }
}
