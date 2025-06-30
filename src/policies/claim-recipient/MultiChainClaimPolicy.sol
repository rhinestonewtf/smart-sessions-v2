// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@forge-std/interfaces/IERC165.sol";

// Contracts
import { EIP712TypeHash } from "@compact-utils/types/EIP712TypeHash.sol";

// Libraries
import { ArgPolicyTreeLib } from
    "@smartsessions/external/policies/ArgPolicy/lib/ArgPolicyTreeLib.sol";
import { ConfigLib, PolicyConfig } from "@policies/claim-recipient/lib/ConfigLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    TokenInConfig,
    TokenOutConfig,
    ParamRules,
    ParamRule,
    TokenAmountConfig
} from "@policies/claim-recipient/types/DataTypes.sol";

import { console } from "@forge-std/console.sol";

/// @title MultiChainClaimPolicy
/// @notice A policy that allows enforcing rules on specific fields of a MultiChainClaim struct:
///         - hasExecutions: executions != empty executions hash
///         - preClaimOps: compare with input (allow specific addresses, data, etc)
///         - recipient + targetChainId: compare with input
///         - tokenIn/amount: per chainId mapping
///         - tokenOut/amount: per targetChainId mapping
///         - qualification: compare with input
///         Uses a bitmap configuration with separate storage for each condition
contract MultiChainClaimPolicy is I1271Policy, EIP712TypeHash {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ConfigLib for PolicyConfig;
    using ConfigLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Token {
        address token;
        uint256 amount;
    }

    struct Op {
        bytes data;
    }

    struct Qualification {
        bytes data;
    }

    struct Target {
        address recipient;
        Token[] tokenOut;
        uint256 targetChain;
        uint256 fillExpires;
    }

    struct Lock {
        bytes12 lockTag;
        address token;
        uint256 amount;
    }

    struct Mandate {
        Target target;
        Op[] preClaimOps;
        Op[] targetOps;
        Qualification q;
    }

    struct Element {
        address arbiter;
        uint256 chainId;
        Lock[] commitments;
        Mandate mandate;
    }

    struct MultichainCompact {
        address sponsor;
        uint256 nonce;
        uint256 expires;
        Element notarizedElement;
        bytes32[] otherElements;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping to store the policy configuration for each account and config ID
    mapping(
        ConfigId id
            => mapping(
                address msgSender => mapping(address userOpSender => PolicyConfig conditionsBitmap)
            )
    ) internal $policyConfig;

    /// @notice Mapping to store token amount configurations per chain id
    mapping(
        ConfigId id
            => mapping(
                address msgSender
                    => mapping(
                        address userOpSender
                            => mapping(uint256 chainId => TokenAmountConfig tokenInConfig)
                    )
            )
    ) internal $tokenInConfig;

    /// @notice Mapping to store token amount configurations per target chain id
    mapping(
        ConfigId id
            => mapping(
                address msgSender
                    => mapping(
                        address userOpSender
                            => mapping(uint256 targetChainId => TokenAmountConfig tokenOutConfig)
                    )
            )
    ) internal $tokenOutConfig;

    /// @notice Mapping to recipient configurations per chain target chain id
    mapping(
        ConfigId id
            => mapping(
                address msgSender
                    => mapping(
                        address userOpSender => mapping(uint256 targetChainId => address recipient)
                    )
            )
    ) internal $recipientConfig;

    /// @notice Mapping to store pre-claim operations configurations
    mapping(
        ConfigId id
            => mapping(
                address msgSender => mapping(address userOpSender => ParamRules preClaimOpsConfig)
            )
    ) internal $preClaimOpsConfig;

    /// @notice Mapping to store qualification params
    mapping(
        ConfigId id
            => mapping(
                address msgSender => mapping(address userOpSender => ParamRules qualificationConfig)
            )
    ) $qualificationConfig;

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 private constant EMPTY_EXECUTIONS_HASH =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the policy with a comprehensive configuration
    /// @param account The account to initialize
    /// @param configId The configuration ID for the policy
    /// @param initData The initialization data containing the PolicyConfig
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        // Parse policy config from first byte of initData
        PolicyConfig config = PolicyConfig.wrap(uint8(initData[0]));

        // Set the policy configuration for the account if the bitmap is not empty
        if (config != PolicyConfig.wrap(0)) {
            // Use the remaining bytes of initData for further configuration
            initData = initData[1:];
            // We only need to load the fields at the offset that are set in the bitmap
            setConfig(account, configId, config, initData);
        } else {
            // Store the sudo configuration
            $policyConfig[configId][msg.sender][account] = config;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the configurations for the enabled conditions, this function only parses the
    ///         configuration data that is set in the bitmap.
    /// @param account The account to set the configuration for
    /// @param configId The configuration ID for the policy
    /// @param configBitmap Bitmap representing enabled conditions
    /// @param configData Additional configuration data for the conditions
    function setConfig(
        address account,
        ConfigId configId,
        PolicyConfig configBitmap,
        bytes calldata configData
    )
        internal
    {
        // Process configuration data based on the bitmap

        // (0) hasExecutions

        // if (configBitmap.hasCheckHasExecutions()) {
        ///    This condition doesn't need any additional data
        // }

        // (1) preClaimOps
        if (configBitmap.hasCheckPreClaimOps()) {
            // Decode preClaimOps configuration
            ParamRules memory preClaimOpsConfig;
            (preClaimOpsConfig, configData) = configData.decodePreClaimOpsConfig();
            // Store the preClaimOps configuration
            $preClaimOpsConfig[configId][msg.sender][account] = preClaimOpsConfig;
        }

        // (2) recipient and targetChainId
        if (configBitmap.hasCheckRecipientAndTargetChain()) {
            // Decode recipient and target chain configuration
            uint256 targetChainId;
            address recipient;
            (targetChainId, recipient, configData) = configData.decodeRecipientAndTargetChain();
            // Store recipient and target chain configuration
            $recipientConfig[configId][msg.sender][account][targetChainId] = recipient;
        }

        // (3) tokenIn
        if (configBitmap.hasCheckTokenIn()) {
            // Decode tokenIn configuration
            TokenInConfig[] memory tokenInConfigs;
            (tokenInConfigs, configData) = configData.decodeTokenInConfig();
            // Store the tokenIn configurations
            for (uint256 i = 0; i < tokenInConfigs.length; i++) {
                TokenInConfig memory tokenInConfig = tokenInConfigs[i];
                $tokenInConfig[configId][msg.sender][account][tokenInConfig.chainId] =
                    tokenInConfig.config;
            }
        }

        // (4) tokenOut
        if (configBitmap.hasCheckTokenOut()) {
            // Decode tokenOut configuration
            TokenOutConfig[] memory tokenOutConfigs;
            (tokenOutConfigs, configData) = configData.decodeTokenOutConfig();
            // Store the tokenOut configurations
            for (uint256 i = 0; i < tokenOutConfigs.length; i++) {
                TokenOutConfig memory tokenOutConfig = tokenOutConfigs[i];
                $tokenOutConfig[configId][msg.sender][account][tokenOutConfig.targetChainId] =
                    tokenOutConfig.config;
            }
        }

        // (5) qualification
        if (configBitmap.hasCheckQualification()) {
            // Decode qualification configuration
            ParamRules memory qualificationConfig;
            (qualificationConfig, configData) = configData.decodeQualificationConfig();
            // Store the qualification configuration
            $qualificationConfig[configId][account][msg.sender] = qualificationConfig;
        }

        // Store the bitmap configuration
        $policyConfig[configId][msg.sender][msg.sender] = configBitmap;
    }

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

    function check1271SignedAction(
        ConfigId id,
        address, /*sender*/
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        override
        returns (bool)
    {
        // Load the policy configuration bitmap
        PolicyConfig config = $policyConfig[id][msg.sender][account];

        console.log("Checking MultiChainClaimPolicy for account:", account);
        console.log("Conditions bitmap:", PolicyConfig.unwrap(config));

        // If no conditions are enabled, allow everything (sudo mode)
        if (config == PolicyConfig.wrap(0)) {
            console.log("No conditions enabled - allowing all actions");
            return true;
        }

        // Extract and decode the MultichainCompact from signature
        MultichainCompact memory multichainCompact = _extractMultichainCompact(signature);

        // Verify hash integrity first
        bytes32 recomputedHash = _rehashMultichainCompact(multichainCompact);
        if (recomputedHash != hash) {
            console.log("Hash mismatch!");
            console.log("Expected:");
            console.logBytes32(hash);
            console.log("Computed:");
            console.logBytes32(recomputedHash);
            return false;
        }
        console.log("Hash verification passed");

        // Check each enabled condition
        return _checkAllConditions(id, account, config, multichainCompact);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Extracts MultichainCompact struct from signature
    function _extractMultichainCompact(bytes calldata signature)
        internal
        pure
        returns (MultichainCompact memory)
    {
        // Extract extraStuff length (first 32 bytes)
        uint256 extraStuffLength;
        assembly {
            extraStuffLength := calldataload(signature.offset)
        }

        // Extract extraStuff
        bytes memory extraStuff = new bytes(extraStuffLength);
        assembly {
            calldatacopy(add(extraStuff, 0x20), add(signature.offset, 0x20), extraStuffLength)
        }

        console.log("Extracted extraStuff length:", extraStuffLength);
        console.logBytes(extraStuff);

        // Decode the extraStuff to get the MultichainCompact struct
        return abi.decode(extraStuff, (MultichainCompact));
    }

    /// @notice Checks all enabled conditions based on the bitmap configuration
    function _checkAllConditions(
        ConfigId id,
        address account,
        PolicyConfig config,
        MultichainCompact memory multichainCompact
    )
        internal
        view
        returns (bool)
    {
        // (0) CHECK_HAS_EXECUTIONS
        if (config.hasCheckHasExecutions()) {
            if (!_checkHasExecutions(multichainCompact)) {
                console.log("Has executions check failed");
                return false;
            }
            console.log("Has executions check passed");
        }

        // (1) CHECK_PRE_CLAIM_OPS
        if (config.hasCheckPreClaimOps()) {
            if (!_checkPreClaimOps(id, multichainCompact)) {
                console.log("PreClaimOps check failed");
                return false;
            }
            console.log("PreClaimOps check passed");
        }

        // (2) CHECK_RECIPIENT_AND_TARGET_CHAIN
        if (config.hasCheckRecipientAndTargetChain()) {
            if (!_checkRecipientAndTargetChain(id, multichainCompact, account)) {
                console.log("Recipient and target chain check failed");
                return false;
            }
            console.log("Recipient and target chain check passed");
        }

        // (3) CHECK_TOKEN_IN
        if (config.hasCheckTokenIn()) {
            if (!_checkTokenIn(id, multichainCompact, account)) {
                console.log("TokenIn check failed");
                return false;
            }
            console.log("TokenIn check passed");
        }

        // (4) CHECK_TOKEN_OUT
        if (config.hasCheckTokenOut()) {
            if (!_checkTokenOut(id, multichainCompact, account)) {
                console.log("TokenOut check failed");
                return false;
            }
            console.log("TokenOut check passed");
        }

        // (5) CHECK_QUALIFICATION
        if (config.hasCheckQualification()) {
            if (!_checkQualification(id, multichainCompact)) {
                console.log("Qualification check failed");
                return false;
            }
            console.log("Qualification check passed");
        }

        console.log("All enabled condition checks passed!");
        return true;
    }

    /// @notice Rehashes the MultichainCompact to verify integrity
    function _rehashMultichainCompact(MultichainCompact memory multichainCompact)
        internal
        view
        returns (bytes32)
    {
        // Hash the target attributes
        bytes32 targetHash = _hashTargetAttributes(
            multichainCompact.notarizedElement.mandate.target.recipient,
            multichainCompact.notarizedElement.mandate.target.tokenOut,
            multichainCompact.notarizedElement.mandate.target.targetChain,
            multichainCompact.notarizedElement.mandate.target.fillExpires
        );

        // Hash the mandate
        bytes32 mandateHash = _hashMandateRaw(
            targetHash,
            multichainCompact.notarizedElement.mandate.preClaimOps,
            multichainCompact.notarizedElement.mandate.targetOps,
            multichainCompact.notarizedElement.mandate.q
        );

        // Hash the notarized element
        bytes32 notarizedElementHash = _hashElementRaw(
            multichainCompact.notarizedElement.arbiter,
            multichainCompact.notarizedElement.chainId,
            multichainCompact.notarizedElement.commitments,
            mandateHash
        );

        // Create the full elements array (notarized element + other elements)
        bytes32[] memory allElements = new bytes32[](multichainCompact.otherElements.length + 1);
        allElements[0] = notarizedElementHash;
        for (uint256 i = 0; i < multichainCompact.otherElements.length; i++) {
            allElements[i + 1] = multichainCompact.otherElements[i];
        }

        // Hash the complete MultichainCompact
        return keccak256(
            abi.encode(
                TYPEHASH_COMPACT,
                multichainCompact.sponsor,
                multichainCompact.nonce,
                multichainCompact.expires,
                keccak256(abi.encodePacked(allElements))
            )
        );
    }

    function _hashTargetAttributes(
        address recipient,
        bytes32 tokenOut,
        uint256 targetChain,
        uint256 fillExpires
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(TYPEHASH_TARGET, recipient, tokenOut, targetChain, fillExpires));
    }

    /// @notice Checks if executions are not empty
    function _checkHasExecutions(MultichainCompact memory multichainCompact)
        internal
        pure
        returns (bool)
    {
        return multichainCompact.notarizedElement.mandate.targetOps != EMPTY_EXECUTIONS_HASH;
    }

    /// @notice Checks preClaimOps using ArgPolicy rules
    function _checkPreClaimOps(
        ConfigId id,
        MultichainCompact memory multichainCompact
    )
        internal
        view
        returns (bool)
    {
        // TODO: Implement ArgPolicy validation
        // ParamRules storage rules = $preClaimOpsConfig[id][msg.sender];
        // return ArgPolicyTreeLib.evaluateExpressionTree(rules, preClaimOpsData);
        console.log("PreClaimOps check");
        return true; // Placeholder
    }

    /// @notice Checks recipient and target chain match expected values
    function _checkRecipientAndTargetChain(
        ConfigId id,
        MultichainCompact memory multichainCompact,
        address account
    )
        internal
        view
        returns (bool)
    {
        address actualRecipient = multichainCompact.notarizedElement.mandate.target.recipient;
        uint256 actualTargetChain = multichainCompact.notarizedElement.mandate.target.targetChain;

        address expectedRecipient = $recipientConfig[id][msg.sender][account][actualTargetChain];

        console.log("Checking recipient and target chain:");
        console.log("  Expected recipient:", expectedRecipient);
        console.log("  Actual recipient:", actualRecipient);
        console.log("  Target chain:", actualTargetChain);

        return actualRecipient == expectedRecipient;
    }

    /// @notice Checks tokenIn amounts per chain
    function _checkTokenIn(
        ConfigId id,
        MultichainCompact memory multichainCompact,
        address account
    )
        internal
        view
        returns (bool)
    {
        // TODO:
        uint256 chainId = multichainCompact.notarizedElement.chainId;
        TokenAmountConfig storage config = $tokenInConfig[id][msg.sender][account][chainId];

        console.log("Checking tokenIn for chain:", chainId);
        console.log("  Config token:", config.token);
        console.log("  Min amount:", uint256(config.minAmount));
        console.log("  Max amount:", uint256(config.maxAmount));

        return config.token != address(0) || config.minAmount > 0 || config.maxAmount > 0;
    }

    /// @notice Checks tokenOut amounts per target chain
    function _checkTokenOut(
        ConfigId id,
        MultichainCompact memory multichainCompact,
        address account
    )
        internal
        view
        returns (bool)
    {
        // TODO:
        uint256 targetChainId = multichainCompact.notarizedElement.mandate.target.targetChain;
        TokenAmountConfig storage config = $tokenOutConfig[id][msg.sender][account][targetChainId];

        console.log("Checking tokenOut for target chain:", targetChainId);
        console.log("  Config token:", config.token);
        console.log("  Min amount:", uint256(config.minAmount));
        console.log("  Max amount:", uint256(config.maxAmount));

        // Return true if we have a config (actual token validation would happen here)
        return config.token != address(0) || config.minAmount > 0 || config.maxAmount > 0;
    }

    /// @notice Checks qualification using ArgPolicy rules
    function _checkQualification(
        ConfigId id,
        MultichainCompact memory multichainCompact
    )
        internal
        view
        returns (bool)
    {
        // TODO: Implement ArgPolicy validation for qualification data
        // ParamRules storage rules = $qualificationConfig[id][msg.sender];
        // return ArgPolicyTreeLib.evaluateExpressionTree(rules, qualificationData);
        console.log("Qualification check");
        return true; // Placeholder
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEW
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if the policy supports the given interface ID
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(I1271Policy).interfaceId
        );
    }

    function __QUALIFIER_EIP712Hash(bytes calldata data)
        public
        view
        virtual
        override
        returns (bytes32)
    { }
}
