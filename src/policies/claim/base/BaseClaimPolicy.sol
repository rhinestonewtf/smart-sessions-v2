// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    ParamRules,
    SubPolicyConfig,
    RecipientStorageConfig,
    FillExpiryStorageConfig,
    TokenOutStorageConfig,
    OriginOpsStorageConfig,
    DestOpsStorageConfig,
    QualificationStorageConfig,
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_ARBITER,
    FIELD_EXPIRY,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION,
    PolicyConfig
} from "@policies/claim/base/types/BaseDataTypes.sol";

// forgefmt: disable-start
/// @title Base Claim Policy
/// @author Rhinestone
/// @notice Abstract base contract for ClaimPolicy implementations
/// @dev Provides shared initialization, storage management, and validation flow.
///      Concrete implementations (CompactClaimPolicy, Permit2ClaimPolicy) must
///      implement protocol-specific tokenIn handling and hash computation.
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                        Inheritance Hierarchy                            │
/// │                                                                         │
/// │                      ┌──────────────────────┐                           │
/// │                      │   BaseClaimPolicy    │                           │
/// │                      │     (abstract)       │                           │
/// │                      └──────────┬───────────┘                           │
/// │                                 │                                       │
/// │              ┌──────────────────┴──────────────────┐                    │
/// │              ▼                                     ▼                    │
/// │  ┌─────────────────────┐             ┌─────────────────────┐            │
/// │  │ CompactClaimPolicy  │             │ Permit2ClaimPolicy  │            │
/// │  │  (tokenIn+lockTag)  │             │   (tokenIn only)    │            │
/// │  └─────────────────────┘             └─────────────────────┘            │
/// └─────────────────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
abstract contract BaseClaimPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint32;
    using BaseConfigLib for uint8;
    using BaseStorageLib for BasePolicyStorage;
    using BaseStorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when policy initialization fails due to invalid configuration data
    error InvalidConfigurationData();

    /// @notice Thrown when an invalid mode is provided
    error InvalidMode();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a policy is initialized for an account
    /// @param configId The configuration ID
    /// @param account The account that was initialized
    /// @param modeConfig The mode configuration bitmap
    event PolicyInitialized(
        ConfigId indexed configId, address indexed account, PolicyConfig modeConfig
    );

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    // forgefmt: disable-start
    /// @notice Initializes the policy with configuration data
    /// @dev Called by SmartSessions when installing the policy.
    ///      Decodes and stores all field configurations based on modes.
    ///
    /// Initialization calldata layout:
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:4]      modeConfig (uint32)                            │
    /// │  [4:...]    field configs (only if field mode != SKIP)     │
    /// │             ├── arbiter config                             │
    /// │             ├── expiry config                              │
    /// │             ├── tokenIn config (PROTOCOL-SPECIFIC)         │
    /// │             ├── recipient config                           │
    /// │             ├── fillExpiry config                          │
    /// │             ├── tokenOut config                            │
    /// │             ├── originOps config                           │
    /// │             ├── destOps config                             │
    /// │             ├── qualification config                       │
    /// │             └── subPolicy configs (if any MODE_SUBPOLICY)  │
    /// └────────────────────────────────────────────────────────────┘
    ///
    /// modeConfig (uint32) - 2 bits per field:
    /// ┌─────────────────────────────────────────────────────────────┐
    /// │  Bits [31:18] = Reserved (unused)                           │
    /// │  Bits [17:0]  = 9 fields × 2 bits each                      │
    /// │                                                             │
    /// │  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐    │
    /// │  │  Q  │ DO  │ OO  │ TO  │ FE  │ RC  │ TI  │ EX  │ AR  │    │
    /// │  │17:16│15:14│13:12│11:10│ 9:8 │ 7:6 │ 5:4 │ 3:2 │ 1:0 │    │
    /// │  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘    │
    /// │                                                             │
    /// │  Mode values:                                               │
    /// │  0b00 = MODE_SKIP         (no validation)                   │
    /// │  0b01 = MODE_CHECK_STORAGE (validate against storage)       │
    /// │  0b10 = MODE_CHECK_CATCHALL (storage with chainId=0)        │
    /// │  0b11 = MODE_CHECK_SUBPOLICY (delegate to sub-policy)       │
    /// └─────────────────────────────────────────────────────────────┘
    ///
    /// Field config encodings (only present if mode != SKIP):
    /// ┌─────────────────┬────────────────────────────────────────────┐
    /// │  Field          │  Encoding                                  │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  arbiter        │  [count (32)] + [addr (20)] × count        │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  expiry         │  [minExpiry (16)] + [maxExpiry (16)]       │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  tokenIn        │  COMPACT:                                  │
    /// │                 │    [count (32)] + entries:                 │
    /// │                 │      [chainId (32)] + [token (20)] +       │
    /// │                 │      [lockTag (12)]                        │
    /// │                 │  PERMIT2:                                  │
    /// │                 │    [count (32)] + entries:                 │
    /// │                 │      [chainId (32)] + [token (20)]         │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  recipient      │  [count (32)] + entries:                   │
    /// │                 │    [targetChainId (32)] + [recipient (20)] │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  fillExpiry     │  [count (32)] + entries:                   │
    /// │                 │    [targetChainId (32)] +                  │
    /// │                 │    [minFillExpiry (16)] +                  │
    /// │                 │    [maxFillExpiry (16)]                    │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  tokenOut       │  [count (32)] + entries:                   │
    /// │                 │    [targetChainId (32)] + [token (20)]     │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  originOps      │  [count (32)] + entries:                   │
    /// │                 │    [chainId (32)] + [required (1)]         │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  destOps        │  [count (32)] + entries:                   │
    /// │                 │    [targetChainId (32)] + [required (1)]   │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  qualification  │  [count (32)] + entries:                   │
    /// │                 │    [chainId (32)] + [arbiter (20)] +       │
    /// │                 │    [rulesLen (32)] + [rules (variable)]    │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  subPolicies    │  [count (32)] + entries:                   │
    /// │  (if any        │    [fieldId (1)] + [policyAddr (20)] +     │
    /// │   SUBPOLICY)    │    [initDataLen (32)] + [initData (...)]   │
    /// └─────────────────┴────────────────────────────────────────────┘
    ///
    /// Example - Compact with arbiter + tokenIn + recipient:
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:4]      0x00000015 (AR=01, TI=01, RC=01, rest=00)      │
    /// │  [4:36]     arbiter count = 1                              │
    /// │  [36:56]    arbiter address                                │
    /// │  [56:88]    tokenIn count = 2                              │
    /// │  [88:120]   tokenIn[0].chainId                             │
    /// │  [120:140]  tokenIn[0].token                               │
    /// │  [140:152]  tokenIn[0].lockTag                             │
    /// │  [152:184]  tokenIn[1].chainId                             │
    /// │  [184:204]  tokenIn[1].token                               │
    /// │  [204:216]  tokenIn[1].lockTag                             │
    /// │  [216:248]  recipient count = 1                            │
    /// │  [248:280]  recipient[0].targetChainId                     │
    /// │  [280:300]  recipient[0].recipient                         │
    /// └────────────────────────────────────────────────────────────┘
    // forgefmt: disable-end
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
    {
        _initializeBase(configId, account, initData);
    }

    /// @notice Internal initialization for base fields
    /// @dev Decodes modeConfig first, then processes each field based on its mode
    /// @param configId The configuration ID
    /// @param account The account being configured
    /// @param initData The initialization data to decode
    // TODO: optimize gas by reducing memory writes
    function _initializeBase(
        ConfigId configId,
        address account,
        bytes calldata initData
    )
        internal
        virtual
    {
        // Load storage pointer for configId/account pair
        BasePolicyStorage storage $ = configId.getStorage(account);

        // ------------------ POLICY CONFIG ------------------ //

        // Decode modeConfig (first 4 bytes)
        PolicyConfig modeConfig = PolicyConfig.wrap(uint32(bytes4(initData[0:4])));

        // Make sure config is valid
        require(modeConfig != PolicyConfig.wrap(0), InvalidConfigurationData());
        $.modeConfig = modeConfig;

        // Move data pointer
        bytes calldata data = initData[4:];

        // ------------------ ARBITER ------------------ //

        // Decode arbiter if enabled
        if (modeConfig.getFieldMode(FIELD_ARBITER).isStorageMode()) {
            address[] memory arbiters;
            (arbiters, data) = BaseConfigLib.decodeArbiterConfig(data);
            for (uint256 i = 0; i < arbiters.length; i++) {
                $.arbiterConfig.add(arbiters[i]);
            }
        }

        // ------------------ CLAIM EXPIRY ------------------ //

        // Decode expiry if enabled
        if (modeConfig.getFieldMode(FIELD_EXPIRY).isStorageMode()) {
            uint256 packedExpiry;
            (packedExpiry, data) = BaseConfigLib.decodeExpiryConfig(data);
            $.expiryConfig = packedExpiry;
        }

        // ------------------ TOKEN IN ------------------ //

        // Decode tokenIn (protocol-specific - handled by subclass)
        data = _initializeTokenIn(configId, account, modeConfig, data);

        // ------------------ RECIPIENT ------------------ //

        // Decode recipient configs
        if (modeConfig.getFieldMode(FIELD_RECIPIENT).isStorageMode()) {
            RecipientStorageConfig[] memory configs;
            (configs, data) = BaseConfigLib.decodeRecipientConfig(data);
            for (uint256 i = 0; i < configs.length; i++) {
                $.recipientConfig[configs[i].targetChainId] = configs[i].recipient;
            }
        }

        // ------------------ FILL EXPIRY ------------------ //

        // Decode fill expiry configs
        if (modeConfig.getFieldMode(FIELD_FILL_EXPIRY).isStorageMode()) {
            FillExpiryStorageConfig[] memory configs;
            (configs, data) = BaseConfigLib.decodeFillExpiryConfig(data);
            for (uint256 i = 0; i < configs.length; i++) {
                uint256 packed =
                    BaseConfigLib.packUint128(configs[i].minFillExpiry, configs[i].maxFillExpiry);
                $.fillExpiryConfig[configs[i].targetChainId] = packed;
            }
        }

        // ------------------ TOKEN OUT ------------------ //

        // Decode token out configs
        if (modeConfig.getFieldMode(FIELD_TOKEN_OUT).isStorageMode()) {
            TokenOutStorageConfig[] memory configs;
            (configs, data) = BaseConfigLib.decodeTokenOutConfig(data);
            for (uint256 i = 0; i < configs.length; i++) {
                $.tokenOutSet[configs[i].targetChainId].add(configs[i].token);
            }
        }

        // ------------------ ORIGIN OPS ------------------ //

        // Decode origin ops configs
        if (modeConfig.getFieldMode(FIELD_ORIGIN_OPS).isStorageMode()) {
            OriginOpsStorageConfig[] memory configs;
            (configs, data) = BaseConfigLib.decodeOriginOpsConfig(data);
            for (uint256 i = 0; i < configs.length; i++) {
                $.originOpsConfig[configs[i].chainId] = configs[i].requireOriginOps;
            }
        }

        // ------------------ DESTINATION OPS ------------------ //

        // Decode dest ops configs
        if (modeConfig.getFieldMode(FIELD_DEST_OPS).isStorageMode()) {
            DestOpsStorageConfig[] memory configs;
            (configs, data) = BaseConfigLib.decodeDestOpsConfig(data);
            for (uint256 i = 0; i < configs.length; i++) {
                $.destOpsConfig[configs[i].targetChainId] = configs[i].requireDestOps;
            }
        }

        // ------------------ QUALIFICATION ------------------ //

        // Decode qualification configs
        if (modeConfig.getFieldMode(FIELD_QUALIFICATION).isStorageMode()) {
            QualificationStorageConfig[] memory configs;
            (configs, data) = BaseConfigLib.decodeQualificationConfig(data);
            for (uint256 i = 0; i < configs.length; i++) {
                $.qualificationConfig[configs[i].chainId][configs[i].arbiter] = configs[i].rules;
            }
        }

        // ------------------ SUB-POLICIES ------------------ //

        // Decode sub-policies if any
        if (data.length > 0) {
            SubPolicyConfig[] memory subPolicies;
            (subPolicies, data) = BaseConfigLib.decodeSubPolicyConfig(data);
            for (uint256 i = 0; i < subPolicies.length; i++) {
                SubPolicyConfig memory subPolicy = subPolicies[i];

                $.subPolicies[subPolicy.fieldId] = subPolicy.policyAddress;

                // Verify the field is actually set to MODE_CHECK_SUBPOLICY
                uint8 mode = modeConfig.getFieldMode(subPolicy.fieldId);
                if (mode != MODE_CHECK_SUBPOLICY) {
                    revert InvalidMode();
                }

                // Initialize the sub-policy with the provided initData
                I1271Policy(subPolicy.policyAddress)
                    .initializeWithMultiplexer(account, configId, subPolicy.initData);
            }
        }

        // Emit initialized event
        emit PolicyInitialized(configId, account, modeConfig);
    }

    /// @notice Protocol-specific tokenIn initialization
    /// @dev Must be implemented by subclasses to handle Compact vs Permit2 tokenIn formats
    /// @param configId The configuration ID
    /// @param account The account being configured
    /// @param modeConfig The mode configuration bitmap
    /// @param initData Remaining init data starting at tokenIn config
    /// @return remaining Remaining init data after tokenIn config
    function _initializeTokenIn(
        ConfigId configId,
        address account,
        PolicyConfig modeConfig,
        bytes calldata initData
    )
        internal
        virtual
        returns (bytes calldata remaining);

    /*//////////////////////////////////////////////////////////////
                            SIGNATURE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc I1271Policy
    /// @notice Validates an EIP-1271 signed action
    /// @dev Main entry point for signature validation. Routes to protocol-specific
    ///      implementation after validating shared fields.
    /// @param configId The configuration ID
    /// @param account The account that signed
    /// @param hash The hash that was signed
    /// @param data The signature/claim data to validate
    /// @return True if the signature is valid according to policy rules
    function check1271SignedAction(
        ConfigId configId,
        address,
        /* multiplexer */
        address account,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        virtual
        override
        returns (bool)
    {
        // Load storage pointer for configId/account pair
        BasePolicyStorage storage $ = configId.getStorage(account);

        // Load mode configuration
        PolicyConfig modeConfig = $.modeConfig;

        // Delegate to protocol-specific validation
        return _validateClaim(configId, account, hash, data, $, modeConfig);
    }

    /// @notice Protocol-specific claim validation
    /// @dev Must be implemented by subclasses to handle full validation flow
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The expected hash
    /// @param data The claim data
    /// @param $ The storage pointer for the account
    /// @param modeConfig The policy configuration
    /// @return True if validation passes
    function _validateClaim(
        ConfigId configId,
        address account,
        bytes32 hash,
        bytes calldata data,
        BasePolicyStorage storage $,
        PolicyConfig modeConfig
    )
        internal
        view
        virtual
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                                VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the mode configuration for an account
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @return The mode configuration bitmap
    function getModeConfig(
        ConfigId configId,
        address account
    )
        external
        view
        returns (PolicyConfig)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return $.modeConfig;
    }

    /// @notice Returns the whitelisted arbiters for an account
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @return arbiters Array of whitelisted arbiter addresses
    function getArbiters(
        ConfigId configId,
        address account
    )
        external
        view
        returns (address[] memory arbiters)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        uint256 length = $.arbiterConfig.length();
        arbiters = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            arbiters[i] = $.arbiterConfig.at(i);
        }
    }

    /// @notice Checks if an arbiter is whitelisted
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param arbiter The arbiter address to check
    /// @return True if the arbiter is whitelisted
    function isArbiterWhitelisted(
        ConfigId configId,
        address account,
        address arbiter
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return $.arbiterConfig.contains(arbiter);
    }

    /// @notice Returns the expiry bounds for an account
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @return minExpiry The minimum expiry timestamp
    /// @return maxExpiry The maximum expiry timestamp
    function getExpiryBounds(
        ConfigId configId,
        address account
    )
        external
        view
        returns (uint128 minExpiry, uint128 maxExpiry)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        (minExpiry, maxExpiry) = BaseConfigLib.unpackUint128($.expiryConfig);
    }

    /// @notice Returns the configured recipient for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The target chain ID
    /// @return The recipient address
    function getRecipient(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (address)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return $.recipientConfig[chainId];
    }

    /// @notice Returns the sub-policy address for a field
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param fieldId The field ID (0-8)
    /// @return The sub-policy contract address
    function getSubPolicy(
        ConfigId configId,
        address account,
        uint8 fieldId
    )
        external
        view
        returns (address)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return $.subPolicies[fieldId];
    }

    /// @notice Checks if this contract implements the given interface
    /// @param interfaceID The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return
            (interfaceID == type(IERC165).interfaceId
                    || interfaceID == type(I1271Policy).interfaceId);
    }
}
