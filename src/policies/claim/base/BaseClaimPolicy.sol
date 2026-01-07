// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { IBaseClaimPolicy } from "@policies/claim/base/interfaces/IBaseClaimPolicy.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    PolicyConfig,
    QualificationRulesStorage,
    FIELD_ARBITER,
    FIELD_EXPIRY,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION,
    EMPTY_CONFIG
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
abstract contract BaseClaimPolicy is IBaseClaimPolicy, I1271Policy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint32;
    using BaseConfigLib for uint8;
    using BaseConfigLib for BasePolicyStorage;
    using BaseStorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

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
    /// │  Bits [31:20] = Reserved (unused)                           │
    /// │  Bits [19:0]  = 10 fields × 2 bits each                     │
    /// │                                                             │
    /// │ ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬────┐│
    /// │ │ RIS │  Q  │ DO  │ OO  │ TO  │ FE  │ RC  │ TI  │ EX  │ AR ││
    /// │ │19:18│17:16│15:14│13:12│11:10│ 9:8 │ 7:6 │ 5:4 │ 3:2 │ 1:0││
    /// │ └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴────┘│
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
    /// │  arbiter        │  [count (1)] + [addr (20)] × count         │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  expiry         │  [minExpiry (16)] + [maxExpiry (16)]       │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  tokenIn        │  COMPACT:                                  │
    /// │                 │    [count (1)] + entries:                  │
    /// │                 │      [chainId (32)] + [token (20)] +       │
    /// │                 │      [lockTag (12)]                        │
    /// │                 │  PERMIT2:                                  │
    /// │                 │    [count (1)] + entries:                  │
    /// │                 │      [chainId (32)] + [token (20)]         │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  recipient      │  [count (1)] + entries:                    │
    /// │                 │    [targetChainId (32)] + [recipient (20)] │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  fillExpiry     │  [count (1)] + entries:                    │
    /// │                 │    [targetChainId (32)] +                  │
    /// │                 │    [minFillExpiry (16)] +                  │
    /// │                 │    [maxFillExpiry (16)]                    │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  tokenOut       │  [count (1)] + entries:                    │
    /// │                 │    [targetChainId (32)] + [token (20)]     │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  originOps      │  [count (1)] + entries:                    │
    /// │                 │    [chainId (32)] + [required (1)]         │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  destOps        │  [count (1)] + entries:                    │
    /// │                 │    [targetChainId (32)] + [required (1)]   │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  qualification  │  [count (1)] + entries:                    │
    /// │                 │    [chainId (32)] + [arbiter (20)] +       │
    /// │                 │    [rulesLen (1)] + [rules (variable)]     │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  subPolicies    │  [count (1)] + entries:                    │
    /// │  (if any        │    [fieldId (1)] + [policyAddr (20)] +     │
    /// │   SUBPOLICY)    │    [initDataLen (32)] + [initData (...)]   │
    /// ├─────────────────┼────────────────────────────────────────────┤
    /// │  recipientIs    │  No init data required - just a flag       │
    /// │  Sponsor        │  If mode != SKIP, enforces recipient ==    │
    /// │                 │  sponsor at validation time                │
    /// └─────────────────┴────────────────────────────────────────────┘
    ///
    /// Example - Compact with arbiter + tokenIn + recipient:
    /// ┌────────────────────────────────────────────────────────────┐
    /// │  [0:4]      0x00000015 (AR=01, TI=01, RC=01, rest=00)      │
    /// │  [4:5]      arbiter count = 1                              │
    /// │  [5:25]     arbiter address                                │
    /// │  [25:26]    tokenIn count = 2                              │
    /// │  [26:58]    tokenIn[0].chainId                             │
    /// │  [58:78]    tokenIn[0].token                               │
    /// │  [78:90]    tokenIn[0].lockTag                             │
    /// │  [90:122]   tokenIn[1].chainId                             │
    /// │  [122:142]  tokenIn[1].token                               │
    /// │  [142:154]  tokenIn[1].lockTag                             │
    /// │  [154:155]  recipient count = 1                            │
    /// │  [155:187]  recipient[0].targetChainId                     │
    /// │  [187:207]  recipient[0].recipient                         │
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
    // solhint-disable-next-line code-complexity
    function _initializeBase(
        ConfigId configId,
        address account,
        bytes calldata initData
    )
        internal
        virtual
    {
        // Load storage pointer for configId/account pair
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });

        // ------------------ POLICY CONFIG ------------------ //

        // Make sure config is not already initialized
        require($.modeConfig == EMPTY_CONFIG, ConfigurationAlreadyExists());

        // Decode and initialize policy mode configuration
        (PolicyConfig modeConfig, bytes calldata data) = $.initializeModeConfig(initData);

        // Make sure at least one field is enabled
        require(modeConfig != EMPTY_CONFIG, InvalidConfigurationData());

        // ------------------ ARBITER ------------------ //

        // Decode and initialize arbiter config if enabled
        if (modeConfig.getFieldMode(FIELD_ARBITER).isStorageMode()) {
            data = $.initializeArbiter(data);
        }

        // ------------------ CLAIM EXPIRY ------------------ //

        // Decode and initialize expiry config if enabled
        if (modeConfig.getFieldMode(FIELD_EXPIRY).isStorageMode()) {
            data = $.initializeExpiry(data);
        }

        // ------------------ TOKEN IN ------------------ //

        // Decode and initialize tokenIn if enabled (protocol-specific - handled by subclass)
        if (modeConfig.getFieldMode(FIELD_TOKEN_IN).isStorageMode()) {
            data = _initializeTokenIn($, data);
        }

        // ------------------ RECIPIENT ------------------ //

        // Decode and initialize recipient configs if enabled
        if (modeConfig.getFieldMode(FIELD_RECIPIENT).isStorageMode()) {
            data = $.initializeRecipient(data);
        }

        // ------------------ FILL EXPIRY ------------------ //

        // Decode and initialize fill expiry configs if enabled
        if (modeConfig.getFieldMode(FIELD_FILL_EXPIRY).isStorageMode()) {
            data = $.initializeFillExpiry(data);
        }

        // ------------------ TOKEN OUT ------------------ //

        // Decode and initialize tokenOut configs if enabled
        if (modeConfig.getFieldMode(FIELD_TOKEN_OUT).isStorageMode()) {
            data = $.initializeTokenOut(data);
        }

        // ------------------ ORIGIN OPS ------------------ //

        // Decode and initialize origin ops configs if enabled
        if (modeConfig.getFieldMode(FIELD_ORIGIN_OPS).isStorageMode()) {
            data = $.initializeOriginOps(data);
        }

        // ------------------ DESTINATION OPS ------------------ //

        // Decode and initialize dest ops configs if enabled
        if (modeConfig.getFieldMode(FIELD_DEST_OPS).isStorageMode()) {
            data = $.initializeDestOps(data);
        }

        // ------------------ QUALIFICATION ------------------ //

        // Decode and initialize qualification configs if enabled
        if (modeConfig.getFieldMode(FIELD_QUALIFICATION).isStorageMode()) {
            data = $.initializeQualification(data);
        }

        // ------------------ SUB-POLICIES ------------------ //

        // Decode and initialize sub-policy configs if any
        if (data.length != 0) {
            data = $.initializeSubPolicies(data, modeConfig, account, configId);
        }

        // Make sure all data is consumed
        require(data.length == 0, InvalidConfigurationData());

        // Emit initialized event
        emit PolicyInitialized(configId, account, modeConfig);
    }

    /// @notice Protocol-specific tokenIn initialization
    /// @dev Must be implemented by subclasses to handle Compact vs Permit2 tokenIn formats
    /// @param $ The storage pointer for the account
    /// @param initData Remaining init data starting at tokenIn config
    /// @return remaining Remaining init data after tokenIn config
    function _initializeTokenIn(
        BasePolicyStorage storage $,
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
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });

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
    function getModeConfig(ConfigId configId, address account)
        external
        view
        returns (PolicyConfig)
    {
        BasePolicyStorage storage $ = configId.getStorage({
            account: account, multiplexer: msg.sender
        });
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
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
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
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return $.arbiterConfig.contains(arbiter);
    }

    /// @notice Returns the claim expiry bounds for an account
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
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
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
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
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
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return $.subPolicies[fieldId];
    }

    /// @notice Returns the fill expiry bounds for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The target chain ID
    /// @return minFillExpiry The minimum fill expiry timestamp
    /// @return maxFillExpiry The maximum fill expiry timestamp
    function getFillExpiryBounds(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (uint128 minFillExpiry, uint128 maxFillExpiry)
    {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        (minFillExpiry, maxFillExpiry) = BaseConfigLib.unpackUint128($.fillExpiryConfig[chainId]);
    }

    /// @notice Returns the whitelisted output tokens for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The target chain ID
    /// @return tokens Array of whitelisted token addresses
    function getTokensOut(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (address[] memory tokens)
    {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        uint256 length = $.tokenOutSet[chainId].length();
        tokens = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            tokens[i] = $.tokenOutSet[chainId].at(i);
        }
    }

    /// @notice Checks if a token is whitelisted for output on a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The target chain ID
    /// @param token The token address to check
    /// @return True if the token is whitelisted
    function isTokenOutWhitelisted(
        ConfigId configId,
        address account,
        uint256 chainId,
        address token
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return $.tokenOutSet[chainId].contains(token);
    }

    /// @notice Returns whether origin operations are required for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The origin chain ID
    /// @return True if origin operations are required
    function getOriginOpsRequired(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return $.originOpsConfig[chainId];
    }

    /// @notice Returns whether destination operations are required for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The destination chain ID
    /// @return True if destination operations are required
    function getDestOpsRequired(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return $.destOpsConfig[chainId];
    }

    /// @notice Returns the qualification rules for a chain/arbiter pair
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID
    /// @param arbiter The arbiter address
    /// @return rules The qualification rules
    function getQualificationRules(
        ConfigId configId,
        address account,
        uint256 chainId,
        address arbiter
    )
        external
        view
        returns (QualificationRulesStorage memory rules)
    {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return $.qualificationConfig[chainId][arbiter];
    }

    /// @notice Checks if this contract implements the given interface
    /// @param interfaceID The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceID) public pure virtual override returns (bool) {
        return (interfaceID == type(IERC165).interfaceId
                || interfaceID == type(I1271Policy).interfaceId
                || interfaceID == type(IBaseClaimPolicy).interfaceId);
    }
}
