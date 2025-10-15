// Library for handling permission IDs and configuration bitmaps
import { PermissionIdLib, ConfigBitMapLib, Permission } from "../lib/SSXLib.sol";
// Library for EIP-712 typed data hashing
import { EIP712TypeHashLib } from "@rhinestone/compact-utils/src/types/EIP712TypeHashLib.sol";
// Solady's efficient enumerable map implementation
import { EnumerableMapLib } from "solady/utils/EnumerableMapLib.sol";
// EIP-712 domain separator and signing utilities
import { IdLib } from "@the-compact/lib/IdLib.sol";

/**
 * @dev Interface for custom qualifier hash generation
 * Arbiters can implement custom hashing logic for qualifier parameters
 */
interface IQualifierHasher {
    /**
     * @dev Creates a qualified hash from qualifier stub data
     * @param qStub The qualifier stub data to hash
     * @return qHash The resulting qualified hash
     */
    function createQHash(bytes calldata qStub) external view returns (bytes32 qHash);
}

interface IInspector {
    function inspect(bytes32 configId, address sponsor, bytes calldata data) external returns (bool);
}

/**
 * @title VerifyClaim
 * @notice Abstract contract for verifying cross-chain claims with configurable policies
 * @dev Implements claim verification logic with support for:
 *      - Arbiter-based qualification
 *      - Token whitelist validation (input/output)
 *      - Recipient restrictions
 *      - Target chain validation
 *      - Operation allowlisting (origin/target ops)
 */
abstract contract VerifyClaim {
    // Library usage declarations for type extensions
    using IdLib for *;
    using EnumerableMapLib for EnumerableMapLib.AddressToBytes32Map;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;
    using EIP712TypeHashLib for *;
    using PermissionIdLib for bytes;
    using ConfigBitMapLib for bytes32;

    /**
     * @dev Keccak256 hash of empty bytes, used to indicate "no execution"
     * This sentinel value signals that no operations should be executed
     * Computed as: keccak256("")
     */

    /**
     * @dev Represents the complete compact claim structure
     * @notice This is the primary data structure for cross-chain claims
     */
    struct CompactFields {
        /// @dev Array of all element hashes in the compact (for multi-element compacts)
        bytes32[] allElements;
        /// @dev Index pointer to the current element being processed
        uint256 elementPtr;
        /// @dev Nonce to prevent replay attacks (increments per claim)
        uint256 nonce;
        /// @dev Expiration timestamp (Unix epoch) after which claim is invalid
        uint256 expires;
        /// @dev The current element being verified
        Element thisElement;
    }

    /**
     * @dev Represents a single element in a compact
     * @notice Each element contains origin chain information and the mandate
     */
    struct Element {
        /// @dev Address of the arbiter who qualifies this element
        /// NOTE: In future versions, this will be replaced with an ID to allow arbiter updates
        address arbiter;
        /// @dev Chain ID where this element originates
        uint256 targetChain;
        /// @dev Array of input tokens: [tokenAddress, amount][]
        /// First element is address (as uint256), second is amount
        uint256[2][] tokenIn;
        /// @dev The mandate specifying what should happen on the target chain
        Mandate mandate;
    }

    /**
     * @dev Permit-based fields for authorization
     * @notice Alternative structure for permit-style claims
     */
    struct PermitFields {
        /// @dev Address of the arbiter authorizing this permit
        /// NOTE: Will be replaced with ID-based lookup in future versions
        address arbiter;
        /// @dev Nonce for replay protection
        uint256 nonce;
        /// @dev Deadline timestamp for permit validity
        uint256 deadline;
        /// @dev Array of input tokens being transferred
        uint256[2][] tokenIn;
        /// @dev The mandate to execute
        Mandate mandate;
    }

    /**
     * @dev Defines the target execution mandate
     * @notice Specifies what should happen on the destination chain
     */
    struct Mandate {
        /// @dev Address receiving the tokens/execution on target chain
        address recipient;
        /// @dev Target chain ID where mandate should be executed
        uint256 targetChain;
        /// @dev Expiration timestamp for filling this mandate
        uint256 fillExpiry;
        /// @dev Version byte or flags for mandate configuration
        uint8 v;
        /// @dev Minimum gas required for execution on target chain
        uint128 minGas;
        /// @dev Hash of operations to execute on origin chain before transfer
        bytes32 originOps;
        /// @dev Hash of operations to execute on target chain after transfer
        bytes32 targetOps;
        /// @dev Qualifier parameters for arbiter validation
        bytes qParam;
        /// @dev Array of output tokens on target chain: [tokenAddress, amount][]
        uint256[2][] tokenOut;
    }

    uint256 constant SENTINEL_ANY_TARGET_CHAIN = type(uint256).max;

    /**
     * @dev Configuration for claim validation policies
     * @notice Defines the rules and whitelists for a specific permission
     */
    struct SessionConfig {
        bytes32 configFlags;
        EnumerableMapLib.AddressToAddressMap enabledArbiter;
        /// @dev Map of whitelisted input tokens (tokenAddress => data)
        Permission tokenIns;
        mapping(uint256 targetChainId => ChainSpecificConfig targetChainConfig) chainConfig;
    }

    struct ChainSpecificConfig {
        uint128 maxClaimExpiry;
        uint128 maxFillExpiry;
        Permission recipient;
        Permission tokenOuts;
    }

    /**
     * @dev Configuration for an arbiter
     * @notice Stores how to validate and hash qualifier data for a specific arbiter
     */
    struct ArbiterConfig {
        /// @dev Whether this arbiter is enabled and can validate claims
        bool enabled;
        /// @dev If true, use simple keccak256 for hashing; if false, use custom hasher
        bool useVanillaKeccak;
        /// @dev Address of custom IQualifierHasher implementation (if useVanillaKeccak is false)
        address qHasher;
    }

    /**
     * @dev Maps arbiter addresses to their configuration
     * @notice Used to look up how to process qualifier data for each arbiter
     */
    mapping(address arbiter => ArbiterConfig config) internal arbiterIds;

    /**
     * @dev Nested mapping: configId => sponsor => Config
     * @notice Stores validation policies per configuration per sponsor
     * The configId is derived from the permission data
     */
    mapping(bytes32 configId => mapping(address sponsor => SessionConfig)) internal configs;

    function _getArbiter(address arbiter, bytes memory qInput)
        internal
        returns (address _arbiter, bytes32 qHash)
    {
        // Load arbiter configuration from storage
        ArbiterConfig memory arbiterConfig = arbiterIds[arbiter];
        if (arbiterConfig.enabled == false) {
            return (address(0), bytes32(0));
        } else {
            _arbiter = arbiter;
        }

        // Ensure arbiter is configured and enabled
        require(arbiter != address(0));

        // Compute qHash based on arbiter's hashing preference
        if (arbiterConfig.useVanillaKeccak) {
            // Use standard keccak256 hashing
            qHash = keccak256(qInput);
        } else {
            // Use custom hasher contract for domain-specific hashing logic
            qHash = IQualifierHasher(arbiterConfig.qHasher).createQHash(qInput);
        }
    }

    function hashElement(address sponsor, bytes12 lockTag, Element calldata element)
        internal
        returns (bytes32 elementHash)
    {
        (address arbiter, bytes32 qHash) = _getArbiter(element.arbiter, element.mandate.qParam);
        // Step 2: Hash the mandate structure (what happens on target chain)
        // First hash the target attributes (recipient, tokens out, chain, expiry)
        // Then combine with operation hashes and qHash
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            EIP712TypeHashLib.hashTargetAttributesRaw({
                recipient: element.mandate.recipient,
                tokenOutHash: EIP712TypeHashLib.hashTokenOut(element.mandate.tokenOut),
                targetChainId: element.mandate.targetChain,
                fillDeadline: element.mandate.fillExpiry
            }),
            element.mandate.originOps,
            element.mandate.targetOps,
            qHash
        );

        elementHash = EIP712TypeHashLib.hashElementRaw({
            arbiter: arbiter,
            originChainId: block.chainid,
            tokenInHash: EIP712TypeHashLib.hashTokenIn(element.tokenIn),
            mandateHash: mandateHash
        });
    }

    function _verifyCompactPolicies(
        address sponsor,
        bytes32 claimHash,
        bytes32 permissionId,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        returns (bool valid)
    {
        valid = true;
        // Extract permission ID from emissary data and convert to config ID
        // bytes32 configId = emissaryData.extractPermissionId().toCompactPolicyId();
        bytes32 configId;

        // TODO: Optimize to use calldata instead of memory for gas efficiency
        // Decode the compact fields starting after the first 32 bytes (permission ID)
        CompactFields calldata fields;
        assembly {
            fields := emissaryData.offset
        }

        require(
            fields.allElements[fields.elementPtr]
                == hashElement(sponsor, lockTag, fields.thisElement)
        );
        //k
        // function hashCompact(address sponsor, uint256 nonce, uint256 expires, bytes32
        // allElementsHash) internal pure returns (bytes32 hash) {

        SessionConfig storage $sessionConfig = configs[configId][sponsor];
        // Extract the bitmap that defines which validations to perform
        bytes32 configFlags = $sessionConfig.configFlags;
        require(configFlags.isEnabled());

        ChainSpecificConfig storage $chainConfig;

        // Load the configuration for this sponsor and permission
        if (configFlags.isAnyTargetChainId()) {
            $chainConfig = $sessionConfig.chainConfig[SENTINEL_ANY_TARGET_CHAIN];
        } else {
            $chainConfig = $sessionConfig.chainConfig[fields.thisElement.mandate.targetChain];
        }

        valid = valid
            && configFlags.inspectRecipient(
                fields.thisElement.mandate.recipient, sponsor, $chainConfig.recipient
            );

        valid = valid
            && configFlags.inspectTokenIns(fields.thisElement.tokenIn, $sessionConfig.tokenIns);

        valid = valid
            && configFlags.inspectTokenOuts(
                fields.thisElement.mandate.tokenOut, $chainConfig.tokenOuts
            );
        valid = valid && configFlags.inspectPreClaimOps(fields.thisElement.mandate.originOps);

        valid = valid && configFlags.inspectTargetOps(fields.thisElement.mandate.originOps);

        valid = valid
            && claimHash
                == EIP712TypeHashLib.hashCompact(
                    sponsor, fields.nonce, fields.expires, abi.encodePacked(fields.allElements)
                );
    }

    /**
     * @dev Converts a struct hash to an EIP-712 typed data hash
     * @notice Must be implemented by the inheriting contract to provide domain separator
     * @param hash The struct hash to convert
     * @return The EIP-712 typed data hash ready for signature verification
     */
    function _getTypedDataHash(bytes32 hash) internal view virtual returns (bytes32);
}
