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
    bytes32 internal constant NO_EXEC =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

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

    /**
     * @dev Computes the complete compact hash for verification
     * @notice Hashes the compact structure including mandate, element, and all fields
     * @param sponsor The address of the claim sponsor
     * @param lockTag A lock identifier for preventing front-running
     * @param fields The complete compact field data
     * @return hash The final compact hash for EIP-712 signing
     *
     * @dev Process:
     *      1. Retrieve arbiter and compute qHash
     *      2. Hash the mandate (target attributes + ops + qHash)
     *      3. Hash the element (arbiter + chain + tokens + mandate)
     *      4. Verify element hash matches the one in allElements array
     *      5. Hash the complete compact structure
     *
     * TODO: Change visibility to internal for security
     */
    function __hashStub_tokenIn(address sponsor, bytes12 lockTag, CompactFields calldata fields)
        external
        returns (bytes32 hash)
    {
        // Step 1: Get arbiter address and compute qualified hash from qualifier params
        (address arbiter, bytes32 qHash) =
            _getArbiter(fields.thisElement.arbiter, fields.thisElement.mandate.qParam);

        // Step 2: Hash the mandate structure (what happens on target chain)
        // First hash the target attributes (recipient, tokens out, chain, expiry)
        // Then combine with operation hashes and qHash
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            EIP712TypeHashLib.hashTargetAttributesRaw({
                recipient: fields.thisElement.mandate.recipient,
                tokenOutHash: EIP712TypeHashLib.hashTokenOut(fields.thisElement.mandate.tokenOut),
                targetChainId: fields.thisElement.mandate.targetChain,
                fillDeadline: fields.thisElement.mandate.fillExpiry
            }),
            fields.thisElement.mandate.originOps,
            fields.thisElement.mandate.targetOps,
            qHash
        );

        // Step 3: Hash the element (origin chain data + mandate)
        // bytes32 elementHash = EIP712TypeHashLib.hashElementRaw({
        // // arbiter: arbiterIds[fields.thisElement.arbiter].arbiter,
        // originChainId: block.chainid,
        // tokenInHash: EIP712TypeHashLib.hashTokenIn(fields.tokenIn),
        // mandateHash: mandateHash
        // });

        // // Step 4: Verify the computed element hash matches the expected hash in allElements
        // // This ensures the element data hasn't been tampered with
        // require(elementHash == fields.allElements[fields.elementPtr]);
        //
        // // Step 5: Hash the complete compact structure (sponsor + nonce + expiry + elements)
        // hash = EIP712TypeHashLib.hashCompact({
        // sponsor: sponsor,
        // nonce: fields.nonce,
        // expires: fields.claimExpiry,
        // allElementsHash: abi.encodePacked(fields.allElements)
        // });
    }

    /**
     * @dev Verifies a claim against the sponsor's configuration
     * @notice Validates all aspects of a claim: recipient, tokens, chains, and operations
     * @param sponsor The address sponsoring this claim
     * @param claimHash The hash of the claim to verify
     * @param emissaryData The encoded claim data from the emissary
     * @param lockTag A lock identifier for synchronization
     * @return valid True if the claim passes all validation checks
     *
     * @dev Validation stages:
     *      1. Extract config ID and load configuration
     *      2. Decode claim fields
     *      3. Validate recipient (sponsor match, whitelist, or policy)
     *      4. Validate input tokens (whitelist check)
     *      5. Validate output tokens (whitelist check)
     *      6. Validate target chain (whitelist check)
     *      7. Validate origin operations (allow/deny)
     *      8. Validate target operations (allow/deny)
     *      9. Compute and verify final typed data hash
     */
    function _verifyClaim(
        address sponsor,
        bytes32 claimHash,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        returns (bool valid)
    {
        // Extract permission ID from emissary data and convert to config ID
        // bytes32 configId = emissaryData.extractPermissionId().toCompactPolicyId();
        bytes32 configId;

        // TODO: Optimize to use calldata instead of memory for gas efficiency
        // Decode the compact fields starting after the first 32 bytes (permission ID)
        CompactFields memory fields = abi.decode(emissaryData[32:], (CompactFields));
        bytes32 tokenOutHash;

        SessionConfig storage $sessionConfig = configs[configId][sponsor];
        // Extract the bitmap that defines which validations to perform
        bytes32 configFlags = $sessionConfig.configFlags;
        require(configFlags.isEnabled());

        ChainSpecificConfig storage $chainConfig;

        // Load the configuration for this sponsor and permission
        if (configFlags.isAnyTargetChainId()) {
            $chainConfig = $chainConfig.chainConfig[SENTINEL_ANY_TARGET_CHAIN];
        } else {
            $chainConfig = $chainConfig.chainConfig[fields.targetChain];
        }

        // /* //////////////////////////////////////////////////////////////
        // RECIPIENT FIELD VALIDATION
        // //////////////////////////////////////////////////////////////*/
        // // Three modes for recipient validation based on config bitmap:
        // // 1. Sponsor must equal recipient (self-transfer)
        // // 2. Recipient determined by policy contract (dynamic validation)
        // // 3. Recipient must be in whitelist (static validation)
        //
        //
        //
        // if (configFlags.isSponsorEqRecipient()) {
        // // Mode 1: Enforce that sponsor is sending to themselves
        // // This is the most restrictive mode - no third-party recipients allowed
        // require(fields.recipient == sponsor);
        // } else if (configFlags.isRecipientViaPolicy()) {
        // // Mode 2: Delegate recipient validation to an external policy contract
        // // TODO: Implement policy contract call for dynamic recipient validation
        // // call policy
        // } else {
        // // Mode 3: Check if recipient is in the pre-approved whitelist
        // // Reverts if recipient address is not in the whitelist map
        // require($config.recipients.contains(fields.recipient));
        //}
        //
        // /* //////////////////////////////////////////////////////////////
        // TOKEN IN FIELD VALIDATION
        // //////////////////////////////////////////////////////////////*/
        // // Validate input tokens on the origin chain
        // // Only enforced if the inspectTokenIn bit is set in config
        //
        // if (configFlags.inspectTokenIn()) {
        // // Iterate through all input tokens in the claim
        // for (uint256 i; i < fields.tokenIn.length; i++) {
        // // Extract token address from the [address, amount] pair
        // // tokenIn[i][0] contains the address encoded as uint256
        // address _checkTokenIn = fields.tokenIn[i][0].toAddress();
        //
        // // Verify token is in the whitelist - reverts if not found
        // require($config.tokenIns.contains(_checkTokenIn));
        //}
        //}
        // // If inspectTokenIn bit is not set, any input tokens are allowed
        //
        // /* //////////////////////////////////////////////////////////////
        // TOKEN OUT FIELD VALIDATION
        // //////////////////////////////////////////////////////////////*/
        // // Validate output tokens on the target chain
        // // Two modes based on inspectTokenOut bit:
        // // 1. Full inspection: compute hash and validate against whitelist
        // // 2. Stub mode: use pre-computed hash without validation
        //
        // if (configBitmap.isInspectTokenOut()) {
        // // Mode 1: Full inspection - compute hash and validate each token
        // // This provides maximum security by checking every output token
        // tokenOutHash = fields.tokenOutHash();
        //
        // // Iterate through all output tokens in the claim
        // for (uint256 i; i < fields.tokenOut.length; i++) {
        // // Extract token address from the [address, amount] pair
        // // tokenOut[i][0] contains the address encoded as uint256
        // address _checkTokenOut = fields.tokenOut[i][0].toAddress();
        //
        // // Verify token is in the whitelist - reverts if not found
        // require($config.tokenOut.contains(_checkTokenOut));
        //}
        // } else {
        // // Mode 2: Stub mode - use pre-computed hash without validation
        // // This saves gas but relies on the hash being computed correctly off-chain
        // tokenOutHash = fields.tokenOutStub();
        //}
        //
        // /* //////////////////////////////////////////////////////////////
        // TARGET CHAIN ID VALIDATION
        // //////////////////////////////////////////////////////////////*/
        // // Validate the destination chain for the claim
        // // If inspection is disabled, any chain is allowed (wildcard mode)
        //
        // if (configBitmap.isInspectTargetChainId()) {
        // // Verify the target chain is in the whitelist
        // // This prevents claims from being executed on unauthorized chains
        // require($config.allowedTargetChains[fields.targetChain]);
        //}
        // // If inspectTargetChainId bit is not set, all chains are allowed
        //
        // /* //////////////////////////////////////////////////////////////
        // ORIGIN OPS VALIDATION
        // //////////////////////////////////////////////////////////////*/
        // // Validate operations to be executed on the origin chain before claim
        // // These are pre-claim operations that run before the main transfer
        //
        // if (!configBitmap.allowPreClaimOps()) {
        // // If pre-claim ops are not allowed by config, enforce NO_EXEC
        // // originOps must be the empty hash (keccak256("")) indicating no operations
        // require(fields.originOps == NO_EXEC);
        //}
        // // If allowPreClaimOps bit is set, any origin operations are permitted
        //
        // /* //////////////////////////////////////////////////////////////
        // TARGET OPS VALIDATION
        // //////////////////////////////////////////////////////////////*/
        // // Validate operations to be executed on the target chain after claim
        // // These are post-claim operations that run after the token transfer
        //
        // if (!configBitmap.allowTargetOps()) {
        // // If target ops are not allowed by config, enforce NO_EXEC
        // // targetOps must be the empty hash (keccak256("")) indicating no operations
        // require(fields.targetOps == NO_EXEC);
        //}
        // // If allowTargetOps bit is set, any target operations are permitted

        /* //////////////////////////////////////////////////////////////
                                FINAL DIGEST COMPUTATION
        //////////////////////////////////////////////////////////////*/
        // Compute the final EIP-712 typed data hash for signature verification
        // This combines all validated fields into a single hash that can be signed

        bytes32 digest =
            _getTypedDataHash(this.__hashStub_tokenIn(sponsor.lockTag, lockTag, fields));

        // Note: The actual signature verification happens in the calling function
        // This function only validates the claim structure and permissions
    }

    /**
     * @dev Converts a struct hash to an EIP-712 typed data hash
     * @notice Must be implemented by the inheriting contract to provide domain separator
     * @param hash The struct hash to convert
     * @return The EIP-712 typed data hash ready for signature verification
     */
    function _getTypedDataHash(bytes32 hash) internal view returns (bytes32);
}
