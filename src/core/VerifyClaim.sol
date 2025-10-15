import { PermissionIdLib, ConfigBitMapLib } from "../lib/SSXLib.sol";
import { EIP712TypeHashLib } from "@rhinestone/compact-utils/src/types/EIP712TypeHashLib.sol";
import { EnumerableMapLib } from "solady/utils/EnumerableMapLib.sol";
import { EIP712 } from "solady/utils/EnumerableMapLib.sol";
import { EIP712Domain } from "solady/utils/EnumerableMapLib.sol";
import { IdLib } from "@the-compact/lib/IdLib.sol";

interface IQualifierHasher {
    function createQHash(bytes calldata qStub) external view returns (bytes32 qHash);
}

abstract contract VerifyClaim {
    using IdLib for *;
    using EnumerableMapLib for EnumerableMapLib.AddressToBytes32Map;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;
    using EIP712TypeHashLib for *;
    using PermissionIdLib for bytes;
    using ConfigBitMapLib for uint8;

    bytes32 internal constant NO_EXEC =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    struct CompactFields {
        bytes32[] allElements;
        uint256 elementPtr;
        uint256 nonce;
        uint256 expires;
        Element thisElement;
    }

    struct Element {
        // need ID here. so when we update arbiters, we can just set the address to the storage
        address arbiter;
        uint256 targetChain;
        uint256[2][] tokenIn;
        Mandate mandate;
    }

    struct PermitFields {
        // need ID here. so when we update arbiters, we can just set the address to the storage
        address arbiter;
        uint256 nonce;
        uint256 deadline;
        uint256[2][] tokenIn;
        Mandate mandate;
    }

    struct Mandate {
        address recipient;
        uint256 targetChain;
        uint256 fillExpiry;
        uint8 v;
        uint128 minGas;
        bytes32 originOps;
        bytes32 targetOps;
        bytes qParam;
        uint256[2][] tokenOut;
    }

    struct Config {
        uint8 configBitmap;
        EnumerableMapLib.AddressToBytes32Map recipients;
        EnumerableMapLib.Uint256ToBytes32Map targetChainIds;
        EnumerableMapLib.AddressToBytes32Map tokenIns;
        EnumerableMapLib.AddressToBytes32Map tokenOuts;
    }

    struct ArbiterConfig {
        bool enabled;
        bool useVanillaKeccak;
        address hasher;
    }

    mapping(address arbiter => ArbiterConfig config) internal arbiterIds;
    mapping(bytes32 configId => mapping(address sponsor => Config)) internal configs;

    function decode(bytes calldata input) internal pure returns (CompactFields calldata fields) {
        assembly {
        // TODO:
        }
    }

    function _getArbiter(uint8 arbiterId, bytes memory qInput)
        internal
        returns (address arbiter, bytes32 qHash)
    {
        ArbiterConfig memory arbiterConfig = arbiterIds[arbiterId];
        arbiter = arbiterConfig.arbiter;
        require(arbiter != address(0));
        if (arbiterConfig.useVanillaKeccak) {
            qHash = keccak256(qInput);
        } else {
            qHash = IQualifierHasher(arbiterConfig.hasher).createQHash(qInput);
        }
    }

    // TODO: internal
    function __hashStub_tokenIn(address sponsor, bytes12 lockTag, CompactFields calldata fields)
        external
        returns (bytes32 hash)
    {
        // get arbiter address and qHash from ownable map
        (address arbiter, bytes32 qHash) = _getArbiter(fields.arbiterId, fields.qParam);

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            EIP712TypeHashLib.hashTargetAttributesRaw({
                recipient: fields.recipient,
                tokenOutHash: EIP712TypeHashLib.hashTokenOut(fields.tokenOut),
                targetChainId: fields.targetChain,
                fillDeadline: fields.fillExpiry
            }),
            fields.originOps,
            fields.targetOps,
            qHash
        );
        bytes32 elementHash = EIP712TypeHashLib.hashElementRaw({
            arbiter: arbiterIds[fields.arbiterId].arbiter,
            originChainId: block.chainid,
            tokenInHash: EIP712TypeHashLib.hashTokenIn(fields.tokenIn),
            mandateHash: mandateHash
        });

        require(elementHash == fields.allElements[fields.elementPtr]);
        hash = EIP712TypeHashLib.hashCompact({
            sponsor: sponsor,
            nonce: fields.nonce,
            expires: fields.claimExpiry,
            allElementsHash: abi.encodePacked(fields.allElements)
        });
    }

    function _verifyClaim(
        address sponsor,
        bytes32 claimHash,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        returns (bool valid)
    {
        bytes32 configId = emissaryData.extractPermissionId().toCompactPolicyId();
        // TODO: use calldata
        CompactFields memory fields = abi.decode(emissaryData[32:], (CompactFields));
        bytes32 tokenOutHash;

        Config storage $config = configs[configId][sponsor];
        uint8 configBitmap = $config.configBitmap;

        // sload config TODO double check if you actually can provide all the config via
        // permissionID in a safe manner recipient == sponsor
        if (configBitmap.isSponsorEqRecipient()) {
            require(fields.recipient == sponsor);
        } else {
            require($config.recipients.contains(fields.recipient));
        }

        if (configBitmap.inspectTokenIn()) {
            for (uint256 i; i < fields.tokenIn.length; i++) {
                address _checkTokenIn = fields.tokenIn[i][0].toAddress();
                require($config.tokenIns.contains(_checkTokenIn));
            }
        }

        // derive tokenOutHash from stub or calc
        if (configBitmap.isInspectTokenOut()) {
            tokenOutHash = fields.tokenOutHash();
            for (uint256 i; i < fields.tokenOut.length; i++) {
                address _checkTokenOut = fields.tokenOut[i][0].toAddress();
                require($config.tokenOut.contains(_checkTokenOut));
            }
        } else {
            tokenOutHash = fields.tokenOutStub();
        }
        // check for wildcard destination chainid
        if (configBitmap.isInspectTargetChainId()) {
            require($config.allowedTargetChains[fields.targetChain]);
        }

        if (!configBitmap.allowTargetOps()) {
            require(fields.targetOps == NO_EXEC);
        }

        if (!configBitmap.allowPreClaimOps()) {
            require(fields.originOps == NO_EXEC);
        }
        bytes32 digest =
            _getTypedDataHash(this.__hashStub_tokenIn(sponsor.lockTag, lockTag, fields));
    }

    function _getTypedDataHash(bytes32 hash) internal view returns (bytes32);
}
