// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionERC7739_Unit_Test } from "../SmartSessionERC7739.t.sol";

// Libraries
import { LibString } from "solady/utils/LibString.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @notice Fuzzes acyclic graphs of 2 to 5 struct types with random field lists, each type's
///         `encodeType` primary type first with its dependencies sorted, as EIP-712 defines it
contract SmartSessionERC7739_nestedTypeFuzz_Test is SmartSessionERC7739_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @dev Field kinds: 0 uint256, 1 address, 2 bytes32, otherwise a reference to a type with a
    /// higher index, so the graph is acyclic.
    struct Graph {
        uint256 seed;
        string[] names;
        uint256[][] fields;
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_nestedTypeFuzz_EnabledPrimaryType_ReturnsMagic(
        uint256 seed,
        uint256 typeCount,
        bool explicitMode
    )
        public
    {
        // Arrange
        Graph memory graph = _graph(seed, bound(typeCount, 2, 5));
        string memory contentsType = _encodeType(graph, 0);
        bytes memory description =
            explicitMode ? abi.encodePacked(contentsType, graph.names[0]) : bytes(contentsType);
        PermissionId permissionId = _enable(description);
        (bytes memory signature, bytes32 hash) =
            _signedEnvelope(permissionId, graph, 0, contentsType, description);

        // Act
        (bool reverted, bytes4 result) = _tryIsValidSignature(hash, signature);

        // Assert
        assertFalse(reverted, "Should not revert");
        assertEq(result, ERC1271_MAGIC_VALUE, "Should accept the enabled primary type");
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_nestedTypeFuzz_OtherTypeOfGraph_NeverReturnsMagic(
        uint256 seed,
        uint256 typeCount,
        uint256 presented,
        bool explicitMode
    )
        public
    {
        // Arrange - the primary type is enabled. Another type of the same graph is presented
        // with its own encodeData and the hash of its struct, once under the enabled description
        // and once under its own description, each signed by the session key as the emissary
        // reads it
        Graph memory graph = _graph(seed, bound(typeCount, 2, 5));
        presented = bound(presented, 1, graph.names.length - 1);
        string memory contentsType = _encodeType(graph, 0);
        bytes memory description =
            explicitMode ? abi.encodePacked(contentsType, graph.names[0]) : bytes(contentsType);
        PermissionId permissionId = _enable(description);

        bytes memory encodeData = _encodeData(graph, presented);
        bytes32 hash =
            _appHash(appDomainSeparator, _hashStruct(_encodeType(graph, presented), encodeData));
        bytes memory underEnabled = _envelope(
            permissionId,
            _sign(
                sessionKey.privateKey,
                _typedDataSignDigest(
                    instance.account,
                    appDomainSeparator,
                    _typedDataSignTypehash(graph.names[0], contentsType),
                    _hashStruct(contentsType, encodeData)
                )
            ),
            appDomainSeparator,
            encodeData,
            description
        );
        (bytes memory underOwn,) = _signedEnvelope(
            permissionId,
            graph,
            presented,
            _encodeType(graph, presented),
            bytes(_encodeType(graph, presented))
        );

        // Act
        (bool revertedUnderEnabled, bytes4 resultUnderEnabled) =
            _tryIsValidSignature(hash, underEnabled);
        (bool revertedUnderOwn, bytes4 resultUnderOwn) = _tryIsValidSignature(hash, underOwn);

        // Assert
        assertFalse(revertedUnderEnabled, "Should not revert under the enabled description");
        assertFalse(revertedUnderOwn, "Should not revert under its own description");
        assertEq(
            resultUnderEnabled, INVALID_SIGNATURE, "Should reject it under the enabled description"
        );
        assertEq(resultUnderOwn, INVALID_SIGNATURE, "Should reject a description not enabled");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _enable(bytes memory description) internal returns (PermissionId) {
        string[] memory descriptions = new string[](1);
        descriptions[0] = string(description);
        return _enableContents(instance, appDomainSeparator, descriptions);
    }

    /// @notice An envelope for type `index` of `graph`, signed by the session key, and its hash
    function _signedEnvelope(
        PermissionId permissionId,
        Graph memory graph,
        uint256 index,
        string memory contentsType,
        bytes memory description
    )
        internal
        view
        returns (bytes memory signature, bytes32 hash)
    {
        bytes memory encodeData = _encodeData(graph, index);
        bytes32 contents = _hashStruct(contentsType, encodeData);
        hash = _appHash(appDomainSeparator, contents);
        signature = _envelope(
            permissionId,
            _sign(
                sessionKey.privateKey,
                _typedDataSignDigest(
                    instance.account,
                    appDomainSeparator,
                    _typedDataSignTypehash(graph.names[index], contentsType),
                    contents
                )
            ),
            appDomainSeparator,
            encodeData,
            description
        );
    }

    /// @notice `typeCount` distinct names in random sort order, each with 1 to 4 random fields
    function _graph(uint256 seed, uint256 typeCount) internal pure returns (Graph memory graph) {
        graph.seed = seed;
        graph.names = new string[](typeCount);
        graph.fields = new uint256[][](typeCount);
        for (uint256 i; i < typeCount; i++) {
            uint256 r = uint256(keccak256(abi.encode(seed, "type", i)));
            // A random prefix orders the names randomly; the index keeps them distinct.
            graph.names[i] = string.concat(
                "T", LibString.toHexStringNoPrefix(r & 0xffffff, 3), LibString.toString(i)
            );
            uint256 fieldCount = 1 + (r >> 24) % 4;
            graph.fields[i] = new uint256[](fieldCount);
            for (uint256 f; f < fieldCount; f++) {
                uint256 kind = uint256(keccak256(abi.encode(r, f))) % 4;
                if (kind == 3) {
                    if (i + 1 == typeCount) {
                        kind = f % 3;
                    } else {
                        kind = 3 + i + 1 + uint256(keccak256(abi.encode(r, f, "ref")))
                            % (typeCount - i - 1);
                    }
                }
                graph.fields[i][f] = kind;
            }
        }
    }

    /// @notice EIP-712 `encodeType`: the type, then its dependencies sorted by name
    function _encodeType(
        Graph memory graph,
        uint256 index
    )
        internal
        pure
        returns (string memory result)
    {
        bool[] memory isDependency = new bool[](graph.names.length);
        _markDependencies(graph, index, isDependency);
        isDependency[index] = false;

        uint256 count;
        uint256[] memory sorted = new uint256[](graph.names.length);
        for (uint256 i; i < graph.names.length; i++) {
            if (!isDependency[i]) continue;
            uint256 j = count++;
            while (j != 0 && LibString.cmp(graph.names[sorted[j - 1]], graph.names[i]) > 0) {
                sorted[j] = sorted[j - 1];
                j--;
            }
            sorted[j] = i;
        }

        result = _typeBody(graph, index);
        for (uint256 i; i < count; i++) {
            result = string.concat(result, _typeBody(graph, sorted[i]));
        }
    }

    function _markDependencies(
        Graph memory graph,
        uint256 index,
        bool[] memory isDependency
    )
        internal
        pure
    {
        if (isDependency[index]) return;
        isDependency[index] = true;
        for (uint256 f; f < graph.fields[index].length; f++) {
            if (graph.fields[index][f] >= 3) {
                _markDependencies(graph, graph.fields[index][f] - 3, isDependency);
            }
        }
    }

    /// @notice `Name(kind f0,kind f1,...)`
    function _typeBody(
        Graph memory graph,
        uint256 index
    )
        internal
        pure
        returns (string memory body)
    {
        body = string.concat(graph.names[index], "(");
        for (uint256 f; f < graph.fields[index].length; f++) {
            uint256 kind = graph.fields[index][f];
            string memory fieldType = kind == 0
                ? "uint256"
                : kind == 1 ? "address" : kind == 2 ? "bytes32" : graph.names[kind - 3];
            body = string.concat(body, f == 0 ? "" : ",", fieldType, " f", LibString.toString(f));
        }
        body = string.concat(body, ")");
    }

    /// @notice EIP-712 `encodeData` with values drawn from the seed
    function _encodeData(
        Graph memory graph,
        uint256 index
    )
        internal
        pure
        returns (bytes memory encodeData)
    {
        for (uint256 f; f < graph.fields[index].length; f++) {
            uint256 kind = graph.fields[index][f];
            uint256 word = uint256(keccak256(abi.encode(graph.seed, "value", index, f)));
            if (kind == 1) word = uint160(word);
            if (kind >= 3) {
                word = uint256(
                    _hashStruct(_encodeType(graph, kind - 3), _encodeData(graph, kind - 3))
                );
            }
            encodeData = abi.encodePacked(encodeData, word);
        }
    }
}
