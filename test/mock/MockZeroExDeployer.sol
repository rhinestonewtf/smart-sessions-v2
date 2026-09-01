// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

/// @title MockZeroExDeployer
/// @notice Mock of the 0x deployer/registry, etched at the real registry address in tests
/// @dev Models the two behaviours the real registry has that the policy must survive:
///      `ownerOf` reverting when a feature is paused, and `prev` reverting when a feature has
///      no prior deployment. Also supports returning a giant revert payload so tests can prove
///      the policy's unbound `catch` does not copy attacker-sized returndata.
contract MockZeroExDeployer {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current Settler per feature
    mapping(uint256 feature => address settler) public owners;

    /// @notice Previous Settler per feature
    mapping(uint256 feature => address settler) public previous;

    /// @notice Whether `ownerOf` should revert for a feature (feature paused)
    mapping(uint256 feature => bool paused) public ownerReverts;

    /// @notice Whether `prev` should revert for a feature (no prior deployment)
    mapping(uint256 feature => bool missing) public prevReverts;

    /// @notice Number of 32-byte words of junk to return in a revert
    uint256 public revertBombWords;

    /*//////////////////////////////////////////////////////////////
                            CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the current Settler for a feature
    function setOwner(uint256 feature, address settler) external {
        owners[feature] = settler;
    }

    /// @notice Sets the previous Settler for a feature
    function setPrevious(uint256 feature, address settler) external {
        previous[feature] = settler;
    }

    /// @notice Makes `ownerOf` revert for a feature, simulating a paused Settler
    function setOwnerReverts(uint256 feature, bool shouldRevert) external {
        ownerReverts[feature] = shouldRevert;
    }

    /// @notice Makes `prev` revert for a feature, simulating no prior deployment
    function setPrevReverts(uint256 feature, bool shouldRevert) external {
        prevReverts[feature] = shouldRevert;
    }

    /// @notice Sets how many words of junk reverts return
    function setRevertBombWords(uint256 words) external {
        revertBombWords = words;
    }

    /*//////////////////////////////////////////////////////////////
                            REGISTRY READS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the current Settler for a feature
    function ownerOf(uint256 tokenId) external view returns (address) {
        if (ownerReverts[tokenId]) _revert();
        return owners[tokenId];
    }

    /// @notice Returns the previous Settler for a feature
    function prev(uint128 feature) external view returns (address) {
        if (prevReverts[feature]) _revert();
        return previous[feature];
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Reverts with `revertBombWords` words of returndata
    /// @dev Written in assembly so the payload size is not bounded by an error selector
    function _revert() private view {
        uint256 size = revertBombWords * 32;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let ptr := mload(0x40)
            revert(ptr, size)
        }
    }
}
