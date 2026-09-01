// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Contracts
import { StaticcallEqualityPolicy } from "@policies/staticcall/StaticcallEqualityPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @notice Minimal view of the 0x Settler registry, an ERC-721 deployed at the same address on
///         every chain 0x supports, where the owner of a feature's tokenId is its live `Settler`
interface IZeroExDeployer {
    /// @notice Returns the live `Settler` for a feature
    /// @dev Reverts when the feature is paused, which correctly denies the action: 0x's
    ///      integration guide is explicit that a paused Settler must not be interacted with.
    /// @param tokenId The 0x feature number
    /// @return The active Settler address
    function ownerOf(uint256 tokenId) external view returns (address);
}

/// @title ZeroEx Settler Policy
/// @author Rhinestone
/// @notice Action policy requiring both `operator` and `target` of an `AllowanceHolder.exec` call
///         to be the 0x Settler that is live at validation time
/// @dev Everything is a constant and there is no constructor, so "both fields are checked" is a
///      property of this source file rather than of how someone deployed it. There is no variant
///      that pins only one of them.
///
///      That matters because `AllowanceHolder.exec` hands the pulled sell token to whatever
///      `target` names and calls it with arbitrary bytes; nothing on-chain requires that target to
///      be a Settler. `operator` is who may pull the token and `target` is who gets called with
///      it, so pinning either alone leaves the pull redirectable to an attacker-chosen contract.
///      Pinning the inner `buyToken` or `recipient` instead is not a substitute, because those
///      bytes only mean what their names say when the callee really is a Settler.
///
/// @dev WHY IT RESOLVES RATHER THAN HARDCODES: 0x redeploys `Settler` regularly and retires the
///      old one - 3 of 11 chains rotated within roughly 10 weeks - so an address frozen at install
///      time goes stale and starts rejecting legitimate swaps. Resolving through `ownerOf` means a
///      rotation takes effect with no re-initialization and no new signature from the account. The
///      cost is that quotes issued just before a rotation stop validating until re-quoted.
///
/// @dev FEATURE 2 ONLY. Feature 2 is the taker-submitted Settler, which ordinary
///      account-submitted swaps use. This does not cover 0x's metatransaction (3), intent (4) or
///      bridge (5) Settlers, and rejects calls naming them.
///
/// @dev ALLOWANCEHOLDER.EXEC ONLY. The offsets below are that function's argument layout, so this
///      is only meaningful for an actionId bound to it.
///
/// @dev ERC-4337 CAVEAT: validation staticcalls the registry, so this must not sit in a user
///      operation validation path against a public mempool. See `StaticcallEqualityPolicy`.
contract ZeroExSettlerPolicy is StaticcallEqualityPolicy {
    /// @notice The 0x Settler registry. Only the Settler behind it moves; this address is stable.
    address internal constant REGISTRY = 0x00000000000004533Fe15556B1E086BB1A72cEae;

    /// @notice 0x feature id for the taker-submitted Settler
    uint256 internal constant SETTLER_FEATURE_ID = 2;

    /// @dev Argument-relative offsets in
    ///      `exec(address operator, address token, uint256 amount, address target, bytes data)`
    uint256 internal constant OPERATOR_OFFSET = 0;
    uint256 internal constant TARGET_OFFSET = 96;

    /// @inheritdoc StaticcallEqualityPolicy
    /// @notice Resolves the live taker-submitted Settler from the 0x registry
    /// @dev Uses `abi.encodeCall` for compiler-checked construction, so the selector and the
    ///      argument cannot drift apart, but keeps a low-level `.staticcall` so failure stays an
    ///      explicit `if` rather than a language subtlety. A `try/catch` on a typed call is
    ///      avoided deliberately: a call to a codeless address succeeds at the EVM level with
    ///      empty returndata, and whether Solidity's inserted `extcodesize` check and a decode
    ///      failure land in the `catch` is compiler-version dependent.
    ///
    ///      The length check is what makes this fail closed. A codeless registry - the case on any
    ///      chain where 0x is not deployed - returns success with empty returndata, which would
    ///      otherwise be read as a zero word and matched by zeroed calldata.
    /// @return The live Settler as a raw word, and whether it could be resolved
    function _readExpected() internal view override returns (bytes32, bool) {
        bytes memory callData = abi.encodeCall(IZeroExDeployer.ownerOf, (SETTLER_FEATURE_ID));

        (bool success, bytes memory result) = REGISTRY.staticcall(callData);
        if (!success || result.length != WORD_SIZE) return (bytes32(0), false);

        bytes32 word;
        assembly ("memory-safe") {
            word := mload(add(result, 0x20))
        }

        return (word, true);
    }

    /// @inheritdoc StaticcallEqualityPolicy
    /// @notice Requires both `operator` and `target` to be the live Settler
    /// @dev Does not check the target or selector of `data`: smart sessions derive the actionId
    ///      from (target, selector) and only route matching calls here. Installing this under the
    ///      fallback actionId removes that binding and pins meaningless words.
    /// @param data The full calldata of the action, including its 4-byte selector
    /// @return VALIDATION_SUCCESS if both fields match, VALIDATION_FAILED otherwise
    function checkAction(
        ConfigId, /* id */
        address, /* account */
        address, /* target */
        uint256, /* value */
        bytes calldata data
    )
        external
        view
        override
        returns (uint256)
    {
        (bytes32 expected, bool ok) = _readExpected();
        if (!ok) return VALIDATION_FAILED;

        if (!_wordEquals(data, OPERATOR_OFFSET, expected)) return VALIDATION_FAILED;
        if (!_wordEquals(data, TARGET_OFFSET, expected)) return VALIDATION_FAILED;

        return VALIDATION_SUCCESS;
    }
}
