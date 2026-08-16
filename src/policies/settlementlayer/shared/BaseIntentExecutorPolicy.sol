// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

import { Types } from "@compact-utils/types/OrderTypes.sol";

import {
    IBaseIntentExecutorPolicy
} from "@policies/settlementlayer/shared/interfaces/IBaseIntentExecutorPolicy.sol";
import {
    IntentExecutorEIP712Lib
} from "@policies/settlementlayer/shared/lib/IntentExecutorEIP712Lib.sol";
import {
    IntentExecutorStorage,
    IntentExecutorStorageLib
} from "@policies/settlementlayer/shared/lib/IntentExecutorStorageLib.sol";
import {
    IntentExecutorConfigLib
} from "@policies/settlementlayer/shared/lib/IntentExecutorConfigLib.sol";
import { OpsCalldataLib } from "@policies/settlementlayer/shared/lib/OpsCalldataLib.sol";
import {
    VARIANT_SINGLE_CHAIN,
    FLAG_REQUIRE_GAS_REFUND,
    FLAG_LOCK_ACCOUNT
} from "@policies/settlementlayer/shared/types/IntentExecutorDataTypes.sol";

/// @title BaseIntentExecutorPolicy
/// @author Rhinestone
/// @notice Abstract smart-session policy that gates ERC-1271 signatures requested by the
///         Rhinestone `StandaloneIntentExecutor`. Concrete subclasses
///         (`StaticIntentExecutorPolicy`, `IntentExecutorPolicy`) own the per-call ACL.
abstract contract BaseIntentExecutorPolicy is IBaseIntentExecutorPolicy, I1271Policy {
    using IntentExecutorStorageLib for ConfigId;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                              ERC-7579 / IPolicy
    //////////////////////////////////////////////////////////////*/

    function onInstall(bytes calldata) external pure {  /* installed via multiplexer */
    }

    function onUninstall(bytes calldata) external pure {  /* state cleared lazily by SS */
    }

    /// @inheritdoc I1271Policy
    function check1271SignedAction(
        ConfigId configId,
        address,
        /* requestSender */
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
        IntentExecutorStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        if ($.intentExecutor == address(0)) {
            revert PolicyNotInitialized(configId, msg.sender, account);
        }
        return _validateClaim(configId, account, hash, data, $);
    }

    /// @notice Whether this policy is configured for an account and configuration
    /// @dev Not part of IPolicy - kept as a convenience overload. It always returns false,
    ///      because storage here is namespaced by multiplexer and this overload is not given one;
    ///      use the three-argument form.
    /// @return Always false
    function isInitialized(address, ConfigId) external pure returns (bool) {
        // Smart sessions calls the multiplexer-aware overload below; this overload is kept
        // for IPolicy completeness but cannot resolve storage without a multiplexer.
        return false;
    }

    /// @notice Whether this policy is configured for an account, multiplexer and configuration
    /// @dev Not part of IPolicy. Storage is namespaced by multiplexer, so this is the form that
    ///      can actually answer
    /// @param account The account to query
    /// @param multiplexer The multiplexer that initialized the configuration
    /// @param configId The configuration ID
    /// @return True if an intent executor has been configured
    function isInitialized(
        address account,
        address multiplexer,
        ConfigId configId
    )
        external
        view
        returns (bool)
    {
        return configId.getStorage({ account: account, multiplexer: multiplexer }).intentExecutor
            != address(0);
    }

    /// @notice Smart-session install hook. Decodes the base config, then forwards the
    ///         unconsumed tail to the subclass.
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        virtual
    {
        IntentExecutorStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        bytes calldata tail = IntentExecutorConfigLib.initializeBase($, account, initData);
        _initializeSubclass($, account, configId, tail);
    }

    /*//////////////////////////////////////////////////////////////
                                CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes the policy data blob, recomputes the IntentExecutor EIP-712 digest,
    ///         compares it to the value smart-sessions handed in, then defers to the
    ///         subclass for per-call ACL.
    /// @dev Data layout (packed):
    ///        [0]       variant            uint8   (0 = SingleChainOps; v1 only value)
    ///        [1]       hasGasRefund       uint8   (0 / 1)
    ///        [2:22]    account            address
    ///        [22:54]   nonce              uint256
    ///        ----- only when hasGasRefund == 1 -----
    ///        [54:74]   gasRefund.token            address
    ///        [74:106]  gasRefund.exchangeRate     uint256
    ///        -----
    ///        [...]     ABI-encoded `Types.Operation { bytes32 vt; Ops[] ops }`
    function _validateClaim(
        ConfigId configId,
        address account,
        bytes32 hash,
        bytes calldata data,
        IntentExecutorStorage storage $
    )
        internal
        view
        virtual
        returns (bool)
    {
        if (data.length < 54) revert DataTruncated(54, data.length);

        uint8 variant = uint8(data[0]);
        if (variant != VARIANT_SINGLE_CHAIN) revert VariantNotSupported(variant);

        uint8 hasGasRefund = uint8(data[1]);
        address blobAccount = address(bytes20(data[2:22]));
        if (blobAccount != account) revert AccountMismatch(account, blobAccount);

        uint8 flags = $.flags;
        if (flags & FLAG_LOCK_ACCOUNT != 0 && $.pinnedAccount != account) {
            revert AccountMismatch($.pinnedAccount, account);
        }

        uint256 nonce = uint256(bytes32(data[22:54]));

        bytes32 gasRefundHash;
        uint256 cursor;
        if (hasGasRefund == 0) {
            if ((flags & FLAG_REQUIRE_GAS_REFUND) != 0) revert GasRefundRequired();
            gasRefundHash = IntentExecutorEIP712Lib.noGasRefund();
            cursor = 54;
        } else {
            if (data.length < 106) revert DataTruncated(106, data.length);
            address gasToken = address(bytes20(data[54:74]));
            uint256 exchangeRate = uint256(bytes32(data[74:106]));
            _enforceGasRefund($, gasToken, exchangeRate);
            gasRefundHash = IntentExecutorEIP712Lib.hashGasRefund(gasToken, exchangeRate);
            cursor = 106;
        }

        Types.Operation calldata ops = _decodeOperation(data, cursor);

        bytes32 structHash =
            IntentExecutorEIP712Lib.structHashSingleChainOps(account, nonce, ops, gasRefundHash);
        bytes32 digest = IntentExecutorEIP712Lib.hashTypedData($.intentExecutor, structHash);
        if (digest != hash) revert DigestMismatch();

        // Pull the ERC-7579 execution array out for the subclass; this also bounds the call
        // count and rejects non-ERC7579 execution types.
        Execution[] calldata calls = OpsCalldataLib.executions(ops);

        // Hand the original `data` blob to the subclass so it can recover any extension
        // bytes appended after the Operation (e.g. multi-layer hint vectors).
        _validateOps(configId, account, $, calls, data);
        return true;
    }

    /// @notice Settlement-layer specific per-call ACL.
    /// @dev Subclasses revert on rejection with their own typed error. The `data` argument
    ///      is the same blob smart-sessions passed in; extension policies use it to read
    ///      trailing bytes.
    function _validateOps(
        ConfigId configId,
        address account,
        IntentExecutorStorage storage $,
        Execution[] calldata calls,
        bytes calldata data
    )
        internal
        view
        virtual;

    /// @notice Subclass init hook. Default no-op accepts an empty tail.
    function _initializeSubclass(
        IntentExecutorStorage storage,
        address,
        ConfigId,
        bytes calldata tail
    )
        internal
        virtual
    {
        if (tail.length != 0) revert IntentExecutorConfigLib.InvalidConfigData();
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    function _enforceGasRefund(
        IntentExecutorStorage storage $,
        address token,
        uint256 exchangeRate
    )
        internal
        view
    {
        // Whitelist is opt-in: an empty set means "any token". Once entries exist, the
        // token must be present. Reason: avoids a footgun where leaving the whitelist
        // unset silently denies everything.
        if ($.gasTokenWhitelist.length() != 0 && !$.gasTokenWhitelist.contains(token)) {
            revert GasTokenNotWhitelisted(token);
        }
        uint256 cap = $.maxExchangeRate;
        // A cap of zero means "uncapped"; the only filter is the whitelist. Setting
        // FLAG_REQUIRE_GAS_REFUND already prevents `NO_GASREFUND` from sneaking past.
        if (cap != 0 && exchangeRate > cap) revert ExchangeRateOverCap(exchangeRate, cap);
    }

    /// @notice ABI-decodes a `Types.Operation` from the policy data blob in place.
    /// @dev We can't `abi.decode(...)` into a calldata pointer directly; instead we set the
    ///      `ops` calldata reference to the head of the encoded struct and trust the
    ///      compiler-emitted bounds-checks downstream when fields are read. The encoding
    ///      matches the standard ABI for `(bytes32, (address,uint256,bytes)[])`.
    function _decodeOperation(
        bytes calldata data,
        uint256 cursor
    )
        internal
        pure
        returns (Types.Operation calldata ops)
    {
        bytes calldata tail = data[cursor:];
        // solhint-disable-next-line no-inline-assembly
        assembly {
            ops := add(tail.offset, 0x20)
        }
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    function getIntentExecutor(
        ConfigId configId,
        address account
    )
        external
        view
        override
        returns (address)
    {
        return configId.getStorage({ account: account, multiplexer: msg.sender }).intentExecutor;
    }

    function getGasTokenWhitelist(
        ConfigId configId,
        address account
    )
        external
        view
        override
        returns (address[] memory tokens)
    {
        IntentExecutorStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        uint256 n = $.gasTokenWhitelist.length();
        tokens = new address[](n);
        for (uint256 i; i < n; i++) {
            tokens[i] = $.gasTokenWhitelist.at(i);
        }
    }

    function getMaxExchangeRate(
        ConfigId configId,
        address account
    )
        external
        view
        override
        returns (uint256)
    {
        return configId.getStorage({ account: account, multiplexer: msg.sender }).maxExchangeRate;
    }

    function supportsInterface(bytes4 interfaceId) public pure virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId
            || interfaceId == type(I1271Policy).interfaceId
            || interfaceId == type(IBaseIntentExecutorPolicy).interfaceId;
    }
}
